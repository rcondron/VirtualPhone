/*
 * ril_shim.c — Android RIL shim for VirtualPhone
 *
 * Replaces the stock rild inside redroid. It:
 * 1. Creates the /dev/socket/rild Unix socket that Android RILJ connects to
 * 2. Opens a TCP connection to the vphone RIL bridge (port 18000)
 * 3. Translates Android Parcel-encoded RIL messages ↔ JSON
 *
 * Android Parcel wire format:
 *   Outer framing: [4-byte big-endian length][payload]
 *   Request payload: [int32le request_id][int32le token][data...]
 *   Solicited response: [int32le 0][int32le token][int32le error][data...]
 *   Unsolicited response: [int32le 1][int32le response_id][data...]
 *
 * Reference: AOSP hardware/ril/libril/ril.cpp, ril.h
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/stat.h>

/* -------------------------------------------------------------------
 * Configuration
 * ------------------------------------------------------------------- */
#define RIL_SOCKET_PATH  "/dev/socket/rild"
#define BRIDGE_PORT      18000
#define MAX_MSG_SIZE     (256 * 1024)
#define JSON_BUF_SIZE    8192
#define PARCEL_INIT_CAP  4096

/* Bridge host comes from environment or defaults to vphone container */
static char bridge_host[256] = "172.28.0.20";

/* RIL request IDs (ril.h) */
#define RIL_REQUEST_GET_SIM_STATUS        1
#define RIL_REQUEST_ENTER_SIM_PIN         2
#define RIL_REQUEST_GET_CURRENT_CALLS     9
#define RIL_REQUEST_DIAL                  10
#define RIL_REQUEST_GET_IMSI              11
#define RIL_REQUEST_HANGUP                12
#define RIL_REQUEST_SIGNAL_STRENGTH       19
#define RIL_REQUEST_VOICE_REG_STATE       20
#define RIL_REQUEST_DATA_REG_STATE        21
#define RIL_REQUEST_OPERATOR              22
#define RIL_REQUEST_RADIO_POWER           23
#define RIL_REQUEST_SEND_SMS              25
#define RIL_REQUEST_SIM_IO                28
#define RIL_REQUEST_GET_IMEI              38
#define RIL_REQUEST_ANSWER                40
#define RIL_REQUEST_DATA_CALL_LIST        57
#define RIL_REQUEST_SET_INITIAL_ATTACH_APN 111
#define RIL_REQUEST_SIM_AUTHENTICATION    125
#define RIL_REQUEST_SET_DATA_PROFILE      128

/* RIL unsolicited IDs */
#define RIL_UNSOL_RADIO_STATE_CHANGED          1000
#define RIL_UNSOL_NETWORK_STATE_CHANGED        1001
#define RIL_UNSOL_CALL_RING                    1002
#define RIL_UNSOL_NEW_SMS                      1003
#define RIL_UNSOL_NITZ_TIME_RECEIVED           1008
#define RIL_UNSOL_SIM_STATUS_CHANGED           1019

/* RIL response types */
#define RESPONSE_SOLICITED    0
#define RESPONSE_UNSOLICITED  1

/* RIL errors */
#define RIL_E_SUCCESS                 0
#define RIL_E_GENERIC_FAILURE         2
#define RIL_E_REQUEST_NOT_SUPPORTED   6

/* -------------------------------------------------------------------
 * Logging
 * ------------------------------------------------------------------- */
#define LOG_TAG "ril_shim"
#define LOGI(...) do { fprintf(stderr, LOG_TAG ": INFO  "); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } while(0)
#define LOGW(...) do { fprintf(stderr, LOG_TAG ": WARN  "); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } while(0)
#define LOGE(...) do { fprintf(stderr, LOG_TAG ": ERROR "); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } while(0)

/* -------------------------------------------------------------------
 * Parcel buffer — little-endian int32 and UTF-16LE strings
 * ------------------------------------------------------------------- */
typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   len;  /* write position */
    size_t   pos;  /* read position */
} parcel_t;

static void parcel_init(parcel_t *p, size_t cap) {
    p->buf = (uint8_t *)calloc(1, cap);
    p->cap = cap;
    p->len = 0;
    p->pos = 0;
}

static void parcel_free(parcel_t *p) {
    free(p->buf);
    p->buf = NULL;
    p->cap = p->len = p->pos = 0;
}

static void parcel_ensure(parcel_t *p, size_t need) {
    while (p->len + need > p->cap) {
        p->cap *= 2;
        p->buf = (uint8_t *)realloc(p->buf, p->cap);
    }
}

static int32_t parcel_read_i32(parcel_t *p) {
    if (p->pos + 4 > p->len) return 0;
    int32_t v;
    memcpy(&v, p->buf + p->pos, 4); /* little-endian on x86 */
    p->pos += 4;
    return v;
}

static void parcel_write_i32(parcel_t *p, int32_t v) {
    parcel_ensure(p, 4);
    memcpy(p->buf + p->len, &v, 4);
    p->len += 4;
}

/*
 * Read a Parcel String16: int32 char_count, then UTF-16LE chars + null + pad.
 * Returns a malloc'd UTF-8 string (caller must free), or NULL for Parcel null.
 */
static char *parcel_read_str16(parcel_t *p) {
    int32_t char_count = parcel_read_i32(p);
    if (char_count < 0) return NULL;  /* null string */

    /* UTF-16LE data: char_count chars + null terminator (2 bytes each) */
    size_t byte_len = ((size_t)char_count + 1) * 2;
    /* Pad to 4-byte boundary */
    size_t padded = (byte_len + 3) & ~(size_t)3;

    if (p->pos + padded > p->len) {
        p->pos = p->len;
        return NULL;
    }

    /* Simple UTF-16LE → ASCII conversion (sufficient for IMSI/IMEI/operators) */
    char *out = (char *)malloc(char_count + 1);
    for (int32_t i = 0; i < char_count; i++) {
        uint16_t c;
        memcpy(&c, p->buf + p->pos + i * 2, 2);
        out[i] = (c < 128) ? (char)c : '?';
    }
    out[char_count] = '\0';
    p->pos += padded;
    return out;
}

/*
 * Write a Parcel String16 from a UTF-8 string.
 */
static void parcel_write_str16(parcel_t *p, const char *s) {
    if (!s) {
        parcel_write_i32(p, -1);
        return;
    }
    int32_t char_count = (int32_t)strlen(s);
    parcel_write_i32(p, char_count);

    size_t byte_len = ((size_t)char_count + 1) * 2;
    size_t padded = (byte_len + 3) & ~(size_t)3;
    parcel_ensure(p, padded);

    for (int32_t i = 0; i < char_count; i++) {
        uint16_t c = (uint8_t)s[i];
        memcpy(p->buf + p->len, &c, 2);
        p->len += 2;
    }
    /* null terminator */
    uint16_t zero = 0;
    memcpy(p->buf + p->len, &zero, 2);
    p->len += 2;
    /* padding */
    while (p->len % 4) {
        p->buf[p->len++] = 0;
    }
}

/* -------------------------------------------------------------------
 * JSON helpers — nesting-aware key lookup
 *
 * These helpers only match keys at the CURRENT nesting depth (depth 0
 * relative to the start of the supplied string). This prevents
 * mis-parsing when nested objects contain duplicate key names.
 * ------------------------------------------------------------------- */

/* Build a JSON request: {"type":0,"serial":N,"id":N,"data":{...}} */
static int json_build(char *buf, size_t cap, int msg_type, int serial,
                      int request_id, const char *data_json) {
    return snprintf(buf, cap,
        "{\"type\":%d,\"serial\":%d,\"id\":%d,\"data\":%s}",
        msg_type, serial, request_id, data_json ? data_json : "{}");
}

/*
 * Find the value position for `key` at the current nesting depth.
 * Tracks { } [ ] depth so that keys inside nested objects are skipped.
 * Returns a pointer to the first non-whitespace character of the value,
 * or NULL if the key was not found at depth 0.
 */
static const char *json_find_key(const char *json, const char *key) {
    if (!json || !key) return NULL;

    size_t key_len = strlen(key);
    int depth = 0;
    const char *p = json;
    int in_string = 0;

    while (*p) {
        /* Handle string literals — skip their contents */
        if (*p == '"' && (p == json || *(p - 1) != '\\')) {
            if (in_string) {
                in_string = 0;
                p++;
                continue;
            }
            /* Start of a string — check if this is our key at depth 1
             * (depth 1 = inside the outermost { }) */
            if (depth == 1) {
                /* Compare the key name */
                if (strncmp(p + 1, key, key_len) == 0 && *(p + 1 + key_len) == '"') {
                    /* Found key — skip past `"key":` */
                    const char *after = p + 1 + key_len + 1; /* past closing " */
                    while (*after == ' ' || *after == '\t' || *after == '\n' || *after == '\r') after++;
                    if (*after == ':') {
                        after++;
                        while (*after == ' ' || *after == '\t' || *after == '\n' || *after == '\r') after++;
                        return after;
                    }
                }
            }
            in_string = 1;
            p++;
            continue;
        }
        if (in_string) {
            p++;
            continue;
        }
        if (*p == '{' || *p == '[') depth++;
        else if (*p == '}' || *p == ']') depth--;
        p++;
    }
    return NULL;
}

/* Extract an integer value for a key (nesting-aware). */
static int json_get_int(const char *json, const char *key, int def) {
    const char *val = json_find_key(json, key);
    if (!val) return def;
    return atoi(val);
}

/* Extract a string value for a key (nesting-aware). Returns malloc'd string. */
static char *json_get_str(const char *json, const char *key) {
    const char *val = json_find_key(json, key);
    if (!val || *val != '"') return NULL;
    val++; /* skip opening " */
    /* Find the closing quote, handling escaped quotes */
    const char *end = val;
    while (*end && !(*end == '"' && *(end - 1) != '\\')) end++;
    if (*end != '"') return NULL;
    size_t len = end - val;
    char *out = (char *)malloc(len + 1);
    memcpy(out, val, len);
    out[len] = '\0';
    return out;
}

/* Check if a JSON boolean key is true (nesting-aware). */
static int json_get_bool(const char *json, const char *key, int def) {
    const char *val = json_find_key(json, key);
    if (!val) return def;
    if (strncmp(val, "true", 4) == 0) return 1;
    if (strncmp(val, "false", 5) == 0) return 0;
    return atoi(val);
}

/* -------------------------------------------------------------------
 * TCP bridge connection
 * ------------------------------------------------------------------- */
static int bridge_connect(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(BRIDGE_PORT);
    if (inet_pton(AF_INET, bridge_host, &addr.sin_addr) <= 0) {
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    LOGI("Connected to RIL bridge at %s:%d", bridge_host, BRIDGE_PORT);
    return fd;
}

/* Send a length-prefixed JSON message over TCP */
static int bridge_send(int fd, const char *json) {
    uint32_t len = htonl((uint32_t)strlen(json));
    if (write(fd, &len, 4) != 4) return -1;
    size_t total = strlen(json);
    size_t sent = 0;
    while (sent < total) {
        ssize_t n = write(fd, json + sent, total - sent);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

/* Receive a length-prefixed JSON response over TCP */
static char *bridge_recv(int fd) {
    uint32_t net_len;
    if (read(fd, &net_len, 4) != 4) return NULL;
    uint32_t len = ntohl(net_len);
    if (len > MAX_MSG_SIZE) return NULL;

    char *buf = (char *)malloc(len + 1);
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) { free(buf); return NULL; }
        got += n;
    }
    buf[len] = '\0';
    return buf;
}

/*
 * Send request and get response from the bridge.
 * bridge_fd_ptr is a pointer to allow reconnection on failure.
 * On bridge disconnect, attempts to reconnect with exponential backoff
 * (up to 4 retries: 1s, 2s, 4s, 8s) before giving up.
 */
static char *bridge_request(int *bridge_fd_ptr, int request_id, int serial,
                            const char *data_json) {
    char json[JSON_BUF_SIZE];
    json_build(json, sizeof(json), 0, serial, request_id,
               data_json ? data_json : "{}");

    for (int retry = 0; retry <= 4; retry++) {
        if (*bridge_fd_ptr >= 0) {
            if (bridge_send(*bridge_fd_ptr, json) == 0) {
                char *resp = bridge_recv(*bridge_fd_ptr);
                if (resp) return resp;
            }
            /* Send or recv failed — bridge connection is dead */
            LOGW("Bridge connection lost (attempt %d/4)", retry + 1);
            close(*bridge_fd_ptr);
            *bridge_fd_ptr = -1;
        }

        if (retry >= 4) break;

        /* Exponential backoff: 1s, 2s, 4s, 8s */
        unsigned int delay = 1u << retry;
        LOGI("Reconnecting to bridge in %us...", delay);
        sleep(delay);

        *bridge_fd_ptr = bridge_connect();
    }

    LOGE("Bridge reconnection failed after 4 retries");
    return NULL;
}

/* -------------------------------------------------------------------
 * RIL Parcel ↔ JSON translation per request type
 * ------------------------------------------------------------------- */

/* Extract the "data" object from a bridge JSON response */
static const char *json_find_data(const char *json) {
    const char *p = strstr(json, "\"data\":");
    if (!p) return "{}";
    p += 7;
    while (*p == ' ') p++;
    return p;
}

/*
 * Build solicited response Parcel:
 *   int32 RESPONSE_SOLICITED (0)
 *   int32 token
 *   int32 error
 *   ... response data (per request type)
 */
static void response_sim_status(parcel_t *resp, const char *data) {
    /* RIL_CardStatus_v6:
     *   cardState, universalPinState, gsmUmtsSubscriptionAppIndex,
     *   cdmaSubscriptionAppIndex, imsSubscriptionAppIndex, numApplications
     *   [for each app: appType, appState, persoSubstate, aidPtr, appLabelPtr,
     *    pin1Replaced, pin1, pin2]
     */
    int card_state = json_get_int(data, "cardState", 0);
    parcel_write_i32(resp, card_state);   /* cardState */
    parcel_write_i32(resp, 5);            /* universalPinState: READY */
    parcel_write_i32(resp, 0);            /* gsmUmtsSubscriptionAppIndex */
    parcel_write_i32(resp, -1);           /* cdmaSubscriptionAppIndex */
    parcel_write_i32(resp, 1);            /* imsSubscriptionAppIndex */

    if (card_state == 1) {
        /* Card present — 2 applications (USIM + ISIM) */
        parcel_write_i32(resp, 2);        /* numApplications */

        /* App 0: USIM */
        parcel_write_i32(resp, 2);        /* appType: USIM */
        parcel_write_i32(resp, 5);        /* appState: READY */
        parcel_write_i32(resp, 0);        /* persoSubstate: UNKNOWN */
        parcel_write_str16(resp, "A0000000871002"); /* aidPtr */
        parcel_write_str16(resp, "USIM"); /* appLabelPtr */
        parcel_write_i32(resp, 0);        /* pin1Replaced */
        parcel_write_i32(resp, 0);        /* pin1 */
        parcel_write_i32(resp, 0);        /* pin2 */

        /* App 1: ISIM */
        parcel_write_i32(resp, 4);        /* appType: ISIM */
        parcel_write_i32(resp, 5);        /* appState: READY */
        parcel_write_i32(resp, 0);        /* persoSubstate */
        parcel_write_str16(resp, "A0000000871004");
        parcel_write_str16(resp, "ISIM");
        parcel_write_i32(resp, 0);
        parcel_write_i32(resp, 0);
        parcel_write_i32(resp, 0);
    } else {
        parcel_write_i32(resp, 0);        /* numApplications */
    }
}

static void response_string_key(parcel_t *resp, const char *data, const char *key) {
    /* Response is a single string, extracted by a specific key */
    char *val = json_get_str(data, key);
    parcel_write_str16(resp, val);
    free(val);
}

static void response_operator(parcel_t *resp, const char *data) {
    /* 3 strings: longName, shortName, numeric */
    parcel_write_i32(resp, 3); /* num_strings */
    char *s;
    s = json_get_str(data, "longName");
    parcel_write_str16(resp, s ? s : "Virtual Operator");
    free(s);
    s = json_get_str(data, "shortName");
    parcel_write_str16(resp, s ? s : "Virtual");
    free(s);
    s = json_get_str(data, "numeric");
    parcel_write_str16(resp, s ? s : "00101");
    free(s);
}

static void response_signal_strength(parcel_t *resp, const char *data) {
    /* GW signal strength (2 ints) */
    parcel_write_i32(resp, 99);  /* signalStrength (unknown) */
    parcel_write_i32(resp, 99);  /* bitErrorRate (unknown) */
    /* CDMA signal strength (2 ints) */
    parcel_write_i32(resp, -1);
    parcel_write_i32(resp, -1);
    /* EVDO signal strength (3 ints) */
    parcel_write_i32(resp, -1);
    parcel_write_i32(resp, -1);
    parcel_write_i32(resp, -1);
    /* LTE signal strength (6 ints) */
    parcel_write_i32(resp, 15);  /* signalStrength (0-31) */
    parcel_write_i32(resp, json_get_int(data, "rsrp", -95));
    parcel_write_i32(resp, json_get_int(data, "rsrq", -10));
    parcel_write_i32(resp, json_get_int(data, "rssnr", 100));
    parcel_write_i32(resp, json_get_int(data, "cqi", 10));
    parcel_write_i32(resp, 0);   /* timingAdvance */
    /* TD-SCDMA (1 int) */
    parcel_write_i32(resp, 99);
}

static void response_reg_state(parcel_t *resp, const char *data) {
    /* Registration state: num_strings then string values */
    parcel_write_i32(resp, 15); /* num_strings */
    char tmp[32];
    int reg = json_get_int(data, "regState", 0);
    snprintf(tmp, sizeof(tmp), "%d", reg);
    parcel_write_str16(resp, tmp);  /* [0] regState */
    parcel_write_str16(resp, "");   /* [1] lac */
    parcel_write_str16(resp, "");   /* [2] cid */
    int rat = json_get_int(data, "rat", 0);
    snprintf(tmp, sizeof(tmp), "%d", rat);
    parcel_write_str16(resp, tmp);  /* [3] radioTechnology */
    parcel_write_str16(resp, "");   /* [4] baseStationId */
    parcel_write_str16(resp, "");   /* [5] baseStationLat */
    parcel_write_str16(resp, "");   /* [6] baseStationLon */
    parcel_write_str16(resp, "");   /* [7] cssSupported */
    parcel_write_str16(resp, "");   /* [8] systemId */
    parcel_write_str16(resp, "");   /* [9] networkId */
    parcel_write_str16(resp, "");   /* [10] roaming */
    parcel_write_str16(resp, "");   /* [11] systemIsInPrl */
    parcel_write_str16(resp, "");   /* [12] defaultRoaming */
    parcel_write_str16(resp, "");   /* [13] reasonForDenial */
    char *mcc = json_get_str(data, "mcc");
    char *mnc = json_get_str(data, "mnc");
    char mccmnc[16] = "";
    if (mcc && mnc) snprintf(mccmnc, sizeof(mccmnc), "%s%s", mcc, mnc);
    parcel_write_str16(resp, mccmnc); /* [14] psc / mccmnc */
    free(mcc);
    free(mnc);
}

static void response_sim_io(parcel_t *resp, const char *data) {
    /* RIL_SIM_IO_Response: sw1, sw2, simResponse (string) */
    parcel_write_i32(resp, json_get_int(data, "sw1", 0x90));
    parcel_write_i32(resp, json_get_int(data, "sw2", 0x00));
    char *sim_resp = json_get_str(data, "simResponse");
    parcel_write_str16(resp, sim_resp);
    free(sim_resp);
}

static void response_void(parcel_t *resp, const char *data) {
    /* No response data */
    (void)data;
}

/* -------------------------------------------------------------------
 * Request Parcel → JSON data extraction
 * ------------------------------------------------------------------- */
static char *request_data_radio_power(parcel_t *req) {
    int32_t count = parcel_read_i32(req);
    int32_t on = (count > 0) ? parcel_read_i32(req) : 1;
    char *json = (char *)malloc(64);
    snprintf(json, 64, "{\"on\":%s}", on ? "true" : "false");
    return json;
}

static char *request_data_sim_io(parcel_t *req) {
    int32_t cmd   = parcel_read_i32(req);
    int32_t fileid = parcel_read_i32(req);
    char *path    = parcel_read_str16(req);
    int32_t p1    = parcel_read_i32(req);
    int32_t p2    = parcel_read_i32(req);
    int32_t p3    = parcel_read_i32(req);
    char *data    = parcel_read_str16(req);
    char *pin2    = parcel_read_str16(req);
    char *aid     = parcel_read_str16(req);

    char *json = (char *)malloc(JSON_BUF_SIZE);
    snprintf(json, JSON_BUF_SIZE,
        "{\"command\":%d,\"fileId\":%d,\"path\":\"%s\","
        "\"p1\":%d,\"p2\":%d,\"p3\":%d,"
        "\"data\":\"%s\",\"pin2\":\"%s\",\"aid\":\"%s\"}",
        cmd, fileid, path ? path : "",
        p1, p2, p3,
        data ? data : "", pin2 ? pin2 : "", aid ? aid : "");

    free(path); free(data); free(pin2); free(aid);
    return json;
}

static char *request_data_sim_auth(parcel_t *req) {
    int32_t auth_context = parcel_read_i32(req);
    char *auth_data = parcel_read_str16(req);
    char *aid = parcel_read_str16(req);

    char *json = (char *)malloc(JSON_BUF_SIZE);
    snprintf(json, JSON_BUF_SIZE,
        "{\"authContext\":%d,\"authData\":\"%s\",\"aid\":\"%s\"}",
        auth_context, auth_data ? auth_data : "", aid ? aid : "");

    free(auth_data); free(aid);
    return json;
}

static char *request_data_send_sms(parcel_t *req) {
    int32_t count = parcel_read_i32(req);
    char *smsc_pdu = (count > 0) ? parcel_read_str16(req) : NULL;
    char *pdu      = (count > 1) ? parcel_read_str16(req) : NULL;

    char *json = (char *)malloc(JSON_BUF_SIZE);
    snprintf(json, JSON_BUF_SIZE,
        "{\"smscPdu\":\"%s\",\"pdu\":\"%s\"}",
        smsc_pdu ? smsc_pdu : "", pdu ? pdu : "");

    free(smsc_pdu); free(pdu);
    return json;
}

static char *request_data_enter_pin(parcel_t *req) {
    int32_t count = parcel_read_i32(req);
    char *pin = (count > 0) ? parcel_read_str16(req) : NULL;
    char *aid = (count > 1) ? parcel_read_str16(req) : NULL;

    char *json = (char *)malloc(256);
    snprintf(json, 256, "{\"pin\":\"%s\",\"aid\":\"%s\"}",
             pin ? pin : "", aid ? aid : "");

    free(pin); free(aid);
    return json;
}

static char *request_data_dial(parcel_t *req) {
    /* RIL_Dial: address (String16), clir (int32), uusInfo (ignored) */
    char *address = parcel_read_str16(req);
    int32_t clir  = parcel_read_i32(req);

    char *json = (char *)malloc(JSON_BUF_SIZE);
    snprintf(json, JSON_BUF_SIZE,
        "{\"address\":\"%s\",\"clir\":%d}",
        address ? address : "", clir);

    free(address);
    return json;
}

static char *request_data_hangup(parcel_t *req) {
    /* RIL_Hangup: gsmIndex (int32) */
    int32_t gsm_index = parcel_read_i32(req);

    char *json = (char *)malloc(64);
    snprintf(json, 64, "{\"gsmIndex\":%d}", gsm_index);
    return json;
}

/* -------------------------------------------------------------------
 * Additional response writers
 * ------------------------------------------------------------------- */

static void response_send_sms(parcel_t *resp, const char *data) {
    /* RIL_SMS_Response: messageRef (int32), ackPdu (String16), errorCode (int32) */
    parcel_write_i32(resp, json_get_int(data, "messageRef", 0));
    char *ack_pdu = json_get_str(data, "ackPdu");
    parcel_write_str16(resp, ack_pdu);
    free(ack_pdu);
    parcel_write_i32(resp, json_get_int(data, "errorCode", 0));
}

/*
 * Parse a JSON array of call objects and write RIL_Call Parcels.
 * The bridge returns: {"calls":[{state, index, isMT, isMpty, number, ...},...]}
 *
 * RIL getCurrentCalls response:
 *   int32 num_calls
 *   For each call:
 *     int32 state, int32 index, int32 toa, int32 isMpty,
 *     int32 isMT, int32 als, int32 isVoice, int32 isVoicePrivacy,
 *     String16 number, int32 numberPresentation, String16 name,
 *     int32 namePresentation, int32 hasUusInfo(0)
 */
/*
 * Find the end of a JSON object starting at `p` (which points to '{').
 * Tracks nested { } and string literals to find the balanced closing '}'.
 * Returns pointer to the closing '}', or NULL if not found.
 */
static const char *json_skip_object(const char *p) {
    if (!p || *p != '{') return NULL;
    const char *start = p;
    int depth = 0;
    int in_str = 0;
    while (*p) {
        if (*p == '"' && (p == start || *(p - 1) != '\\')) {
            in_str = !in_str;
        } else if (!in_str) {
            if (*p == '{') depth++;
            else if (*p == '}') { depth--; if (depth == 0) return p; }
        }
        p++;
    }
    return NULL;
}

/*
 * Parse call objects from a JSON array. Uses bracket-balanced parsing
 * to correctly handle nested objects (e.g. call objects containing
 * sub-objects). Each top-level object in the array is extracted as a
 * null-terminated substring and parsed with json_get_int/str.
 */
static void response_current_calls(parcel_t *resp, const char *data) {
    /* Find the calls array */
    const char *arr_start = strstr(data, "[");
    if (!arr_start) {
        parcel_write_i32(resp, 0);
        return;
    }

    /* First pass: count call objects using balanced bracket parsing */
    int num_calls = 0;
    const char *scan = arr_start + 1;
    while (*scan) {
        while (*scan == ' ' || *scan == ',' || *scan == '\n' || *scan == '\r' || *scan == '\t') scan++;
        if (*scan == ']' || *scan == '\0') break;
        if (*scan == '{') {
            const char *end = json_skip_object(scan);
            if (!end) break;
            num_calls++;
            scan = end + 1;
        } else {
            break;
        }
    }

    parcel_write_i32(resp, num_calls);
    if (num_calls == 0) return;

    /* Second pass: extract each call object */
    scan = arr_start + 1;
    for (int i = 0; i < num_calls; i++) {
        while (*scan == ' ' || *scan == ',' || *scan == '\n' || *scan == '\r' || *scan == '\t') scan++;
        if (*scan != '{') break;

        const char *obj_end = json_skip_object(scan);
        if (!obj_end) break;

        size_t obj_len = obj_end - scan + 1;
        char *call_json = (char *)malloc(obj_len + 1);
        memcpy(call_json, scan, obj_len);
        call_json[obj_len] = '\0';

        parcel_write_i32(resp, json_get_int(call_json, "state", 0));
        parcel_write_i32(resp, json_get_int(call_json, "index", i + 1));
        parcel_write_i32(resp, 145);    /* TOA: international */
        parcel_write_i32(resp, json_get_bool(call_json, "isMpty", 0));
        parcel_write_i32(resp, json_get_bool(call_json, "isMT", 0));
        parcel_write_i32(resp, 0);      /* als */
        parcel_write_i32(resp, 1);      /* isVoice = true */
        parcel_write_i32(resp, 0);      /* isVoicePrivacy */

        char *number = json_get_str(call_json, "number");
        parcel_write_str16(resp, number ? number : "");
        free(number);

        parcel_write_i32(resp, json_get_int(call_json, "numberPresentation", 0));

        char *name = json_get_str(call_json, "name");
        parcel_write_str16(resp, name ? name : "");
        free(name);

        parcel_write_i32(resp, 0);      /* namePresentation */
        parcel_write_i32(resp, 0);      /* hasUusInfo = false */

        free(call_json);
        scan = obj_end + 1;
    }
}

static void response_data_call_list(parcel_t *resp, const char *data) {
    /* DataCallResponse: count of active data calls, each with:
     *   status, suggestedRetryTime, cid, active, type, ifname, addresses,
     *   dnses, gateways, pcscf, mtu
     * Simplified: just return count=0 or count=1 with default values. */
    int active = json_get_int(data, "active", 0);
    if (active == 0 && !strstr(data, "\"cid\"")) {
        parcel_write_i32(resp, 0); /* version */
        parcel_write_i32(resp, 0); /* num calls */
        return;
    }
    parcel_write_i32(resp, 11);    /* version */
    parcel_write_i32(resp, 1);     /* num calls */
    parcel_write_i32(resp, 0);     /* status: SUCCESS */
    parcel_write_i32(resp, -1);    /* suggestedRetryTime */
    parcel_write_i32(resp, json_get_int(data, "cid", 1));
    parcel_write_i32(resp, json_get_int(data, "active", 2));
    parcel_write_str16(resp, "IP");          /* type */
    parcel_write_str16(resp, "rmnet0");      /* ifname */
    parcel_write_str16(resp, "10.45.0.2");   /* addresses */
    parcel_write_str16(resp, "172.28.0.50"); /* dnses */
    parcel_write_str16(resp, "10.45.0.1");   /* gateways */
    parcel_write_str16(resp, "");             /* pcscf */
    parcel_write_i32(resp, 1500);             /* mtu */
}

/* -------------------------------------------------------------------
 * Main request handler
 * ------------------------------------------------------------------- */
typedef void (*response_writer_t)(parcel_t *, const char *);

static void handle_request(int client_fd, int *bridge_fd_ptr,
                           const uint8_t *payload, size_t payload_len) {
    parcel_t req;
    parcel_init(&req, payload_len + 16);
    memcpy(req.buf, payload, payload_len);
    req.len = payload_len;

    int32_t request_id = parcel_read_i32(&req);
    int32_t token      = parcel_read_i32(&req);

    LOGI("RIL request: id=%d token=%d", request_id, token);

    /* Extract request-specific data as JSON */
    char *data_json = NULL;
    response_writer_t writer = response_void;

    switch (request_id) {
    case RIL_REQUEST_GET_SIM_STATUS:
        writer = response_sim_status;
        break;
    case RIL_REQUEST_GET_IMSI:
        /* Response handled specially below (single string by key) */
        break;
    case RIL_REQUEST_OPERATOR:
        writer = response_operator;
        break;
    case RIL_REQUEST_RADIO_POWER:
        data_json = request_data_radio_power(&req);
        break;
    case RIL_REQUEST_SIGNAL_STRENGTH:
        writer = response_signal_strength;
        break;
    case RIL_REQUEST_VOICE_REG_STATE:
    case RIL_REQUEST_DATA_REG_STATE:
        writer = response_reg_state;
        break;
    case RIL_REQUEST_SIM_IO:
        data_json = request_data_sim_io(&req);
        writer = response_sim_io;
        break;
    case RIL_REQUEST_SIM_AUTHENTICATION:
        data_json = request_data_sim_auth(&req);
        writer = response_sim_io;
        break;
    case RIL_REQUEST_SEND_SMS:
        data_json = request_data_send_sms(&req);
        writer = response_send_sms;
        break;
    case RIL_REQUEST_ENTER_SIM_PIN:
        data_json = request_data_enter_pin(&req);
        break;
    case RIL_REQUEST_GET_IMEI:
        /* Response handled specially below (single string by key) */
        break;
    case RIL_REQUEST_GET_CURRENT_CALLS:
        writer = response_current_calls;
        break;
    case RIL_REQUEST_DIAL:
        data_json = request_data_dial(&req);
        break;
    case RIL_REQUEST_HANGUP:
        data_json = request_data_hangup(&req);
        break;
    case RIL_REQUEST_ANSWER:
        /* ANSWER has no request data */
        break;
    case RIL_REQUEST_DATA_CALL_LIST:
        writer = response_data_call_list;
        break;
    case RIL_REQUEST_SET_INITIAL_ATTACH_APN:
    case RIL_REQUEST_SET_DATA_PROFILE:
        break;
    default:
        LOGW("Unsupported RIL request: %d", request_id);
        break;
    }

    /* Forward to bridge (bridge_fd_ptr allows reconnection on failure) */
    char *resp_json = bridge_request(bridge_fd_ptr, request_id, token, data_json);
    free(data_json);

    /* Build response Parcel */
    parcel_t resp;
    parcel_init(&resp, PARCEL_INIT_CAP);

    parcel_write_i32(&resp, RESPONSE_SOLICITED);
    parcel_write_i32(&resp, token);

    if (resp_json) {
        const char *data_part = json_find_data(resp_json);
        /* Check for error */
        if (strstr(data_part, "REQUEST_NOT_SUPPORTED")) {
            parcel_write_i32(&resp, RIL_E_REQUEST_NOT_SUPPORTED);
        } else {
            parcel_write_i32(&resp, RIL_E_SUCCESS);
            /* Write response-type-specific data */
            if (request_id == RIL_REQUEST_GET_IMSI) {
                /* IMSI: extract from "imsi" key */
                char *imsi = json_get_str(data_part, "imsi");
                parcel_write_str16(&resp, imsi);
                free(imsi);
            } else if (request_id == RIL_REQUEST_GET_IMEI) {
                char *imei = json_get_str(data_part, "imei");
                parcel_write_str16(&resp, imei ? imei : "358240051111110");
                free(imei);
            } else {
                writer(&resp, data_part);
            }
        }
        free(resp_json);
    } else {
        parcel_write_i32(&resp, RIL_E_GENERIC_FAILURE);
    }

    /* Send length-prefixed response */
    uint32_t net_len = htonl((uint32_t)resp.len);
    write(client_fd, &net_len, 4);
    write(client_fd, resp.buf, resp.len);

    parcel_free(&resp);
    parcel_free(&req);
}

/* -------------------------------------------------------------------
 * Unsolicited indication forwarder
 *
 * Listens on the bridge TCP connection for unsolicited messages and
 * forwards them to the Android client.
 * ------------------------------------------------------------------- */
struct unsol_ctx {
    int client_fd;
    int bridge_fd;
};

static void send_unsolicited(int client_fd, int indication_id, const char *data) {
    parcel_t resp;
    parcel_init(&resp, PARCEL_INIT_CAP);

    parcel_write_i32(&resp, RESPONSE_UNSOLICITED);
    parcel_write_i32(&resp, indication_id);

    switch (indication_id) {
    case RIL_UNSOL_RADIO_STATE_CHANGED:
        parcel_write_i32(&resp, json_get_int(data, "radioState", 10));
        break;
    case RIL_UNSOL_NETWORK_STATE_CHANGED:
    case RIL_UNSOL_SIM_STATUS_CHANGED:
        /* No additional data */
        break;
    case RIL_UNSOL_CALL_RING:
        /* isGsm (int32) — for VoLTE calls, isGsm=0 */
        parcel_write_i32(&resp, json_get_bool(data, "isGsm", 0));
        break;
    case RIL_UNSOL_NEW_SMS:
        {
            char *pdu = json_get_str(data, "pdu");
            parcel_write_str16(&resp, pdu);
            free(pdu);
        }
        break;
    case RIL_UNSOL_NITZ_TIME_RECEIVED:
        {
            /* NITZ time string, e.g. "26/03/03,12:00:00+00" */
            char *nitz = json_get_str(data, "nitz");
            parcel_write_str16(&resp, nitz ? nitz : "");
            free(nitz);
        }
        break;
    default:
        break;
    }

    uint32_t net_len = htonl((uint32_t)resp.len);
    write(client_fd, &net_len, 4);
    write(client_fd, resp.buf, resp.len);
    parcel_free(&resp);
}

/* -------------------------------------------------------------------
 * Bridge → Android unsolicited forwarder thread
 *
 * Reads length-prefixed JSON messages from the bridge TCP connection
 * and converts them to Parcel-encoded unsolicited indications for
 * the Android RILJ client.
 * ------------------------------------------------------------------- */
struct unsol_fwd_ctx {
    int client_fd;
    int bridge_fd;
    volatile int *alive;
};

static void *unsol_forward_thread(void *arg) {
    struct unsol_fwd_ctx *ctx = (struct unsol_fwd_ctx *)arg;
    int bridge_fd = ctx->bridge_fd;
    int client_fd = ctx->client_fd;

    LOGI("Unsolicited forwarder started");

    while (*(ctx->alive)) {
        char *json = bridge_recv(bridge_fd);
        if (!json) break;

        int msg_type = json_get_int(json, "type", 0);
        if (msg_type != RESPONSE_UNSOLICITED) {
            /* This is a solicited response — shouldn't happen on the
             * unsol-only bridge connection, but ignore gracefully. */
            free(json);
            continue;
        }

        int indication_id = json_get_int(json, "id", 0);
        const char *data_part = json_find_data(json);

        LOGI("Unsolicited: id=%d", indication_id);
        send_unsolicited(client_fd, indication_id, data_part);
        free(json);
    }

    LOGI("Unsolicited forwarder exiting");
    free(ctx);
    return NULL;
}

/* -------------------------------------------------------------------
 * Client handler (runs in a thread)
 * ------------------------------------------------------------------- */
static volatile int running = 1;

static void *client_thread(void *arg) {
    int client_fd = *(int *)arg;
    free(arg);

    /* Connect to the bridge for solicited requests */
    int bridge_fd = -1;
    for (int attempt = 0; attempt < 30 && bridge_fd < 0; attempt++) {
        bridge_fd = bridge_connect();
        if (bridge_fd < 0) {
            LOGW("Bridge connect failed, retrying in 2s (attempt %d/30)", attempt + 1);
            sleep(2);
        }
    }
    if (bridge_fd < 0) {
        LOGE("Failed to connect to RIL bridge after 30 attempts");
        close(client_fd);
        return NULL;
    }

    /* Connect a second bridge connection for unsolicited indications.
     * The bridge sends unsolicited messages on ANY connected client,
     * so this second connection receives those independently. */
    int unsol_bridge_fd = bridge_connect();
    volatile int unsol_alive = 1;

    if (unsol_bridge_fd >= 0) {
        struct unsol_fwd_ctx *ctx = (struct unsol_fwd_ctx *)malloc(sizeof(*ctx));
        ctx->client_fd = client_fd;
        ctx->bridge_fd = unsol_bridge_fd;
        ctx->alive = &unsol_alive;

        pthread_t unsol_tid;
        pthread_create(&unsol_tid, NULL, unsol_forward_thread, ctx);
        pthread_detach(unsol_tid);
    }

    /* Send initial radio state indication */
    send_unsolicited(client_fd, RIL_UNSOL_RADIO_STATE_CHANGED,
                     "{\"radioState\":10}");
    /* Notify SIM present */
    send_unsolicited(client_fd, RIL_UNSOL_SIM_STATUS_CHANGED, "{}");

    /* Read loop: receive Parcel requests from Android */
    while (running) {
        uint32_t net_len;
        ssize_t n = read(client_fd, &net_len, 4);
        if (n != 4) break;

        uint32_t payload_len = ntohl(net_len);
        if (payload_len > MAX_MSG_SIZE) {
            LOGE("Message too large: %u bytes", payload_len);
            break;
        }

        uint8_t *payload = (uint8_t *)malloc(payload_len);
        size_t got = 0;
        while (got < payload_len) {
            n = read(client_fd, payload + got, payload_len - got);
            if (n <= 0) { free(payload); goto done; }
            got += n;
        }

        handle_request(client_fd, &bridge_fd, payload, payload_len);
        free(payload);
    }

done:
    LOGI("Client disconnected");
    unsol_alive = 0;
    close(bridge_fd);
    if (unsol_bridge_fd >= 0) close(unsol_bridge_fd);
    close(client_fd);
    return NULL;
}

/* -------------------------------------------------------------------
 * Signal handling
 * ------------------------------------------------------------------- */
static void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

/* -------------------------------------------------------------------
 * Main — create rild socket and accept connections
 * ------------------------------------------------------------------- */
int main(int argc, char **argv) {
    /* Allow bridge host override via env or argument */
    const char *env_host = getenv("RIL_BRIDGE_HOST");
    if (env_host) {
        strncpy(bridge_host, env_host, sizeof(bridge_host) - 1);
    }
    if (argc > 1) {
        strncpy(bridge_host, argv[1], sizeof(bridge_host) - 1);
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    /* Remove stale socket */
    unlink(RIL_SOCKET_PATH);

    /* Create Unix socket */
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        LOGE("socket() failed: %s", strerror(errno));
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, RIL_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOGE("bind(%s) failed: %s", RIL_SOCKET_PATH, strerror(errno));
        close(server_fd);
        return 1;
    }

    /* rild socket needs to be accessible by the system_server (uid 1000) */
    chmod(RIL_SOCKET_PATH, 0666);

    if (listen(server_fd, 4) < 0) {
        LOGE("listen() failed: %s", strerror(errno));
        close(server_fd);
        return 1;
    }

    LOGI("VirtualPhone RIL shim started");
    LOGI("Listening on %s, bridge at %s:%d", RIL_SOCKET_PATH, bridge_host, BRIDGE_PORT);

    while (running) {
        int *client_fd = (int *)malloc(sizeof(int));
        *client_fd = accept(server_fd, NULL, NULL);
        if (*client_fd < 0) {
            free(client_fd);
            if (errno == EINTR) continue;
            LOGE("accept() failed: %s", strerror(errno));
            break;
        }

        LOGI("Android RILJ client connected");
        pthread_t tid;
        pthread_create(&tid, NULL, client_thread, client_fd);
        pthread_detach(tid);
    }

    close(server_fd);
    unlink(RIL_SOCKET_PATH);
    LOGI("RIL shim exiting");
    return 0;
}
