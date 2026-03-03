# ePDG (Evolved Packet Data Gateway) for VoWiFi
# Uses strongSwan with EAP-AKA authentication via simaka-sql backend
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan \
    strongswan-charon \
    strongswan-swanctl \
    libcharon-extra-plugins \
    libstrongswan-extra-plugins \
    openssl \
    sqlite3 \
    iproute2 \
    iptables \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /etc/swanctl/conf.d /etc/swanctl/x509 /etc/swanctl/x509ca \
    /etc/swanctl/private /var/lib/epdg /var/log/epdg

# Copy configuration
COPY strongswan.conf /etc/strongswan.conf
COPY swanctl.conf /etc/swanctl/swanctl.conf
COPY epdg_init.sh /opt/epdg_init.sh
RUN chmod +x /opt/epdg_init.sh

ENTRYPOINT ["/opt/epdg_init.sh"]
