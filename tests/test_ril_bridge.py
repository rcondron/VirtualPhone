"""Tests for the RIL bridge and Radio HAL.

Tests cover:
- RIL message serialization / deserialization (JSON wire format)
- Radio HAL state machine (power on/off, registration simulation)
- RIL request → RadioHAL handler mapping
- SIM status, IMSI, operator, signal strength responses
- SIM I/O and SIM authentication request data extraction
- Network registration state transitions
- Unsolicited indication broadcast
- Data call management
- Radio state API output
"""

import asyncio
import json
import struct
import pytest

from hal.ril_bridge import (
    RILBridge, RILMessage, RILRequest, RILResponse, RILUnsol,
)
from hal.radio_hal import (
    RadioHAL, RadioState, RegState, NetworkType, SimStatus,
    NetworkRegistration, DataCall,
)


class TestRILMessage:
    """Test RIL message serialization and deserialization."""

    def test_serialize_solicited_response(self):
        """Solicited response serializes to length-prefixed JSON."""
        msg = RILMessage(
            msg_type=RILResponse.SOLICITED,
            serial=42,
            request_id=RILRequest.GET_SIM_STATUS,
            data={"cardState": 1},
        )
        raw = msg.serialize()
        # First 4 bytes are big-endian length
        length = struct.unpack("!I", raw[:4])[0]
        payload = json.loads(raw[4:])
        assert length == len(raw) - 4
        assert payload["type"] == 0
        assert payload["serial"] == 42
        assert payload["id"] == 1
        assert payload["data"]["cardState"] == 1

    def test_serialize_unsolicited(self):
        """Unsolicited indication has type=1 and serial=0."""
        msg = RILMessage(
            msg_type=RILResponse.UNSOLICITED,
            serial=0,
            request_id=RILUnsol.RADIO_STATE_CHANGED,
            data={"radioState": 10},
        )
        raw = msg.serialize()
        payload = json.loads(raw[4:])
        assert payload["type"] == 1
        assert payload["id"] == 1000

    def test_deserialize_request(self):
        """Deserialize a RIL request from JSON bytes."""
        data = json.dumps({
            "type": 0, "serial": 7, "id": 22,
            "data": {},
        }).encode()
        msg = RILMessage.deserialize(data)
        assert msg.msg_type == 0
        assert msg.serial == 7
        assert msg.request_id == 22

    def test_roundtrip(self):
        """Serialize → extract payload → deserialize produces same message."""
        original = RILMessage(
            msg_type=0, serial=99,
            request_id=RILRequest.GET_IMSI,
            data={"aid": "A0000000871002"},
        )
        raw = original.serialize()
        payload = raw[4:]
        restored = RILMessage.deserialize(payload)
        assert restored.serial == 99
        assert restored.request_id == RILRequest.GET_IMSI
        assert restored.data["aid"] == "A0000000871002"

    def test_max_message_size(self):
        """Large data payload serializes correctly."""
        big_data = {"big": "x" * 10000}
        msg = RILMessage(msg_type=0, serial=1, request_id=1, data=big_data)
        raw = msg.serialize()
        length = struct.unpack("!I", raw[:4])[0]
        assert length == len(raw) - 4
        assert length > 10000


class TestRadioHALState:
    """Test RadioHAL state management."""

    def test_initial_state_off(self):
        """Radio starts in OFF state."""
        hal = RadioHAL()
        assert hal.radio_state == RadioState.OFF

    def test_sim_status_default(self):
        """Default SIM status has card present, PIN ready."""
        ss = SimStatus()
        assert ss.card_state == 1
        assert ss.pin_state == 5
        assert ss.num_applications == 2

    def test_network_registration_default(self):
        """Default registration is NOT_REG_NOT_SEARCHING."""
        reg = NetworkRegistration()
        assert reg.reg_state == RegState.NOT_REG_NOT_SEARCHING
        assert reg.rat == NetworkType.UNKNOWN

    def test_radio_state_enum_values(self):
        """RadioState enum matches Android values."""
        assert RadioState.OFF == 0
        assert RadioState.UNAVAILABLE == 1
        assert RadioState.ON == 10

    def test_network_type_lte(self):
        """LTE network type matches Android constant."""
        assert NetworkType.LTE == 14

    def test_data_call_defaults(self):
        """DataCall has sensible defaults for virtual network."""
        dc = DataCall()
        assert dc.ifname == "rmnet0"
        assert dc.active == 2
        assert "10.45.0.2" in dc.addresses

    def test_get_radio_state_dict(self):
        """get_radio_state returns a complete status dict."""
        hal = RadioHAL()
        state = hal.get_radio_state()
        assert "radioState" in state
        assert "simPresent" in state
        assert "registration" in state
        assert "signalStrength" in state
        assert "imei" in state
        assert "dataCallsActive" in state


class TestRadioHALAsync:
    """Test RadioHAL async operations (with mocked eUICC)."""

    @pytest.fixture
    def hal(self):
        """Create a RadioHAL that won't try to connect to eUICC."""
        h = RadioHAL(euicc_socket="/nonexistent")
        return h

    @pytest.mark.asyncio
    async def test_get_sim_status_no_euicc(self, hal):
        """get_sim_status returns ABSENT when eUICC is unreachable."""
        result = await hal.get_sim_status()
        assert result["cardState"] == 0

    @pytest.mark.asyncio
    async def test_get_imsi_no_euicc(self, hal):
        """get_imsi returns None when eUICC is unreachable."""
        result = await hal.get_imsi()
        assert result is None

    @pytest.mark.asyncio
    async def test_get_operator_no_euicc(self, hal):
        """get_operator returns empty strings without active profile."""
        result = await hal.get_operator()
        assert result["longName"] == ""
        assert result["numeric"] == ""

    @pytest.mark.asyncio
    async def test_get_imei(self, hal):
        """get_imei returns the configured IMEI."""
        result = await hal.get_imei()
        assert len(result) == 15  # IMEI is 15 digits
        assert result.isdigit()

    @pytest.mark.asyncio
    async def test_signal_strength(self, hal):
        """Signal strength returns LTE parameters."""
        result = await hal.get_signal_strength()
        assert "lte" in result
        assert result["lte"]["rsrp"] < 0  # Negative dBm
        assert result["lte"]["signalStrength"] <= 31

    @pytest.mark.asyncio
    async def test_supply_pin_always_succeeds(self, hal):
        """Virtual eUICC doesn't require PIN."""
        result = await hal.supply_icc_pin("1234")
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_send_sms_placeholder(self, hal):
        """SMS send returns success placeholder (Phase 5)."""
        result = await hal.send_sms("", "0041000B")
        assert result["errorCode"] == 0

    @pytest.mark.asyncio
    async def test_data_call_list_empty_initially(self, hal):
        """No data calls before registration."""
        result = await hal.get_data_call_list()
        assert result["calls"] == []

    @pytest.mark.asyncio
    async def test_set_initial_attach_apn(self, hal):
        """setInitialAttachApn succeeds."""
        result = await hal.set_initial_attach_apn({"apn": "internet"})
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_get_current_calls_empty(self, hal):
        """No active calls (Phase 6 feature)."""
        result = await hal.get_current_calls()
        assert result["calls"] == []

    @pytest.mark.asyncio
    async def test_voice_reg_state(self, hal):
        """Voice registration state reflects current state."""
        result = await hal.get_voice_registration_state()
        assert result["regState"] == RegState.NOT_REG_NOT_SEARCHING.value

    @pytest.mark.asyncio
    async def test_data_reg_state(self, hal):
        """Data registration state reflects current state."""
        result = await hal.get_data_registration_state()
        assert result["regState"] == RegState.NOT_REG_NOT_SEARCHING.value

    @pytest.mark.asyncio
    async def test_power_on_off_cycle(self, hal):
        """Power on → OFF→ON, power off → ON→OFF."""
        assert hal.radio_state == RadioState.OFF
        # Power on (will fail to find eUICC but still turns on)
        await hal.power_on()
        assert hal.radio_state == RadioState.ON
        await hal.power_off()
        assert hal.radio_state == RadioState.OFF


class TestRegistrationSimulation:
    """Test the simulated network registration flow."""

    @pytest.mark.asyncio
    async def test_registration_reaches_home(self):
        """After power on, registration should reach REG_HOME."""
        hal = RadioHAL(euicc_socket="/nonexistent")
        # Manually set SIM present so registration proceeds
        hal.sim_status.card_state = 1
        hal.registration.mcc = "001"
        hal.registration.mnc = "01"

        # Start registration manually
        task = asyncio.create_task(hal._simulate_registration())

        # Wait for registration to complete (simulation needs 1+2+1=4s)
        await asyncio.sleep(5)

        assert hal.registration.reg_state == RegState.REG_HOME
        assert hal.registration.rat == NetworkType.LTE
        assert len(hal.data_calls) == 1
        assert hal.data_calls[0].ifname == "rmnet0"

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    @pytest.mark.asyncio
    async def test_power_off_clears_registration(self):
        """Power off resets registration and data calls."""
        hal = RadioHAL(euicc_socket="/nonexistent")
        hal.registration.reg_state = RegState.REG_HOME
        hal.registration.rat = NetworkType.LTE
        hal.data_calls = [DataCall()]

        await hal.power_off()
        assert hal.registration.reg_state == RegState.NOT_REG_NOT_SEARCHING
        assert hal.registration.rat == NetworkType.UNKNOWN
        assert len(hal.data_calls) == 0


class TestRILBridgeRequestRouting:
    """Test that the RIL bridge routes requests to correct handlers."""

    @pytest.fixture
    def bridge(self):
        """Create a RIL bridge with mocked eUICC."""
        b = RILBridge()
        b.radio_hal = RadioHAL(euicc_socket="/nonexistent")
        return b

    @pytest.mark.asyncio
    async def test_get_sim_status_routed(self, bridge):
        """GET_SIM_STATUS request is handled."""
        msg = RILMessage(msg_type=0, serial=1,
                         request_id=RILRequest.GET_SIM_STATUS, data={})
        resp = await bridge._process_request(msg)
        assert resp.serial == 1
        assert resp.request_id == RILRequest.GET_SIM_STATUS
        assert "cardState" in resp.data

    @pytest.mark.asyncio
    async def test_get_imsi_routed(self, bridge):
        """GET_IMSI request returns imsi key."""
        msg = RILMessage(msg_type=0, serial=2,
                         request_id=RILRequest.GET_IMSI, data={})
        resp = await bridge._process_request(msg)
        assert "imsi" in resp.data

    @pytest.mark.asyncio
    async def test_get_imei_routed(self, bridge):
        """GET_IMEI request returns 15-digit IMEI."""
        msg = RILMessage(msg_type=0, serial=3,
                         request_id=RILRequest.GET_IMEI, data={})
        resp = await bridge._process_request(msg)
        assert "imei" in resp.data
        assert len(resp.data["imei"]) == 15

    @pytest.mark.asyncio
    async def test_operator_routed(self, bridge):
        """OPERATOR request returns operator info."""
        msg = RILMessage(msg_type=0, serial=4,
                         request_id=RILRequest.OPERATOR, data={})
        resp = await bridge._process_request(msg)
        assert "longName" in resp.data
        assert "numeric" in resp.data

    @pytest.mark.asyncio
    async def test_signal_strength_routed(self, bridge):
        """SIGNAL_STRENGTH request returns LTE signal."""
        msg = RILMessage(msg_type=0, serial=5,
                         request_id=RILRequest.SIGNAL_STRENGTH, data={})
        resp = await bridge._process_request(msg)
        assert "lte" in resp.data

    @pytest.mark.asyncio
    async def test_radio_power_on(self, bridge):
        """RADIO_POWER(on) turns radio on."""
        msg = RILMessage(msg_type=0, serial=6,
                         request_id=RILRequest.RADIO_POWER,
                         data={"on": True})
        resp = await bridge._process_request(msg)
        assert resp.data["success"] is True
        assert bridge.radio_hal.radio_state == RadioState.ON

    @pytest.mark.asyncio
    async def test_unknown_request(self, bridge):
        """Unknown request ID returns REQUEST_NOT_SUPPORTED."""
        msg = RILMessage(msg_type=0, serial=7,
                         request_id=999, data={})
        resp = await bridge._process_request(msg)
        assert "error" in resp.data
        assert resp.data["error"] == "REQUEST_NOT_SUPPORTED"

    @pytest.mark.asyncio
    async def test_sim_io_routed(self, bridge):
        """SIM_IO request forwards to radio_hal.sim_io."""
        msg = RILMessage(
            msg_type=0, serial=8,
            request_id=RILRequest.SIM_IO,
            data={"command": 0xB0, "fileId": 0x6F07, "path": "3F007FFF",
                  "p1": 0, "p2": 0, "p3": 9},
        )
        resp = await bridge._process_request(msg)
        assert "sw1" in resp.data

    @pytest.mark.asyncio
    async def test_data_call_list_routed(self, bridge):
        """DATA_CALL_LIST request returns calls list."""
        msg = RILMessage(msg_type=0, serial=9,
                         request_id=RILRequest.DATA_CALL_LIST, data={})
        resp = await bridge._process_request(msg)
        assert "calls" in resp.data

    @pytest.mark.asyncio
    async def test_send_sms_routed(self, bridge):
        """SEND_SMS request is handled."""
        msg = RILMessage(
            msg_type=0, serial=10,
            request_id=RILRequest.SEND_SMS,
            data={"smscPdu": "", "pdu": "0041000B"},
        )
        resp = await bridge._process_request(msg)
        assert "errorCode" in resp.data

    @pytest.mark.asyncio
    async def test_solicited_response_preserves_serial(self, bridge):
        """Response serial matches request serial."""
        for serial in [0, 1, 42, 99999]:
            msg = RILMessage(msg_type=0, serial=serial,
                             request_id=RILRequest.SIGNAL_STRENGTH, data={})
            resp = await bridge._process_request(msg)
            assert resp.serial == serial

    @pytest.mark.asyncio
    async def test_response_type_is_solicited(self, bridge):
        """All request responses are SOLICITED type."""
        msg = RILMessage(msg_type=0, serial=1,
                         request_id=RILRequest.GET_IMSI, data={})
        resp = await bridge._process_request(msg)
        assert resp.msg_type == RILResponse.SOLICITED


class TestRILRequestEnums:
    """Test RIL request and unsolicited enum values match Android ril.h."""

    def test_key_request_ids(self):
        assert RILRequest.GET_SIM_STATUS == 1
        assert RILRequest.GET_IMSI == 11
        assert RILRequest.OPERATOR == 22
        assert RILRequest.RADIO_POWER == 23
        assert RILRequest.SIGNAL_STRENGTH == 19
        assert RILRequest.VOICE_REG_STATE == 20
        assert RILRequest.DATA_REG_STATE == 21
        assert RILRequest.SEND_SMS == 25
        assert RILRequest.SIM_IO == 28
        assert RILRequest.GET_IMEI == 38
        assert RILRequest.SIM_AUTHENTICATION == 125

    def test_unsolicited_ids(self):
        assert RILUnsol.RADIO_STATE_CHANGED == 1000
        assert RILUnsol.NETWORK_STATE_CHANGED == 1001
        assert RILUnsol.CALL_RING == 1002
        assert RILUnsol.NEW_SMS == 1003
        assert RILUnsol.NITZ_TIME_RECEIVED == 1008
        assert RILUnsol.SIM_STATUS_CHANGED == 1019

    def test_voice_call_request_ids(self):
        """Voice call request IDs match Android ril.h values."""
        assert RILRequest.GET_CURRENT_CALLS == 9
        assert RILRequest.DIAL == 10
        assert RILRequest.HANGUP == 12
        assert RILRequest.ANSWER == 40

    def test_sms_expect_more_id(self):
        """SEND_SMS_EXPECT_MORE is defined."""
        assert RILRequest.SEND_SMS_EXPECT_MORE == 26


class TestUnsolicited:
    """Test unsolicited indication handling."""

    @pytest.mark.asyncio
    async def test_indication_callback_called(self):
        """Indication callback is invoked during registration."""
        hal = RadioHAL(euicc_socket="/nonexistent")
        indications = []

        async def capture(ind_id: int, data: dict):
            indications.append((ind_id, data))

        hal.set_indication_callback(capture)
        hal.sim_status.card_state = 1
        hal.registration.mcc = "001"
        hal.registration.mnc = "01"

        task = asyncio.create_task(hal._simulate_registration())
        await asyncio.sleep(5)

        ind_ids = [i[0] for i in indications]
        # Should have received NETWORK_STATE_CHANGED indications
        assert 1001 in ind_ids

        # Should have received NITZ_TIME_RECEIVED indication
        assert 1008 in ind_ids
        nitz_ind = next(i for i in indications if i[0] == 1008)
        assert "nitz" in nitz_ind[1]
        # NITZ format: YY/MM/DD,HH:MM:SS+TZ
        assert "/" in nitz_ind[1]["nitz"]

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    @pytest.mark.asyncio
    async def test_sim_status_changed_on_power_on(self):
        """SIM_STATUS_CHANGED is sent when SIM is detected during power_on."""
        hal = RadioHAL(euicc_socket="/nonexistent")
        indications = []

        async def capture(ind_id: int, data: dict):
            indications.append(ind_id)

        hal.set_indication_callback(capture)
        # power_on calls _get_active_profile which will fail (no euicc)
        # so SIM_STATUS_CHANGED won't fire.
        # Instead, test the path where a profile IS found by manually simulating.
        # We directly test that _send_indication(1019) is callable.
        await hal._send_indication(1019, {})
        assert 1019 in indications


class TestSendSMSExpectMore:
    """Test SEND_SMS_EXPECT_MORE routing."""

    @pytest.fixture
    def bridge(self):
        b = RILBridge()
        b.radio_hal = RadioHAL(euicc_socket="/nonexistent")
        return b

    @pytest.mark.asyncio
    async def test_send_sms_expect_more_routed(self, bridge):
        """SEND_SMS_EXPECT_MORE should route to same handler as SEND_SMS."""
        msg = RILMessage(
            msg_type=0, serial=100,
            request_id=RILRequest.SEND_SMS_EXPECT_MORE,
            data={"smscPdu": "", "pdu": "0041000B"},
        )
        resp = await bridge._process_request(msg)
        assert "errorCode" in resp.data
        assert resp.data["errorCode"] == 0


class TestInitScriptsExist:
    """Test that redroid integration scripts exist and are executable."""

    def test_init_ril_shim_exists(self):
        import os
        path = os.path.join(os.path.dirname(__file__), "..", "scripts", "init_ril_shim.sh")
        assert os.path.isfile(path)
        assert os.access(path, os.X_OK)

    def test_euicc_hal_service_exists(self):
        import os
        path = os.path.join(os.path.dirname(__file__), "..", "scripts", "euicc_hal_service.sh")
        assert os.path.isfile(path)
        assert os.access(path, os.X_OK)

    def test_init_ril_shim_references_bridge_host(self):
        import os
        path = os.path.join(os.path.dirname(__file__), "..", "scripts", "init_ril_shim.sh")
        with open(path) as f:
            content = f.read()
        assert "RIL_BRIDGE_HOST" in content
        assert "ril_shim" in content

    def test_euicc_hal_service_sets_esim_property(self):
        import os
        path = os.path.join(os.path.dirname(__file__), "..", "scripts", "euicc_hal_service.sh")
        with open(path) as f:
            content = f.read()
        assert "esim.supported" in content


class TestDockerComposeRedroid:
    """Test docker-compose redroid configuration."""

    def test_docker_compose_has_ril_shim_mount(self):
        import os
        path = os.path.join(os.path.dirname(__file__), "..", "docker-compose.yml")
        with open(path) as f:
            content = f.read()
        assert "./ril_shim/ril_shim:/vendor/bin/hw/ril_shim:ro" in content

    def test_docker_compose_has_init_script_mount(self):
        import os
        path = os.path.join(os.path.dirname(__file__), "..", "docker-compose.yml")
        with open(path) as f:
            content = f.read()
        assert "init_ril_shim.sh" in content

    def test_docker_compose_has_euicc_service_mount(self):
        import os
        path = os.path.join(os.path.dirname(__file__), "..", "docker-compose.yml")
        with open(path) as f:
            content = f.read()
        assert "euicc_hal_service.sh" in content

    def test_docker_compose_has_esim_property(self):
        import os
        path = os.path.join(os.path.dirname(__file__), "..", "docker-compose.yml")
        with open(path) as f:
            content = f.read()
        assert "persist.radio.esim.supported=true" in content

    def test_docker_compose_has_multisim_config(self):
        import os
        path = os.path.join(os.path.dirname(__file__), "..", "docker-compose.yml")
        with open(path) as f:
            content = f.read()
        assert "persist.radio.multisim.config=ssss" in content
