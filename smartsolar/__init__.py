#!/usr/bin/env python3

import logging
import time
import threading
import io

import gatt.gatt_linux as gatt
import cbor2
import dbus
import dbus.service


logger = logging.getLogger(__name__)


def volts(data): return int.from_bytes(data, byteorder='little') * 0.01
def watts(data): return int.from_bytes(data, byteorder='little') * 0.01
def amps(data): return int.from_bytes(data, byteorder='little') * 0.1
def kelvin(data): return int.from_bytes(data, byteorder='little') * 0.01


class VEDevice(gatt.Device):
    GATT_SERVICE = "306b0001-b081-4037-83dc-e59fcc3cdfd0"

    GATT_CHAR0021 = "306b0002-b081-4037-83dc-e59fcc3cdfd0"
    GATT_CHAR0024 = "306b0003-b081-4037-83dc-e59fcc3cdfd0"
    GATT_CHAR0027 = "306b0004-b081-4037-83dc-e59fcc3cdfd0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.gatt_service: gatt.Service = None
        self.gatt_char0021: gatt.Characteristic = None
        self.gatt_char0024: gatt.Characteristic = None
        self.gatt_char0027: gatt.Characteristic = None

        self.gatt_chars_notify = 0

        device = self

        class Values(dict):
            def __setitem__(self, key, value):
                logger.info("[%s] updated %s: %s", device.mac_address, key, value)
                super().__setitem__(key, value)

        self.values = Values()
        self.ack = 0

    def update(self, vreg, data):
        if vreg == bytes.fromhex("0102"):
            self.values["Firmware version"] = data.hex()
        elif vreg == bytes.fromhex("0200"):
            self.values["Device mode"] = int.from_bytes(data, byteorder='little')
        elif vreg == bytes.fromhex("2211"):
            self.values["Adjustable voltage minimum (V)"] = volts(data)
        elif vreg == bytes.fromhex("2212"):
            self.values["Adjustable voltage maximum (V)"] = volts(data)
        elif vreg == bytes.fromhex("ec5a"):
            self.values["Uptime (s)"] = int.from_bytes(data, byteorder='little')
        elif vreg == bytes.fromhex("edad"):
            self.values["Load output actual current"] = amps(data)
        elif vreg == bytes.fromhex("ed8d"):
            self.values["Channel 1 voltage (V)"] = volts(data)
        elif vreg == bytes.fromhex("ed8f"):
            self.values["Channel 1 current (A)"] = amps(data)
        elif vreg == bytes.fromhex("eda8"):
            self.values["Load output status"] = int.from_bytes(data, byteorder='little')
        elif vreg == bytes.fromhex("eda9"):
            self.values["Load output voltage (V)"] = volts(data)
        elif vreg == bytes.fromhex("edac"):
            self.values["Load output offset voltage (V)"] = volts(data)
        elif vreg == bytes.fromhex("edec"):
            self.values["Battery temperature (K)"] = kelvin(data)
        elif vreg == bytes.fromhex("ec66"):
            self.values["Mac address"] = ':'.join('%02x' % b for b in data)
        elif vreg == bytes.fromhex("edbc"):
            self.values["Input power (W)"] = watts(data)
        elif vreg == bytes.fromhex("edbb"):
            self.values["Input Voltage (V)"] = volts(data)
        elif vreg in [
            bytes.fromhex("9342"),
            bytes.fromhex("010d"),
            bytes.fromhex("ec65"),
            bytes.fromhex("ec7d"),
            bytes.fromhex("ec3f"),
            bytes.fromhex("ec12"),
            bytes.fromhex("0100"),
            bytes.fromhex("ed8c"),
            bytes.fromhex("ec88"),
            bytes.fromhex("0202"),
            bytes.fromhex("010e"),
            bytes.fromhex("9041"),
            bytes.fromhex("0150"),
            bytes.fromhex("ec89"),
            bytes.fromhex("ec8a"),
        ]:
            logger.info("[%s] VREG %s ignored: %s", self.mac_address, vreg.hex(), data.hex() if isinstance(data, bytes) else data)
        else:
            logger.warning("[%s] VREG %s unknown: %s", self.mac_address, vreg.hex(), data.hex() if isinstance(data, bytes) else data)

    def connect_succeeded(self):
        logger.info("[%s] connected", self.mac_address)

    def services_resolved(self):
        logger.info("[%s] services resolved", self.mac_address)
        super().services_resolved()

        # print available services
        for _service in self.services:
            _service: gatt.Service
            logger.debug("[%s] service %s", self.mac_address, _service.uuid)
            for char in _service.characteristics:
                char: gatt.Characteristic
                logger.debug("[%s]  char %s", self.mac_address, char.uuid)

        # get ATT service
        self.gatt_service = [s for s in self.services if s.uuid == VEDevice.GATT_SERVICE][0]
        logger.info("[%s] got gatt service %s", self.mac_address, self.gatt_service.uuid)

        # get ATT write char
        self.gatt_char0021 = [c for c in self.gatt_service.characteristics if c.uuid == VEDevice.GATT_CHAR0021][0]
        self.gatt_char0021.enable_notifications()
        self.gatt_char0024 = [c for c in self.gatt_service.characteristics if c.uuid == VEDevice.GATT_CHAR0024][0]
        self.gatt_char0024.enable_notifications()
        self.gatt_char0027 = [c for c in self.gatt_service.characteristics if c.uuid == VEDevice.GATT_CHAR0027][0]
        self.gatt_char0027.enable_notifications()
        logger.info("[%s] got chars", self.mac_address)

    def write_init(self):
        logger.info("[%s] Writing init sequence", self.mac_address)
        # self.gatt_char0021.write_value(bytes.fromhex('fa80ff'))
        # self.gatt_char0021.write_value(bytes.fromhex('f980'))
        # self.gatt_char0024.write_value(bytes.fromhex('01'))
        # self.gatt_char0024.write_value(bytes.fromhex('0300'))
        # self.gatt_char0024.write_value(bytes.fromhex('060082189342102703010303'))
        # self.gatt_char0027.write_value(bytes.fromhex('05008119ec0f05008119ec0e05008119010c0500'))
        # self.gatt_char0024.write_value(bytes.fromhex('81189005008119ec3f05008119ec12'))
        # self.gatt_char0024.write_value(bytes.fromhex('19ecdc05038119eceb05038119eced'))
        # self.gatt_char0021.write_value(bytes.fromhex('f941'))
        # self.gatt_char0024.write_value(bytes.fromhex('0600821893421027'))
        # self.gatt_char0021.write_value(bytes.fromhex('f941'))

        # BT-Trace
        self.gatt_char0021.write_value(bytes.fromhex('fa80ff'))
        self.gatt_char0021.write_value(bytes.fromhex('f980'))
        # 0x0021 < f901 (ack)

        self.gatt_char0024.write_value(bytes.fromhex('01'))
        # 0x0021 < f901 (ack)
        # < 1 Value

        self.gatt_char0024.write_value(bytes.fromhex('0300'))
        # 0x0021 < f901 (ack)
        # < 1 Value

        self.gatt_char0024.write_value(bytes.fromhex('0600821893421027'+'05008219ec6619ec65'+'03010303'))
        # 0x0021< f901 (ack)
        # < 5 Values

        self.gatt_char0024.write_value(bytes.fromhex('05008119010d'+'05008119ec7d'+'0500811890'+'05008119ec3f'+'05008119ec12'))
        # 0x0021 < f901 (ack)
        # < 5 Values

        self.gatt_char0024.write_value(bytes.fromhex('050181190100'+'050181190100'))
        # 0x0021 < f901 (ack)
        # < 5 Values

        self.gatt_char0027.write_value(bytes.fromhex(
            '05018119ec7d'+'0501811890'+'05018119ec3f'+'05018119ec12'+'050381190102'+'05038119ed8c'+'05038119edec'+'050381192211'+'050381192212'+'05038119eda8'+'0600821893421027'+'05038119eda905'))
        self.gatt_char0024.write_value(bytes.fromhex(
            '038119edac'))  # '0503811910500503811910a00503811910510503811910a10503811910520503811910a20503811910530503811910a30503811910540503811910a4050381191055050381'))
        # self.gatt_char0024.write_value(bytes.fromhex(
        #     '1910a50503811910560503811910a60503811910570503811910a70503811910580503811910a806008218934210270503811910590503811910a905038119105a0503811910aa'))
        # 0x0021 < f901 (ack)

        # self.gatt_char0027.write_value(bytes.fromhex(
        #     '05038119105b0503811910ab05038119105c0503811910ac05038119105d0503811910ad05038119105e0503811910ae05038119105f0503811910af0503811910600503811910b00503'))
        # self.gatt_char0027.write_value(bytes.fromhex(
        #     '811910610503811910b10503811910620503811910b206008218934210270503811910630503811910b30503811910640503811910b40503811910650503811910b50503811910660503'))
        # self.gatt_char0024.write_value(bytes.fromhex(
        #     '811910b60503811910670503811910b70503811910680503811910b80503811910690503811910b905038119106a0503811910ba05038119106b0503811910bb05038119106c'))
        # # 0x0021 < f901 (ack)
        # # < 49 Values

        # self.gatt_char0027.write_value(bytes.fromhex(
        #     '0503811910bc060082189342102705038119106d0503811910bd05038119106e0503811910be05038119104f05038119eddc05038119eddd05038119010a050381190140050381190150'))
        # self.gatt_char0027.write_value(bytes.fromhex(
        #     '05038119edbb05038119eccb05038119eccd05038119eccc05038119ecdb05038119ecdd05038119ecdc05038119eceb05038119eced05038119ecec060082189342102705038119ecfb'))
        # self.gatt_char0024.write_value(bytes.fromhex(
        #     '05038119ecfd05038119ecfc05038119edbd05038119edb805038119edb105038119034e05038119202705038119020705038119020505038119024405038119012005038119ec5d'))
        # # < many values

        # self.gatt_char0021.write_value(bytes.fromhex('f941'))

        # self.gatt_char0027.write_value(bytes.fromhex(
        #     '05038119ec5c05038119ec5b05038119ec6305038119ec6405038119ec5f05038119ec5a05038119ec4a060082189342102705038119ec5205038119ec4b05038119ec5305038119ec4c'))
        # self.gatt_char0027.write_value(bytes.fromhex(
        #     '05038119ec5405038119ec4d05038119ec5505038119ec4e05038119ec5605038119ec4f05038119ec5705038119ec5005038119ec5805038119ec5105038119ec590503811902000503'))
        # self.gatt_char0024.write_value(bytes.fromhex(
        #     '8119020205038119ede805038119edea05038119edef060082189342102705038119edf105038119edf005038119edf705038119edf605038119edf405038119edc605038119edfb'))
        # # < many values

        # self.gatt_char0027.write_value(bytes.fromhex(
        #     '05038119edfd05038119edf205038119ede605038119ede005038119ede205038119ed2e05038119ede305038119ede405038119edc705038119ede505038119edfe05038119ede70503'))
        # self.gatt_char0027.write_value(bytes.fromhex(
        #     '8119edca060082189342102705038119d0c005038119ed2f05038119d4d705038119edab05038119ed9c05038119ed9d05038119ed9005038119ed9e05038119ed9805038119edd90503'))
        # self.gatt_char0024.write_value(bytes.fromhex(
        #     '8119100a05038119035005038119035105038119035205038119035305038119edba05038119edb905038119eda005038119eda105038119eda2060082189342102705038119eda3'))
        # self.gatt_char0021.write_value(bytes.fromhex('f941'))
        # # < many values

        # self.gatt_char0027.write_value(bytes.fromhex(
        #     '05038119eda405038119eda505038119ed9a05038119ed9605038119ed9905038119ed9705038119ed9b05038119eda705038119203105038119040805038119040405038119edce0503'))
        # self.gatt_char0027.write_value(bytes.fromhex(
        #     '8119eddf0503811890050381189105038119edd405038119ec7d05038119ec3f05038119ec12060082189342102705038119ec1305038119ec1405038119ec1505038119ec1605038119'))
        # self.gatt_char0024.write_value(bytes.fromhex(
        #     'ec3005018119014206038219203142dc0306038219ec6344e65e010006038219ec6444e65e0100'))
        # self.gatt_char0021.write_value(bytes.fromhex('f941'))
        # # < many values

        # self.gatt_char0024.write_value(bytes.fromhex('06038219ec5b4600e95e010001'))

        # self.gatt_char0027.write_value(bytes.fromhex(
        #     '06038219ec5b4600e85e01003806038219ec5b4600b05e01003806038219ec5b4600785e01003806038219ec5b4600835e01000106038219ec5b46006e5e01003806038219ec5b4600de'))
        # self.gatt_char0027.write_value(bytes.fromhex(
        #     '5701003806038219ec5b46004e5101003806038219ec5b4600be4a01003806038219ec5b46002e4401003806038219ec5b46007143010001060082189342102706038219ec5b46006242'))
        # self.gatt_char0024.write_value(bytes.fromhex(
        #     '01003806038219ec5b4600c20001003806038219ec5b460022bf00003806038219ec5b4600827d00003806038219ec5b4600e23b00003806038219ec5b4601e95e010001'))
        # self.gatt_char0021.write_value(bytes.fromhex('f941'))

        # # < many values

        # self.gatt_char0027.write_value(bytes.fromhex(
        #     '06038219ec5b4601e85e01001c06038219ec5b4601cc5e01001c06038219ec5b4601b05e01001c06038219ec5b4601945e01001c06038219ec5b4601785e01001c06038219ec5b460183'))
        # self.gatt_char0027.write_value(bytes.fromhex(
        #     '5e01000106038219ec5b46016e5e01001c06038219ec5b4601265b01001c06038219ec5b4601de5701001c06038219ec5b4601965401001c06038219ec5b46014e5101001c06038219ec'))
        # self.gatt_char0024.write_value(bytes.fromhex(
        #     '5b4601064e01001c06038219ec5b4601be4a01001c06038219ec5b4601764701001c060082189342102706038219ec5b46012e4401001c06038219ec5b46017143010001'))
        # self.gatt_char0021.write_value(bytes.fromhex('f941'))
        # # < many values

        # self.gatt_char0027.write_value(bytes.fromhex(
        #     '06038219ec5b4601624201001c06038219ec5b4601922101001c06038219ec5b4601c20001001c06038219ec5b4601f2df00001c06038219ec5b460122bf00001c06038219ec5b460152'))
        # self.gatt_char0027.write_value(bytes.fromhex(
        #     '9e00001c06038219ec5b4601827d00001c06038219ec5b4601b25c00001c06038219ec5b4601e23b00001c06038219ec5b4601121b00001c06038219ec5b4602e95e01000106038219ec'))
        # self.gatt_char0024.write_value(bytes.fromhex(
        #     '5b4602e85e01001c06038219ec5b4602cc5e01001c06038219ec5b4602b05e01001c06038219ec5b4602945e01001c06038219ec5b4602785e01001c06038219ec5b4602835e010001'))
        # self.gatt_char0021.write_value(bytes.fromhex('f941'))
        # # < many values

        # self.gatt_char0027.write_value(bytes.fromhex(
        #     '06038219ec5b46026e5e01001c060082189342102706038219ec5b4602265b01001c06038219ec5b4602de5701001c06038219ec5b4602965401001c06038219ec5b46024e5101001c06'))
        # self.gatt_char0027.write_value(bytes.fromhex(
        #     '038219ec5b4602064e01001c06038219ec5b4602be4a01001c06038219ec5b4602764701001c06038219ec5b46022e4401001c06038219ec5b4602714301000106038219ec5b46026242'))
        # self.gatt_char0024.write_value(bytes.fromhex(
        #     '01001c06038219ec5b4602922101001c06038219ec5b4602c20001001c06038219ec5b4602f2df00001c06038219ec5b460222bf00001c06038219ec5b4602529e00001c'))
        # self.gatt_char0021.write_value(bytes.fromhex('f941'))
        # # < many values

        self.gatt_char0021.write_value(bytes.fromhex('f941'))

    def write_ping(self):
        logger.info("[%s] Writing ping", self.mac_address)
        self.gatt_char0024.write_value(bytes.fromhex('0600821893421027'))
        # self.gatt_char0021.write_value(bytes.fromhex('f941'))

    def connect_failed(self, error):
        logger.warning("[%s] connect failed: %s", self.mac_address, error)
        return super().connect_failed(error)

    def characteristic_value_updated(self, characteristic: gatt.Characteristic, value):
        logger.debug("[%s] char %s value updated: %s", self.mac_address, characteristic.uuid, value.hex())
        fp = io.BytesIO(value)
        key = fp.read(3)
        while len(key):
            if key[0] in [0x08, 0x09] and \
                    key[1] in [0x00, 0x01, 0x03] and \
                    key[2] in [0x18, 0x19]:

                vreg = fp.read(2)

                try:
                    # data = cbor2.loads(value[5:])
                    data = cbor2.CBORDecoder(fp).decode()
                    self.update(vreg, data)

                    if vreg == bytes.fromhex('010e') and data == bytes.fromhex('00'):
                        self.disconnect()

                except cbor2.CBORDecodeEOF as error:
                    logger.warning("[%s] VREG %s decode error: %s", self.mac_address, vreg.hex(), error)

            elif key == b"\xf9\x01":
                self.ack += 1
                logger.debug("[%s] ack %s", self.mac_address, self.ack)
                # if self.ack == 7:
                #     self.write_ping()
            else:
                logger.info("[%s] unknown value: %s", self.mac_address, key.hex())

            key = fp.read(3)

    def characteristic_read_value_failed(self, characteristic: gatt.Characteristic, error):
        logger.warning("[%s] char %s read failed: %s", self.mac_address, characteristic.uuid, error)

    def characteristic_write_value_succeeded(self, characteristic: gatt.Characteristic):
        logger.debug("[%s] char %s write succeeded", self.mac_address, characteristic.uuid)

    def characteristic_write_value_failed(self, characteristic: gatt.Characteristic, error):
        logger.warning("[%s] char %s write failed: %s", self.mac_address, characteristic.uuid, error)

    def characteristic_enable_notifications_succeeded(self, characteristic: gatt.Characteristic):
        logger.debug("[%s] char %s enable notifications succeeded", self.mac_address, characteristic.uuid)

        # count notification succeeds and init write if complete.
        self.gatt_chars_notify += 1
        if self.gatt_chars_notify >= 3:
            self.write_init()

    def characteristic_enable_notifications_failed(self, characteristic: gatt.Characteristic, error):
        logger.warning("[%s] char %s enable notifications failed: %s", self.mac_address, characteristic.uuid, error)

    def disconnect_succeeded(self):
        return super().disconnect_succeeded()

    def pair(self):
        if not self._properties.Get("org.bluez.Device1", "Trusted"):
            logger.debug("[%s] Trusting device...", self.mac_address)
            self._properties.Set("org.bluez.Device1", "Trusted", True)

        logger.debug("[%s] Attempting to pair...", self.mac_address)
        # Pair does not seem to get a reply, hence we dismiss the reply / error, and wait for pairing
        sem = threading.Semaphore(0)
        self._object.Pair(
            reply_handler=lambda *args: sem.release(),
            error_handler=lambda *args: sem.release(),
        )
        sem.acquire()

        paired = self._properties.Get('org.bluez.Device1', 'Paired')
        logger.debug("[%s] Paired: %s", self.mac_address, paired)

        return bool(paired)


class VEPasskeyAgent(dbus.service.Object):
    AGENT_INTERFACE = 'org.bluez.Agent1'

    def __init__(self, bus, path="/victronenergy/agent", passkey="000000", **kwargs):
        super().__init__(bus, path)
        self.passkey = passkey

        bluez = bus.get_object('org.bluez', "/org/bluez")
        agent_manager = dbus.Interface(bluez, "org.bluez.AgentManager1")
        agent_manager.RegisterAgent(path, "KeyboardDisplay")

    @dbus.service.method(AGENT_INTERFACE, in_signature="o", out_signature="u")
    def RequestPasskey(self, device):
        logger.debug("VEPasskeyAgent: Request passkey (%s): %s", device, self.passkey)
        return dbus.UInt32(self.passkey)


class VEDeviceManager(gatt.DeviceManager, threading.Thread):
    def __init__(self, *args, adapter_name="hci0", **kwargs):
        gatt.DeviceManager.__init__(self, adapter_name)
        threading.Thread.__init__(self, *args, **kwargs)

    def stop(self):
        gatt.DeviceManager.stop(self)
        self.join()

    def connect_nearest_vedevice(self, delay_s: float = 5.0, passkey='000000') -> VEDevice:
        self.start_discovery(service_uuids=[])
        time.sleep(delay_s)
        devices = []

        for d in list(self.devices()):
            # filter out non VE-devices based on the ManufacturerData value
            try:
                manufacturerData = d._properties.Get('org.bluez.Device1', 'ManufacturerData')
                if 0x2e1 not in manufacturerData:
                    continue

                # add device
                logger.info("[%s] Discovered VictronEnergy device \"%s\", RSSI: %s", d.mac_address, d.alias(), d._properties.Get('org.bluez.Device1', "RSSI"))
                devices.append(d)

                # print debug info
                data = d._properties.GetAll('org.bluez.Device1')
                for key, value in data.items():
                    logger.debug("[%s]  %s: %s", d.mac_address, key, value)

            except dbus.exceptions.DBusException:
                continue

        if len(devices) < 1:
            raise RuntimeError("Did not discover any VictronEnergy devices...")

        d: gatt.Device = max(devices, key=lambda d: d._properties.Get('org.bluez.Device1', "RSSI"))
        logger.info("[%s] Selected nearest device \"%s\"", d.mac_address, d.alias())
        d = VEDevice(d.mac_address, self, managed=True)

        # pair if not paired yet
        if not d._properties.Get('org.bluez.Device1', "Paired"):
            # register pairing agent
            logger.info("Creating VictronEnergy pairing agent")
            agent = VEPasskeyAgent(self._bus, passkey=passkey)

            if not d.pair():
                logger.error("[%s] Pairing failed, rasing RuntimeError.", d.mac_address)
                raise RuntimeError("Pairing VictronEnergy Device '%s' [%s] failed.", d.alias(), d.mac_address)
            else:
                logger.info("[%s] Pairing successful!", d.mac_address)

        logger.info("[%s] connecting", d.mac_address)
        d.connect()

        return d


def read_nearest_vedevice(discovery_duration: float = 5.0, query_duration: float = 20.0, passkey='000000', **kwargs):
    logger.info("Starting manager")
    manager = VEDeviceManager()
    manager.start()

    logger.info("Connecting to nearest VEDevice")
    try:
        d = manager.connect_nearest_vedevice(discovery_duration, passkey=passkey)

        logger.info("Querying data from %s [%s]", d.alias(), d.mac_address)
        timeout = time.time() + query_duration
        while d.is_connected() and time.time() < timeout:
            time.sleep(1)
    finally:
        manager.stop()
        logger.info("Querying finished.")

    return d.values
