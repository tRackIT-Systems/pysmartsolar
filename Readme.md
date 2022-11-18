# SmartSolar Connector

This software connects to a VictronEnergy SmartSolar devices and retrieves some supported values. 

> **Caution: Implementation is based on reverse engineering and may not work, harm or destroy your devices. Please only use if you understand this risk.**

## Usage

```
usage: smartsolar [-h] [-v] [-p PASSKEY] [-d DISCOVERY_DURATION] [-q QUERY_DURATION]

Connects to the Victron Energy device of nearest proximity via BLE and queries its values

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity (default: 0)
  -p PASSKEY, --passkey PASSKEY
                        passkey for pairing BLE device (default: 000000)
  -d DISCOVERY_DURATION, --discovery-duration DISCOVERY_DURATION
                        duration to discover BLE devices (s) (default: 5)
  -q QUERY_DURATION, --query-duration QUERY_DURATION
                        duration to wait for data from device (s) (default: 20)
````

The script works such, that it connects to the device of nearest proximity, collects all parsable data and outputs the data as json only after the connection is terminated from the device. A successful run takes around 20 seconds:

```bash
pi@umr-test-00001:~/SmartSolar $ python -m smartsolar 
WARNING:smartsolar:[c7:c8:06:27:13:11] VREG 9001 decode error: premature end of stream (expected to read 1 bytes, got 0 instead)
WARNING:smartsolar:[c7:c8:06:27:13:11] VREG 9001 decode error: premature end of stream (expected to read 1 bytes, got 0 instead)
{"Mac address": "c7:c8:06:27:13:11", "Firmware version": "00590100", "Battery temperature (K)": 655.35, "Adjustable voltage minimum (V)": 8.0, "Load output status": 0, "Channel 1 voltage (V)": 4.17, "Adjustable voltage maximum (V)": 17.400000000000002, "Load output voltage (V)": 0.13, "Load output offset voltage (V)": 0.0, "Uptime (s)": 587970, "Device mode": 1}
```

## Notable Mentions

- [vvvrrooomm/victron](https://github.com/vvvrrooomm/victron): Implementation of VictronEnergy protocol and Wireshark disssector
- [birdie1/victron](https://github.com/birdie1/victron): Fork of vvvrrooomm's approach for multiple outputs
- [Olen/VictronConnect](https://github.com/Olen/VictronConnect): Reverse engineering approach to VictronEnergy's BLE protocol

### VictronEnergy Community Discussions

- [Victron Bluetooth BLE protocol?](https://community.victronenergy.com/questions/40048/victron-data-capture-via-bluetooth.html): Some details on the protocol (CBOR + VREGs), some explanation on messages parsing.
- [Victron Bluetooth BLE Protocol announcement](https://community.victronenergy.com/questions/93919/victron-bluetooth-ble-protocol-publication.html): Details on the stalling BLE GATT characteristic service (only available on SmartShunt devices).
- [VictronConnect Instant readout: see readings immediately on the Device list](https://community.victronenergy.com/questions/137214/victronconnect-see-readings-immediately-on-the-dev.html): Information on the 2022 Bluetooth Broadcast feature.

### Documentation 

- [VE.Can registers](https://community.victronenergy.com/storage/attachments/2273-vecan-registers-public.pdf): including VREGs
