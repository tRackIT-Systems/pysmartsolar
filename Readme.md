# SmartSolar Connector

This software connects to a VictronEnergy SmartSolar devices and retrieves some supported values. 

> **Caution: Implementation is based on reverse engineering and may not work, harm or destroy your devices. Please only use if you understand this risk.**

## Usage

Initial pairing needs to be done on your device, [as described by Olen](https://github.com/Olen/VictronConnect#bluetoothctl). After that this script can be used to query the connected device based on the mac address. 

```
usage: SmartSolar [-h] [--mac MAC] [-v]

Connects to Victron Energy Smart Solar devices via BLE

optional arguments:
  -h, --help     show this help message and exit
  --mac MAC      Mac Address of the device to connect to
  -v, --verbose  increase output verbosity
````

The script works such, that it connects to the device, collects all parsable data and outputs the data only after the connection is terminated from the device. A successful run takes around 20 seconds:

```bash
pi@umr-test-00001:~/SmartSolar $ ./SmartSolar.py --mac ee:be:95:b5:67:53
WARNING:root:[ee:be:95:b5:67:53] VREG 9001 decode error: premature end of stream (expected to read 1 bytes, got 0 instead)
WARNING:root:[ee:be:95:b5:67:53] VREG 9001 decode error: premature end of stream (expected to read 1 bytes, got 0 instead)
WARNING:root:[ee:be:95:b5:67:53] VREG 9041 unknown: 1
WARNING:root:[ee:be:95:b5:67:53] VREG 0150 unknown: 21000000
{'Mac address': 'ee:be:95:b5:67:53', 'Firmware version': '00590100', 'Battery temperature (K)': 655.35, 'Adjustable voltage minimum (V)': 8.0, 'Load output status': 1, 'Adjustable voltage maximum (V)': 17.400000000000002, 'Load output voltage (V)': 12.68, 'Load output offset voltage (V)': 0.0, 'Uptime (s)': 287920, 'Device mode': 1}
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
