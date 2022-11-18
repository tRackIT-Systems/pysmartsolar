import argparse
import json
import logging

from . import read_nearest_vedevice

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="smartsolar",
        description="Connects to the Victron Energy device of nearest proximity via BLE and queries its values",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="count", default=0)
    parser.add_argument("-p", "--passkey", help="passkey for pairing BLE device", type=str, default="000000")
    parser.add_argument("-d", "--discovery-duration", help="duration to discover BLE devices (s)", type=float, default=5)
    parser.add_argument("-q", "--query-duration", help="duration to wait for data from device (s)", type=float, default=20)
    args = parser.parse_args()

    # configure logging
    logging_level = max(0, logging.WARNING - (10 * args.verbose))
    logging.basicConfig(level=logging_level)
    logging.debug("Logging level: %s", logging.getLevelName(logging_level))

    # read values & print
    values = read_nearest_vedevice(**args.__dict__)
    print(json.dumps(values))
    logging.info("Program finished.")
