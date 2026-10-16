import logging
import signal
import sys

import pyudev


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

logger = logging.getLogger("usb-airlock")
running = True


def handle_signal(signum, frame):
    global running
    running = False


def identify_device(device):
    usb_parent = device.find_parent("usb", "usb_device")

    return {
        "action": device.action or "unknown",
        "device_node": device.device_node or "unknown",
        "device_type": device.device_type or "unknown",
        "sys_path": device.sys_path,
        "is_usb": usb_parent is not None,
        "usb_vendor": usb_parent.get("ID_VENDOR_ID") if usb_parent else None,
        "usb_model": usb_parent.get("ID_MODEL_ID") if usb_parent else None,
        "usb_serial": usb_parent.get("ID_SERIAL_SHORT") if usb_parent else None,
    }


def main():
    global running

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem="block")
    monitor.start()

    logger.info("USB Airlock detection daemon started")
    logger.info("Listening for block-device events; observation only")

    try:
        while running:
            device = monitor.poll(timeout=1)

            if device is None:
                continue

            try:
                details = identify_device(device)
                logger.info("DEVICE_EVENT %s", details)
            except (OSError, ValueError) as exc:
                logger.exception("Failed to inspect device event: %s", exc)
    finally:
        logger.info("USB Airlock detection daemon stopped")


if __name__ == "__main__":
    main()
