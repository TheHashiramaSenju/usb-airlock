import logging
import signal
import threading

import pyudev

from host.device_identity import get_device_identity
from host.quarantine import LinuxQuarantineController, QuarantineStatus


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("usb-airlock")
stop_event = threading.Event()
devices = {}
quarantine_controller = LinuxQuarantineController()


def get_usb_parent(device):
    return device.find_parent("usb", "usb_device")


def get_disk(device):
    if device.properties.get("DEVTYPE") == "disk":
        return device
    if device.properties.get("DEVTYPE") == "partition":
        return device.find_parent("block", "disk")
    return None


def describe_device(device):
    usb_parent = get_usb_parent(device)
    disk = get_disk(device)
    return {
        "action": device.action or "inventory",
        "device_node": device.properties.get("DEVNAME"),
        "device_type": device.properties.get("DEVTYPE"),
        "disk_node": disk.properties.get("DEVNAME") if disk is not None else None,
        "is_usb": usb_parent is not None,
        "usb_vendor": usb_parent.properties.get("ID_VENDOR_ID") if usb_parent else None,
        "usb_model": usb_parent.properties.get("ID_MODEL_ID") if usb_parent else None,
        "sys_path": device.sys_path,
    }


def handle_device(device):
    details = describe_device(device)
    details["device_id"] = (
        get_device_identity(details) if details["is_usb"] else None
    )
    key = device.sys_path

    if device.action == "remove":
        previous = devices.pop(key, None)
        if previous is not None:
            logger.info("DEVICE_REMOVED %s", details)
        else:
            logger.info("DEVICE_REMOVE_UNTRACKED %s", details)
        return

    if not details["is_usb"]:
        return

    if not details["device_id"]:
        logger.warning("DEVICE_IDENTITY_UNAVAILABLE %s", details)
        return

    previous = devices.get(key)
    devices[key] = details

    if previous is None:
        logger.info("DEVICE_DISCOVERED %s", details)
    elif previous != details:
        logger.info("DEVICE_UPDATED %s", details)

    if details["device_type"] != "disk" or not details["disk_node"]:
        return

    result = quarantine_controller.quarantine(
        details["device_id"], details["disk_node"]
    )
    if result.status is QuarantineStatus.QUARANTINED:
        logger.info("QUARANTINE_CONFIRMED %s", result)
    else:
        logger.warning("QUARANTINE_FAILED_CLOSED %s", result)


def handle_signal(signum, frame):
    stop_event.set()


def main():
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem="block")
    monitor.start()

    for device in context.list_devices(subsystem="block"):
        try:
            handle_device(device)
        except (OSError, ValueError) as exc:
            logger.warning("INVENTORY_ERROR %s", exc)

    logger.info("USB Airlock observer started; tracked devices: %d", len(devices))

    try:
        while not stop_event.is_set():
            device = monitor.poll(timeout=1)
            if device is None:
                continue
            try:
                handle_device(device)
            except (OSError, ValueError) as exc:
                logger.exception("DEVICE_EVENT_ERROR %s", exc)
    finally:
        logger.info("USB Airlock observer stopped; tracked devices: %d", len(devices))


if __name__ == "__main__":
    main()
