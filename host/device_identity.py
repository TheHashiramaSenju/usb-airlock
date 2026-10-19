
def get_device_identity(details):
    """Build an identity from USB attributes and the device's sysfs path."""
    if not isinstance(details, dict):
        return None

    sys_path = details.get("sys_path")
    vendor = details.get("usb_vendor")
    model = details.get("usb_model")

    if not all(
        isinstance(value, str) and value.strip()
        for value in (sys_path, vendor, model)
    ):
        return None

    if not sys_path.startswith("/sys/"):
        return None

    return f"{sys_path}|{vendor.lower()}|{model.lower()}"
