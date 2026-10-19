
from enum import Enum

from host.scan_result import validate_scan_result


class DeviceState(Enum):
    DISCOVERED = "discovered"
    QUARANTINED = "quarantined"
    SCANNING = "scanning"
    VALIDATED = "validated"
    RELEASED = "released"
    BLOCKED = "blocked"
    REMOVED = "removed"


ALLOWED_TRANSITIONS = {
    DeviceState.DISCOVERED: {
        DeviceState.QUARANTINED,
        DeviceState.BLOCKED,
        DeviceState.REMOVED,
    },
    DeviceState.QUARANTINED: {
        DeviceState.SCANNING,
        DeviceState.BLOCKED,
        DeviceState.REMOVED,
    },
    DeviceState.SCANNING: {
        DeviceState.VALIDATED,
        DeviceState.BLOCKED,
        DeviceState.REMOVED,
    },
    DeviceState.VALIDATED: {
        DeviceState.RELEASED,
        DeviceState.BLOCKED,
        DeviceState.REMOVED,
    },
    DeviceState.RELEASED: {DeviceState.REMOVED},
    DeviceState.BLOCKED: {DeviceState.REMOVED},
    DeviceState.REMOVED: set(),
}


def transition(current_state, next_state):
    if next_state not in ALLOWED_TRANSITIONS[current_state]:
        raise ValueError(
            f"Invalid device-state transition: "
            f"{current_state.value} -> {next_state.value}"
        )
    return next_state


def begin_scanning(current_state, quarantine_confirmed):
    if current_state is not DeviceState.QUARANTINED:
        raise ValueError("Device must be quarantined before scanning")

    if quarantine_confirmed is not True:
        return transition(current_state, DeviceState.BLOCKED)

    return transition(current_state, DeviceState.SCANNING)


def apply_scan_result(current_state, result, expected_device_id):
    if current_state is not DeviceState.SCANNING:
        raise ValueError("Scan results can only be processed while scanning")

    if validate_scan_result(result, expected_device_id):
        return transition(current_state, DeviceState.VALIDATED)

    return transition(current_state, DeviceState.BLOCKED)


def release_allowed(current_state):
    return current_state is DeviceState.VALIDATED
