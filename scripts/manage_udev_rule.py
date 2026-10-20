#!/usr/bin/env python3
"""Manage the USB Airlock udev rule with explicit dry-run and rollback."""
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "config/99-usb-airlock.rules"
TARGET = Path("/etc/udev/rules.d/99-usb-airlock.rules")
BACKUP = Path("/etc/udev/rules.d/99-usb-airlock.rules.usb-airlock-backup"
              )
STATE = Path("/etc/udev/rules.d/99-usb-airlock.install-state")


def run(command):
    return subprocess.run(command, check=True, text=True,
                          capture_output=True)


def reload_rules():
    run(["udevadm", "control", "--reload-rules"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("status", "install", "rollback"))
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    if args.action == "status":
        print(f"Source rule exists: {SOURCE.is_file()}")
        print(f"Installed rule exists: {TARGET.exists()}")
        print(f"Backup exists: {BACKUP.exists()}")
        print(f"Install state exists: {STATE.exists()}")
        if TARGET.exists():
            print("Installed rule contents:")
            print(TARGET.read_text())
        return 0

    if not args.apply:
        print(f"DRY RUN: {args.action}; no system changes made.")
        return 0

    if os.geteuid() != 0:
        print("ERROR: --apply requires root.", file=sys.stderr)
        return 2

    if args.action == "install":
        if not SOURCE.is_file():
            print(f"ERROR: source rule missing: {SOURCE}", file=sys.stderr)
            return 2
        if STATE.exists() or BACKUP.exists():
            print("ERROR: existing install state or backup; inspect status first.",
                  file=sys.stderr)
            return 2

        had_previous = TARGET.exists()
        if had_previous:
            shutil.copy2(TARGET, BACKUP)

        STATE.write_text("previous_rule=present\n" if had_previous
                         else "previous_rule=absent\n")
        try:
            shutil.copy2(SOURCE, TARGET)
            run(["udevadm", "verify", str(TARGET)])
            reload_rules()
        except Exception:
            TARGET.unlink(missing_ok=True)
            if had_previous and BACKUP.exists():
                shutil.move(str(BACKUP), str(TARGET))
            STATE.unlink(missing_ok=True)
            try:
                reload_rules()
            except Exception:
                pass
            raise

        print("Rule installed and udev rules reloaded.")
        print("Existing devices were not retriggered.")
        return 0

    if not STATE.exists():
        print("ERROR: no recorded USB Airlock installation to roll back.",
              file=sys.stderr)
        return 2

    state = STATE.read_text().strip()
    TARGET.unlink(missing_ok=True)
    if state == "previous_rule=present":
        if not BACKUP.exists():
            print("ERROR: previous-rule backup missing; refusing to continue.",
                  file=sys.stderr)
            return 2
        shutil.move(str(BACKUP), str(TARGET))
    elif state == "previous_rule=absent":
        BACKUP.unlink(missing_ok=True)
    else:
        print("ERROR: unrecognized install state; inspect manually.",
              file=sys.stderr)
        return 2

    reload_rules()
    STATE.unlink(missing_ok=True)
    print("Rollback completed and udev rules reloaded.")
    print("Existing device-node permissions may persist until device re-add.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
