#!/usr/bin/env python3
"""Safely stage, install, or remove the USB Airlock udev rule."""
import argparse
import shutil
import subprocess
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "config/99-usb-airlock.rules"
TARGET = Path("/etc/udev/rules.d/99-usb-airlock.rules")
BACKUP = Path("/etc/udev/rules.d/99-usb-airlock.rules.usb-airlock-backup")


def run(command):
    return subprocess.run(command, check=True, text=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("status", "install", "rollback"))
    parser.add_argument("--apply", action="store_true",
                        help="perform the requested system change")
    args = parser.parse_args()

    if args.action == "status":
        print(f"Source rule exists: {SOURCE.is_file()}")
        print(f"Installed rule exists: {TARGET.exists()}")
        print(f"Backup exists: {BACKUP.exists()}")
        if TARGET.exists():
            print("Installed rule contents:")
            print(TARGET.read_text())
        return 0

    if not args.apply:
        print(f"DRY RUN: {args.action}; no system changes made.")
        print("Re-run with --apply only after reviewing the action.")
        return 0

    if os.geteuid() != 0:
        print("ERROR: --apply requires root; use sudo explicitly.", file=sys.stderr)
        return 2

    if args.action == "install":
        if not SOURCE.is_file():
            print(f"ERROR: source rule missing: {SOURCE}", file=sys.stderr)
            return 2
        if TARGET.exists():
            if BACKUP.exists():
                print("ERROR: target and backup both exist; refusing to overwrite.",
                      file=sys.stderr)
                return 2
            shutil.copy2(TARGET, BACKUP)
            print(f"Backed up existing rule to {BACKUP}")
        shutil.copy2(SOURCE, TARGET)
        try:
            run(["udevadm", "verify", str(TARGET)])
        except subprocess.CalledProcessError:
            TARGET.unlink(missing_ok=True)
            if BACKUP.exists():
                shutil.move(str(BACKUP), str(TARGET))
            raise
        run(["udevadm", "control", "--reload-rules"])
        print("Rule installed and rules reloaded.")
        print("Existing devices were not retriggered.")
        return 0

    if not TARGET.exists():
        print("No installed USB Airlock rule to remove.")
        return 0
    TARGET.unlink()
    if BACKUP.exists():
        shutil.move(str(BACKUP), str(TARGET))
        print("Restored the previous rule.")
    run(["udevadm", "control", "--reload-rules"])
    print("Rule removed/restored and rules reloaded.")
    print("Existing device permissions may persist until unplug/replug.")
    return 0


if __name__ == "__main__":
    import os
    raise SystemExit(main())
