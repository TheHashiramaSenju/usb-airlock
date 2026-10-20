"""Fail-closed ClamAV adapter for the USB Airlock guest."""
from pathlib import Path
import os
import subprocess


def make_clamav_scanner(
    scan_root="/scan/input",
    executable="clamscan",
    timeout_seconds=900,
    max_database_age_days=7,
):
    """Return a scanner callback compatible with guest.agent.run_scan.

    Only the configured scan root is scanned. The caller must mount the
    untrusted filesystem read-only at that location inside the guest.
    """
    root = Path(scan_root).resolve()

    def scan(request):
        if not isinstance(request, dict):
            raise ValueError("Invalid scan request")

        if not root.exists() or not (root.is_file() or root.is_dir()):
            raise RuntimeError("Configured scan root is unavailable")

        command = [
            executable,
            "--infected",
            "--no-summary",
            "--recursive=yes",
            "--cross-fs=no",
            f"--fail-if-cvd-older-than={max_database_age_days}",
            str(root),
        ]

        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_seconds,
                check=False,
                env={**os.environ, "LC_ALL": "C"},
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("ClamAV scan timed out") from exc
        except OSError as exc:
            raise RuntimeError("ClamAV could not be executed") from exc

        output = completed.stdout or ""
        errors = completed.stderr or ""
        detections = sum(
            1 for line in output.splitlines()
            if line.rstrip().endswith(" FOUND")
        )

        if completed.returncode == 0:
            if detections:
                raise RuntimeError("ClamAV exit code contradicts its output")
            return {"clean": True, "findings": 0}

        if completed.returncode == 1:
            if detections < 1:
                raise RuntimeError(
                    "ClamAV reported detections without identifiable findings"
                )
            return {"clean": False, "findings": detections}

        detail = errors.strip()[:500]
        raise RuntimeError(
            "ClamAV failed"
            + (f": {detail}" if detail else
               f" with exit code {completed.returncode}")
        )

    return scan
