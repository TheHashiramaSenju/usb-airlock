# Firecracker VM contract

## Status
Configuration contract only. No VM is launched by this file.

## Required resources
- Firecracker executable compatible with x86_64 and KVM.
- Guest Linux kernel image.
- Read-only guest root filesystem containing the scanner and guest agent.
- A dedicated scratch filesystem for scan output.
- A per-scan input image or read-only block device explicitly assigned to the VM.

Host system disks and the project HDD must never be attached to the guest.

## Isolation requirements
- Do not expose a host block device until host-side admission and isolation are confirmed.
- Do not use host networking for the initial scanner.
- Do not trust guest output merely because the guest process exits successfully.
- A missing, malformed, mismatched, incomplete, or non-clean result must fail closed.

## Result protocol
The guest must eventually emit one JSON object with:
- schema_version: integer, initially 1
- device_id: the expected host-issued device identifier
- scan_id: a unique non-empty scan identifier
- completed: boolean
- clean: boolean
- findings: non-negative integer

The host must validate every field and bind the result to the expected device and scan session. Only a completed clean scan with zero findings may become eligible for release.

## Current limitation
The host quarantine controller is verification-only. Real host isolation, guest assets, scanner implementation, and controlled release are not yet implemented.
