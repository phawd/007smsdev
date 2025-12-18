# QMI Adapter Design & Extension Guide
==================================

## Purpose

This document describes the modular design for `tools/qmi_adapter.py`, how to add
support for new devices and chipsets, how to write device profiles, and how to add
vendor- or chipset-specific adapter modules.

## Goals

- Keep the adapter conservative by default (dry-run, no destructive operations).
- Make it easy to add new backends (qmicli wrapper, libqmi bindings, adb shims, or
  vendor-specific Python adapters).
- Make adapters discoverable via device profiles so the tool can choose the
  correct backend for new devices without changing the core adapter logic.

## Core concepts

- Backends: Python classes that implement the `Backend` interface in
  `tools/qmi_adapter.py` (methods: `available()`, `info()`, `read_nv()`, `write_nv()`).
- Device profiles: JSON files placed under `tools/device_profiles/` that declare
  device-matching criteria and (optionally) an `adapter_module` to import a
  specialized backend factory.
- Safe defaults: `--dry-run` is the default and writes require both a PR-level
  `DO IT` sign-off and a runtime guard (env `ZEROSMS_DANGER_DO_IT=1` or
  `--danger-do-it`).

## Device profile schema (example)

Example file: `tools/device_profiles/example.json`

```json
{
  "vendor": "example-vendor",
  "model_regex": "EX-.*",
  "default_device_node": "/dev/cdc-wdm0",
  "qmicli_opts": "-d /dev/cdc-wdm0",
  "adapter_module": "tools.vendor_adapters.example_adapter",
  "notes": "Use `example_adapter` for specialized NV handling"
}
```

## `adapter_module` contract

- The adapter module should be importable as a regular Python module.
- It should expose a `get_backend(profile: dict) -> Backend` function which
  returns an instance of a `Backend` subclass. The adapter may use the
  `profile` dict for per-device customization.

## Adding a new chipset/vendor adapter

1. Create `tools/vendor_adapters/<vendor>_adapter.py`.
2. Implement `get_backend(profile)` returning a `Backend` instance.
3. Add an example device profile JSON referencing the module path.
4. Add unit tests under `tools/tests/` that mock the module and validate
  `probe_backends(profiles=...)` selects the adapter.

## Testing & CI

- A small pytest skeleton is provided under `tools/tests/test_qmi_adapter.py`.
- Tests should avoid touching hardware; use dry-run and environment-based
  configuration to validate behavior.

## Notes for AI agents and future contributors

- When adding or modifying adapters, update this document and add a
  `PHASE_*` note describing test plans and risk mitigation for device-level
  operations.
- Keep destructive operations gated behind both repo-level sign-offs and
  runtime flags (see `DO IT` policy in `.github/copilot-instructions.md`).

## Contact

If you add a new adapter or profile, please open a PR and request a device
expert review (add `@phawd` or the relevant owner as reviewer).
