````instructions
# ZeroSMS Agent Playbook (Extended)

Purpose
- Provide actionable guidance to contributors and AI agents: architecture overview, workflows, key files, code patterns, and strict safety rules for device operations.

What this repository contains
- `app/` — Android Compose application implementing SMS/MMS/RCS testing and AT command backends.
- `tools/` — Python CLI helpers (`tools/zerosms_cli.py`) mirroring in-app root/diag flows and modem probing.
- `docs/` — Device guides, safety rules (`SAFE_OPERATIONS_GUIDE.md`), phase planning and forensic notes.
- `analysis/` — Binary analysis and reverse-engineering artifacts.

Where to start (quick)
- `README.md` and `docs/ARCHITECTURE_DIAGRAM.md` for a high-level view.
- `app/src/main/java/com/zerosms/testing/core/*` for core behavior.
- `tools/zerosms_cli.py` for desktop automation and reference commands.

Key code areas (high-value entry points)
- Models & tests: `app/src/main/java/com/zerosms/testing/core/model/Models.kt`, `TestScenarios*.kt`.
- SMS logic: `SmsManagerWrapper.kt` — encoding, concatenation, AT/Api fallback flows.
- AT command backends: `AtCommandManager`, `HidlAtciManager`, `MipcDeviceManager` in `core/at/`.
- Root and device access: `RootAccessManager.kt` and `QualcommDiagManager.kt`.

Build & test commands
```bash
./gradlew assembleDebug
./gradlew installDebug
./gradlew test
./gradlew connectedAndroidTest
```

Python tools / CLI quick commands
```bash
python3 tools/zerosms_cli.py probe --deep --include-response
python3 tools/zerosms_cli.py diag --ai
python3 tools/zerosms_cli.py sms +15551234567 "Hello" --auto
```

Project conventions
- Logging: use `com.zerosms.testing.core.Logger`; keep debug logs behind `BuildConfig.DEBUG`.
- Message encoding: always call `calculateSmsInfo(text, SmsEncoding.AUTO)` to determine encoding and parts.
- Root operations: wrap all root operations through `RootAccessManager` (centralizes permission checks and command execution).
- Retain backwards compatibility across message flows: when adding new features, default to API fallbacks when AT or root is unavailable.

Device & NV safety (must follow)
- Read `docs/SAFE_OPERATIONS_GUIDE.md` before touching device-level commands.
- NV writes, SPC validation, and carrier unlocks are high risk — they require:
  - An explicit human sign-off with the string `DO IT` in the PR description or issue body
  - A documented, tested rollback strategy in the docs/PHASE_* file
  - Unit + instrumentation tests (if applicable) that do not execute the dangerous command by default (mock them)
- Never write to these NV items without an explicit `DO IT`: `0xEA64`, `0xEAAC`, `0xEA62`, `0x0D89`.
 - New CLI safety gate: our Python tools (`tools/zerosms_cli.py`, `tools/mifi_controller.py`, `tools/spc_calculator.py`) now require a runtime confirmation flag `--danger-do-it` and an interactive typed `DO IT` for potentially destructive operations (NV writes, unlocking, EFS writes). Automation can set `ZEROSMS_DANGER_DO_IT=1` to skip prompts, but PRs must still include the `DO IT` sign-off and recovery plan.

Agent-specific rules (operational)
- Always identify the target area (app vs. tools vs. analysis) early; ask clarifying questions when unclear.
- For any change that touches `core/at` or `tools/zerosms_cli.py`, include a command example & a non-root fallback.
- For any device-affecting change, add a `PHASE_*` note in the root describing the testing plan and safety checks.

PR Ready checklist
- Summary: clear description + list of changed files.
- Tests: unit tests and/or instrumentation test skeletons added.
- Docs: Add/modify `docs/` with device/flow changes.
- CLI: Include command examples for `tools/zerosms_cli.py` if behavior is modified.
- Device Ops: If PR includes NV/SPC/unlock operations, the PR body MUST include `DO IT` and a safety plan (recovery steps, steps to verify success, and where backup NV items are saved).

Where to look for additional guidance
- `docs/ROOT_ACCESS_GUIDE.md` — uses and limitations of root operations.
- `docs/MIFI_DEVICE_GUIDE.md` — MiFi-specific commands and paths.
- `PHASE_*` files — ongoing research, testing artifacts and constraints.
 - PR template: `.github/PULL_REQUEST_TEMPLATE.md` — Required fields and `DO IT` authorization for device ops.
 - PR template: `.github/PULL_REQUEST_TEMPLATE.md` — Required fields and `DO IT` authorization for device ops.
 - PR Safety workflow: `.github/workflows/pr-safety-check.yml` — checks PR diff for dangerous NV/device changes and requires `DO IT` sign-off.

QMI & Qualcomm guidance
- QMI overview: Prefer using `libqmi` and `qmicli` for Linux-hosted MiFi devices and Qualcomm-based modems when interacting with QMI endpoints. For Android, prefer platform-provided QMI bindings or the `at`/HIDL layers used in `core/at/`.
- Backwards compatibility: Keep a small adapter layer in `tools/` (e.g., `qmi_adapter.py`) that abstracts calls to different QMI clients (`qmicli`, `libqmi` Python bindings, or ADB shell wrappers). This allows older devices to use `qmicli` while newer devices use direct bindings.
- Forwards compatibility: Use capability detection at runtime (query supported QMI services, check modem firmware version, and fall back to AT/HIDL if QMI not available). Add feature flags and versioned adapters (v1, v2) so the codebase can accept newer QMI variants without breaking older adapters.
- Security & safety: Treat any QMI operation that writes NV, EFS, or performs unlock/erase as high-risk. Require the same `DO IT` PR sign-off and runtime `--danger-do-it` guard used in other tools.
- References & examples: Look for `libqmi` docs, `qmicli` examples, and Qualcomm QMI documentation when implementing adapters. Maintain a short list of vetted example links in `docs/QMI_SOURCES.md` and update quarterly.
 - See `docs/QMI_ADAPTER.md` for design notes on adding new backends, device profile schema, and how to add vendor-specific adapter modules.
 - A scheduled CI job `.github/workflows/update-device-inventory.yml` runs `tools/update_device_info.sh` weekly and opens a draft PR for human review when device inventory changes are detected.

Android (root) QMI procedures — exhaustive (assumes device with root)
- Goal: Provide a safe, repeatable sequence to interact with QMI on rooted Android devices while preserving backward and forward compatibility.
- Preconditions (must verify before running any commands):
  - Device connected via `adb devices` and in `device` state.
  - `adb root` works or `su` is available on-device.
  - A backup of IMEI, EFS, and NV items exists (`tools/mifi_backup/` or `tools/backup_nv.py`).

- Discovery steps (non-destructive):
  1. Confirm device presence: `adb devices`.
  2. Check root: `adb shell su -c id` (expect uid=0). If not rooted, use `adb root` or skip QMI flows.
  3. List serial ports and QMI-capable devices on the device:
     - `adb shell ls -l /dev | grep -E "smd|qcqmi|qcqmi*|ttyUSB|wwan"`
     - `adb shell getprop | grep -i modem`
  4. Probe QMI services (safe read-only): use `tools/qmi_adapter.py --probe` which attempts backends in order: host `qmicli`, `libqmi` Python bindings, `adb shell qmicli`.

- Read-only operations (safe):
  - Query supported QMI services and basic modem information: `tools/qmi_adapter.py --info`
  - Read NV items (read-only): `tools/qmi_adapter.py --read-nv 0xNNNN` — always safe.

- High-risk operations (REQUIRE `DO IT` + runtime `--danger-do-it`):
  - Any write to NV, EFS edits, SPC validation, carrier unlocks, IMEI writes.
  - Workflow to perform such ops safely:
    1. Create a PHASE note in repo root describing intent, rollback plan, and verification steps.
    2. Create a full device backup: IMEI, EFS dump, NV dump. Store in `mifi_backup/`.
    3. Add `DO IT` to PR body and set `ZEROSMS_DANGER_DO_IT=1` in CI for automated runs.
    4. Use `tools/qmi_adapter.py --write-nv 0xNNNN --value <hex>` with `--danger-do-it` and interactive confirmation.

- Compatibility strategy (how to write code):
  - Always detect capabilities at runtime: firmware version, supported QMI services, chipset vendor ID.
  - Provide multiple backends behind a single adapter `tools/qmi_adapter.py` or `tools/qmi_adapter/` package.
  - Default backend preference: `qmicli` (host) -> `libqmi` (Python) -> `adb shell qmicli` -> `adb shell at` fallback.
  - Version adapters (v1, v2) with small stable public functions: `get_modem_info()`, `read_nv(id)`, `write_nv(id, value, dry_run=False)`.

Device inventory & update schedule
- Keep `docs/device_inventory.md` updated by `tools/update_device_info.sh` when available. For active device sets, run weekly; for passive sets, run monthly.
- CI: add a scheduled job (placeholder) to run `tools/update_device_info.sh` and open an automated PR with changes to `docs/device_inventory.md`.

Device information and scheduling
- Device inventory: Keep `docs/device_inventory.md` that lists device families, known firmware versions, supported interfaces (AT, QMI, USB, MTP), and safety notes. Update this file on a regular cadence (recommended: weekly for active device sets, monthly otherwise).
- Update automation: Provide a small script `tools/update_device_info.sh` (placeholder) that can be run in CI to fetch known vendor pages, probeable device signatures, and regenerate `docs/device_inventory.md` automatically.
- Change management: Any automated update that changes device safety guidance must create a draft `PHASE_*` note and require human review before merging.

If you want more
- Want an example `PULL_REQUEST_TEMPLATE.md` or a unit test skeleton for `SmsManagerWrapper`? Reply with which template you prefer and I’ll add it.
````````instructions
# ZeroSMS Agent Playbook — Copilot Instructions

Purpose
- This file orients AI contributors and maintainers to the ZeroSMS repo. It provides the immediate knowledge needed to be productive: where to start, important design patterns, build and test workflows, device-specific caveats, and safety rules.

High-level architecture
- `app/` — Android app (Kotlin + Jetpack Compose). Core messaging logic lives under `com.zerosms.testing.core`.
  - `core/model` — message models, enums; update here for new message types.
  - `core/sms` — `SmsManagerWrapper` for SMS handling; central encoding and send flows.
  - `core/at` — AT command managers for chipset-specific flows (`AtCommandManager`, `HidlAtciManager`, `MipcDeviceManager`).
  - `core/root` — `RootAccessManager` to abstract `su`/root operations and device node discovery.
  - `ui/` — Jetpack Compose screens and navigation.
- `tools/` — Python-based desktop CLI helpers (`tools/zerosms_cli.py`) to probe modems, enable diag ports, and send SMS from a host.
- `docs/` — Device guides, safe operations, and forensic findings (must read before device changes).
- `analysis/` — binaries, disassembly, and scripts for reverse-engineering.

Developer workflows (essential commands)
- Android build & test (standard):
  - `./gradlew assembleDebug`
  - `./gradlew installDebug`
  - `./gradlew test` (unit tests)
  - `./gradlew connectedAndroidTest` (instrumentation tests, device required)
- CLI & device debug (desktop):
  - `python3 tools/zerosms_cli.py probe --deep --include-response`
  - `python3 tools/zerosms_cli.py diag --ai`
  - `python3 tools/zerosms_cli.py sms +15551234567 "Hello" --auto`

Primary coding patterns & conventions
- Logging: use `com.zerosms.testing.core.Logger` and guard noisy logs with `BuildConfig.DEBUG`.
- SMS encoding: call `calculateSmsInfo(text, SmsEncoding.AUTO)` to decide encoding/parts and use the result to build PDU or choose `SmsManager` API.
- Root & device access: use `RootAccessManager.isRootAvailable()` and `executeRootCommand()` for all privileged operations—do not spawn `su` directly.
- Device scanning: `RootAccessManager.getModemPorts()` and `tools/zerosms_cli.py` have shared lists of candidate `/dev/*` paths.

Key files — where to look and why
- `app/src/main/java/com/zerosms/testing/core/model/Models.kt` — enumerations and data models (MessageType, SmsEncoding).
- `app/src/main/java/com/zerosms/testing/core/sms/SmsManagerWrapper.kt` — how messages are encoded, segmented, and how AT flows are integrated (fallback to Android API if no AT available).
- `app/src/main/java/com/zerosms/testing/core/root/RootAccessManager.kt` — root detection, command execution, and device node discovery.
- `app/src/main/java/com/zerosms/testing/core/qualcomm/QualcommDiagManager.kt` — enables diag via `setprop` sequences; useful for toggling USB diagnostic modes.
- `tools/zerosms_cli.py` — read for CLI automation; it mirrors in-app flows and is useful for integration tests.
- `docs/ROOT_ACCESS_GUIDE.md`, `docs/MIFI_DEVICE_GUIDE.md`, `docs/SAFE_OPERATIONS_GUIDE.md` — required reading for any device-level changes.

Safety & device-specific rules (read before acting)
- Read `docs/SAFE_OPERATIONS_GUIDE.md` thoroughly before making or suggesting changes that write to NV, perform SPC, or perform carrier unlock.
- Do NOT write to the following NV items without explicit sign-off: 0xEA64 (NCK), 0xEAAC, 0xEA62, 0x0D89 — writing them can permanently brick or lock devices.
- Avoid recommending direct NV writes, SPC validation or carrier unlock steps in code or automation scripts. If a user specifically requests them, require a documented, tested plan and a human acknowledgment.

How to add features safely (example: add a new MessageType)
1) Add a new enum entry to `Models.kt`.
2) Add business logic in `SmsManagerWrapper`/`RcsManagerWrapper` following existing message routing.
3) Add UI entries (navigation + screen) and update `core/model/TestScenarios*.kt`.
4) Add unit & instrumented tests: unit tests for encoding/segmentation; an instrumentation test for AT vs. API fallback.
5) Add a short doc in `docs/` and if needed a `PHASE_*` note for device workflow changes.

Example code snippets (safe defaults)
```kotlin
// Models.kt
enum class MessageType { SMS_TEXT, SMS_FLASH, SMS_SILENT, SMS_BINARY, SMS_CUSTOM }

// SmsManagerWrapper (pseudocode)
when (msg.type) {
  MessageType.SMS_TEXT -> sendText(msg)
  MessageType.SMS_CUSTOM -> sendCustom(msg)
  else -> fallbackSend(msg)
}
```

Debugging & troubleshooting tips
- ADB logs: `adb logcat`—watch for `RootAccessManager` and `SmsManagerWrapper` tags.
- Device connection: `adb devices` → if offline, kill server: `adb kill-server && adb start-server`.
- Verify root: `adb shell su -c id` or from app logs via `RootAccessManager`.
- If diag/AT doesn't appear: run `python3 tools/zerosms_cli.py diag --ai` or check `QualcommDiagManager.getActiveUsbConfig()`.

PR guidelines & safety checklist (for reviewers)
- Title & short summary; list changed files and rationale.
- Tests: unit tests for logic, instrumentation tests for hardware-dependent changes.
- Docs: Update `docs/` (Root/Device) for device-level changes; add a `PHASE_*` note if research affects device flash/unlock workflows.
- CLI: Update `tools/zerosms_cli.py` when introducing new commands; include sample CLI commands in PR description.
- Safety: Mark and document any change touching NV items or unlock flows; include recovery/backout plan.

Agent behavior rules
- Ask clarifying questions before touching device-specific code or writing scripts that modify modem/nv state.
- Provide code modifications that are backward-compatible by default.
- Don't propose or commit NV writes, SPC reset, or unlock flows without explicit human sign-off and thorough testing instructions.

Where to ask questions or find more context
- PHASE_* files track research goals and in-progress device work.
- `docs/ARCHITECTURE_DIAGRAM.md` and `docs/QUICK_REFERENCE.md` are quick visual/context pointers.
- If unsure, flag PRs with a `PHASE_*` note and request a domain expert review.

Want me to add:
- An automated PR template that includes safety checkboxes for device-level changes? (Yes/No)
- A sample `SmsManagerWrapper` unit test and skeleton instrumentation test? (Yes/No)
````````instructions
# Copilot Instructions for ZeroSMS — Concise

Overview
- ZeroSMS: Android message-testing app (SMS/MMS/RCS) plus research tools for modem (MiFi) analysis.
- Main areas: `app/` (Kotlin Compose + core logic), `tools/` (Python CLI), `docs/` (device guides & safe ops), `analysis/` (reverse-engineering).

Essentials for contributors
- Key files: `app/src/.../Models.kt`, `SmsManagerWrapper.kt`, `RootAccessManager.kt`, `QualcommDiagManager.kt`, `tools/zerosms_cli.py`, `docs/ROOT_ACCESS_GUIDE.md`.
- Build & test: `./gradlew assembleDebug`, `./gradlew installDebug`, `./gradlew test`, `./gradlew connectedAndroidTest`.
- CLI tasks: `python3 tools/zerosms_cli.py probe --deep --include-response`, `diag --ai`, `sms +NUM msg --auto`.

Conventions & patterns
- Use central `Logger` for logs and `BuildConfig.DEBUG` gating for verbose debug messages.
- Use `calculateSmsInfo()` to pick encoding/parts. Add new message types in `Models.kt` and handle them in `SmsManagerWrapper`/`RcsManagerWrapper`.
- Root operations use `RootAccessManager`; prefer `executeRootCommand()` over raw `su` invocations.

Safety: Must-read
- Read `docs/SAFE_OPERATIONS_GUIDE.md` before any NV writes, SPC operations, or unlocking flows.
- DO NOT write NV items: 0xEA64 (NCK), 0xEAAC, 0xEA62, 0x0D89 (lock flags) without explicit sign-off; NV changes can permanently brick devices.

PR & agent rules (short)
- PR checklist: brief summary, files changed, tests added, docs updated (`PHASE_*` if device ops), CLI examples, safety note if NV/root.
- Agents: ask clarifying Qs when device-level changes are involved; do NOT propose NV writes/SPC unlocks unless user explicitly requests and documents a safe test plan.

Where to look first
- If editing protocol logic: `app/src/main/java/com/zerosms/testing/core/sms/SmsManagerWrapper.kt`, `model/Models.kt`.
- If editing modem/diag behavior: `app/src/main/java/com/zerosms/testing/core/qualcomm/QualcommDiagManager.kt` and `tools/zerosms_cli.py`.
- For device test patterns and research: `docs/MIFI_DEVICE_GUIDE.md`, `docs/ROOT_ACCESS_GUIDE.md`, `docs/SAFE_OPERATIONS_GUIDE.md`, and `PHASE_*` files.

Questions or follow-up
- Want a 1-click PR template or example unit/instrumentation tests added? Tell me which, and I’ll add them.
````````instructions
# Copilot Instructions for ZeroSMS — Updated

## Quick Summary
- ZeroSMS is both an Android test app (SMS/MMS/RCS) and a research suite (MiFi / modem analysis). Work divides into: UI/engine (`app/`), tools & CLI (`tools/`), binary analysis (`analysis/`), and docs (`docs/`).

## Why this structure (big picture)
- `app/`: Kotlin Compose UI + core messaging logic under `com.zerosms.testing.core`. Use `SmsManagerWrapper`, `MmsManagerWrapper`, `RcsManagerWrapper` as primary plumbing.
- `tools/` & `docs/`: Desktop/adb helpers (`tools/zerosms_cli.py`) mirror in-app root/diag behaviors and include scripts for modem probing, usb-mode switching, and device-specific operations (Inseego / MiFi). `docs/` contains device guides and safe operation instructions — always consult docs before making changes related to devices or NV writes.

## Key files & places to look (examples)
- `app/src/main/java/com/zerosms/testing/core/model/Models.kt` — central enums & message models (add new MessageTypes/encodings here).
- `app/src/main/java/com/zerosms/testing/core/sms/SmsManagerWrapper.kt` — primary SMS sending flow; follow same structure for new message types.
- `app/src/main/java/com/zerosms/testing/core/root/RootAccessManager.kt` — shared root helpers and device scanning (follow for root operations).
- `app/src/main/java/com/zerosms/testing/core/qualcomm/QualcommDiagManager.kt` — USB/diag profiles and enabling routines.
- `tools/zerosms_cli.py` — reference CLI flow for `adb` root-based operations and modem probes. Use it for desktop automation examples.
- `docs/ROOT_ACCESS_GUIDE.md`, `docs/MIFI_DEVICE_GUIDE.md`, `docs/SAFE_OPERATIONS_GUIDE.md` — required reading before touching device-level commands.

## Project-specific conventions & patterns
- Use `Logger` (see `core/Logger.kt`) instead of `android.util.Log` directly. Keep debug logs guarded by `BuildConfig.DEBUG`.
- Encoding/segment handling centralised by `calculateSmsInfo(...)`. Always use it to decide encoding before send.
- Root access is abstracted by `RootAccessManager`; use `isRootAvailable()` and `executeRootCommand()` rather than raw `su` calls.
- When adding new message types: 1) add enum entry in `Models.kt`, 2) implement handling in `SmsManagerWrapper`/`RcsManagerWrapper`, 3) add UI route in `ui/navigation/Navigation.kt`, 4) add new test scenarios in `core/model/TestScenarios*.kt`.

## Build, Test, and Debug workflows
- Android builds & instrumentation tests are run with Gradle wrappers in repo root:
  - `./gradlew assembleDebug` — build debug APK
  - `./gradlew installDebug` — install to connected device
  - `./gradlew test` — JVM unit tests
  - `./gradlew connectedAndroidTest` — device instrumentation tests (requires device with root for some tests)
- CLI and Python tools: Use Python 3.8+; recommended: virtualenv with `pip install -r tools/requirements.txt` (add if missing). CLI examples from repo:
  - `python3 tools/zerosms_cli.py probe --deep --include-response`
  - `python3 tools/zerosms_cli.py diag --ai`  # enable diag profiles via adb root
  - `python3 tools/zerosms_cli.py sms +15551234567 "Test" --auto`

## Testing & Device/Hardware conventions
- Instrumented tests that require root/hardware live under `app/src/androidTest/`. Use a dedicated test device with root (Magisk recommended) and a separate test profile.
- `RootAndModemTest.kt` demonstrates a rooted-device test that expects `RootAccessManager.isRootAvailable()`.

## Integration Points & External dependencies
- ADB/fastboot — used extensively (adb root, adb shell `su -c`).
- USB vendor/product detection uses `lsusb` / `adb shell` inside `tools/zerosms_cli.py` and `usb-switch` operations rely on `usb_modeswitch`.
- MiFi devices use `modem2_cli`, `nwcli` with EFS/NV item access under `/opt/nvtl/bin/` on the device — treat MiFi commands as different from Android ones.

## Safety: Critical operations and 'do not touch' list
- Read-only: `read_nv` / `modem2_cli get_*` — safe and encouraged for discovery.
- Danger (do not run without explicit human review and sign-off): NV writes / SPC validation / unlocking flows — see `docs/SAFE_OPERATIONS_GUIDE.md`. Examples: `nwcli write_nv`, `modem2_cli validate_spc`, `modem2_cli unlock_carrier`.
- NV items to never write: NV 0xEA64 (NCK), 0xEAAC / 0xEA62 / 0x0D89 (lock flags). If in doubt, consult `docs/SAFE_OPERATIONS_GUIDE.md`.

## How to add features safely
1. Add or modify model in `core/model/Models.kt` and update tests under `core/model/TestScenarios*.kt`.
2. Implement business logic in the appropriate wrapper (e.g., `SmsManagerWrapper`, `MmsManagerWrapper`, `AtCommandManager`), keep platform-specific code in `core/at/` or `core/qualcomm/`.
3. Add UI entries in `ui/navigation/Navigation.kt` and `ui/screens` as Compose screens and wire `StateFlow` for state.
4. Add unit tests (JVM) and instrumented tests (device/requires root or hardware) as appropriate.
5. If modifying modem device code, also update `tools/zerosms_cli.py` if it's a CLI workflow change.

## Quick checklist for PRs & suggested test steps
- Make sure all public functions have Kotlin docs/comments and follow existing naming conventions.
- Add or update `TestScenarios` to cover encoding/segmentation boundary cases.
- If change touches device/driver interactions, include `docs/` update and a `PHASE_*` note for any research work.
- For device commands, provide an example `python3 tools/zerosms_cli.py` snippet for QA to reproduce.

## Where to find help and research tasks
- Phase tracking: `PHASE_*` files in repo root (e.g., `PHASE_5_*`) describe on-going research and tasks; check those if your change affects forensic or device-specific flows.
- For disassembly / reverse engineering references, see `analysis/*` and `arm_analysis_tools/`.

## Final agent guidance
- Always run `./gradlew assembleDebug` locally to validate build after any Kotlin/Gradle changes.
- Validate new root/device flows by referencing `tools/zerosms_cli.py` and `docs/ROOT_ACCESS_GUIDE.md` before adding/removing device-level changes.
- Never add direct NV write commands without explicit instruction or documented test plan (dangerous).

**Ask follow-up:** If anything in these instructions are unclear or incomplete — what part of the development workflow would you like me to expand (e.g., example PR, test harness, or contributor checklist)?
 
---
## Granular Example: Add a new MessageType (step-by-step) ⚙️
This is a common change requested from contributors:

1. Update model enum
  - File: `app/src/main/java/com/zerosms/testing/core/model/Models.kt`
  - Add a new `MessageType` entry (e.g. `SMS_CUSTOM`) and any expected `SmsEncoding` defaults.
  - Keep enum docs consistent with other entries.

2. Add core handling
  - File: `app/src/main/java/com/zerosms/testing/core/sms/SmsManagerWrapper.kt`
  - Add new branch in `when(messageType)` / message dispatch to call new send/receive handlers.
  - Reuse `calculateSmsInfo(...)` for encoding/parts and adhere to existing sending flow (text -> PDU / AT if rooted -> fallback to SmsManager API).

3. Add UI route and screen
  - File: `app/src/main/java/com/zerosms/testing/ui/navigation/Navigation.kt` and `ui/screens/` folder
  - Add a new `Screen` destination where the user can create the new message test. Wire nav args and `StateFlow` state to ViewModel.

4. Add tests and scenarios
  - File: `app/src/main/java/com/zerosms/testing/core/model/TestScenarios*.kt`
  - Add a scenario that uses the new `MessageType`, expected `SmsEncoding`, and a sample message. Add a unit test for the encoding and for `SmsManagerWrapper` send flow. If code depends on root/hardware, add an instrumentation test (in `androidTest`) that asserts graceful fallback and/or successful send on a rooted device.

5. Update CLI & Tools (if needed)
  - If the new feature needs a CLI probe or similar: Update `tools/zerosms_cli.py`—add relevant argument parsing and dispatching. Keep the CLI interface consistent and append an example to the docs.

6. Document and safety checks
  - Add doc changes under `docs/` if the new message type changes user-facing behavior or testing instructions.
  - If the change touches device behavior or NV items, reference `docs/SAFE_OPERATIONS_GUIDE.md` and create a `PHASE_*` note in the repo root.

7. Build & test locally
  - Build: `./gradlew assembleDebug`
  - Unit tests: `./gradlew test`
  - Instrumented tests with device: `./gradlew connectedAndroidTest`

### Minimal code snippet: Add enum & dispatch
```kotlin
// Models.kt
enum class MessageType {
   SMS_TEXT,
   SMS_FLASH,
   SMS_SILENT,
   SMS_CUSTOM // new entry
}

// SmsManagerWrapper.kt (pseudocode)
when (message.type) {
   MessageType.SMS_TEXT -> sendText(message)
   MessageType.SMS_CUSTOM -> sendCustomSms(message)
   else -> fallbackSend(message)
}
```

## PR Checklist & Example Template ✅
Use this checklist when opening a PR for changes that touch core logic or device behavior:

- Title & description: Clear summary + list of changed files and the reason
- Tests: Unit-level tests added/updated; `TestScenarios` entries added for new message types
- Docs: Update `docs/` and add a `PHASE_*` note if device-level changes are included
- CLI: Add new `zerosms_cli.py` flags as needed and include example commands
- Code style: Follow existing Kotlin conventions, use `Logger` for logs, `BuildConfig.DEBUG` for debug-only logs
- Device/Root: Mark whether the change requires root/device and list steps to validate on a test device
- Safety: If NV writes / SPC validation or unlocking flows involved, add explicit review and a backup plan in docs

Example PR body snippet (short):
```text
Summary: Add `SMS_CUSTOM` for carrier test pattern
Files changed: Models.kt, SmsManagerWrapper.kt, TestScenarios.kt, Navigation.kt, docs/TODO.md
Testing: Unit tests added for `calculateSmsInfo` encoding; instrumentation test validates fallback to SmsManager.
Notes: Requires root to use AT flow; no NV writes.
```

## Agent Do / Don't Rules for ZeroSMS 🤖🚫
To make AI contributions safe and high-quality, follow these rules:

Do:
- Ask clarifying questions if a change touches device-level operations (NV writes, SPC, unlocking)
- Add tests for behavior changes and keep existing tests passing
- Use `./gradlew test` locally and `./gradlew assembleDebug` before pushing
- Document changes particularly for device flows in `docs/` and `PHASE_*` files

Don't:
- Do not suggest or perform NV writes or SPC/unlock sequences in code or tests without an explicit sign-off
- Do not change `docs/SAFE_OPERATIONS_GUIDE.md` content that relaxes safety checks without peer review
- Avoid direct device ids or vendor-specific commands in logic—keep them behind CLI tools or profiles

---
If you'd like, I can add an example PR template to `.github/PULL_REQUEST_TEMPLATE.md` and a sample unit test for `SmsManagerWrapper` in `app/src/test/`.
````# Copilot Instructions for ZeroSMS

## Project Overview

ZeroSMS is a dual-purpose project:
1.  **Android App**: A comprehensive SMS/MMS/RCS testing suite with RFC compliance (GSM 03.40, OMA MMS, GSMA RCS UP 2.4).
2.  **Research Suite**: A set of Python tools and documentation for reverse-engineering modem firmware (specifically Inseego MiFi), analyzing NV items, and interacting with modems via AT commands.

## Architecture

### Android App (`app/`)
- **Core Logic**: `com.zerosms.testing.core`
    - `model/`: Data classes (`Message`, `TestResult`) and Enums (`MessageType`, `SmsEncoding`).
    - `sms/`: `SmsManagerWrapper` handles Android SMS APIs.
    - `at/`: `AtCommandManager` (Generic), `HidlAtciManager` (HIDL), `MipcDeviceManager` (MediaTek) for direct modem control.
    - `root/`: `RootAccessManager` for executing root commands.
- **UI**: Jetpack Compose in `com.zerosms.testing.ui`.
- **State**: `StateFlow` used for reactive UI updates.

### Research & Tools (`tools/`, `analysis/`)
- **CLI**: `tools/zerosms_cli.py` is the primary entry point for desktop-based modem interaction via ADB.
- **Analysis**: `analysis/` and `arm_analysis_tools/` contain scripts for binary analysis (Ghidra/IDA helpers) and NV item exploration.
- **Docs**: `docs/` contains deep technical documentation on device specifics (MiFi, Android), RFC compliance, and reverse engineering findings.

## Critical Patterns

### Android Development
- **SMS Encoding**: Always use `smsManager.calculateSmsInfo(text, SmsEncoding.AUTO)` before sending.
- **Message Types**: New types must be added to `MessageType` enum, handled in `SmsManagerWrapper`, and added to UI.
- **Logging**: Use `com.zerosms.testing.core.Logger` instead of `android.util.Log`.
- **Root Access**: Check `RootAccessManager.hasRootAccess()` before attempting AT commands or direct device file access.

### Research & CLI
- **Modem Interaction**: Use `zerosms_cli.py` for reliable AT command execution and mode switching.
    - Example: `python3 tools/zerosms_cli.py sms +15551234567 "Test" --auto`
- **Device Discovery**: `python3 tools/zerosms_cli.py probe --deep` is essential for finding modem ports on new devices.
- **Phase Tracking**: The project uses `PHASE_X_*.md` files in the root to track active research and reverse engineering tasks. Check the latest Phase file for current objectives.

## Workflows

### Android Build & Test
```bash
./gradlew assembleDebug        # Build Debug APK
./gradlew installDebug         # Install on device
./gradlew connectedAndroidTest # Run instrumentation tests (Device Required)
```

### Research & Analysis
- **Probe Device**: `python3 tools/zerosms_cli.py probe --deep --include-response`
- **Diag Mode**: `python3 tools/zerosms_cli.py diag --ai` (Auto-detects profile)
- **Binary Analysis**: Use scripts in `arm_analysis_tools/` for Ghidra/IDA integration.

## Key Files & Directories
- `app/src/main/java/com/zerosms/testing/core/model/Models.kt`: Central definitions for Message types and Enums.
- `tools/zerosms_cli.py`: The "Swiss Army Knife" for modem interaction.
- `docs/ANDROID_DEVICE_GUIDE.md`: Setup guide for Android devices.
- `docs/MIFI_DEVICE_GUIDE.md`: Setup guide for Inseego MiFi devices (Linux-based).
- `PHASE_*`: Current project status and plans.

## Common Gotchas
- **Device Specifics**: Android and MiFi devices behave very differently. Check `docs/` for specific guides.
- **Root Latency**: Root commands via ADB can be slow. Always use generous timeouts (30s+).
- **Modem Paths**: `/dev/smd*` (Qualcomm), `/dev/ttyUSB*` (Generic), `/dev/at_mdm0` (MiFi). Auto-detect using `DeviceInfoManager` or CLI probe.
- **Legacy Code**: `legacy/` contains reference implementations. Do not modify.

## AI Agent Guidelines
- **Context First**: Before suggesting code, check if the task relates to the Android App or the Research Tools.
- **Device Awareness**: When writing scripts, handle both Android (ADB/Shell) and Linux (MiFi) environments.
- **Safety**: Avoid commands that could brick a modem (e.g., raw NV writes) without explicit user confirmation.
