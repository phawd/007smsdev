# AGENTS.md

## Mission and Scope
- Default to the modem research/tooling side of the repo: `tools/`, `analysis/`, `arm_analysis_tools/`, `docs/`, `mifi_backup/`.
- Only switch to Android app code (`app/`) when a task explicitly requires app integration.
- Treat `legacy/silent-sms-flash1` as read-only historical reference.

## Research-First Architecture
- Primary operator surface is `tools/smstest_cli.py` (adb-backed probe/diag/sms/usb tooling).
- Typical flow: discover ports (`probe`) -> enable mode (`diag`) -> validate AT path -> send/test (`sms`) -> collect artifacts/docs.
- Offline reverse-engineering flow centers on extracted binaries in `mifi_backup/` plus helper scripts in `analysis/` and `arm_analysis_tools/`.
- Session direction is phase-driven; use root `PHASE_*` docs as source-of-truth for current priorities.

## Critical Project Conventions
- Start new device work with deep probing: `python tools/smstest_cli.py probe --deep --include-response`.
- Prefer adaptive diag enablement before manual profile guessing: `python tools/smstest_cli.py diag --ai`.
- Use safe test numbers in tooling examples (for example `+15551234567`) and avoid committing real subscriber data.
- When `su` is unavailable, keep workflows functional with `--adb-non-root` instead of failing early.
- Keep operations conservative: probing/read commands are default; require explicit user confirmation before any destructive NV-write behavior.

## Safety and Device Handling
- Assume Android phones and MiFi/Linux targets have different modem node layouts; do not hardcode a single `/dev/*` path strategy.
- Handle root latency/timeouts generously for adb shell operations touching modem nodes.
- Prefer evidence-producing commands (`probe`, `--include-response`, logs) before proposing deeper changes.
- If a command might alter USB mode or modem state (`diag`, `usb-switch`), state impact and rollback expectations first.

## Workflows That Matter (Windows PowerShell)
- `python tools/smstest_cli.py probe --deep --include-response`
- `python tools/smstest_cli.py diag --ai`
- `python tools/smstest_cli.py sms +15551234567 "Test" --auto --deep`
- `python tools/smstest_cli.py usb --json`
- `python tools/smstest_cli.py comscan --json`
- Android integration checks only when needed: `./gradlew.bat assembleDebug`, `./gradlew.bat testDebugUnitTest`

## Integration Touchpoints (When Crossing into App)
- Runtime package is `com.smstest.app` (older docs may still reference `com.007smsdev.testing`).
- Core contract: `app/src/main/java/com/smstest/app/core/model/Models.kt`.
- SMS route and fallback logic: `app/src/main/java/com/smstest/app/core/sms/SmsManagerWrapper.kt`.
- Root gate and `/dev/*` access checks: `app/src/main/java/com/smstest/app/core/root/RootAccessManager.kt`.
- AT implementation used by app path: `app/src/main/java/com/smstest/app/core/at/AtCommandManager.kt`.

## Phase and File Priorities
- Read latest status first: `PHASE_5_SESSION_STATUS.md` and `PHASE_5_STARTUP_CHECKLIST.md`.
- Keep findings and command evidence synchronized with docs in `docs/` and analysis outputs under `analysis/`.
- If phase docs and code disagree, follow current code behavior and document the mismatch.

