# Copilot Instructions for SMS Test

## Project Overview

SMS Test is a dual-purpose project:
1.  **Android App**: A comprehensive SMS/MMS/RCS testing suite with RFC compliance (GSM 03.40, OMA MMS, GSMA RCS UP 2.4).
2.  **Research Suite**: A set of Python tools and documentation for reverse-engineering modem firmware (specifically Inseego MiFi), analyzing NV items, and interacting with modems via AT commands.

## Architecture

### Android App (`app/`)
- **Core Logic**: `com.007smsdev.testing.core`
    - `model/`: Data classes (`Message`, `TestResult`) and Enums (`MessageType`, `SmsEncoding`).
    - `sms/`: `SmsManagerWrapper` handles Android SMS APIs.
    - `at/`: `AtCommandManager` (Generic), `HidlAtciManager` (HIDL), `MipcDeviceManager` (MediaTek) for direct modem control.
    - `root/`: `RootAccessManager` for executing root commands.
- **UI**: Jetpack Compose in `com.007smsdev.testing.ui`.
- **State**: `StateFlow` used for reactive UI updates.

### Research & Tools (`tools/`, `analysis/`)
- **CLI**: `tools/smstest_cli.py` is the primary entry point for desktop-based modem interaction via ADB.
- **Analysis**: `analysis/` and `arm_analysis_tools/` contain scripts for binary analysis (Ghidra/IDA helpers) and NV item exploration.
- **Docs**: `docs/` contains deep technical documentation on device specifics (MiFi, Android), RFC compliance, and reverse engineering findings.

## Critical Patterns

### Android Development
- **SMS Encoding**: Always use `smsManager.calculateSmsInfo(text, SmsEncoding.AUTO)` before sending.
- **Message Types**: New types must be added to `MessageType` enum, handled in `SmsManagerWrapper`, and added to UI.
- **Logging**: Use `com.007smsdev.testing.core.Logger` instead of `android.util.Log`.
- **Root Access**: Check `RootAccessManager.hasRootAccess()` before attempting AT commands or direct device file access.

### Research & CLI
- **Modem Interaction**: Use `smstest_cli.py` for reliable AT command execution and mode switching.
    - Example: `python3 tools/smstest_cli.py sms +15551234567 "Test" --auto`
- **Device Discovery**: `python3 tools/smstest_cli.py probe --deep` is essential for finding modem ports on new devices.
- **Phase Tracking**: The project uses `PHASE_X_*.md` files in the root to track active research and reverse engineering tasks. Check the latest Phase file for current objectives.

## Workflows

### Android Build & Test
```bash
./gradlew assembleDebug        # Build Debug APK
./gradlew installDebug         # Install on device
./gradlew connectedAndroidTest # Run instrumentation tests (Device Required)
```

### Research & Analysis
- **Probe Device**: `python3 tools/smstest_cli.py probe --deep --include-response`
- **Diag Mode**: `python3 tools/smstest_cli.py diag --ai` (Auto-detects profile)
- **Binary Analysis**: Use scripts in `arm_analysis_tools/` for Ghidra/IDA integration.

## Key Files & Directories
- `app/src/main/java/com/007smsdev/testing/core/model/Models.kt`: Central definitions for Message types and Enums.
- `tools/smstest_cli.py`: The "Swiss Army Knife" for modem interaction.
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
