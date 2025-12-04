# Copilot Instructions for ZeroSMS

## Project Overview

Android SMS/MMS/RCS testing suite with RFC compliance (GSM 03.40, OMA MMS, GSMA RCS UP 2.4). Tests messaging protocols including Flash SMS (Class 0), Silent SMS (Type 0), and direct AT modem commands.

## Architecture

```
app/src/main/java/com/zerosms/testing/
├── core/
│   ├── model/Models.kt           # Message, TestResult, MessageType, DeliveryStatus enums
│   ├── sms/SmsManagerWrapper.kt  # SMS operations, AT command fallback
│   ├── at/
│   │   ├── AtCommandManager.kt   # Generic modem AT commands (root)
│   │   ├── HidlAtciManager.kt    # HIDL-based AT (API 26+)
│   │   └── MipcDeviceManager.kt  # MediaTek IPC protocol
│   ├── root/RootAccessManager.kt # Root detection and execution
│   ├── qualcomm/QualcommDiagManager.kt  # Diag USB mode control
│   ├── mms/MmsManagerWrapper.kt  # MMS PDU encoding
│   ├── rcs/RcsManagerWrapper.kt  # RCS Universal Profile
│   ├── device/DeviceInfoManager.kt  # Chipset-specific modem detection
│   ├── receiver/SmsReceiver.kt   # Incoming SMS capture (incl. Class 0/Type 0)
│   └── Logger.kt                 # Debug-only logging utility
├── ui/screens/              # Jetpack Compose screens (home/, monitor/, test/, settings/)
└── ZeroSMSApplication.kt
```

## Critical Patterns

### SMS Encoding (GSM 03.38)

Always use `calculateSmsInfo()` before sending to determine encoding and parts:

```kotlin
val smsInfo = smsManager.calculateSmsInfo(text, SmsEncoding.AUTO)
// GSM 7-bit: 160 chars single, 153 per part (concatenated)
// UCS-2: 70 chars single, 67 per part (concatenated)
```

### Message Type Flow

1. Add enum to `MessageType` in `Models.kt`
2. Implement in `SmsManagerWrapper.sendSms()` → dispatches by `message.type`
3. Add UI card in `HomeScreen.kt`
4. Document RFC in `docs/RFC_COMPLIANCE.md`

### AT Commands (Root Required)

`AtCommandManager` and `RootAccessManager` are singletons. SMS sending auto-falls back:

```kotlin
// SmsManagerWrapper tries AT commands first for Class 0/Type 0
if (atCommandsAvailable && AtCommandManager.isInitialized()) {
    // Direct modem PDU send
} else {
    // Standard Android SmsManager API
}
```

Modem paths: `/dev/smd0`, `/dev/smd11`, `/dev/ttyUSB*` - detected via `DeviceInfoManager`

### State Management

Use `StateFlow` for reactive updates. UI collects with `collectAsState()`:

```kotlin
val messageStatus: Flow<Map<String, DeliveryStatus>> = _messageStatus.asStateFlow()
```

### Logging

Use `Logger` object (not `Log.d` directly) - suppresses debug logs in release builds:

```kotlin
Logger.d(TAG, "Debug message")  // Only in BuildConfig.DEBUG
Logger.e(TAG, "Error", exception)  // Always logged
```

## Build Commands

```bash
./gradlew assembleDebug       # Debug APK
./gradlew assembleRelease     # Release with ProGuard
./gradlew installDebug        # Install on connected device
./gradlew test                # Unit tests
./gradlew connectedAndroidTest # Instrumentation tests (requires device)
```

## Tech Stack

- Kotlin 2.1.0, Compose BOM 2024.11.00, Material 3
- Min SDK 24, Target/Compile SDK 35, Java 21
- Coroutines + StateFlow, Navigation Compose
- DataStore for preferences, WorkManager for background ops

## Desktop CLI Helper

`tools/zerosms_cli.py` mirrors app functionality via ADB:

```bash
python3 tools/zerosms_cli.py probe --deep  # Scan modem devices
python3 tools/zerosms_cli.py sms +15551234567 "Hello" --auto  # Send via AT
python3 tools/zerosms_cli.py diag --profile generic  # Enable Qualcomm diag
```

## Key Constants (SmsManagerWrapper)

```kotlin
SMS_MAX_LENGTH_GSM = 160      // Single part GSM 7-bit
SMS_MAX_LENGTH_UNICODE = 70   // Single part UCS-2
SMS_CONCAT_MAX_LENGTH_GSM = 153   // Per part with UDH
SMS_CONCAT_MAX_LENGTH_UNICODE = 67
```

## Common Gotchas

- Flash SMS (`MessageClass.CLASS_0`) behavior varies by device/carrier
- Silent SMS (`protocolId = 0x40`) may be blocked by carriers
- RCS requires Google Play Services + carrier support
- Root detection caches result - restart app after gaining root
- `IncomingSmsDatabase` is in-memory only (no Room persistence yet)

## Legacy Reference

The original Java project lives in `legacy/silent-sms-flash1/` - use for:

- Comparing behavior when porting features forward
- Historical APK builds for compliance review
- Groovy Gradle scripts reference (vs current Kotlin DSL)

**Do not modify legacy/** - it's read-only reference material.

## Testing Requirements

**Device required**: Instrumentation tests (`connectedAndroidTest`) and all SMS/AT functionality require a real Android device connected via ADB. Emulators cannot send real SMS or access modem hardware.

```bash
adb devices                    # Verify device connected
./gradlew connectedAndroidTest # Run on-device tests
```

## Device-Specific Guides

For detailed device setup, discovery, and troubleshooting, see the dedicated guides:

| Device Type | Guide                                                           | Description                                    |
| ----------- | --------------------------------------------------------------- | ---------------------------------------------- |
| **Android** | [docs/ANDROID_DEVICE_GUIDE.md](../docs/ANDROID_DEVICE_GUIDE.md) | Standard Android phones/tablets                |
| **MiFi**    | [docs/MIFI_DEVICE_GUIDE.md](../docs/MIFI_DEVICE_GUIDE.md)       | Inseego MiFi 8800L, M2000, M2100 (Linux-based) |

### Quick Device Type Detection

```bash
# Step 1: Check if device responds to ADB
adb devices -l

# Step 2: Detect OS type
adb shell "cat /etc/os-release 2>/dev/null"       # Linux-based (MiFi)
adb shell "getprop ro.build.product 2>/dev/null"  # Android

# Step 3: Branch to appropriate guide
# - MiFiOS2: See docs/MIFI_DEVICE_GUIDE.md
# - Android: See docs/ANDROID_DEVICE_GUIDE.md
```

## Documentation Index

| Document                              | Purpose                                      |
| ------------------------------------- | -------------------------------------------- |
| `docs/ANDROID_DEVICE_GUIDE.md`        | Android device setup and AT commands         |
| `docs/MIFI_DEVICE_GUIDE.md`           | MiFi device setup, CLI tools, carrier config |
| `docs/MIFI_8800L_DEVICE_REFERENCE.md` | Comprehensive MiFi hardware catalog          |
| `docs/RFC_COMPLIANCE.md`              | Protocol implementation details              |
| `docs/ROOT_ACCESS_GUIDE.md`           | AT commands, MMSC config                     |
| `docs/TESTING_GUIDE.md`               | User testing workflows                       |
| `docs/MEDIATEK_FLASH_SMS_RESEARCH.md` | MediaTek device quirks                       |
| `docs/SESSION_2_FINDINGS.md`          | Experimental session notes                   |

## AI Agent Integration

For AI agents working autonomously with devices:

1. **Always use 30+ second timeouts** for device operations - modems are slow
2. **Check prerequisites first**: `adb`, `fastboot`, `python3`, pyserial installed
3. **Detect device type FIRST**: Android vs MiFiOS (Linux) requires different commands
4. **Escalate gracefully**: ADB → fastboot → EDL → web interface → manual intervention
5. **Log everything**: Use `python3 tools/zerosms_cli.py probe --deep --include-response > probe-log.txt`
6. **Handle driver issues**: Windows devices may show "Unknown" status - need admin
7. **Document findings**: Update `docs/SESSION_*_FINDINGS.md` with device-specific discoveries
