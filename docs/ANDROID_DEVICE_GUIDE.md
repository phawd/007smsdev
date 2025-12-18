# Android Device Guide for SMS Test

This guide covers Android device setup, discovery, and SMS/AT command operations for the SMS Test testing suite.

## Device Requirements

- **Real Android device** (not emulator) - emulators cannot send real SMS or access modem hardware
- **Root access** recommended for AT command functionality
- **ADB enabled** in developer options

## Device Discovery

### Step 1: Verify Connection

```bash
adb devices                    # Verify device connected
adb shell getprop ro.build.product  # Device codename
```

### Step 2: Probe Modem Hardware

```bash
python3 tools/smstest_cli.py probe --deep --include-response  # Scan all modem paths
python3 tools/smstest_cli.py usb --json        # USB vendor/product IDs for chipset ID
```

### Step 3: Check Root & Modem Access

```bash
adb shell su -c "ls -la /dev/smd* /dev/ttyUSB* 2>/dev/null"  # Modem device nodes
```

## Modem Paths

Common modem device paths on Android:

| Path | Description |
|------|-------------|
| `/dev/smd0` | Qualcomm SMD channel 0 |
| `/dev/smd11` | Qualcomm SMD channel 11 |
| `/dev/ttyUSB*` | USB serial modem interfaces |
| `/dev/ttyACM*` | ACM modem interfaces |

Modem paths are auto-detected via `DeviceInfoManager`.

## AT Command Managers

SMS Test supports multiple AT command backends for different chipsets:

| Manager | Description | Requirements |
|---------|-------------|--------------|
| `AtCommandManager.kt` | Generic AT via `/dev/smd*` or `/dev/ttyUSB*` | Root access |
| `HidlAtciManager.kt` | Android HIDL interface | API 26+, root |
| `MipcDeviceManager.kt` | MediaTek MIPC protocol | MediaTek chipset, root |

### AT Command Flow

```kotlin
// SmsManagerWrapper tries AT commands first for Class 0/Type 0
if (atCommandsAvailable && AtCommandManager.isInitialized()) {
    // Direct modem PDU send
} else {
    // Standard Android SmsManager API
}
```

## Autonomous Device Control (Root Required)

### Enable Qualcomm Diagnostic Mode

```bash
# Auto-cycle all known profiles
python3 tools/smstest_cli.py diag --ai

# Specify profile
python3 tools/smstest_cli.py diag --profile generic
```

### Reboot Device

```bash
adb reboot                     # Standard reboot
adb shell su -c "reboot"       # Root reboot if needed
```

### USB Mode Switching

```bash
# Qualcomm default
python3 tools/smstest_cli.py usb-switch -v 0x05c6 -p 0x90b4
```

### In-App Diag Management

The app exposes `QualcommDiagManager` (`core/qualcomm/QualcommDiagManager.kt`) for programmatic control:

- `getPresetProfiles()` - Available diag USB configurations
- `getActiveUsbConfig()` - Current USB mode
- `applyProfile(profile)` - Switch diag mode (requires root)

## SMS Operations

### SMS Encoding (GSM 03.38)

Always use `calculateSmsInfo()` before sending to determine encoding and parts:

```kotlin
val smsInfo = smsManager.calculateSmsInfo(text, SmsEncoding.AUTO)
// GSM 7-bit: 160 chars single, 153 per part (concatenated)
// UCS-2: 70 chars single, 67 per part (concatenated)
```

### Key Constants (SmsManagerWrapper)

```kotlin
SMS_MAX_LENGTH_GSM = 160          // Single part GSM 7-bit
SMS_MAX_LENGTH_UNICODE = 70       // Single part UCS-2
SMS_CONCAT_MAX_LENGTH_GSM = 153   // Per part with UDH
SMS_CONCAT_MAX_LENGTH_UNICODE = 67
```

### CLI SMS Operations

```bash
python3 tools/smstest_cli.py sms +15551234567 "Hello" --auto  # Send via AT
```

## Troubleshooting

### Device Not Responding to ADB

```bash
adb kill-server
adb start-server
adb devices  # Retry
```

### Device Stuck - Force Reboot

```bash
adb reboot                          # Soft reboot
adb shell su -c "reboot -f"         # Force reboot (root)
# Hardware: Hold power 10-15 seconds
```

### USB Interface Issues (Windows)

```bash
pnputil /scan-devices               # Rescan (needs admin)
# Device Manager → USB device → Uninstall → Rescan
```

### Diag Mode Not Enabling

```bash
adb shell su -c "setprop persist.sys.usb.config diag,adb"
adb shell su -c "setprop sys.usb.config diag,adb"
adb reboot  # Reboot to apply
```

### Serial/COM Port Not Appearing

- Check Device Manager for yellow ! icons
- Install Qualcomm USB drivers or use generic usbser.sys
- Try: `python3 tools/smstest_cli.py comscan --json`

## Common Gotchas

- Flash SMS (`MessageClass.CLASS_0`) behavior varies by device/carrier
- Silent SMS (`protocolId = 0x40`) may be blocked by carriers
- RCS requires Google Play Services + carrier support
- Root detection caches result - restart app after gaining root
- `IncomingSmsDatabase` is in-memory only (no Room persistence yet)

## Build & Test Commands

```bash
./gradlew assembleDebug       # Debug APK
./gradlew assembleRelease     # Release with ProGuard
./gradlew installDebug        # Install on connected device
./gradlew test                # Unit tests
./gradlew connectedAndroidTest # Instrumentation tests (requires device)
```

## Related Documentation

- `docs/RFC_COMPLIANCE.md` - Protocol implementation details
- `docs/ROOT_ACCESS_GUIDE.md` - AT commands, MMSC config
- `docs/TESTING_GUIDE.md` - User testing workflows
- `docs/MEDIATEK_FLASH_SMS_RESEARCH.md` - MediaTek device quirks
