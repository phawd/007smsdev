# ZeroSMS Testing Suite

Comprehensive SMS, MMS, and RCS testing application with full RFC compliance for Android.

## Overview

ZeroSMS is a professional-grade testing tool designed to validate messaging protocols against industry standards. It provides extensive testing capabilities for:

- **SMS (Short Message Service)** - GSM 03.40, GSM 03.38, 3GPP TS 23.040
- **MMS (Multimedia Messaging Service)** - OMA MMS Encapsulation Protocol, WAP-209
- **RCS (Rich Communication Services)** - GSMA RCS Universal Profile 2.4

## Features

### SMS Testing

- ✅ Standard text messages (GSM 7-bit, 8-bit, UCS-2)
- ✅ Binary SMS with port addressing
- ✅ Flash SMS (Class 0 - immediate display)
- ✅ Silent SMS (Type 0 - network testing)
- ✅ Message concatenation (multi-part messages)
- ✅ Character encoding validation
- ✅ Delivery and read reports
- ✅ Message class handling (Class 0-3)
- ✅ Validity period configuration
- ✅ Priority levels
- ✅ **AT command support for direct modem access (requires root)**
- ✅ **Incoming SMS monitor for Class 0/Type 0 messages**
- ✅ **Command Line Interface (CLI) with cursor navigation support**

### MMS Testing

- ✅ Text-only MMS
- ✅ Image attachments (JPEG, PNG, GIF)
- ✅ Video attachments (MP4, 3GPP)
- ✅ Audio attachments (AMR, MP3)
- ✅ vCard attachments
- ✅ Mixed media messages
- ✅ Subject and priority
- ✅ Delivery and read receipts
- ✅ Size validation and compression
- ✅ **MMSC configuration with carrier presets**

### RCS Testing

- ✅ Rich text messages (up to 8000 chars)
- ✅ File transfer (up to 100MB)
- ✅ Group chat (up to 100 participants)
- ✅ Typing indicators
- ✅ Read receipts
- ✅ Delivery reports
- ✅ Capability discovery
- ✅ Fallback to SMS/MMS

## RFC & Standards Compliance

### SMS Standards

- **GSM 03.40** - Technical realization of SMS
- **GSM 03.38** - Alphabets and language-specific information
- **3GPP TS 23.040** - Technical realization of SMS
- **3GPP TS 23.038** - Alphabets and language-specific information

### MMS Standards

- **OMA MMS Encapsulation Protocol** - Message structure
- **WAP-209-MMSEncapsulation** - Encoding specifications
- **WAP-230-WSP** - Wireless Session Protocol
- **RFC 2046** - MIME Media Types

### RCS Standards

- **GSMA RCS Universal Profile 2.4** - Core specifications
- **RFC 4975** - MSRP (Message Session Relay Protocol)
- **RFC 6120** - XMPP Core (Extensible Messaging)

## Architecture

ZeroSMS is organized to keep device-facing protocol work, UI, and reference materials isolated from one another:

- `app/` — Android application code. `core/` holds protocol wrappers and device utilities; `ui/` contains the Compose surfaces; `ZeroSMSApplication.kt` and `MainActivity.kt` wire everything together.
- `tools/` — Desktop and helper utilities for AT command probing and modem enablement.
- `legacy/` — A read-only snapshot of the original silent-sms-flash1 project for behavioral comparison.
- `docs/` — Deep-dive research notes, forensic traces, and implementation guides for each device family.
- `binaries/`, `mifi_catalog/`, and other hardware artifacts — Collected firmware and extracted assets for investigations.

The modern Android module follows an MVVM-style separation: protocol and data logic (the **Model**) live under `core/`, lifecycle-aware state holders that expose `StateFlow` to the UI act as **ViewModels`, and Jetpack Compose screens and navigation under `ui/` are the **View**, depending only on stable interfaces from `core`.

## Tools: Direct Device Access (Python)

For advanced users and debugging, a standalone Python script is provided to send AT commands directly to modem device files (e.g., Qualcomm, Inseego, MediaTek, USB modems) from a PC or rooted Android with Python support.

**Script:** `tools/qualcomm_modem_access.py`

**Requirements:**

- Python 3.x
- `pyserial` package (`pip install pyserial`)
- Root access (if running on Android)

**Usage:**

Scan and list all available serial ports and USB IDs:

```sh
python tools/qualcomm_modem_access.py scan
```

Enable diagnostic/AT ports (device-dependent):

```sh
python tools/qualcomm_modem_access.py enable <device_type>
# device_type: qualcomm | mtk | samsung | generic
# Example for Qualcomm:
python tools/qualcomm_modem_access.py enable qualcomm
# Example for MediaTek:
python tools/qualcomm_modem_access.py enable mtk
```

Send a single AT command:

```sh
python tools/qualcomm_modem_access.py <device_path> <AT_command> [baudrate]
# Example:
python tools/qualcomm_modem_access.py /dev/smd0 "AT+CSQ"
```

Send an SMS (supports Qualcomm, MTK, and generic modems):

```sh
python tools/qualcomm_modem_access.py <device_path> sms <modem_type> <phone_number> <message>
# Example for Qualcomm:
python tools/qualcomm_modem_access.py /dev/smd0 sms qualcomm +1234567890 "Hello from Python!"
# Example for MediaTek:
python tools/qualcomm_modem_access.py /dev/ttyUSB0 sms mtk +1234567890 "Test MTK SMS"
```

This script can be used to:

- Test AT command responses on any supported device path
- Send SMS directly from PC or rooted Android
- Enable diagnostic/AT ports for supported device types
- Debug modem access issues outside the Android app
- Validate port permissions and connectivity

**Warning:** Use with caution. Writing to the wrong device file or enabling diagnostic ports incorrectly can cause instability. Always verify device path, permissions, and device type.

```
app/
├── src/main/java/com/zerosms/testing/
│   ├── core/
│   │   ├── model/         # Data models for messages and tests
│   │   ├── sms/           # SMS manager with RFC compliance
│   │   ├── mms/           # MMS manager with OMA compliance
│   │   ├── rcs/           # RCS manager with GSMA compliance
│   │   └── receiver/      # Broadcast receivers for incoming messages
│   ├── ui/
│   │   ├── screens/       # Composable UI screens
│   │   ├── navigation/    # Navigation graph
│   │   └── theme/         # Material 3 theming
│   └── ZeroSMSApplication.kt
└── AndroidManifest.xml
```

## Legacy Reference

The original “silent-sms-flash1” Java project has been imported verbatim under
`legacy/silent-sms-flash1`. This snapshot retains its Groovy Gradle scripts,
drawables, documentation, and historical APK builds for compliance review. It
is intentionally isolated from the primary ZeroSMS module—treat it as a
read-only reference when comparing behaviors or porting features forward.

## Key Components

### SmsManagerWrapper

Handles all SMS operations with full GSM compliance:

- Message encoding (GSM 7-bit, 8-bit, UCS-2)
- Message segmentation and concatenation
- Binary SMS with port addressing
- Flash SMS (Class 0)
- Silent SMS (Type 0)
- Delivery status tracking

### MmsManagerWrapper

Manages MMS operations per OMA specifications:

- PDU (Protocol Data Unit) encoding
- WSP (Wireless Session Protocol) encoding
- MIME multipart message assembly
- Attachment handling and validation
- Size limit enforcement
- MMSC gateway communication

### RcsManagerWrapper

Implements RCS Universal Profile:

- Rich messaging capabilities
- Large file transfers
- Group chat management
- Capability negotiation
- Fallback mechanisms

## Build Instructions

### Prerequisites

- Android Studio Hedgehog (2023.1.1) or later

For advanced users and debugging, a standalone Python script is provided to send AT commands and SMS directly to modem device files (Qualcomm, Inseego, MediaTek, USB, etc.) from a PC or rooted Android with Python support.

**Script:** `tools/qualcomm_modem_access.py`

**Requirements:**

- Python 3.x
- `pyserial` package (`pip install pyserial`)
- Root access (if running on Android)

**Usage:**

Scan and list all available serial ports and USB IDs:

```sh
python tools/qualcomm_modem_access.py scan
```

Send a single AT command:

```sh
python tools/qualcomm_modem_access.py <device_path> <AT_command> [baudrate]
# Example:
python tools/qualcomm_modem_access.py /dev/smd0 "AT+CSQ"
```

Send an SMS (supports Qualcomm, MTK, and generic modems):

```sh
python tools/qualcomm_modem_access.py <device_path> sms <modem_type> <phone_number> <message>
# Example for Qualcomm:
python tools/qualcomm_modem_access.py /dev/smd0 sms qualcomm +1234567890 "Hello from Python!"
# Example for MediaTek:
python tools/qualcomm_modem_access.py /dev/ttyUSB0 sms mtk +1234567890 "Test MTK SMS"
```

This script can be used to:

- Test AT command responses on any supported device path
- Send SMS directly from PC or rooted Android
- Debug modem access issues outside the Android app
- Validate port permissions and connectivity

**Warning:** Use with caution. Writing to the wrong device file can cause instability. Always verify device path and permissions.

```

### Gradle Configuration

- **Min SDK**: 24 (Android 7.0)
- **Target SDK**: 35 (Android 15)
- **Compile SDK**: 35
- **Java**: 21 LTS (Latest Long Term Support)
- **Kotlin**: 2.1.0
- **Compose**: BOM 2024.11.00
- **Android Gradle Plugin**: 8.8.0

### Configuration & Secrets

- Set the Apify API key via `APIFY_API_KEY` in `~/.gradle/gradle.properties` or an environment variable before building. The `app/build.gradle.kts` script reads from Gradle properties first, then falls back to environment variables, and finally to a `REPLACE_ME` placeholder if nothing is provided.
- Avoid committing real credentials to the repo—prefer `~/.gradle/gradle.properties` or a `.env`-style environment export instead.
- Confirm that `local.properties` (used for local SDK paths and similar settings) and generated binary artifacts remain untracked before opening pull requests.
- Linux and Bash/WSL examples:
  - `~/.gradle/gradle.properties`
    ```
    APIFY_API_KEY=your_apify_key_here
    ```
  - or export for a single shell session:
    ```bash
    export APIFY_API_KEY=your_apify_key_here
    ```

## Permissions Required

```xml
<!-- SMS Permissions -->
<uses-permission android:name="android.permission.SEND_SMS" />
<uses-permission android:name="android.permission.RECEIVE_SMS" />
<uses-permission android:name="android.permission.READ_SMS" />
<uses-permission android:name="android.permission.READ_PHONE_STATE" />

<!-- MMS Permissions -->
<uses-permission android:name="android.permission.RECEIVE_MMS" />
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />

<!-- Storage for attachments -->
<uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
<uses-permission android:name="android.permission.READ_MEDIA_VIDEO" />
<uses-permission android:name="android.permission.READ_MEDIA_AUDIO" />

<!-- Notifications (Android 13+) -->
<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
```

## Advanced Features (Root Required)

### AT Command Support

- **Direct modem access** for sending SMS via AT commands
- **Class 0 (Flash SMS)** with enhanced control
- **Type 0 (Silent SMS)** for network testing
- **PDU mode** encoding with full GSM 03.40 compliance
- Supports multiple modem device paths: `/dev/smd0`, `/dev/smd11`, `/dev/ttyUSB0`, etc.
- Qualcomm diag-port enabler with device-specific USB profiles (Generic Snapdragon, Inseego MiFi, custom diag_mdm)
- Chipset-aware scanner that probes Qualcomm, MediaTek, Samsung, and fallback modem nodes to confirm AT/SMS readiness

### Incoming SMS Monitor

- **Real-time monitoring** of all incoming SMS
- **Capture and display** Class 0 (Flash) and Type 0 (Silent) SMS
- **Persistent storage** of normally hidden messages
- **PDU inspection** with protocol details
- **Filter by message type** (Flash, Silent, Normal)

### MMSC Configuration

- **Custom MMSC settings** for MMS sending
- **Carrier presets** (T-Mobile, AT&T, Verizon, Vodafone, etc.)
- **Proxy and port configuration**
- **Automatic carrier detection**

**Note:** Root access is required for AT command functionality. The app will fall back to standard Android SMS APIs if root is not available.

### Command Line Interface (CLI)

- **Interactive CLI** with ANSI color support and cursor navigation
- **Menu-driven interface** for easy navigation
- **All core functions** accessible via command line
- **Cross-platform support** (Android terminal, ADB shell)
- **Command history** and auto-completion

### Desktop Helper (Python)

ZeroSMS ships with a lightweight helper script for desktop automation (`tools/zerosms_cli.py`). It mirrors the APK’s Qualcomm diag toggle and AT-based SMS sending via adb:

- `python3 tools/zerosms_cli.py diag --profile inseego-m2000` — enable diag ports for a given preset
- `python3 tools/zerosms_cli.py diag --ai` — AI mode cycles every preset until diag is active
- `python3 tools/zerosms_cli.py sms +15551234567 "Hello" --auto --deep` — auto-select modem and send SMS
- `python3 tools/zerosms_cli.py probe --deep --include-response` — deep AT scan (Qualcomm/MediaTek/Samsung)
- `python3 tools/zerosms_cli.py usb --json` — enumerate USB vendor/product IDs (uses `lsusb`/system profiler)
- `python3 tools/zerosms_cli.py usb-switch -v 0x05c6 -p 0x90b4` — run `usb_modeswitch` for dongles and MiFi
- `python3 tools/zerosms_cli.py comscan` — list desktop COM ports via pySerial (great for USB modem drivers)
- Add `--adb-non-root` when the connected device cannot provide `su`

The helper assumes `adb` is installed. Commands that touch modem nodes may still require root; non-root mode attempts the same calls without `su` but may lack permissions.

#### CLI Commands

```bash
test sms <number>     # Send SMS test to specified number
test mms <number>     # Send MMS test to specified number
test rcs <number>     # Send RCS test to specified number
monitor start         # Start message monitoring
monitor stop          # Stop message monitoring
results              # Show test results
settings             # Show current settings
menu                 # Interactive menu (cursor navigation)
clear                # Clear screen
help                 # Show help
exit                 # Exit CLI
```

## Testing Capabilities

### Test Categories

1. **SMS Text** - Standard text message testing
2. **SMS Binary** - 8-bit data and port addressing
3. **SMS Flash** - Class 0 immediate display
4. **SMS Silent** - Type 0 network testing
5. **Concatenation** - Multi-part message handling
6. **Encoding** - Character set validation
7. **MMS Basic** - Text and single attachment
8. **MMS Mixed** - Multiple attachments
9. **RCS Messaging** - Rich text features
10. **RCS File Transfer** - Large file support
11. **Delivery Reports** - Status tracking
12. **Stress Testing** - High-volume scenarios

### Test Parameters

- **Encoding**: GSM 7-bit, 8-bit, UCS-2, Auto
- **Message Class**: Class 0-3, None
- **Priority**: Low, Normal, High, Urgent
- **Reports**: Delivery reports, read receipts
- **Repeat Count**: Multiple message sending
- **Delay**: Time between messages
- **Randomization**: Content variation

## Usage

### Quick Start

1. Launch ZeroSMS application
2. Grant required permissions
3. Select test category (SMS/MMS/RCS)
4. Configure test parameters
5. Enter recipient phone number
6. Run test
7. View results and metrics

### Example Test Flow

```kotlin
// Create SMS test message
val message = Message(
    id = UUID.randomUUID().toString(),
    type = MessageType.SMS_TEXT,
    destination = "+1234567890",
    body = "Test message",
    encoding = SmsEncoding.AUTO,
    messageClass = MessageClass.NONE,
    priority = Priority.NORMAL,
    deliveryReport = true
)

// Send via SmsManager
val result = smsManager.sendSms(message)
```

## Test Results

Results include:

- ✅ **Status**: Passed/Failed/Timeout
- ✅ **Delivery Status**: Sent/Delivered/Failed
- ✅ **Performance Metrics**: Send/delivery duration
- ✅ **Message Parts**: Sent/received count
- ✅ **Message Size**: Bytes transmitted
- ✅ **RFC Violations**: Standards compliance issues
- ✅ **Error Details**: Failure reasons

## Development

### Technology Stack

- **Language**: Kotlin
- **UI Framework**: Jetpack Compose (Material 3)
- **Architecture**: MVVM with Clean Architecture
- **Async**: Coroutines + Flow
- **Dependency Injection**: Manual (can add Hilt/Koin)
- **Navigation**: Navigation Compose

### Code Organization

- `core/model/` - Domain models and data classes
- `core/sms/` - SMS protocol implementation
- `core/mms/` - MMS protocol implementation
- `core/rcs/` - RCS protocol implementation
- `core/receiver/` - Broadcast receivers
- `ui/screens/` - Composable UI screens
- `ui/theme/` - Material 3 theming

## Future Enhancements

- [ ] Database persistence for test history
- [ ] Export test results (CSV, JSON, PDF)
- [ ] Scheduled test execution
- [ ] Network condition simulation
- [ ] Message timing analysis
- [ ] Comparative testing
- [ ] Automated test suites
- [ ] CI/CD integration
- [ ] REST API for remote testing
- [ ] Multi-device synchronization

## License

This project is intended for testing and educational purposes. Ensure compliance with local telecommunications regulations when testing messaging protocols.

## Contributing

Contributions welcome! Areas of focus:

- Additional RFC compliance tests
- Performance optimizations
- UI/UX improvements
- Test automation
- Documentation

## Contact

For issues, questions, or contributions, please open an issue on the repository.

---

**ZeroSMS** - Professional messaging protocol testing for Android is an Android application that allows users to send silent SMS messages without notifying the recipient. This can be useful for various purposes, such as network testing or discreet communication. This is not meant for public distribution and should be used responsibly.
