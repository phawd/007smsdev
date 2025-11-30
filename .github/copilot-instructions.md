# Copilot Instructions for `zerosms`

## Project Overview
**ZeroSMS** is a comprehensive SMS/MMS/RCS testing suite for Android with full RFC compliance. The application enables testing of all messaging protocols against industry standards (GSM 03.40, OMA MMS, GSMA RCS UP 2.4).

## Architecture

### Layer Structure
```
app/src/main/java/com/zerosms/testing/
├── core/
│   ├── model/         # Domain models (Message, TestResult, etc.)
│   ├── sms/           # SMS protocol implementation (GSM 03.40)
│   ├── mms/           # MMS protocol implementation (OMA MMS)
│   ├── rcs/           # RCS implementation (GSMA UP 2.4)
│   └── receiver/      # Broadcast receivers for incoming messages
├── ui/
│   ├── screens/       # Jetpack Compose screens (Home, Test, Results, Settings)
│   ├── navigation/    # Navigation graph
│   └── theme/         # Material 3 theming
└── ZeroSMSApplication.kt
```

### Key Components

**SmsManagerWrapper** (`core/sms/`):
- Handles GSM 03.40 compliant SMS operations
- Encoding: GSM 7-bit, 8-bit, UCS-2
- Message types: Standard, Binary, Flash (Class 0), Silent (Type 0)
- Concatenation with UDH for multi-part messages
- Delivery and read reports
- **AT command support** for direct modem access (requires root)
- **Fallback mechanism** when AT commands unavailable

**MmsManagerWrapper** (`core/mms/`):
- OMA MMS Encapsulation Protocol implementation
- PDU encoding with WSP format
- MIME multipart message assembly
- Attachment handling (images, video, audio, vCard)
- Size validation (300KB typical limit)

**RcsManagerWrapper** (`core/rcs/`):
- GSMA RCS Universal Profile 2.4
- Rich messaging (8000 char limit)
- File transfer (100MB limit)
- Group chat (100 participants)
- Capability discovery and fallback

### Data Models (`core/model/Models.kt`)
- `Message`: Core message entity with type, encoding, class, priority
- `MessageType`: Enum for SMS_TEXT, SMS_BINARY, SMS_FLASH, SMS_SILENT, MMS_*, RCS_*
- `TestResult`: Test execution results with metrics and RFC violations
- `DeliveryStatus`: Tracking states (PENDING, SENT, DELIVERED, FAILED, etc.)

## RFC Compliance

### Standards Implemented
- **GSM 03.40**: SMS Point-to-Point protocol
- **GSM 03.38**: Character encoding (7-bit, extended, UCS-2)
- **3GPP TS 23.040**: Technical SMS realization
- **OMA MMS Encapsulation**: MMS PDU structure
- **WAP-209/WAP-230**: MMS encoding and WSP
- **GSMA RCS UP 2.4**: Rich Communication Services
- **RFC 2046**: MIME types
- **RFC 4975**: MSRP protocol (RCS)

### Encoding Rules
- **GSM 7-bit**: 160 chars single, 153 chars per part (concatenated)
- **UCS-2**: 70 chars single, 67 chars per part (concatenated)
- **Extended GSM**: Characters like `^{}[]\|~€` require escape (2 char cost)
- Always check `containsUnicodeCharacters()` to determine encoding

### Message Class Significance
- **CLASS_0**: Flash SMS - immediate display, no storage
- **CLASS_1**: Default mobile storage
- **CLASS_2**: SIM card storage
- **CLASS_3**: Terminal equipment storage
- **NONE**: Standard inbox delivery

## Build & Development

### Tech Stack
- **Language**: Kotlin 1.9.20
- **UI**: Jetpack Compose (BOM 2023.10.01) with Material 3
- **Min SDK**: 24 (Android 7.0)
- **Target/Compile SDK**: 34 (Android 14)
- **Build System**: Gradle 8.2 with Kotlin DSL
- **Async**: Coroutines + StateFlow
- **Navigation**: Navigation Compose
- **Permissions**: Accompanist Permissions library

### Build Commands
```bash
./gradlew assembleDebug      # Build debug APK
./gradlew assembleRelease    # Build release APK  
./gradlew test               # Run unit tests
./gradlew connectedAndroidTest # Run instrumentation tests
./gradlew installDebug       # Install on device
```

### Critical Permissions
```xml
<!-- Required for core functionality -->
SEND_SMS, RECEIVE_SMS, READ_SMS, READ_PHONE_STATE
RECEIVE_MMS, INTERNET, ACCESS_NETWORK_STATE
READ_MEDIA_IMAGES, READ_MEDIA_VIDEO, READ_MEDIA_AUDIO
POST_NOTIFICATIONS (Android 13+)
```

## Development Patterns

### Adding New Message Type
1. Add enum to `MessageType` in `Models.kt`
2. Implement send logic in appropriate manager (SMS/MMS/RCS)
3. Add UI test card in `HomeScreen.kt` test categories
4. Create test templates in `TestScreen.kt`
5. Add RFC references in `getRfcForType()`
6. Update `RFC_COMPLIANCE.md` documentation

### Handling Broadcasts
- **SmsReceiver**: Handles incoming SMS via `SMS_RECEIVED`
  - **ENHANCED**: Captures and stores Class 0 (Flash) and Type 0 (Silent) SMS
  - Detects message class and protocol ID (PID = 0x40 for Type 0)
  - Persists to `IncomingSmsDatabase` for operator monitoring
  - Provides detailed logging with PDU hex dump
- **MmsReceiver**: Handles incoming MMS via `WAP_PUSH_RECEIVED`
- **DeliveryReceiver**: Tracks send/delivery status with `PendingIntent`

### Root Access & AT Commands
- **RootAccessManager** (`core/root/`): Detects root, executes root commands
- **AtCommandManager** (`core/at/`): Direct modem communication
- Use `SmsManagerWrapper.initializeAtCommands()` on app startup
- Use `sendSmsViaAt()` for Class 0/Type 0 with enhanced control
- Automatic fallback to standard API if root unavailable
- Modem device paths: `/dev/smd0`, `/dev/smd11`, `/dev/ttyUSB*`

### Incoming SMS Monitoring
- **IncomingSmsDatabase** (`core/database/`): In-memory message storage
- **MonitorScreen** (`ui/screens/monitor/`): Real-time SMS viewer
- Auto-refresh every second for live monitoring
- Filter by All/Flash/Silent message types
- Click message for full PDU and technical details
- Access via "SMS Monitor" button on home screen

### State Management
- Use `StateFlow` for reactive status updates
- `SmsManagerWrapper._messageStatus` tracks per-message delivery
- UI observes flows with `collectAsState()` in Composables

### Testing Best Practices
1. Always validate phone number format (E.164 recommended)
2. Calculate message parts before sending (`calculateSmsInfo()`)
3. Monitor delivery status via PendingIntents
4. Log RFC violations in `TestResult.rfcViolations`
5. Track performance metrics (send duration, size, parts)

## Common Tasks

### Implementing New Test Scenario
```kotlin
// 1. Define test parameters
val testScenario = TestScenario(
    id = "NEW_TEST_ID",
    name = "Test Name",
    description = "What this tests",
    messageType = MessageType.SMS_TEXT,
    testParameters = TestParameters(
        repeatCount = 1,
        testConcatenation = true
    ),
    rfcCompliance = listOf("GSM 03.40")
)

// 2. Execute test
val message = Message(
    id = UUID.randomUUID().toString(),
    type = messageType,
    destination = phoneNumber,
    body = testBody,
    encoding = encoding
)

val result = smsManager.sendSms(message)

// 3. Record results
val testResult = TestResult(
    scenarioId = testScenario.id,
    messageId = message.id,
    status = TestStatus.RUNNING,
    deliveryStatus = DeliveryStatus.PENDING
)
```

### Debugging Message Encoding
```kotlin
// Check character classification
val isUnicode = containsUnicodeCharacters(text)
val smsInfo = calculateSmsInfo(text, SmsEncoding.AUTO)

Log.d("Encoding", """
    Text: $text
    Unicode: $isUnicode
    Parts: ${smsInfo.parts}
    Remaining: ${smsInfo.remainingChars}
    Encoding: ${smsInfo.encoding}
""")
```

### Validating MMS Before Send
```kotlin
val validation = validateMmsMessage(message)
if (!validation.isValid) {
    // Handle errors
    validation.errors.forEach { error ->
        Log.e("MMS", "Validation error: $error")
    }
    return Result.failure(Exception(validation.errors.joinToString()))
}
```

## File Locations

### Essential Files
- **Core Logic**: `app/src/main/java/com/zerosms/testing/core/`
  - `sms/SmsManagerWrapper.kt` - SMS operations + AT commands
  - `at/AtCommandManager.kt` - Modem communication
  - `root/RootAccessManager.kt` - Root detection and execution
  - `database/IncomingSmsDatabase.kt` - Message storage
  - `mmsc/MmscConfigManager.kt` - MMSC configuration
- **UI Screens**: `app/src/main/java/com/zerosms/testing/ui/screens/`
  - `monitor/MonitorScreen.kt` - Incoming SMS viewer (NEW)
- **Models**: `core/model/Models.kt`
- **Manifest**: `app/src/main/AndroidManifest.xml`
- **Build Config**: `app/build.gradle.kts`

### Documentation
- **README.md**: Project overview and quick start
- **docs/RFC_COMPLIANCE.md**: Detailed RFC implementation
- **docs/TESTING_GUIDE.md**: User testing guide
- **docs/ROOT_ACCESS_GUIDE.md**: Root access, AT commands, MMSC configuration (NEW)

## When Making Changes

### Code Style
- Use Kotlin idioms (data classes, sealed classes, when expressions)
- Prefer coroutines over threads
- Use `StateFlow` for reactive state
- Keep Composables focused and reusable
- Extract business logic from UI

### Adding Dependencies
Document in README with:
- Maven coordinates
- Version number
- Purpose/justification
- Any licensing considerations

### Updating RFCs
When implementing new RFC features:
1. Add to relevant manager (SMS/MMS/RCS)
2. Update `RFC_COMPLIANCE.md` with implementation details
3. Add test scenarios to verify compliance
4. Include RFC number in test metadata

### Testing Strategy
- Unit tests for encoding logic, validation rules
- Integration tests for manager classes (mock Android APIs)
- Instrumentation tests for actual message sending (require device/emulator)
- Always test on real device for final validation

## Known Limitations

- RCS requires Google Play Services and carrier support
- MMS PDU encoding is simplified; production needs carrier APN config
- Silent SMS may be blocked by carriers
- Flash SMS support varies by device manufacturer
- Binary SMS port addressing may have restrictions

## Future Enhancements Roadmap
- Database persistence (Room) for test history
- Export results (CSV, JSON, PDF)
- Scheduled test execution (WorkManager)
- REST API for remote testing
- CI/CD integration for automated tests
- Network condition simulation
- Multi-device synchronization

When contributing, prioritize RFC compliance and maintain comprehensive test coverage. Always document protocol behavior and carrier-specific quirks.
