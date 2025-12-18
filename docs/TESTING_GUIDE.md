# SMS Test Testing Guide

## Quick Start

### 1. Installation

```bash
# Clone repository
git clone https://github.com/itds-consulting/android-silent-ping-sms.git
cd 007smsdev

# Build debug APK
./gradlew assembleDebug

# Install on device
./gradlew installDebug
```

### 2. Grant Permissions

On first launch, SMS Test will request:
- SMS send/receive permissions
- Phone state access
- Storage access (for MMS attachments)
- Notification permissions (Android 13+)

**Important:** All permissions are required for full functionality.

### 3. Basic Test

1. Open SMS Test app
2. Select "SMS Testing" from home screen
3. Enter a phone number
4. Type test message
5. Tap "Send Test"
6. View results in Results screen

## Test Categories

### SMS Testing

#### Standard Text SMS
- **Purpose:** Test basic SMS functionality
- **RFC:** GSM 03.40
- **Parameters:**
  - Encoding: AUTO, GSM_7BIT, UCS2
  - Message Class: NONE, CLASS_0, CLASS_1, CLASS_2, CLASS_3
  - Delivery Report: ON/OFF

**Example Test:**
```
Phone: +1234567890
Message: "Hello, this is a test message"
Encoding: AUTO
Class: NONE
Delivery Report: ON
```

#### Long Message (Concatenation)
- **Purpose:** Test multi-part message handling
- **RFC:** GSM 03.40 (with UDH)
- **Behavior:**
  - Messages >160 chars split into parts
  - Each part: 153 chars (GSM) or 67 chars (Unicode)
  - Parts reassembled at recipient

**Example Test:**
```
Message: [200 character string]
Expected: 2 parts (153 + 47 chars)
```

#### Unicode Messages
- **Purpose:** Test UCS-2 encoding
- **RFC:** GSM 03.38
- **Characters:** Emoji, Chinese, Arabic, etc.

**Example Test:**
```
Message: "Hello 世界 🌍"
Encoding: UCS2
Max Length: 70 chars per message
```

#### Binary SMS
- **Purpose:** Test 8-bit data transmission
- **RFC:** GSM 03.40
- **Use Cases:**
  - Silent data transfer
  - OTA provisioning
  - Push notifications

**Example Test:**
```
Type: BINARY
Data: [hex encoded]
Destination Port: 9200
```

#### Flash SMS (Class 0)
- **Purpose:** Test immediate display messages
- **RFC:** GSM 03.40
- **Behavior:**
  - Displays immediately
  - Not stored in inbox
  - User cannot reply

**Example Test:**
```
Message: "Emergency Alert"
Class: CLASS_0
Storage: None
```

#### Silent SMS (Type 0)
- **Purpose:** Network testing, location tracking
- **RFC:** GSM 03.40
- **Behavior:**
  - No user notification
  - No storage
  - Confirms device connectivity

**Example Test:**
```
Type: SILENT
Body: "" (empty or minimal)
Notification: None
```

### MMS Testing

#### Text-Only MMS
- **Purpose:** Test basic MMS structure
- **RFC:** OMA MMS Encapsulation
- **Content:** Text subject and body

**Example Test:**
```
Subject: "Test MMS"
Body: "This is a test MMS message"
Attachments: None
```

#### Image MMS
- **Purpose:** Test image transmission
- **Supported Formats:**
  - JPEG (image/jpeg)
  - PNG (image/png)
  - GIF (image/gif)

**Example Test:**
```
Subject: "Image Test"
Attachments: [test-image.jpg]
Size Limit: 300KB (typical)
```

#### Video MMS
- **Purpose:** Test video transmission
- **Supported Formats:**
  - MP4 (video/mp4)
  - 3GPP (video/3gpp)

**Size Recommendations:**
- Max file size: 300KB-600KB (carrier dependent)
- Resolution: 640x480 or lower
- Duration: <30 seconds

#### Mixed Media MMS
- **Purpose:** Test multiple attachments
- **Example:**
  - Text body
  - Image (JPEG)
  - Audio clip (AMR)
  - vCard contact

**Example Test:**
```
Subject: "Mixed Media Test"
Body: "Multiple attachments"
Attachments:
  - photo.jpg (150KB)
  - audio.amr (50KB)
  - contact.vcf (2KB)
Total: 202KB
```

### RCS Testing

#### Rich Text Messages
- **Purpose:** Test extended character limits
- **RFC:** GSMA RCS UP 2.4
- **Features:**
  - Up to 8000 characters
  - Rich formatting
  - Read receipts
  - Typing indicators

**Example Test:**
```
Message: [2000 character text]
Features:
  - Read Receipt: ON
  - Typing Indicator: ON
  - Delivery Report: ON
```

#### File Transfer
- **Purpose:** Test large file sharing
- **Max Size:** 100MB
- **Supported Types:**
  - Images, videos, audio
  - Documents (PDF, etc.)

**Example Test:**
```
File: large-video.mp4 (50MB)
Features:
  - Progress tracking
  - Pause/resume
  - Fallback to MMS if needed
```

#### Group Chat
- **Purpose:** Test multi-party messaging
- **Max Participants:** 100
- **Features:**
  - Group subject
  - Admin controls
  - Participant management

**Example Test:**
```
Participants: +1234567890, +0987654321, +1122334455
Subject: "Test Group"
Admin: [creator]
```

## Advanced Testing

### Encoding Tests

#### GSM 7-bit Basic
```
Characters: ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
Expected: 1 part (160 chars max)
```

#### GSM 7-bit Extended
```
Characters: {}[]\\^€|~
Behavior: Each requires escape (counts as 2 chars)
```

#### Unicode (UCS-2)
```
Characters: 你好世界 Привет مرحبا
Expected: 1 part (70 chars max)
```

### Stress Testing

#### Rapid Fire
- Send multiple messages quickly
- Test carrier throttling
- Monitor delivery rates

**Configuration:**
```
Messages: 10
Delay: 100ms
Content: Randomized
```

#### Bulk Messages
- Test queue management
- Monitor memory usage
- Verify all deliveries

**Configuration:**
```
Messages: 100
Delay: 1000ms
Content: Sequential numbering
```

### Network Condition Testing

#### Poor Signal
- Test retry mechanisms
- Monitor timeout behavior
- Verify error handling

#### Airplane Mode
- Test queue persistence
- Verify send on reconnect

#### WiFi vs Cellular
- Compare delivery times
- Test MMS routing

## Interpreting Results

### Status Codes

**Success Statuses:**
- `SENT` - Message accepted by network
- `DELIVERED` - Confirmed receipt by recipient
- `PASSED` - Test completed successfully

**Failure Statuses:**
- `FAILED` - Send operation failed
- `TIMEOUT` - No response within timeout period
- `REJECTED` - Network rejected message
- `UNDELIVERABLE` - Cannot reach recipient

### Metrics

**Timing Metrics:**
- **Send Duration**: Time from API call to network acceptance
- **Delivery Duration**: Time from send to delivery confirmation
- **Total Duration**: End-to-end time

**Size Metrics:**
- **Message Size**: Total bytes transmitted
- **Parts Sent/Received**: For concatenated messages

**Quality Metrics:**
- **Success Rate**: Percentage of successful deliveries
- **Average Latency**: Mean delivery time
- **Error Rate**: Percentage of failures

### RFC Violations

Common violations detected:
- Message exceeds length limits
- Invalid character encoding
- Unsupported MIME type
- Missing required headers
- Invalid phone number format

## Best Practices

### Test Design

1. **Start Simple**
   - Begin with basic SMS
   - Verify permissions
   - Test with known working number

2. **Incremental Complexity**
   - Add encoding variations
   - Test concatenation
   - Move to MMS/RCS

3. **Document Results**
   - Export test logs
   - Track success rates
   - Note carrier differences

### Carrier Considerations

**SMS:**
- Length limits strictly enforced
- Concatenation support varies
- Flash SMS may be blocked

**MMS:**
- Size limits vary (100KB-600KB)
- Format support differs
- Gateway configuration varies

**RCS:**
- Carrier support required
- Google Jibe integration needed
- Fallback to SMS/MMS common

### Regulatory Compliance

⚠️ **Important:**
- Obtain recipient consent
- Respect opt-out requests
- Follow local regulations (TCPA, GDPR, etc.)
- Use rate limiting
- Avoid spam patterns

## Troubleshooting

### Messages Not Sending

**Check:**
- [ ] Permissions granted
- [ ] Phone number format (+country code)
- [ ] Network connectivity
- [ ] SIM card inserted
- [ ] Default SMS app (Android 4.4+)

### Delivery Reports Not Received

**Possible Causes:**
- Carrier doesn't support delivery reports
- Recipient network doesn't send reports
- Report timeout (try increasing wait time)

### MMS Failures

**Check:**
- [ ] Mobile data enabled
- [ ] APN settings configured
- [ ] File size within limits
- [ ] Supported MIME type
- [ ] Network not on WiFi only

### RCS Not Available

**Requirements:**
- Android 9.0 or higher
- Google Play Services
- Carrier RCS support
- RCS enabled in settings

## Export & Reporting

### Export Results

1. Navigate to Results screen
2. Tap export icon
3. Choose format:
   - CSV (spreadsheet)
   - JSON (programmatic)
   - PDF (report)

### Result Fields

- Test ID
- Timestamp
- Message Type
- Status
- Delivery Status
- Send Duration
- Delivery Duration
- Message Size
- Parts
- Errors
- RFC Violations

## API Integration

For automated testing, integrate with SMS Test:

```kotlin
// Example: Programmatic test execution
val smsManager = SmsManagerWrapper(context)
val message = Message(
    id = UUID.randomUUID().toString(),
    type = MessageType.SMS_TEXT,
    destination = "+1234567890",
    body = "Automated test message",
    deliveryReport = true
)

val result = smsManager.sendSms(message)
```

## Support

For issues or questions:
1. Check documentation
2. Review RFC compliance guide
3. Verify device compatibility
4. Test with different carrier
5. Open GitHub issue

---

Happy Testing! 🧪📱
