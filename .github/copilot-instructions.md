# Silent SMS Flash - AI Coding Agent Instructions

## Project Overview

**Silent SMS Flash** is an Android security research application for detecting and sending silent SMS messages. The app supports two SMS types:
- **Class-0 SMS (Flash SMS)**: Visible detection, no root required
- **Type-0 SMS (Completely hidden)**: Requires root access for detection via log scanning

**Key Stats**: ~20 Java files, Android Gradle project, targets API 33, supports Android 6.0+ (API 23+)

## Critical Architecture

### SMS Type Distinction (Essential Concept)
This is the core architectural concept that permeates the entire codebase:

1. **Class-0 SMS**: Uses Android's public `SmsManager.sendDataMessage()` on port 9200. Detected via `BroadcastReceiver` with `DATA_SMS_RECEIVED_ACTION` intent filter. **No root required** for sending or receiving.

2. **Type-0 SMS**: Attempts to mimic hidden SMS behavior using binary data messages. Detection requires **root access** to scan Android system logs for `GsmInboundSmsHandler` entries. Uses background service `Type0SmsMonitorService` with 30-second scanning intervals.

### Component Architecture

```
MainActivity (UI & orchestration)
├── PingSmsReceiver (Class-0 detection) → StoreActivity (view history)
├── Type0SmsMonitorService (Type-0 background scanning)
│   ├── RootChecker (verify root access)
│   └── LogParser (scan system logs for Type-0 indicators)
└── Type0SmsSender (send Type-0 SMS via data message)
```

**Critical Data Flow**: Class-0 SMS → `PingSmsReceiver.onReceive()` → `SharedPreferences` storage → `StoreActivity` display. Type-0 SMS → system logs → `LogParser.scanLogsForType0Sms()` → notification.

## Build & Test Commands

### Build (Verified Working)
```bash
# Clean build (always run this first if you encounter build issues)
./gradlew clean

# Build debug APK
./gradlew assembleDebug

# Build release APK  
./gradlew assembleRelease

# Install on connected device/emulator
./gradlew installDebug
```

**IMPORTANT**: Always run `./gradlew clean` before building after changing dependencies or if you see "duplicate class" errors.

### Testing
```bash
# Run all unit tests
./gradlew test

# Run specific test class
./gradlew test --tests Type0SmsSenderTest

# Run tests with detailed output
./gradlew test --info
```

**Test Coverage**: Unit tests exist for `LogParser`, `RootChecker`, and `Type0SmsSender`. No instrumented tests. Tests are in `app/src/test/java/com/telefoncek/silentsms/detector/`.

### Compatibility Validation
```bash
# Run compatibility checker script (validates Android 12-14 best practices)
bash scripts/check_compatibility.sh
```

This script checks: PendingIntent flags, SDK versions, exported components, notification permissions. **Run this before committing Android compatibility changes.**

## Project-Specific Conventions

### Android Version Compatibility Patterns

**Critical**: This project maintains compatibility with Android 6.0-14 (API 23-34). Every Android API call must consider version differences:

1. **PendingIntent Creation** (Android 12+ requirement):
   ```java
   // ALWAYS include FLAG_MUTABLE or FLAG_IMMUTABLE
   PendingIntent.getBroadcast(context, id, intent, 
       PendingIntent.FLAG_CANCEL_CURRENT | PendingIntent.FLAG_MUTABLE);
   ```

2. **Notification Channels** (Android 8.0+ requirement):
   ```java
   if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
       NotificationChannel channel = new NotificationChannel(CHANNEL_ID, name, importance);
       notificationManager.createNotificationChannel(channel);
   }
   ```

3. **Runtime Permissions** (Android 13+ added POST_NOTIFICATIONS):
   - Check `MainActivity.checkPermissions()` for the canonical pattern
   - Always request SEND_SMS, RECEIVE_SMS, READ_PHONE_STATE, and POST_NOTIFICATIONS
   - See inline comments in `MainActivity.java` lines 148-165

### Code Documentation Standards

**Pattern**: Every Android version-specific code MUST have inline comments explaining the "why":
```java
// Android 13+ (API 33+): Requires POST_NOTIFICATIONS permission for displaying notifications
if (postNotificationPermission != PackageManager.PERMISSION_GRANTED) {
    missingPermissions.add(Manifest.permission.POST_NOTIFICATIONS);
}
```

Look at existing files (MainActivity, PingSmsReceiver, Type0SmsMonitorService) for this pattern. Comments include API level, reason, and context.

### Root Access Pattern

**Always check root before attempting root operations**:
```java
if (!RootChecker.isRootAvailable()) {
    Log.w(TAG, "Root access not available");
    // Handle gracefully - show UI message, disable feature, return
    return;
}
```

This pattern appears in `Type0SmsMonitorService.onStartCommand()` and `MainActivity.initializeType0Monitoring()`. Never assume root is available.

### Shared Preferences Keys

**Centralized in MainActivity as public static final**:
- `PREF_LAST_NUMBER`: Last phone number used
- `PREF_HISTORY`: Comma-separated history of numbers
- `PREF_DATA_SMS_STORE`: Stored received SMS PDUs

Access pattern: `getPreferences(Context.MODE_PRIVATE)` in activities, `getSharedPreferences(PREF_DATA_SMS_STORE, MODE_PRIVATE)` in receivers.

## Key Files & Their Purpose

- **`app/build.gradle`**: Android SDK versions (compileSdk 33, minSdk 23, targetSdk 33), dependencies (mobicents SS7 for PDU parsing)
- **`MainActivity.java`**: Main orchestrator (474 lines) - permission handling, UI bindings, SMS sending logic, Type-0 monitoring toggle
- **`PingSmsReceiver.java`**: BroadcastReceiver for Class-0 SMS, registers for `DATA_SMS_RECEIVED_ACTION` on port 9200
- **`Type0SmsMonitorService.java`**: Background service, 30s interval log scanning, notification creation
- **`LogParser.java`**: Root-based logcat scanning for "GsmInboundSmsHandler.*Received short message type 0" pattern
- **`RootChecker.java`**: Tests for su binary in 10 common paths, executes `su -c id` to verify root
- **`AndroidManifest.xml`**: Permissions (SEND_SMS, RECEIVE_SMS, POST_NOTIFICATIONS), receiver for port 9200 data SMS

## Integration Points

### SMS Port 9200 Standard
Port 9200 is used for silent SMS detection per GSM 03.40/3GPP 23.040 standards. This is **not arbitrary** - the receiver is registered for this port in the manifest:
```xml
<receiver android:name=".PingSmsReceiver" android:exported="true">
    <intent-filter>
        <action android:name="android.provider.Telephony.DATA_SMS_RECEIVED" />
        <data android:scheme="sms" android:port="9200" />
    </intent-filter>
</receiver>
```

### External Dependencies
- **mobicents SS7 (org.mobicents.protocols.ss7.map:map-impl:8.0.112)**: PDU parsing for SMS status reports and delivery confirmations. Used in `MainActivity` for parsing `lastSendResultPDU`. MTP modules are explicitly excluded.

### System Log Integration
Type-0 detection depends on Android's system log format. Pattern: `GsmInboundSmsHandler.*Received short message type 0`. This is a **stable pattern** from Android 2.3 onward but requires root access to read logs via `logcat -t <duration>`.

## Common Pitfalls & Workarounds

1. **PendingIntent Crash on Android 12+**: If you see "Targeting S+ requires FLAG_IMMUTABLE or FLAG_MUTABLE", you forgot the flag. Search codebase for "FLAG_MUTABLE" to see correct usage.

2. **Type-0 SMS Not Detected**: Check three things in order:
   - Root access available? (`RootChecker.isRootAvailable()`)
   - Service running? (check toggle switch state)
   - Logcat accessible? (`LogParser.isLogScanningAvailable()`)

3. **Gradle Build Failure**: If you see "Duplicate class" errors, it's likely MTP module conflicts. Check `app/build.gradle` lines 37-42 for the `withoutMTP` exclusion pattern and ensure it's applied to any SS7 dependencies.

4. **SMS Not Received**: Class-0 SMS must be sent to port 9200. Any other port won't be received by `PingSmsReceiver`. The port is hardcoded in multiple places (MainActivity line 119, manifest).

## Documentation Files

- **`ANDROID_COMPATIBILITY.md`**: Detailed Android 12-14 compatibility matrix, permission requirements per version
- **`TESTING_GUIDE.md`**: Manual testing procedures for each Android version (12, 13, 14)
- **`CREDITS.md`**: Project history and contributors (important context for understanding code evolution)
- **`QUICK_REFERENCE.md`**: User-facing quick start guide

**When to consult**: Before making Android version-specific changes, read `ANDROID_COMPATIBILITY.md` first to understand requirements and existing patterns.

## Trust These Instructions

These instructions are generated from comprehensive codebase analysis including all Java source files, build configurations, documentation, and validation scripts. If information seems incomplete, check the referenced files directly (file paths provided throughout). For Android compatibility questions, the compatibility checker script (`scripts/check_compatibility.sh`) is the source of truth.
