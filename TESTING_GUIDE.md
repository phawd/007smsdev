# Testing Guide for Android 12, 13, and 14 Compatibility

## Overview
This guide provides comprehensive testing procedures to verify the Silent SMS Detector app works correctly on Android 12, 13, and 14 devices.

## Test Environment Setup

### Required Test Devices/Emulators
1. **Android 12 (API 31)** - One device or emulator
2. **Android 13 (API 33)** - One device or emulator  
3. **Android 14 (API 34)** - One device or emulator (optional, for future-proofing)

### Setting Up Android Emulators
```bash
# Create Android 12 emulator
avdmanager create avd -n Android12_Test -k "system-images;android-31;google_apis;x86_64" -d pixel

# Create Android 13 emulator
avdmanager create avd -n Android13_Test -k "system-images;android-33;google_apis;x86_64" -d pixel

# Create Android 14 emulator
avdmanager create avd -n Android14_Test -k "system-images;android-34;google_apis;x86_64" -d pixel
```

## Test Cases

### 1. Installation and First Launch

#### Test 1.1: Fresh Installation
**Steps:**
1. Install APK on test device
2. Launch the app
3. Observe permission request dialogs

**Expected Results:**
- App installs without errors
- App launches successfully
- Permission dialogs appear for:
  - SMS permissions (SEND_SMS, RECEIVE_SMS)
  - Phone state (READ_PHONE_STATE)
  - Notifications (POST_NOTIFICATIONS on Android 13+)

**Android Version Differences:**
- **Android 12**: No POST_NOTIFICATIONS permission requested
- **Android 13+**: POST_NOTIFICATIONS permission requested
- **Android 14**: Same as Android 13

---

### 2. Permission Handling

#### Test 2.1: Grant All Permissions
**Steps:**
1. Fresh install the app
2. Grant all permissions when prompted
3. Try to send a silent SMS

**Expected Results:**
- All permissions granted successfully
- SMS sending functionality works
- No further permission prompts

**Pass Criteria:** ✅ SMS can be sent, app functions normally

---

#### Test 2.2: Deny SMS Permissions
**Steps:**
1. Fresh install the app
2. Deny SMS permissions (SEND_SMS, RECEIVE_SMS)
3. Try to send a silent SMS
4. Grant permissions via Settings > Apps > Silent SMS Detector > Permissions
5. Try to send again

**Expected Results:**
- App handles denial gracefully (no crash)
- SMS sending fails when permission denied
- After granting from Settings, functionality works

**Pass Criteria:** ✅ App doesn't crash, functionality works after granting

---

#### Test 2.3: Deny Notification Permission (Android 13+ only)
**Steps:**
1. Install app on Android 13+ device
2. Grant SMS permissions but deny POST_NOTIFICATIONS
3. Receive a silent SMS (send from another device)
4. Check if notification appears

**Expected Results:**
- SMS is still received and detected
- No notification appears (as permission denied)
- App continues to function
- Silent SMS is stored in storage

**Pass Criteria:** ✅ SMS detection works, no crash when notification blocked

**Android 12 Note:** This test is not applicable as POST_NOTIFICATIONS doesn't exist

---

### 3. Silent SMS Sending

#### Test 3.1: Send Silent SMS to Valid Number
**Steps:**
1. Grant all permissions
2. Enter a valid phone number
3. Click Send button
4. Observe status messages

**Expected Results:**
- "Sent" status appears
- If device is reachable: "Delivered - Phone is online" appears
- If device is unreachable: "Offline - No response" appears
- PDU details button becomes visible

**Pass Criteria:** ✅ SMS sends successfully, status updates correctly

---

#### Test 3.2: Send SMS with Invalid Number
**Steps:**
1. Enter invalid phone number (e.g., "abc123")
2. Try to send SMS

**Expected Results:**
- Send button does nothing or shows error
- App validates phone number format

**Pass Criteria:** ✅ App handles invalid input gracefully

---

### 4. Silent SMS Reception

#### Test 4.1: Receive Class-0 SMS
**Setup:** Need two devices or one device + SMS gateway

**Steps:**
1. Device A: Install Silent SMS Detector, grant all permissions
2. Device B: Install Silent SMS Detector (or use SMS gateway)
3. Device B: Send silent SMS to Device A
4. Device A: Observe notification and check storage

**Expected Results:**
- Device A receives notification about silent SMS
- Notification shows sender's phone number
- Silent SMS details saved in storage
- Clicking notification opens storage activity

**Pass Criteria:** ✅ SMS detected, notification shown, data stored

**Android Version Testing:**
- Test on each Android version (12, 13, 14)
- Verify notification behavior is consistent

---

#### Test 4.2: Multiple Silent SMS Reception
**Steps:**
1. Send 3-5 silent SMS messages to test device
2. Check notification behavior
3. Open storage to view all messages

**Expected Results:**
- Each SMS triggers separate notification (or notification is updated)
- All SMS messages stored correctly
- Storage shows all received messages in chronological order

**Pass Criteria:** ✅ All messages detected and stored

---

### 5. Notification Behavior

#### Test 5.1: Notification Channel Configuration (Android 8+)
**Steps:**
1. Receive silent SMS
2. Long-press on notification
3. Check notification channel settings
4. Verify channel properties

**Expected Results:**
- Notification channel named "com.telefoncek.silentsms.detector" exists
- Channel importance is HIGH
- LED light enabled (if device supports)
- Vibration enabled
- Sound enabled

**Pass Criteria:** ✅ Channel configured correctly

---

#### Test 5.2: Notification Actions (Android 12+)
**Steps:**
1. Receive silent SMS notification
2. Test notification action button ("Open Silent SMS detector")
3. Test dismissing notification

**Expected Results:**
- Action button opens StoreActivity
- Notification is dismissible
- No "sticky" notification behavior

**Pass Criteria:** ✅ Notification is interactive and dismissible

---

### 6. Data Storage and Retrieval

#### Test 6.1: View Stored Silent SMS
**Steps:**
1. Send and receive few silent SMS
2. Click menu icon > "Data Messages Storage"
3. View stored messages
4. Click on a message
5. Long-press on a message

**Expected Results:**
- All received SMS listed in reverse chronological order
- Each entry shows date/time, SMSC, sender, port info, data hex
- Click on message logs to logcat
- Long-press copies PDU to clipboard

**Pass Criteria:** ✅ All data displayed correctly, clipboard works

---

### 7. Background Behavior

#### Test 7.1: SMS Reception While App in Background
**Steps:**
1. Launch app and grant permissions
2. Press Home button (app in background)
3. Send silent SMS to device
4. Check notification appears

**Expected Results:**
- Notification appears even when app is in background
- App doesn't need to be running in foreground
- Notification tapping opens app

**Pass Criteria:** ✅ Background SMS reception works

---

#### Test 7.2: SMS Reception After Device Reboot (Android 12+)
**Steps:**
1. Install app and grant permissions
2. Reboot device
3. Send silent SMS (without opening app first)
4. Check if SMS is detected

**Expected Results:**
- BroadcastReceiver activated automatically
- SMS detected after reboot
- Notification shown

**Pass Criteria:** ✅ SMS detection works after reboot

**Note:** Battery optimization may affect this. Test with and without battery optimization.

---

### 8. Battery Optimization and Doze Mode

#### Test 8.1: Doze Mode Impact (Android 12+)
**Steps:**
1. Install app, grant permissions
2. Force device into Doze mode:
   ```bash
   adb shell dumpsys deviceidle force-idle
   ```
3. Send silent SMS to device
4. Check if notification appears
5. Exit Doze mode:
   ```bash
   adb shell dumpsys deviceidle unforce
   ```

**Expected Results:**
- SMS may be delayed in Doze mode (expected Android behavior)
- SMS is processed when device exits Doze
- App doesn't crash

**Pass Criteria:** ✅ App handles Doze gracefully, SMS processed eventually

---

#### Test 8.2: Battery Optimization Exemption
**Steps:**
1. Go to Settings > Apps > Silent SMS Detector > Battery
2. Set to "Unrestricted" battery usage
3. Repeat Test 8.1

**Expected Results:**
- SMS processed more reliably in Doze mode
- Lower latency for SMS reception

**Pass Criteria:** ✅ Exemption improves SMS reception reliability

---

### 9. PendingIntent Behavior (Android 12+)

#### Test 9.1: PendingIntent Mutability
**Verification:** Code review

**Steps:**
1. Review `MainActivity.java` lines 111-112
2. Review `PingSmsReceiver.java` line 80
3. Verify FLAG_MUTABLE is set

**Expected Results:**
- All PendingIntents use FLAG_MUTABLE or FLAG_IMMUTABLE appropriately
- FLAG_MUTABLE used for SMS callbacks (as they receive extras)
- FLAG_MUTABLE used for notification actions

**Pass Criteria:** ✅ All PendingIntents have explicit mutability flags

---

### 10. Exported Component Security (Android 12+)

#### Test 10.1: Manifest Export Declarations
**Verification:** Code review

**Steps:**
1. Review `AndroidManifest.xml`
2. Check all activities with intent-filters have android:exported
3. Check all receivers with intent-filters have android:exported

**Expected Results:**
- MainActivity: android:exported="true" ✓
- PingSmsReceiver: android:exported="true" ✓
- StoreActivity: No intent-filter, export not required ✓

**Pass Criteria:** ✅ All components properly declared

---

### 11. Predictive Back Gesture (Android 14)

#### Test 11.1: Predictive Back Animation
**Steps (Android 14 only):**
1. Enable Predictive Back in Developer Options
2. Open app
3. Navigate to Storage activity
4. Perform back gesture slowly (don't complete)
5. Complete back gesture

**Expected Results:**
- Preview animation shows during gesture
- App responds to back gesture predictably
- No crashes during back navigation

**Pass Criteria:** ✅ Back gesture works smoothly

**Note:** This requires android:enableOnBackInvokedCallback="true" (already set)

---

### 12. Contact Picker Integration

#### Test 12.1: Pick Contact for Phone Number
**Steps:**
1. Click contacts icon in toolbar
2. Select a contact with phone number
3. Verify phone number populated

**Expected Results:**
- Contact picker opens
- Selected phone number appears in input field
- No permission errors

**Pass Criteria:** ✅ Contact picker works on all Android versions

---

### 13. History Management

#### Test 13.1: Send History Persistence
**Steps:**
1. Send SMS to 3 different numbers
2. Close and reopen app
3. Check history list

**Expected Results:**
- History shows all sent numbers
- History persists across app restarts
- Tapping history item populates phone number field

**Pass Criteria:** ✅ History works correctly

---

### 14. PDU Parsing and Display

#### Test 14.1: PDU Details Dialog
**Steps:**
1. Send SMS and receive delivery report
2. Click PDU details button (info icon)
3. Review PDU information

**Expected Results:**
- Dialog shows detailed PDU information
- Information is readable and formatted
- Close button works

**Pass Criteria:** ✅ PDU parsing and display work correctly

---

### 15. Error Handling

#### Test 15.1: No SIM Card
**Steps:**
1. Remove SIM card or use device without SIM
2. Try to send SMS

**Expected Results:**
- App handles gracefully
- Appropriate error shown (from system)
- No crash

**Pass Criteria:** ✅ App doesn't crash without SIM

---

#### Test 15.2: Airplane Mode
**Steps:**
1. Enable Airplane mode
2. Try to send SMS
3. Receive delivery status

**Expected Results:**
- "Not sent" status shown
- Or SMS queued until airplane mode off
- No crash

**Pass Criteria:** ✅ App handles offline state gracefully

---

## Automated Testing

### Unit Tests
```bash
cd /path/to/silent-sms-flash
./gradlew test
```

**Expected:** All unit tests pass (currently only basic addition test exists)

### Lint Checks
```bash
./gradlew lint
```

**Expected:** No critical lint errors related to Android 12-14 compatibility

---

## Test Matrix Summary

| Test Case | Android 12 | Android 13 | Android 14 | Priority |
|-----------|------------|------------|------------|----------|
| Installation | ✅ | ✅ | ✅ | High |
| Permission Requests | ✅ | ✅ | ✅ | High |
| SMS Sending | ✅ | ✅ | ✅ | High |
| SMS Reception | ✅ | ✅ | ✅ | High |
| Notifications | ✅ | ✅ | ✅ | High |
| Background Reception | ✅ | ✅ | ✅ | High |
| Storage/Retrieval | ✅ | ✅ | ✅ | Medium |
| Doze Mode | ✅ | ✅ | ✅ | Medium |
| Contact Picker | ✅ | ✅ | ✅ | Low |
| Predictive Back | N/A | N/A | ✅ | Low |

---

## Known Issues and Workarounds

### Issue 1: SMS Not Detected in Doze Mode
**Workaround:** Advise users to exempt app from battery optimization in Settings

### Issue 2: Notification Permission Repeatedly Denied (Android 13+)
**Workaround:** Users must manually grant from Settings > Apps > Permissions

### Issue 3: Build Environment Dependencies
**Note:** Google Maven repositories may be restricted in some environments. Build failures don't affect runtime compatibility.

---

## Regression Testing Checklist

Before each release, verify:
- [ ] App installs on Android 12, 13, and 14
- [ ] All permissions can be granted
- [ ] SMS can be sent and received
- [ ] Notifications appear correctly
- [ ] No crashes during normal operation
- [ ] Background SMS reception works
- [ ] Data persists across app restarts
- [ ] PDU parsing works correctly

---

## Reporting Test Results

When reporting test results, include:
1. Android version (12/13/14)
2. Device model or emulator specification
3. Test case number and name
4. Pass/Fail status
5. Screenshots (if applicable)
6. Logcat output (for failures)
7. Steps to reproduce (for failures)

---

## Conclusion

This testing guide ensures comprehensive coverage of Android 12, 13, and 14 compatibility for the Silent SMS Detector app. All critical functionality related to SMS sending, receiving, notifications, and permissions should be tested on each target Android version.
