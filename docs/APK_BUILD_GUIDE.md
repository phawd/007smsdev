# Android APK Build & Deployment Guide

This guide covers building, signing, and deploying the SMS Test Android APK
for production use.

---

## Prerequisites

| Requirement | Version |
|-------------|---------|
| JDK | 17 or 21 (Temurin recommended) |
| Android SDK | Build-tools 35 |
| Gradle wrapper | Included (`./gradlew`) |

---

## 1. Debug Build (development / testing)

```bash
./gradlew assembleDebug
```

Output: `app/build/outputs/apk/debug/app-debug.apk`

---

## 2. Release Build

### 2a. Create a Signing Keystore

Only do this once.  Store the keystore file in a secure location that is
**not** committed to the repository.

```bash
keytool -genkey -v \
  -keystore smstest-release.jks \
  -alias smstest \
  -keyalg RSA -keysize 2048 \
  -validity 10000
```

### 2b. Configure Signing Credentials

Add the following to `local.properties` (this file is already excluded from
version control by `.gitignore`):

```properties
# local.properties – never commit this file
release.keystore.file=/absolute/path/to/smstest-release.jks
release.keystore.password=YOUR_KEYSTORE_PASSWORD
release.key.alias=smstest
release.key.password=YOUR_KEY_PASSWORD

# Apify API key (optional)
apify.api.key=YOUR_APIFY_KEY
```

Alternatively export environment variables (useful for CI/CD pipelines):

```bash
export RELEASE_KEYSTORE_FILE=/path/to/smstest-release.jks
export RELEASE_KEYSTORE_PASSWORD=YOUR_KEYSTORE_PASSWORD
export RELEASE_KEY_ALIAS=smstest
export RELEASE_KEY_PASSWORD=YOUR_KEY_PASSWORD
export APIFY_API_KEY=YOUR_APIFY_KEY
```

### 2c. Build the Signed APK

```bash
./gradlew assembleRelease
```

Output: `app/build/outputs/apk/release/app-release.apk`

### 2d. Build an App Bundle (recommended for Play Store)

```bash
./gradlew bundleRelease
```

Output: `app/build/outputs/bundle/release/app-release.aab`

---

## 3. Verify the APK

```bash
# Check signing certificate
apksigner verify --verbose app/build/outputs/apk/release/app-release.apk

# Check minimum SDK and other manifest attributes
aapt dump badging app/build/outputs/apk/release/app-release.apk | head -20
```

---

## 4. Install on a Device

```bash
# USB debugging must be enabled on the device
adb install -r app/build/outputs/apk/release/app-release.apk
```

---

## 5. Device Compatibility Notes

| Android Version | API Level | Notes |
|----------------|-----------|-------|
| Android 7.0 (Nougat) | 24 | Minimum supported version |
| Android 8–9 | 26–28 | Full feature support |
| Android 10 | 29 | Scoped storage applies; MMS attachments handled via MediaStore |
| Android 11 | 30 | Package visibility rules apply |
| Android 12+ | 31+ | Notification permission required at runtime |
| Android 13 | 33 | `READ_MEDIA_*` permissions replace `READ_EXTERNAL_STORAGE` |
| Android 14 | 34 | Photo picker for media access |
| Android 15 | 35 | Target SDK; full compatibility verified |

### Known Device-Specific Considerations

**Qualcomm (Snapdragon) devices**
- Diagnostic port (`/dev/smd*`) available for AT command access when rooted.
- Use `QualcommDiagManager` for raw modem communication.

**MediaTek devices**
- MIPC interface exposed via `/dev/ccci_ipc_uart*`.
- Use `MipcDeviceManager` for AT command passthrough.

**Samsung (Exynos / Snapdragon)**
- Default SMS app restrictions may require granting SMS Test as the
  default messaging app.
- Some firmware versions block Class-0 (Flash) SMS; fallback to Class-1 is
  automatic.

**Low-memory devices (< 2 GB RAM)**
- Disable background WorkManager tasks in Settings → Advanced → Background.
- Reduce MMS attachment size limits in Settings → MMS.

---

## 6. CI/CD Pipeline

The `android-ci.yml` workflow builds the debug APK automatically on every
push.  To enable signed release builds in CI:

1. Store the keystore as a GitHub Secret (Base64-encoded):
   ```bash
   base64 smstest-release.jks | pbcopy   # macOS
   ```
2. Add secrets to the repository:
   - `RELEASE_KEYSTORE_BASE64`
   - `RELEASE_KEYSTORE_PASSWORD`
   - `RELEASE_KEY_ALIAS`
   - `RELEASE_KEY_PASSWORD`
3. Decode the keystore in the workflow before building:
   ```yaml
   - name: Decode keystore
     run: |
       echo "${{ secrets.RELEASE_KEYSTORE_BASE64 }}" | base64 -d > smstest-release.jks
       echo "RELEASE_KEYSTORE_FILE=$PWD/smstest-release.jks" >> $GITHUB_ENV
   ```

---

## 7. Optimisation Checklist

- [x] `isMinifyEnabled = true` (R8 code shrinking)
- [x] `isShrinkResources = true` (remove unused resources)
- [x] ProGuard rules in `app/proguard-rules.pro`
- [ ] Enable APK splits for ABI (optional, reduces per-device download size)
- [ ] Run Firebase Test Lab for automated device matrix testing
- [ ] Review manifest permissions – remove any not needed for the target
      device category
