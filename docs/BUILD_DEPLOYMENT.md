# Build, Testing & Deployment Guide

## Overview

This document describes how to build, test, and deploy the **SMS Test** Android application.
The app targets Android API 24 (Android 7.0) and above, with a compile / target SDK of 35.

---

## Prerequisites

| Tool | Version |
|------|---------|
| JDK | 21 (Temurin recommended) |
| Android SDK | API 35 |
| Gradle | 8.x (via wrapper) |
| Android Gradle Plugin | 8.8.0 |
| Kotlin | 2.1.0 |

---

## Building the APK

### Debug APK

```bash
./gradlew assembleDebug
# Output: app/build/outputs/apk/debug/app-debug.apk
```

### Release APK

```bash
./gradlew assembleRelease
# Output: app/build/outputs/apk/release/app-release.apk
```

> **Note:** Release builds use R8/ProGuard minification (`isMinifyEnabled = true`,
> `isShrinkResources = true`).  A signing keystore must be configured before
> distributing a release build.

---

## Running Unit Tests

```bash
./gradlew testDebugUnitTest
```

Tests live under `app/src/test/` and run on the JVM using JUnit 4 and Robolectric
(no physical device required).

### Test packages

| Package | Description |
|---------|-------------|
| `core.model` | Data-model construction and enum coverage |
| `core.compat` | `DeviceCompatibilityHelper` per-chipset logic |

---

## Running Instrumentation Tests

Instrumentation tests (in `app/src/androidTest/`) require a connected device or emulator:

```bash
./gradlew connectedAndroidTest
```

> The `RootAndModemTest` suite requires a rooted device.

---

## Continuous Integration

The GitHub Actions workflow (`.github/workflows/android-ci.yml`) runs on every push
and pull request that touches Android sources:

1. **Set up JDK 21** – matches the `jvmToolchain(21)` in `app/build.gradle.kts`.
2. **Cache Gradle** – caches `~/.gradle/caches` and `~/.gradle/wrapper`.
3. **Build Debug APK** – `./gradlew assembleDebug`.
4. **Run Unit Tests** – `./gradlew testDebugUnitTest`.
5. **Upload APK artifact** – the debug APK is uploaded as a workflow artifact named
   `debug-apk` for every run (using `actions/upload-artifact@v4`).
6. **ktlint / detekt** – optional quality gates (run if configured).

---

## Device-Specific Configurations

### Modem Chipset Detection

`DeviceInfoManager` auto-detects the modem chipset at runtime and populates a
`ModemInfo` instance.  The detected chipset drives the choice of AT-command
delivery method:

| Chipset Family | AT Method | Notes |
|----------------|-----------|-------|
| Qualcomm (all) | `QCRIL_SMD` | Uses `/dev/smd*` character devices |
| MediaTek (all) | `MEDIATEK_CCCI` | Uses `/dev/ccci_*` |
| Samsung Exynos | `SAMSUNG_IPC` | Samsung IPC bridge |
| HiSilicon Kirin | `HUAWEI_APPVCOM` | `/dev/appvcom*` |
| Intel XMM | `INTEL_TTY` | `/dev/ttyACM*` |
| Generic / USB | `STANDARD_TTY` | `/dev/ttyUSB*` |

### `DeviceCompatibilityHelper`

`com.smstest.app.core.compat.DeviceCompatibilityHelper` provides per-chipset
compatibility decisions at runtime:

```kotlin
val chipset = DeviceInfoManager.modemInfo.value?.chipset ?: ModemChipset.UNKNOWN

// Choose optimal SMS part size for concatenated messages
val partLen = DeviceCompatibilityHelper.maxSmsPartLength(chipset, isUnicode = false)

// Check whether a network-type workaround is needed before sending MMS
if (DeviceCompatibilityHelper.requiresMmsNetworkWorkaround(chipset)) {
    // force LTE network before MMS attempt
}
```

### Android API Version Differences

| API Level | Behaviour |
|-----------|-----------|
| < 31 (Android < 12) | Use `SmsManager.getDefault()` (deprecated but supported) |
| ≥ 31 (Android 12+) | Use `context.getSystemService(SmsManager::class.java)` |
| ≥ 33 (Android 13+) | `POST_NOTIFICATIONS` permission required for delivery receipts |

`DeviceCompatibilityHelper.requiresContextSmsManager()` abstracts the API-level
check so call-sites remain clean.

### Screen Resolution / Density

The UI is built with Jetpack Compose and scales automatically.  Compose uses
`dp`/`sp` units throughout, so no explicit density buckets are needed.  The
vector launcher icon (`mipmap-anydpi-v26`) covers all densities on API 26+;
raster fallbacks are provided for mdpi through xxxhdpi.

---

## Known Issues & Device Quirks

| Device / Chipset | Issue | Workaround |
|-----------------|-------|------------|
| MediaTek (Helio/Dimensity) | Occasional SMSC rejection for 153-char parts | `DeviceCompatibilityHelper` reduces part size to 152 chars |
| Qualcomm (Android 9–11) | MMS stalls on mobile data if network type not explicitly switched | `requiresMmsNetworkWorkaround()` triggers force-LTE switch |
| Samsung Exynos (One UI) | `READ_SMS` restricted for non-default apps | App must be set as default SMS app |
| Generic USB (MiFi) | No Android telephony stack | Use CLI tools in `tools/smstest_cli.py` instead |

---

## Setting as Default SMS App

Some SMS features (reading the SMS inbox, receiving delivery reports) require the
app to be the system-default SMS application.  On Android 10+ this is enforced by
the OS.  The app requests the role via `android.app.role.SMS` if supported.

---

## Deployment Checklist

- [ ] All unit tests pass (`./gradlew testDebugUnitTest`)
- [ ] Debug APK builds without errors (`./gradlew assembleDebug`)
- [ ] Release build is signed with a production keystore
- [ ] `versionCode` incremented in `app/build.gradle.kts`
- [ ] `versionName` updated appropriately
- [ ] `APIFY_API_KEY` in `BuildConfig` replaced with a production secret managed via
      [`local.properties`](https://developer.android.com/studio/releases/gradle-plugin#local-properties)
      or a CI/CD environment variable (GitHub Secret injected via Gradle).  **Never
      commit API keys directly in `build.gradle.kts`.**  If a key was accidentally
      committed, rotate it immediately and rewrite history using `git filter-repo`.
- [ ] Permissions in `AndroidManifest.xml` reviewed for minimal required set
- [ ] ProGuard rules tested with release build
- [ ] Tested on at least one Qualcomm device and one MediaTek device

---

## Related Documentation

- [`docs/ANDROID_DEVICE_GUIDE.md`](ANDROID_DEVICE_GUIDE.md) – per-device setup and ADB configuration
- [`docs/TESTING_GUIDE.md`](TESTING_GUIDE.md) – end-to-end SMS/MMS/RCS test procedures
- [`docs/RFC_COMPLIANCE.md`](RFC_COMPLIANCE.md) – GSM 03.40 / OMA MMS / GSMA RCS compliance matrix
- [`GEMINI.md`](../GEMINI.md) – CI/CD automation and GEMINI integration guide
