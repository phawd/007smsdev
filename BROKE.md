# BROKE

Repository-wide issues observed during a first pass of running the available tooling.

## Android build tooling
- **What broke:** `./gradlew :app:assembleDebug` fails at configuration time with `SDK location not found`.
- **How to reproduce:** Run from repository root without a valid Android SDK installed or without `ANDROID_HOME`/`sdk.dir` pointing to a real SDK.
- **Notes:** The checked-in `local.properties` points to a Windows host path, so Linux and WSL builds require overriding it with a valid SDK path before Gradle tasks can run.

## Python modem utility dependencies
- **What broke:** `tools/qualcomm_modem_access.py scan` exits with `ModuleNotFoundError: No module named 'serial'`.
- **How to reproduce:** `python tools/qualcomm_modem_access.py scan`
- **Notes:** Install `pyserial` (e.g., `pip install pyserial`) to enable the tool.

## Desktop helper prerequisites
- **What broke:** `python tools/zerosms_cli.py --help` aborts with `adb is not available on PATH`.
- **How to reproduce:** `python tools/zerosms_cli.py --help`
- **Notes:** The helper assumes Android Platform Tools are installed and available on the PATH.
