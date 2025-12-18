# QMI / libqmi / qmicli Sources (curated)

Below are links and notes useful when working with QMI and Qualcomm modems.
Keep this list up-to-date (quarterly recommended).

- libqmi (Project): [libqmi on freedesktop.org](https://www.freedesktop.org/wiki/Software/libqmi/)
  - qmicli (tool and docs): [libqmi / qmicli docs](https://www.freedesktop.org/wiki/Software/libqmi/)
  - qmicli manpage: `man qmicli` (installed with libqmi)

- OpenEmbedded/meta-mobile recipes: search for `libqmi` packages for
  cross-compilation examples

- Qualcomm QMI protocol references: vendor docs (internal) and community
  notes — treat as reference only

Example tutorials:

- [qmi-example on GitHub](https://github.com/thesofproject/qmi-example) — example
  usage patterns
- [Linux Foundation forums](https://discuss.linuxfoundation.org/) — search for
  libqmi and qmicli examples

Local notes:

- Prefer `qmicli` for host-side probing and `adb shell qmicli` as a fallback
  for Android devices.
- Use `tools/qmi_adapter.py` as a small adapter for basic operations; for
  production workflows rely on tested vendor tooling.
