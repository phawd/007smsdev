# Credits & Contributors

## 🤠 Current Maintainer (2025+)

**phawd** - *New Sheriff in Town*
- Leading active development and feature expansion
- Type-0 SMS sending and detection implementation
- Enhanced UI/UX and user experience improvements
- Comprehensive test coverage and documentation
- Security enhancements and warning systems
- GitHub: [@phawd](https://github.com/phawd)

---

## 🌟 Major Contributors

### Matej Kovacic (2023)
**Modernization & Android 13 Support**
- Revived the project from archived state
- Updated to Android SDK 33 and Java 11
- Implemented Android 12/13 compatibility fixes
- Enhanced notification system for modern Android
- Created comprehensive compatibility documentation
- Redesigned application icon
- Established testing framework
- GitHub: [@MatejKovacic](https://github.com/MatejKovacic)

### itds-consulting (2016-2020)
**Original Creator - Android Silent SMS Ping**
- Created the original application concept and implementation
- Established silent SMS detection methodology
- Built the foundation for Class-0 SMS handling
- Pioneered open-source SMS security research
- Maintained the project through its initial years
- GitHub: [@itds-consulting](https://github.com/itds-consulting)
- Original Repository: [android-silent-ping-sms](https://github.com/itds-consulting/android-silent-ping-sms)

---

## 🔧 Technical Contributions by Era

### 2025: Type-0 SMS Functionality Era
**Lead: phawd**

*New Features:*
- `Type0SmsSender.java` - Complete Type-0 SMS transmission implementation
- `Type0SmsMonitorService.java` - Background service for Type-0 detection
- `LogParser.java` - System log analysis for hidden SMS detection
- `RootChecker.java` - Root access verification and management
- Enhanced `MainActivity.java` with dual SMS type support
- Comprehensive UI updates with toggle switches
- Unit test suite for all new components
- Security warning dialogs and user consent flows

*Documentation:*
- Updated README with complete feature overview
- Created comprehensive CREDITS.md (this file)
- Enhanced NOTICE file with proper attribution
- Inline code documentation for maintainability

### 2023: Modernization Era
**Lead: Matej Kovacic**

*Technical Updates:*
- Migration to Android SDK 33 (API level 33)
- Java 11 compatibility
- Android 12+ PendingIntent flag fixes (FLAG_MUTABLE)
- Android 13+ notification permission handling (POST_NOTIFICATIONS)
- Notification channel implementation for Android 8+
- Runtime permission request system

*Documentation:*
- `ANDROID_COMPATIBILITY.md` - Comprehensive compatibility guide
- `TESTING_GUIDE.md` - Testing procedures
- `QUICK_REFERENCE.md` - Quick setup and usage
- `COMPATIBILITY_REVIEW_SUMMARY.md` - Technical review

### 2016-2020: Foundation Era
**Lead: itds-consulting**

*Original Implementation:*
- Core SMS detection using BroadcastReceiver
- Class-0 SMS (Flash SMS) handling
- PDU parsing and interpretation
- Contact picker integration
- History tracking system
- Data message storage
- Basic notification system

*Original Architecture:*
- `MainActivity.java` - Core application logic
- `PingSmsReceiver.java` - SMS broadcast receiver
- `StoreActivity.java` - Data message storage viewer
- Layout and resource files
- Gradle build configuration

---

## 🙏 Additional Recognition

### Security Research Community
- **Akaki Chakaberia** - Research on Type-0 SMS detection via logs
  - Blog post: [Transmission and Detection of Silent SMS in Android](https://akaki.io/2022/transmission_and_detection_of_silent_sms_in_android)

### Standards Organizations
- **3GPP** - SMS standards (23.040/GSM 03.40 and 23.038/GSM 03.38)
- **GSM Association** - Mobile telecommunications standards

### Open Source Libraries
- **AndroidX** - Android support libraries (Apache License 2.0)
- **Mobicents SS7** - Telephony protocol implementation (GNU AGPL v3)

---

## 🤝 Contributing

This project thrives on community contributions! Whether you're fixing bugs, adding features, improving documentation, or helping with testing, your contribution is valued.

### How to Contribute:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Contribution Guidelines:
- Follow existing code style and conventions
- Add tests for new functionality
- Update documentation as needed
- Ensure Android compatibility (API 23+)
- Test on multiple Android versions when possible
- Respect the GPL v3+ license

---

## 📜 Historical Timeline

| Year | Milestone | Leader |
|------|-----------|--------|
| 2016 | Initial release of Android Silent SMS Ping | itds-consulting |
| 2017-2019 | Active maintenance and updates | itds-consulting |
| 2020 | Repository archived | itds-consulting |
| 2021-2022 | Community using F-Droid version | - |
| 2023 | Project revival and modernization | Matej Kovacic |
| 2023 | Android 13 compatibility achieved | Matej Kovacic |
| 2025 | New maintainer takes over | phawd |
| 2025 | Type-0 SMS functionality added | phawd |
| 2025+ | Active development continues | phawd |

---

## 💝 Special Thanks

To everyone who has:
- Reported bugs and issues
- Tested on their devices
- Shared feedback and suggestions
- Spread awareness about mobile privacy
- Contributed to discussions
- Star-gazed and forked the repository

Your support keeps this project alive and improving!

---

## 📞 Contact & Support

- **Issues**: [GitHub Issues](https://github.com/phawd/silent-sms-flash/issues)
- **Discussions**: [GitHub Discussions](https://github.com/phawd/silent-sms-flash/discussions)
- **Security**: For security concerns, please contact maintainers privately

---

*This project stands on the shoulders of giants. We honor those who came before us and commit to maintaining their legacy of transparency, security research, and open-source excellence.*

**🤠 Yeehaw! The new sheriff is committed to riding this project into the sunset... and beyond!**
