# Security Policy

## Supported Versions

We actively support the following versions of ZeroSMS Testing Suite with security updates:

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

### How to Report

If you discover a security vulnerability in ZeroSMS, please report it privately:

1. **Email**: Send details to the repository maintainer via GitHub's private vulnerability reporting feature
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)
   - Your contact information

### What to Expect

- **Acknowledgment**: Within 48 hours of your report
- **Initial Assessment**: Within 5 business days
- **Resolution Timeline**: 
  - Critical: 7 days
  - High: 30 days
  - Medium: 60 days
  - Low: 90 days
- **Public Disclosure**: Coordinated with reporter after fix is released

## Security Considerations

### Root Access and AT Commands

ZeroSMS includes functionality for direct modem access via AT commands, which requires root privileges. This is intended for:
- **Professional Testing**: SMS/MMS/RCS protocol validation
- **Research**: Modem behavior analysis
- **Debugging**: Carrier-specific issue investigation

**Security Implications**:
- Root access bypasses Android security sandbox
- Direct modem commands can affect device stability
- AT command execution should only be used by experienced users

**Best Practices**:
- Never grant root access on production devices
- Use dedicated test devices for AT command functionality
- Review AT command implementations in `core/at/AtCommandManager.kt`
- Consult `docs/ROOT_ACCESS_GUIDE.md` before enabling root features

### SMS/MMS Content

ZeroSMS handles potentially sensitive messaging data:
- **No Telemetry**: We do not collect or transmit message content
- **Local Storage**: Incoming SMS monitor stores messages in-memory only
- **No Cloud**: All testing occurs on-device

**User Responsibilities**:
- Do not test with real phone numbers containing PII
- Use test numbers like `+15551234567` for development
- Clear test data before sharing devices

### Secrets and Credentials

**What ZeroSMS Stores**:
- MMSC URLs and configurations (carrier-specific)
- APN settings (for MMS testing)
- Local preferences via Android DataStore

**What ZeroSMS Does NOT Store**:
- Phone numbers (beyond temporary test data)
- Personal messages
- Account credentials
- API keys

**CI/CD Security**:
- GitHub Actions workflows include `detect-secrets` scan
- `bandit` security scanner checks Python code
- `pip-audit` monitors dependency vulnerabilities
- No secrets should be committed to repository

### Third-Party Dependencies

We monitor dependencies for known vulnerabilities:

**Android**:
- Jetpack Compose, Material 3, AndroidX libraries
- Updated regularly via Gradle dependency management
- ProGuard rules applied for release builds

**Python**:
- `pyserial` for serial port communication
- Minimal dependency footprint
- Scanned by `pip-audit` in CI

### Vulnerability Disclosure

When a security issue is fixed:
1. Patch released in supported versions
2. Security advisory published on GitHub
3. CVE assigned if applicable
4. Reporter credited (unless anonymity requested)

## Known Security Considerations

### Flash SMS (Class 0)

Flash SMS messages bypass inbox and display directly:
- **Risk**: Can be used for phishing or spoofing
- **Mitigation**: ZeroSMS is for testing only; educate users on Flash SMS risks
- **Detection**: Incoming SMS monitor logs Class 0 messages for analysis

### Silent SMS (Type 0)

Silent SMS messages don't trigger notifications:
- **Risk**: Used for location tracking by network operators
- **Mitigation**: ZeroSMS logs all incoming Type 0 messages for transparency
- **Disclosure**: Users should understand network operator Silent SMS capabilities

### AT Command Risks

Direct modem access enables low-level operations:
- **Risk**: Incorrect AT commands can brick devices or violate carrier ToS
- **Mitigation**: 
  - Root check prevents accidental execution
  - Commands validated before sending
  - Documentation warns about risks
- **Recommendation**: Only use on dedicated test devices

## Secure Coding Practices

### Code Review

All code changes undergo:
- Automated security scanning (bandit, detekt)
- Manual review for security implications
- RFC compliance validation
- Test coverage requirements

### Input Validation

- Phone numbers validated with regex patterns
- Message content sanitized before encoding
- AT commands validated against allowlist
- File paths checked for directory traversal

### Error Handling

- Sensitive data excluded from error messages
- Exceptions logged without exposing PII
- User-facing errors provide minimal technical detail

## Compliance

ZeroSMS is designed for:
- **Research**: Academic and professional protocol testing
- **Development**: SMS/MMS/RCS implementation validation
- **Compliance**: RFC and 3GPP specification verification

**Not intended for**:
- Spamming or unsolicited messaging
- Bypassing carrier restrictions
- Surveillance or unauthorized monitoring
- Malicious use of Flash/Silent SMS

## Security Updates

Stay informed about security updates:
- Watch this repository for security advisories
- Subscribe to release notifications
- Check `CHANGELOG.md` for security-related fixes

## Contact

For security concerns:
- **Vulnerability Reports**: Use GitHub private vulnerability reporting
- **Security Questions**: Open a GitHub Discussion (non-sensitive topics)
- **General Issues**: Standard GitHub issue tracker

---

*This security policy is reviewed quarterly and updated as needed.*

*Last Updated: 2025-12-04*
