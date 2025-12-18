# Contributing to SMS Test Testing Suite

Thank you for your interest in contributing to SMS Test! This document provides guidelines and best practices for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [RFC Compliance](#rfc-compliance)

## Code of Conduct

We are committed to providing a welcoming and inclusive environment. All contributors are expected to:
- Be respectful and constructive in discussions
- Focus on the technical merits of contributions
- Help maintain a safe and productive community

## Getting Started

### Prerequisites

**For Android Development**:
- Android Studio Arctic Fox or later
- JDK 17 (Temurin recommended)
- Android SDK 24-35
- Physical Android device for SMS/MMS/RCS testing (emulators have limitations)

**For Python Tools**:
- Python 3.11+
- `pip install pyserial` for AT command tools

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/007smsdev.git
   cd 007smsdev
   ```
3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/phawd/007smsdev.git
   ```

### Build and Test

**Android**:
```bash
./gradlew assembleDebug
./gradlew testDebugUnitTest
```

**Python**:
```bash
python3 tools/smstest_cli.py --help
pytest  # If tests exist
```

## Development Workflow

### Branching Strategy

- `master` - Stable releases
- `develop` - Integration branch for features
- `feature/*` - New features
- `fix/*` - Bug fixes
- `docs/*` - Documentation updates
- `tools/*` - CLI and tooling improvements

### Making Changes

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following [Coding Standards](#coding-standards)

3. Test your changes thoroughly

4. Commit with descriptive messages:
   ```bash
   git commit -m "feat: Add support for GSM 7-bit Extended characters"
   ```

5. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

6. Open a Pull Request

## Coding Standards

### Kotlin (Android)

- Follow [Kotlin Coding Conventions](https://kotlinlang.org/docs/coding-conventions.html)
- Use Jetpack Compose for UI components
- Prefer coroutines and `StateFlow` for async operations
- Document public APIs with KDoc comments
- Use meaningful variable names (avoid abbreviations)

**Example**:
```kotlin
/**
 * Calculates SMS encoding information based on message content.
 *
 * @param text The message text to analyze
 * @param encoding Requested encoding (AUTO, GSM_7BIT, UCS2)
 * @return SmsInfo containing encoding type and part count
 */
fun calculateSmsInfo(text: String, encoding: SmsEncoding): SmsInfo {
    // Implementation
}
```

### Python (Tools)

- Follow PEP 8 style guide (enforced by `black`)
- Use type hints for function signatures
- Write docstrings for modules, classes, and public functions
- Prefer f-strings for string formatting

**Example**:
```python
def send_at_command(device: str, command: str, timeout: int = 5) -> str:
    """
    Send AT command to modem device.

    Args:
        device: Path to serial device (e.g., /dev/smd0)
        command: AT command string (without AT prefix)
        timeout: Read timeout in seconds

    Returns:
        Raw response from modem

    Raises:
        SerialException: If device communication fails
    """
    # Implementation
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting, no logic change)
- `refactor:` - Code refactoring
- `test:` - Test additions or updates
- `chore:` - Build system or dependency updates

## Testing Requirements

### Unit Tests

- Write unit tests for all new business logic
- Aim for >80% code coverage on core protocol implementations
- Mock external dependencies (SmsManager, network, etc.)

**Android Example**:
```kotlin
@Test
fun `calculateSmsInfo should detect GSM 7-bit encoding`() {
    val text = "Hello World"
    val info = smsManager.calculateSmsInfo(text, SmsEncoding.AUTO)
    assertEquals(SmsEncoding.GSM_7BIT, info.encoding)
    assertEquals(1, info.partCount)
}
```

### Integration Tests

- Test with real Android devices when possible
- Document device-specific behavior (MediaTek, Qualcomm quirks)
- Include carrier-specific test results in PR description

### Test Data

- Never commit real phone numbers or PII
- Use test numbers like `+15551234567`
- Document test scenarios in `docs/TESTING_GUIDE.md`

## Pull Request Process

### Before Submitting

1. **Run Local Checks**:
   ```bash
   # Python
   black . && ruff check . && mypy .
   
   # Android
   ./gradlew assembleDebug testDebugUnitTest
   ```

2. **Update Documentation**:
   - Update `README.md` if adding user-facing features
   - Update `docs/RFC_COMPLIANCE.md` for protocol changes
   - Add inline code comments for complex logic

3. **Write Descriptive PR**:
   - Explain the problem being solved
   - Describe your solution approach
   - Include test results and device compatibility
   - Reference related issues with `Fixes #123`

### PR Review Criteria

Your PR will be reviewed for:
- **RFC Compliance**: Correct implementation of SMS/MMS/RCS standards
- **Code Quality**: Readability, maintainability, performance
- **Test Coverage**: Adequate unit and integration tests
- **Documentation**: Clear comments and updated docs
- **Security**: No vulnerabilities or hardcoded secrets
- **Compatibility**: Works across Android versions and device types

### CI Checks

All PRs must pass:
- Python CI (linting, type checks, tests)
- Android CI (build, unit tests)
- Security scans (bandit, pip-audit, detect-secrets)

*Note*: Some checks currently use `|| true` and won't block merges. We're establishing a baseline and will enforce stricter checks in future releases.

## RFC Compliance

### SMS (GSM 03.40, 3GPP TS 23.040)

When implementing SMS features:
- Always reference the relevant RFC/3GPP section in code comments
- Test with multiple encodings (GSM 7-bit, 8-bit, UCS-2)
- Validate message classes (0-3) and protocol identifiers
- Test concatenation for multi-part messages

### MMS (OMA MMS, WAP-209)

For MMS implementations:
- Follow OMA MMS Encapsulation Protocol for PDU encoding
- Test with various media types (image, video, audio, vCard)
- Validate MMSC configuration for major carriers
- Check message size limits and compression

### RCS (GSMA RCS UP 2.4)

For RCS features:
- Implement capability discovery before attempting RCS
- Gracefully fallback to SMS/MMS when RCS unavailable
- Follow GSMA UP 2.4 specifications for group chat and file transfer

### Helpful Resources

- `docs/RFC_COMPLIANCE.md` - Detailed compliance matrix
- `docs/ROOT_ACCESS_GUIDE.md` - AT command implementation
- `docs/MEDIATEK_FLASH_SMS_RESEARCH.md` - Device-specific findings

## Getting Help

- **Issues**: Open an issue for bugs or feature requests
- **Discussions**: Use GitHub Discussions for questions
- **Documentation**: Check `docs/` directory for technical details
- **Code Review**: Tag maintainers for review feedback

## License

By contributing to SMS Test, you agree that your contributions will be licensed under the MIT License.

---

*Thank you for contributing to SMS Test! Your efforts help improve messaging protocol compliance and testing for the Android ecosystem.*
