# Contributing to ZeroSMS

Thank you for your interest in contributing to ZeroSMS! This document provides guidelines and instructions for contributing to the project.

## Table of Contents
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Testing](#testing)
- [Hardware Requirements](#hardware-requirements)
- [Code Style](#code-style)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Security](#security)

## Getting Started

ZeroSMS is an Android SMS/MMS/RCS testing suite with RFC compliance. It includes both Android application code (Kotlin) and Python CLI tools for desktop workflows.

### Prerequisites
- **Android development**: Android Studio, JDK 17+, Android SDK 24-35
- **Python development**: Python 3.11+, pip
- **Optional**: Root access on Android device for AT command testing
- **Optional**: ADB for device debugging

## Development Setup

### Android Setup
```bash
# Clone the repository
git clone https://github.com/phawd/zerosms.git
cd zerosms

# Build the project
./gradlew assembleDebug

# Install on connected device
./gradlew installDebug

# Run tests
./gradlew testDebugUnitTest
```

### Python Setup
```bash
# Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install development dependencies
pip install black ruff mypy pytest pip-audit bandit

# Optional: Install pyserial for USB device enumeration
pip install pyserial

# Run Python tools
python3 tools/zerosms_cli.py --help
```

### IDE Configuration
**Android Studio:**
- Open project in Android Studio
- Sync Gradle files
- Enable Kotlin plugin
- Configure code style: Settings → Editor → Code Style → Kotlin (use official style guide)

**VS Code (for Python):**
- Install Python extension
- Install Pylance for type checking
- Configure formatters: black, ruff

## Testing

### Android Tests
```bash
# Unit tests (fast, no device required)
./gradlew testDebugUnitTest

# Instrumentation tests (requires connected device)
./gradlew connectedAndroidTest

# Run specific test
./gradlew test --tests "com.zerosms.testing.core.sms.SmsManagerWrapperTest"
```

### Python Tests
```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_cli.py

# Run tests with coverage
pytest --cov=tools --cov-report=html
```

### Hardware-Dependent Tests
Tests requiring actual device hardware should be marked and excluded from CI:

**Python:**
```python
@pytest.mark.hardware
def test_real_sms_sending():
    # Test that sends actual SMS
    pass
```

**Kotlin:**
```kotlin
@Ignore("Requires real device")
@Test
fun testAtCommandExecution() {
    // Test that executes AT commands
}
```

## Hardware Requirements

### Minimum Requirements
- Android device running Android 7.0 (API 24) or higher
- SIM card for SMS/MMS testing
- ADB connection for debugging

### Recommended Hardware
- Qualcomm Snapdragon device for AT command testing
- Root access for direct modem communication
- Multiple devices for cross-platform testing

### Supported Chipsets
- Qualcomm Snapdragon (most features)
- MediaTek (limited AT command support)
- Samsung Exynos (limited features)

### Testing Without Hardware
For development without physical devices:
- Use mocks for hardware-dependent functionality
- Write unit tests that don't require SMS/modem access
- Use Android Emulator for UI testing (SMS sending will be simulated)

## Code Style

### Kotlin/Android
- Follow [Android Kotlin Style Guide](https://developer.android.com/kotlin/style-guide)
- Use ktlint for formatting: `./gradlew ktlintFormat`
- Run detekt for static analysis: `./gradlew detekt`
- Use meaningful variable names and comments for complex logic
- Keep functions focused and small

### Python
- Follow [PEP 8](https://peps.python.org/pep-0008/)
- Use black for formatting: `black .`
- Use ruff for linting: `ruff check .`
- Add type hints for function signatures
- Use docstrings for public functions

### Documentation
- Update `README.md` for user-facing changes
- Update `docs/` for technical documentation
- Add inline comments for complex logic
- Document RFC compliance in `docs/RFC_COMPLIANCE.md`

## Commit Guidelines

### Commit Message Format
Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style (formatting, whitespace)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(sms): Add Flash SMS (Class 0) support

Implements GSM 03.40 Class 0 message delivery with
automatic popup on compatible devices.

Closes #123

---

fix(at): Handle modem timeout errors

Adds retry logic and better error handling for AT
command timeouts on MediaTek devices.

---

docs(readme): Update installation instructions

Clarifies root access requirements and adds troubleshooting
section for common setup issues.
```

### Commit Best Practices
- Make atomic commits (one logical change per commit)
- Write clear, descriptive commit messages
- Reference related issues with `Fixes #123` or `Closes #456`
- Keep commits focused and reviewable

## Pull Request Process

### Before Opening a PR
1. **Sync with main branch**: `git pull origin master`
2. **Run local checks**:
   ```bash
   # Python checks
   black --check .
   ruff check .
   mypy .
   pytest
   
   # Android checks
   ./gradlew assembleDebug
   ./gradlew testDebugUnitTest
   ./gradlew ktlintCheck
   ./gradlew detekt
   ```
3. **Update documentation** if behavior changes
4. **Add tests** for new functionality

### PR Title and Description
**Title:** Use conventional commits format
```
feat(sms): Add Silent SMS (Type 0) support
```

**Description template:**
```markdown
## Description
Brief description of changes

## Motivation
Why is this change needed?

## Changes Made
- Change 1
- Change 2

## Testing
- [ ] Unit tests added/updated
- [ ] Manual testing on device
- [ ] CI passes

## Checklist
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] Tests pass locally
- [ ] No new warnings/errors

Fixes #123
```

### Review Process
1. CI must pass (Python CI and Android CI)
2. At least one approval required
3. All review comments addressed
4. No merge conflicts

### After Merge
- Delete feature branch
- Update related issues
- Monitor CI on main branch

## Security

### Reporting Vulnerabilities
**DO NOT** open public issues for security vulnerabilities. See `SECURITY.md` for reporting procedures.

### Security Best Practices
- Never commit credentials, API keys, or tokens
- Use environment variables for sensitive data
- Run security scans before committing:
  ```bash
  bandit -r .           # Python security scan
  pip-audit             # Dependency vulnerabilities
  ```
- Review `SECURITY.md` for detailed security guidelines

### Dangerous Operations
Operations that interact with real hardware or send actual SMS messages MUST:
1. Require explicit confirmation flags (`--confirm`, `--yes`, `--force`)
2. Display clear warnings before execution
3. Be documented in `GEMINI.md`

Example:
```python
@click.option('--confirm', is_flag=True, required=True,
              help='Required to confirm SMS sending')
def send_sms(phone: str, message: str, confirm: bool):
    if not confirm:
        raise click.UsageError("--confirm flag required")
```

## Getting Help

### Resources
- **README**: Project overview and quick start
- **GEMINI.md**: CI and automation guidelines
- **docs/**: Technical documentation and RFCs
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and community support

### Common Issues
1. **Build failures**: Clean and rebuild: `./gradlew clean assembleDebug`
2. **Python import errors**: Activate virtual environment and reinstall dependencies
3. **Device not detected**: Check ADB connection: `adb devices`
4. **AT commands fail**: Verify root access and modem paths

### Contact
- Open an issue for bugs or feature requests
- Use GitHub Discussions for questions
- Tag maintainers for urgent issues

## License
By contributing to ZeroSMS, you agree that your contributions will be licensed under the project's license.

Thank you for contributing to ZeroSMS! 🚀
