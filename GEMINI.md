# GEMINI Integration Guide

## Index
1. [Purpose](#purpose)
2. [CI workflows added](#ci-workflows-added)
3. [Running GEMINI checks locally](#running-gemini-checks-locally)
4. [Safety and dangerous operations](#safety-and-dangerous-operations)
5. [GEMINI-specific conventions](#gemini-specific-conventions)

## Purpose
This file explains how GEMINI (automation) integrates with this repository and what it expects from contributors.

GEMINI is an AI-powered automation system that helps maintain code quality, run tests, and ensure security standards across the ZeroSMS project. It interacts with CI workflows, performs code reviews, and validates changes before they are merged.

## CI workflows added

### Python CI (`.github/workflows/python-ci.yml`)
Runs linters, type checks, tests, and dependency audits for Python code in the `tools/` directory.

**Checks performed:**
- **Black**: Code formatting verification
- **Ruff**: Fast Python linting
- **Mypy**: Static type checking
- **Pytest**: Unit test execution
- **pip-audit**: Dependency vulnerability scanning
- **Bandit**: Security issue detection

### Android CI (`.github/workflows/android-ci.yml`)
Builds Android APK and runs static checks for Kotlin/Java code.

**Checks performed:**
- **Gradle build**: Compiles debug APK
- **Unit tests**: Runs Android unit tests
- **ktlint**: Kotlin code style checking
- **detekt**: Static code analysis for Kotlin

## Running GEMINI checks locally

### Python checks
```bash
# Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt  # If requirements.txt exists
pip install black ruff mypy pytest pip-audit bandit

# Run individual checks
black --check .           # Format checking
black .                   # Auto-format
ruff check .              # Linting
mypy .                    # Type checking
pytest                    # Run tests
pip-audit                 # Dependency audit
bandit -r .               # Security scan
```

### Android checks
```bash
# Build project
./gradlew assembleDebug

# Run tests
./gradlew testDebugUnitTest

# Run static analysis
./gradlew ktlintCheck
./gradlew detekt

# Fix formatting issues
./gradlew ktlintFormat
```

## Safety and dangerous operations

**CRITICAL**: ZeroSMS includes functionality that can interact with real hardware and send actual SMS messages. To prevent accidental execution of dangerous operations, the following rules MUST be followed:

### Required confirmation flags
Dangerous operations MUST require explicit confirmation flags:
- `--confirm` or `--yes`: For operations that send real SMS/MMS messages
- `--force`: For operations that modify system settings or modem configurations
- `--allow-hardware`: For tests that require actual device hardware

### Examples
```bash
# ❌ WRONG - Will not execute without confirmation
python3 tools/zerosms_cli.py sms +15551234567 "Test message"

# ✅ CORRECT - Explicit confirmation required
python3 tools/zerosms_cli.py sms +15551234567 "Test message" --confirm

# ❌ WRONG - Dangerous diag mode without confirmation
python3 tools/zerosms_cli.py diag --profile generic

# ✅ CORRECT - Explicit confirmation for hardware changes
python3 tools/zerosms_cli.py diag --profile generic --confirm
```

### Hardware-dependent tests
GEMINI automation will NOT run hardware-dependent tests by default. Mark such tests appropriately:

**Python:**
```python
import pytest

@pytest.mark.hardware
def test_sms_sending():
    # Test requires real device
    pass
```

**Kotlin/Android:**
```kotlin
import org.junit.Ignore

@Ignore("Requires real device")
@Test
fun testSmsDelivery() {
    // Test requires real device
}
```

### CI behavior
- Hardware tests are skipped in CI by default
- Mock interfaces should be used for hardware-dependent functionality
- Integration tests requiring real devices should be marked and run manually

## GEMINI-specific conventions

### Code style
**Python:**
- Use **black** for formatting (line length: 88 characters)
- Use **ruff** for linting (replaces flake8, isort, pyupgrade)
- Use **mypy** for type hints and static type checking
- Follow PEP 8 naming conventions

**Kotlin:**
- Use **ktlint** for formatting (official Kotlin style guide)
- Use **detekt** for static analysis
- Follow Android Kotlin Style Guide

### Testing requirements
- Add tests for new functionality
- Use mocks for hardware interfaces to enable CI coverage
- Keep tests fast and deterministic
- Avoid flaky tests that depend on timing or external services

### Commit messages
Follow conventional commits format:
```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style changes (formatting, no logic change)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(sms): Add support for Flash SMS (Class 0)
fix(at): Handle modem timeout errors gracefully
docs(readme): Update installation instructions
test(mms): Add unit tests for PDU encoding
```

### Pull request guidelines
1. Run local checks before opening PR
2. Ensure CI passes (both Python and Android workflows)
3. Include test coverage for new code
4. Update documentation if behavior changes
5. Reference related issues with `Fixes #123` or `Closes #456`

### Security practices
- Never commit credentials, API keys, or secrets
- Use environment variables for sensitive configuration
- Run `pip-audit` and `bandit` before committing Python changes
- Review `SECURITY.md` for vulnerability reporting procedures
- GEMINI will automatically scan for common security issues

### File structure conventions
```
zerosms/
├── .github/
│   └── workflows/          # CI workflow definitions
├── app/                    # Android application code
├── docs/                   # Documentation files
├── tools/                  # Python CLI tools
├── GEMINI.md              # This file
├── CONTRIBUTING.md        # Contribution guidelines
├── SECURITY.md            # Security policy
└── README.md              # Project overview
```

## Getting help

If you encounter issues with GEMINI automation or CI checks:
1. Check this documentation first
2. Review CI logs in GitHub Actions tab
3. Run checks locally to reproduce issues
4. Consult the `CONTRIBUTING.md` for setup instructions
5. Open an issue with `[GEMINI]` prefix in the title

## References
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Black Documentation](https://black.readthedocs.io/)
- [Ruff Documentation](https://docs.astral.sh/ruff/)
- [ktlint Style Guide](https://pinterest.github.io/ktlint/)
- [Conventional Commits](https://www.conventionalcommits.org/)
