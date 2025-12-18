# GEMINI Integration Guide

## Overview

This document describes how GEMINI (Google's AI assistant) integrates with the SMS Test Testing Suite repository to maintain code quality, ensure RFC compliance, and streamline development workflows.

## Purpose

GEMINI assists with:
- **Code Review**: Automated analysis of pull requests for RFC compliance, security vulnerabilities, and best practices
- **CI/CD Integration**: Monitoring and responding to GitHub Actions workflow failures
- **Documentation**: Maintaining up-to-date technical documentation aligned with code changes
- **Issue Triage**: Helping categorize and prioritize issues based on RFC standards and project goals
- **Code Generation**: Generating compliant SMS/MMS/RCS protocol implementations following GSM, OMA, and GSMA specifications

## CI/CD Workflows

### Python CI (`python-ci.yml`)

Runs on every push and pull request to main/master branches:

**Linting & Formatting**:
- `black --check .` - Code formatting validation
- `ruff check .` - Fast Python linter
- `mypy .` - Static type checking

**Testing**:
- `pytest -q` - Run Python test suite

**Security & Auditing**:
- `pip-audit --progress` - Scan dependencies for known vulnerabilities
- `bandit -r .` - Security issue scanner for Python code
- `detect-secrets scan` - Detect hardcoded secrets and credentials

**Note**: All checks use `|| true` to avoid blocking merges initially. This allows the team to establish a baseline and address issues incrementally.

### Android CI (`android-ci.yml`)

Triggers on changes to Kotlin code, Gradle files, or app directory:

**Build & Test**:
- `./gradlew assembleDebug` - Build debug APK
- `./gradlew testDebugUnitTest` - Run unit tests

**Code Quality**:
- `./gradlew ktlintCheck` - Kotlin linting (if configured)
- `./gradlew detekt` - Static analysis for Kotlin (if configured)

**Optimizations**:
- Gradle dependency caching for faster builds
- Path filtering to run only when Android code changes

## GEMINI Safety & Conventions

### Security Principles

1. **No Secret Commits**: GEMINI will never commit secrets, API keys, or credentials
2. **Vulnerability Awareness**: Security scans (bandit, pip-audit) are reviewed before merge
3. **Minimal Permissions**: GEMINI operates with read-only access to most systems
4. **Audit Trail**: All GEMINI-suggested changes are reviewed by human maintainers

### Code Conventions

**SMS/MMS/RCS Compliance**:
- All SMS encoding must reference GSM 03.38 and 3GPP TS 23.040
- MMS implementations follow OMA MMS Encapsulation Protocol
- RCS features adhere to GSMA RCS Universal Profile 2.4

**Kotlin Style**:
- Follow official Kotlin coding conventions
- Use Jetpack Compose best practices for UI
- Prefer coroutines and StateFlow for asynchronous operations

**Python Style**:
- PEP 8 compliance (enforced by black and ruff)
- Type hints for all public functions
- Docstrings for modules, classes, and functions

**Testing Requirements**:
- Android: Minimum unit test coverage for core protocol logic
- Python: Test coverage for CLI tools and AT command implementations
- Integration tests require real Android devices (see `TESTING_GUIDE.md`)

### Documentation Standards

- **RFC References**: Always cite RFC/spec section when implementing protocol features
- **Code Comments**: Explain *why*, not *what* (code should be self-documenting)
- **Commit Messages**: Use conventional commits format (feat:, fix:, docs:, etc.)
- **PR Descriptions**: Include test results, device compatibility notes, and RFC compliance checklist

## GEMINI Interaction Workflow

### Pull Request Review

1. **Automated Analysis**: GEMINI scans PR diff for:
   - RFC compliance violations
   - Security vulnerabilities
   - Test coverage gaps
   - Documentation updates needed

2. **Feedback Generation**: Comments inline with code suggestions:
   ```
   🤖 GEMINI: This SMS encoding violates GSM 03.38 section 6.2.1
   - Issue: UCS-2 encoding used for GSM 7-bit compatible text
   - Suggestion: Use `SmsEncoding.AUTO` to optimize encoding selection
   - Ref: core/sms/SmsManagerWrapper.kt:calculateSmsInfo()
   ```

3. **Human Review**: Maintainers review GEMINI suggestions and approve/modify

### Issue Triage

GEMINI helps categorize issues:
- **RFC Compliance**: Tags issues related to protocol violations
- **Security**: Flags potential security vulnerabilities
- **Device Compatibility**: Identifies device-specific bugs (MediaTek, Qualcomm, etc.)
- **Priority**: Suggests priority based on impact and complexity

### CI Failure Response

When workflows fail:
1. GEMINI analyzes logs from GitHub Actions
2. Identifies root cause (build error, test failure, linting issue)
3. Suggests fix or opens draft PR with potential solution
4. Escalates to maintainers if issue is complex

## Developer Workflows

### Before Committing

1. **Run Local Checks**:
   ```bash
   # Python
   black . && ruff check . && mypy .
   
   # Android
   ./gradlew assembleDebug testDebugUnitTest
   ```

2. **Review GEMINI Feedback**: Check PR comments before requesting review

3. **Update Documentation**: Ensure `docs/RFC_COMPLIANCE.md` reflects protocol changes

### Requesting GEMINI Assistance

Use GitHub issue templates or PR comments:

```
@gemini-bot Please review this MMS PDU encoding implementation for 
OMA MMS Encapsulation Protocol compliance (WAP-209 section 7.3.34)
```

### GEMINI Limitations

**What GEMINI Can Do**:
- Review code for compliance and best practices
- Suggest fixes for common issues
- Generate boilerplate protocol implementations
- Analyze CI/CD logs and suggest debugging steps

**What GEMINI Cannot Do**:
- Test on physical Android devices (requires human testing)
- Make carrier-specific configuration decisions (needs operator knowledge)
- Override human maintainer decisions
- Commit directly to main/master (all changes via PR)

## Configuration Files

### Pre-Commit Hooks (`.github/pre-commit-config.yaml`)

Automated checks before commits:
- Python: black, ruff, mypy
- Secrets detection
- File size limits
- Trailing whitespace cleanup

### Code Owners (`CODEOWNERS`)

Defines reviewers for different areas:
- Core SMS/MMS/RCS logic: Lead developers
- Documentation: Technical writers + GEMINI
- CI/CD: DevOps team
- Python tools: Script maintainers

## Metrics & Monitoring

GEMINI tracks:
- CI success rate trend
- Test coverage changes
- Security vulnerability discoveries
- RFC compliance issue frequency
- Average time to merge PRs

## Future Enhancements

- **Automated RFC Compliance Reports**: Generate compliance matrix on release
- **Device Lab Integration**: GEMINI-driven automated testing on physical devices
- **Performance Benchmarking**: Track SMS encoding efficiency across Android versions
- **Carrier Profile Validation**: Verify MMSC configurations against carrier specs

## Resources

- **RFC Database**: https://www.rfc-editor.org/
- **3GPP Specs**: https://www.3gpp.org/specifications
- **GSMA RCS**: https://www.gsma.com/futurenetworks/rcs/
- **OMA MMS**: https://www.openmobilealliance.org/

## Contact

For questions about GEMINI integration:
- Open an issue with `gemini` label
- Review `CONTRIBUTING.md` for guidelines
- Check `SECURITY.md` for vulnerability reporting

---

*Last Updated: 2025-12-04*
*GEMINI Version: Compatible with GitHub Copilot Workspace*
