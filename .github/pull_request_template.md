## Description

<!-- Provide a clear and concise description of your changes -->

## Type of Change

<!-- Mark the relevant option with an "x" -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring
- [ ] CI/CD or tooling update

## Related Issues

<!-- Link to related issues using #issue_number -->
Fixes #
Related to #

## RFC/Standards Compliance

<!-- For SMS/MMS/RCS changes, specify relevant standards -->

- [ ] GSM 03.40 / 3GPP TS 23.040 (SMS)
- [ ] GSM 03.38 / 3GPP TS 23.038 (SMS Encoding)
- [ ] OMA MMS Encapsulation Protocol (MMS)
- [ ] GSMA RCS Universal Profile 2.4 (RCS)
- [ ] Other: _____________________
- [ ] N/A - Not protocol-related

**Specification References**:
<!-- e.g., "GSM 03.38 Section 6.2.1 - UCS-2 encoding" -->

## Testing

### Test Environment

- **Device**: <!-- e.g., Pixel 7 Pro, Samsung Galaxy S23 -->
- **Android Version**: <!-- e.g., Android 13 -->
- **Chipset**: <!-- e.g., Qualcomm Snapdragon 8 Gen 2, MediaTek Dimensity 9200 -->
- **Carrier**: <!-- e.g., Verizon, T-Mobile, AT&T -->
- **Root Access**: <!-- Yes/No -->

### Test Cases

<!-- Describe how you tested your changes -->

- [ ] Unit tests added/updated
- [ ] Integration tests performed on physical device
- [ ] Tested with real SMS/MMS/RCS messages
- [ ] Tested without root access (if applicable)
- [ ] Tested with root access and AT commands (if applicable)

### Test Results

<!-- Paste test output or describe results -->

```
# Example:
./gradlew testDebugUnitTest
> Task :app:testDebugUnitTest
✓ calculateSmsInfo should detect GSM 7-bit encoding (12ms)
✓ sendFlashSms should use message class 0 (8ms)
BUILD SUCCESSFUL
```

## Device Compatibility

<!-- Mark tested platforms -->

- [ ] Qualcomm chipset
- [ ] MediaTek chipset
- [ ] Samsung Exynos chipset
- [ ] Google Tensor chipset
- [ ] Generic Android (AOSP)

**Known Issues**:
<!-- Document any device-specific quirks or limitations -->

## Checklist

<!-- Ensure all items are addressed before requesting review -->

- [ ] My code follows the coding style of this project (Kotlin conventions / PEP 8)
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] Any dependent changes have been merged and published
- [ ] I have checked my code for security vulnerabilities
- [ ] I have updated `docs/RFC_COMPLIANCE.md` if applicable
- [ ] No secrets or credentials are included in my changes

## Screenshots / Logs

<!-- If applicable, add screenshots or logs to demonstrate the change -->

### Before:
<!-- Screenshot or description of current behavior -->

### After:
<!-- Screenshot or description of new behavior -->

## Additional Context

<!-- Add any other context about the PR here -->

## Breaking Changes

<!-- If this PR introduces breaking changes, describe them and migration path -->

## Deployment Notes

<!-- Special instructions for deploying this change -->

---

<!-- 
Thanks for contributing to ZeroSMS!

Please review:
- CONTRIBUTING.md for contribution guidelines
- GEMINI.md for CI/CD and GEMINI integration info
- docs/RFC_COMPLIANCE.md for protocol implementation standards
-->
