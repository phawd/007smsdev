# Security Policy

## Overview

ZeroSMS is a testing tool for SMS/MMS/RCS protocols that can interact with real device hardware and send actual messages. Security is a critical concern, and we take all vulnerability reports seriously.

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| Latest  | ✅ Yes             |
| < Latest| ⚠️  Best effort    |

We recommend always using the latest version from the `master` branch.

## Reporting a Vulnerability

**DO NOT** open public GitHub issues for security vulnerabilities.

### How to Report

Please report security vulnerabilities through one of the following methods:

1. **GitHub Security Advisories** (preferred):
   - Navigate to the repository's Security tab
   - Click "Report a vulnerability"
   - Fill out the advisory form with details

2. **Email** (alternative):
   - Contact the repository maintainers via email
   - Use subject line: `[SECURITY] ZeroSMS Vulnerability Report`
   - Include detailed description and reproduction steps

### What to Include

When reporting a vulnerability, please provide:

1. **Description**: Clear description of the vulnerability
2. **Impact**: Potential impact and attack scenarios
3. **Reproduction**: Step-by-step instructions to reproduce
4. **Environment**: Device, Android version, affected components
5. **Proposed fix**: If you have suggestions (optional)
6. **Disclosure timeline**: Your preferred disclosure timeline

### Example Report

```
Component: AT Command Manager
Severity: High

Description:
Improper input validation in AT command execution allows
command injection when processing user-supplied phone numbers.

Impact:
Attacker could execute arbitrary AT commands with root privileges,
potentially compromising device security or sending unauthorized messages.

Reproduction:
1. Enable AT command mode with root access
2. Send SMS with phone number: "+1234; AT+CFUN=1,1"
3. Observe command injection in modem logs

Environment:
- ZeroSMS version: commit abc123
- Device: Pixel 6 (Qualcomm)
- Android: 13
- Root: Yes

Proposed Fix:
Add strict input validation for phone numbers before passing to AT commands.
Whitelist only valid E.164 format: ^[+]?[0-9]{1,15}$
```

## Response Timeline

We aim to respond to security reports according to the following timeline:

- **Initial response**: Within 72 hours
- **Vulnerability confirmation**: Within 1 week
- **Fix development**: Depends on severity (see below)
- **Public disclosure**: After fix is released and users have time to update

### Severity Levels

**Critical** (Fix within 7 days):
- Remote code execution
- Privilege escalation
- Data exfiltration of sensitive information
- Bypassing security controls

**High** (Fix within 14 days):
- Command injection
- Unauthorized message sending
- Information disclosure
- Denial of service

**Medium** (Fix within 30 days):
- Security feature bypass
- Weak cryptography
- Minor information disclosure

**Low** (Fix when possible):
- Security misconfigurations
- Missing security headers
- Non-exploitable issues

## Security Considerations

### Dangerous Operations

ZeroSMS includes functionality that can:
- Send real SMS/MMS messages (may incur carrier charges)
- Modify device modem settings (requires root)
- Execute AT commands with system privileges
- Access telephony stack internals

These operations are powerful and potentially dangerous. Always:
- Require explicit confirmation flags (`--confirm`, `--yes`)
- Display clear warnings before execution
- Log all dangerous operations
- Implement rate limiting where appropriate

### Hardware Access

Features requiring root access or direct modem communication:
- AT command execution
- Diagnostic port access
- Direct PDU manipulation
- Modem configuration changes

These features should:
- Check for root access before execution
- Validate all inputs strictly
- Handle errors gracefully
- Never expose credentials or sensitive data

### Network Considerations

When using ZeroSMS on production devices or networks:
- Test in isolated environments when possible
- Be aware of carrier ToS and compliance
- Monitor message charges and quotas
- Respect rate limits and fair use policies

## Known Security Issues

### Current Limitations

1. **Root requirement**: Some features require root access, which inherently increases device attack surface
2. **AT command risks**: Direct modem access bypasses Android security layers
3. **No message encryption**: Test messages sent in plaintext (by design for protocol testing)
4. **Limited input validation**: Some edge cases may not be fully validated

### Mitigations

We implement the following security measures:
- Input validation for phone numbers and message content
- Confirmation requirements for destructive operations
- Logging of all sensitive operations
- Clear user warnings for dangerous features
- Security scanning in CI pipeline (bandit, pip-audit)

## Security Best Practices

### For Users

- **Keep updated**: Always use the latest version
- **Test safely**: Use test devices and SIM cards when possible
- **Verify inputs**: Double-check phone numbers before sending
- **Review logs**: Check logs after sensitive operations
- **Report issues**: Report any suspicious behavior immediately

### For Developers

- **Code review**: All changes affecting security require review
- **Input validation**: Validate and sanitize all user inputs
- **Least privilege**: Request minimum necessary permissions
- **Secure storage**: Never commit secrets or credentials
- **Security scanning**: Run `bandit` and `pip-audit` before commits
- **Test coverage**: Write tests for security-critical code

### For Contributors

Before contributing code that touches security-sensitive areas:
1. Review this security policy
2. Review `GEMINI.md` for dangerous operation requirements
3. Add appropriate input validation
4. Write tests for edge cases
5. Run security scanners locally
6. Document security implications in PR

## GEMINI Automation

The GEMINI automation system references this security policy and will:
- Scan for common security issues (via bandit)
- Check dependency vulnerabilities (via pip-audit)
- Validate that dangerous operations require confirmation flags
- Flag potential security issues in code reviews

See `GEMINI.md` for detailed automation guidelines.

## Security Hardening

### Recommended Configuration

```python
# Example: Secure configuration for CLI tools
SECURITY_CONFIG = {
    'require_confirmation': True,      # Force --confirm flags
    'log_sensitive_ops': True,         # Log all dangerous operations
    'validate_phone_numbers': True,    # Strict E.164 validation
    'rate_limit': True,                # Enable rate limiting
    'max_messages_per_hour': 10,       # Conservative rate limit
}
```

### Environment Variables

Sensitive configuration should use environment variables:
```bash
# Example: Safe environment variable usage
export ZEROSMS_TEST_DEVICE="/dev/smd0"
export ZEROSMS_LOG_LEVEL="DEBUG"

# Never do this:
export ZEROSMS_API_KEY="secret123"  # ❌ Don't commit secrets!
```

## Compliance

ZeroSMS implements several RFC standards for SMS/MMS/RCS:
- GSM 03.40 (SMS)
- OMA MMS Encapsulation
- GSMA RCS Universal Profile 2.4

Security vulnerabilities related to RFC compliance or protocol implementation are considered high priority.

## Disclosure Policy

### Public Disclosure

We follow a **coordinated disclosure** approach:
1. Vulnerability is reported privately
2. We confirm and develop a fix
3. Fix is released in a new version
4. After reasonable time for users to update (typically 30 days):
   - Public advisory is published
   - Credit is given to reporter (if desired)
   - CVE is requested if applicable

### Credit

We believe in recognizing security researchers:
- Security researchers will be credited in release notes (if desired)
- We maintain a security acknowledgments section
- Significant findings may be featured in project documentation

## Security Acknowledgments

We thank the following security researchers for their responsible disclosure:

*(This section will be updated as vulnerabilities are reported and fixed)*

## Contact

For security-related questions or reports:
- **GitHub Security Advisories**: [Use Security tab]
- **General questions**: Open a public issue with `[SECURITY]` tag (for non-sensitive topics)
- **Discussions**: Use GitHub Discussions for security best practices

## Updates to This Policy

This security policy may be updated as the project evolves. Material changes will be announced in release notes and commit messages.

**Last updated**: 2024-12-04

---

**Thank you for helping keep ZeroSMS and its users secure!** 🔒
