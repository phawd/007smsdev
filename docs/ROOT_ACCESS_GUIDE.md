# Root Access & AT Command Guide

## Overview

ZeroSMS includes advanced features that require root access on Android devices. These features enable direct modem communication via AT commands, allowing operators to:

- Send SMS via AT commands for enhanced control
- Monitor incoming Class 0 (Flash) and Type 0 (Silent) SMS
- Access low-level modem functionality
- Configure MMSC settings for MMS

## Root Access Requirements

### Why Root is Needed

Root access is required to:
1. **Access serial devices** (`/dev/smd*`, `/dev/tty*`) where the modem is exposed
2. **Execute AT commands** directly to the modem hardware
3. **Capture all SMS types** including those normally hidden by the system
4. **Modify system properties** for advanced testing

### Rooting Your Device

**WARNING:** Rooting your device:
- Voids most manufacturer warranties
- May brick your device if done incorrectly
- Exposes security risks if not managed properly
- May prevent OTA updates

Popular rooting methods:
- **Magisk** - Systemless root solution (recommended)
- **SuperSU** - Traditional root management
- **KingRoot** - One-click rooting (limited device support)

For testing purposes, we recommend:
- Using a dedicated test device
- Android emulator with root access (AVD with Google APIs, rooted)
- Devices with unlocked bootloaders (Pixel, OnePlus Developer Edition)

### Verifying Root Access

The app will automatically detect root access on startup. You can verify manually:

```bash
adb shell
su
id
# Should show uid=0(root) gid=0(root)
```

## AT Command Interface

### What are AT Commands?

AT commands (Attention commands) are a standard command set for controlling modems. Originally designed for dial-up modems, they're still used in cellular modems for SMS and data operations.

### Supported AT Commands

ZeroSMS uses the following AT commands:

| Command | Purpose | Example |
|---------|---------|---------|
| `AT` | Test modem connection | `AT` → `OK` |
| `AT+CMGF=0` | Set PDU mode | `AT+CMGF=0` → `OK` |
| `AT+CMGF=1` | Set text mode | `AT+CMGF=1` → `OK` |
| `AT+CMGS` | Send SMS | `AT+CMGS=24` → `>` |
| `AT+CSCA?` | Get Service Center | `AT+CSCA?` → `+CSCA: "+12063130004",145` |
| `AT+CSCA="number"` | Set Service Center | `AT+CSCA="+12063130004"` |

### Modem Device Detection

ZeroSMS automatically searches for modem devices in priority order:

1. `/dev/smd0` - Qualcomm Snapdragon modems (primary)
2. `/dev/smd11` - Qualcomm Snapdragon modems (alternate)
3. `/dev/smd7` - Qualcomm modems (data channel)
4. `/dev/ttyUSB0` - USB modems
5. `/dev/ttyUSB1`, `/dev/ttyUSB2` - Additional USB modems
6. `/dev/ttyACM0` - ACM class modems
7. `/dev/ttyGS0` - Generic serial

**Note:** Device paths vary by manufacturer:
- **Qualcomm/Snapdragon** - Usually `/dev/smd0` or `/dev/smd11`
- **MediaTek** - May use `/dev/ttyMT*` or `/dev/ccci*`
- **Samsung Exynos** - May use `/dev/umts*`
- **Huawei HiSilicon** - May use `/dev/ttyAMA*`

### PDU Mode Encoding

AT commands use PDU (Protocol Data Unit) mode for SMS. ZeroSMS automatically:

1. **Encodes phone numbers** in BCD (Binary Coded Decimal)
2. **Sets message class** for Flash SMS (Class 0)
3. **Sets protocol ID** for Silent SMS (Type 0 = 0x40)
4. **Handles encoding** (GSM 7-bit, 8-bit, UCS-2)
5. **Calculates lengths** in bytes/septets

Example PDU for Flash SMS:
```
00          SMSC (use default)
10          PDU Type (Flash SMS)
00          Message Reference
0B          Dest length (11 digits)
91          Dest type (international)
2143658709F0  Dest number (+1234567890)
00          Protocol ID
10          DCS (Class 0 - Flash)
A7          Validity Period (24 hours)
05          UDL (5 chars)
48656C6C6F  User Data ("Hello")
```

## Incoming SMS Monitor

### Class 0 (Flash SMS)

**Characteristics:**
- Displays immediately on screen
- Not stored in inbox by default
- Used for alerts and notifications
- GSM 03.40 Message Class 0

**Use Cases:**
- Emergency alerts
- Network notifications
- Promotional messages
- OTP delivery (some carriers)

### Type 0 (Silent SMS)

**Characteristics:**
- No user notification
- Not displayed to user
- Protocol ID = 0x40
- Used for network testing

**Use Cases:**
- Location tracking (controversial)
- Network diagnostics
- Device presence checks
- Carrier testing

### Monitoring Interface

The SMS Monitor screen (`/monitor` route) provides:

1. **Real-time updates** - Refreshes every second
2. **Message filtering** - View All, Flash only, or Silent only
3. **Summary statistics** - Total, Flash, Silent counts
4. **Message details** - Click any message for full details
5. **PDU inspection** - View raw protocol data

### Security Considerations

**IMPORTANT:** The ability to monitor Silent SMS raises privacy concerns:

- Silent SMS can be used for tracking without user knowledge
- Legitimate uses include carrier network testing
- This feature is for **testing and development only**
- Always obtain proper authorization before testing
- Comply with local telecommunications regulations

## MMSC Configuration

### What is MMSC?

MMSC (Multimedia Messaging Service Center) is the gateway server for MMS. Each carrier operates its own MMSC with specific configuration.

### Configuration Parameters

- **MMSC URL** - Gateway address (e.g., `http://mms.example.com`)
- **MMSC Proxy** - Optional proxy server (some carriers require this)
- **MMSC Port** - Proxy port (usually 80 or 8080)

### Carrier Presets

ZeroSMS includes presets for major carriers:

#### United States
- **T-Mobile USA**
  - URL: `http://mms.msg.eng.t-mobile.com/mms/wapenc`
  - Proxy: None
  - Port: 80

- **AT&T USA**
  - URL: `http://mmsc.mobile.att.net`
  - Proxy: `proxy.mobile.att.net`
  - Port: 80

- **Verizon USA**
  - URL: `http://mms.vtext.com/servlets/mms`
  - Proxy: None
  - Port: 80

#### United Kingdom
- **Vodafone UK**
  - URL: `http://mms.vodafone.co.uk/servlets/mms`
  - Proxy: `212.183.137.12`
  - Port: 8799

- **O2 UK**
  - URL: `http://mmsc.mms.o2.co.uk:8002`
  - Proxy: `193.113.200.195`
  - Port: 8080

#### Europe
- **Orange France**
  - URL: `http://mms.orange.fr`
  - Proxy: `192.168.10.200`
  - Port: 8080

- **T-Mobile Germany**
  - URL: `http://mms.t-mobile.de/servlets/mms`
  - Proxy: `172.28.23.131`
  - Port: 8008

### Custom Configuration

For carriers not in presets:

1. Contact your carrier's technical support
2. Check carrier's APN settings documentation
3. Look for "MMS Settings" in device configuration
4. Some devices show MMSC in: Settings → Mobile Networks → Access Point Names

### Testing MMSC Configuration

To verify MMSC settings:

1. Configure MMSC in Settings → Advanced Features
2. Send a test MMS
3. Check logs for connection errors
4. Verify MMS PDU is sent to correct gateway
5. Monitor for delivery confirmation

## Troubleshooting

### Root Access Issues

**Problem:** Root not detected
- **Solution:** Ensure device is properly rooted with Magisk or SuperSU
- **Check:** Run `adb shell su -c "id"` to verify
- **Note:** Some root solutions (KingRoot) may not work

**Problem:** Root permission denied
- **Solution:** Grant root access when prompted by root manager
- **Check:** ZeroSMS should appear in Magisk/SuperSU app list

### AT Command Issues

**Problem:** No modem device found
- **Solution:** Device may use non-standard path
- **Check:** Run `ls -la /dev/smd* /dev/tty*` as root
- **Try:** Manually test with `echo -ne "AT\r\n" > /dev/smd0`

**Problem:** AT commands timeout
- **Solution:** Modem may be in use by system
- **Check:** Ensure no other apps are using AT interface
- **Note:** Some manufacturers lock AT interface

**Problem:** SMS not sent via AT
- **Solution:** Verify PDU encoding is correct
- **Check:** Enable debug logs to see full AT command sequence
- **Fallback:** App will use standard Android SMS API

### Monitor Not Showing Messages

**Problem:** Class 0/Type 0 messages not appearing
- **Solution:** Ensure receiver is registered in manifest
- **Check:** Receiver priority should be high (999)
- **Note:** Some carriers block Silent SMS

**Problem:** Messages arrive but no notification
- **Solution:** This is expected for Type 0 (Silent) SMS
- **Check:** Open Monitor screen to see captured messages
- **Feature:** Monitor updates in real-time

### MMSC Configuration Issues

**Problem:** MMS not sending
- **Solution:** Verify MMSC URL is correct for carrier
- **Check:** Ensure internet/data connection is active
- **Try:** Use carrier preset if available

**Problem:** Proxy connection timeout
- **Solution:** Some carriers require VPN or specific APN
- **Check:** Proxy IP and port must match carrier settings
- **Note:** MMSC may be restricted to carrier network

## Legal & Ethical Considerations

### Regulatory Compliance

- **FCC (USA)** - Requires consent for automated messaging
- **GDPR (EU)** - Requires data protection for message contents
- **TCPA (USA)** - Restricts unsolicited SMS marketing
- **Local Laws** - Check telecommunications regulations

### Responsible Use

This software is for:
- ✅ Testing and development
- ✅ Security research
- ✅ Network diagnostics
- ✅ RFC compliance verification

This software is NOT for:
- ❌ Unauthorized surveillance
- ❌ Spam or harassment
- ❌ Privacy violations
- ❌ Illegal tracking

### Testing Best Practices

1. **Use test numbers** only (your own devices)
2. **Obtain written authorization** for carrier testing
3. **Document all tests** for compliance
4. **Respect privacy** and local regulations
5. **Disable features** when not actively testing

## Support & Resources

### Documentation
- **GSM 03.40** - SMS Point-to-Point Protocol
- **GSM 03.38** - Character Set and Encoding
- **3GPP TS 23.040** - Technical Realization
- **AT Command Reference** - Standard AT commands
- **Carrier APNs** - Mobile network settings

### Community
- Open issues on GitHub for bugs
- Contribute improvements via pull requests
- Share carrier MMSC configurations
- Report security vulnerabilities responsibly

### Disclaimer

Root access and AT command usage can:
- Damage your device if used incorrectly
- Violate carrier terms of service
- Expose security vulnerabilities
- Result in legal consequences if misused

Use at your own risk. The developers assume no liability for misuse of this software.
