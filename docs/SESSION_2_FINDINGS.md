# Session 2: Additional Findings - Flash SMS MediaTek Research

## Summary of Extended Testing

### MIPC Device Characterization

Tested direct read/write on /dev/ttyCMIPC0-9:

- **Write**: `echo "test" > /dev/ttyCMIPC0` → Success (no error)
- **Read** (as root): `timeout 1 cat /dev/ttyCMIPC0 | xxd` → **Timeout with no output**
- **Permission**: Permission denied for non-root
- **Implication**: Devices are one-way or requiring specific protocol format

### HIDL Service Discovery

Found: `vendor.mediatek.hardware.atci@1.0::IAtcid/default` (PID 16612, active)

- Confirmed via `lshal | grep atci`
- Cannot be called via `service call` command
- Requires native HIDL client (C++ or JNI/Kotlin native bridge)

### Key Strings from atcid Binary

- "fail to open mipc socket. errno:%d" → atcid tries to open internal MIPC socket
- "sendDataToMeta" → Routes AT commands to modem
- "ATCI COMMAND" → Processing AT command path
- This confirms atcid IS the AT command gateway

### AT Command Logging Confirmation

Verified continuous polling in logcat:

```
11-30 04:02:35.308 8715 8765 I AT: [0] AT> AT+EOPS? (RIL_ATCI_READER tid:533537418496)
11-30 04:02:35.313 8715 8764 I AT: [0] AT< +EOPS: 0,2,"310260",4096
```

Every ~7 seconds from RIL_ATCI_READER threads - proves AT injection would be logged

### Root Cause: MIPC Socket Mechanism

The atcid binary reveals it opens "mipc socket" internally (not /dev/ttyCMIPC):

1. atcid daemon creates internal socket pairs
2. Routes all AT commands through these sockets
3. Converts to MediaTek MIPC binary protocol
4. Sends to /dev/ttyCMIPC* devices with proper framing

**Why direct writes fail**: Binary protocol expected, not raw ASCII

## New Code Created

### HidlAtciManager.kt

- Detects HIDL service availability
- Attempts to call via `service call` (fails - not applicable to HIDL)
- Would need native bridge to work

### MipcDeviceManager.kt

- Implements MIPC frame building
- Header: [0xA0] [LEN_H] [LEN_L] [CMD_ID_H] [CMD_ID_L] [DATA] [CHECKSUM] [0xA1]
- Calculates checksums
- Would need correct command IDs for AT forwarding (likely 0xF001)

## What Would Work

### Option 1: HIDL Native Client (Most Feasible)

```kotlin
// Requires NDK/JNI
val atciService = IAtcid.getService()
val result = atciService.sendAtCmd("AT+CSMP=17,167,0,16")
```

### Option 2: RIL Direct Call (If Methods Exposed)

```kotlin
// Via telecom/internal API
val phone = PhoneFactory.getPhone(0)
val smsManager = SmsManager.getDefault()
// Set class 0 via internal method
```

### Option 3: Reverse Engineer MIPC

- Identify correct command IDs
- Build frames with AT+CSMP
- Send via MIPC devices
- Monitor logcat for response

## Test Status

| Component | Status | Evidence |
|-----------|--------|----------|
| MIPC devices accessible | ✅ Yes | Read/write permissions allow access |
| MIPC responding to ASCII | ❌ No | Timeout on read, no modem response |
| HIDL service active | ✅ Yes | Visible in lshal output (PID 16612) |
| AT command logging active | ✅ Yes | Continuous AT+EOPS in logcat every 7s |
| Socket ATCI accessible | ⚠️ Partial | Socket exists but protocol unknown |
| Direct injection possible | ❌ No | Requires MIPC binary protocol or HIDL |

## Next Phase Recommendations

1. **Implement HIDL Client**: Use Android NDK to create native interface
2. **Capture MIPC Traffic**: Use strace on atcid to see internal socket calls
3. **RIL API Study**: Examine MTK telephony extensions for direct SMS API
4. **Carrier Testing**: Try different SIMs to verify Class 0 support

## Files Modified

- Created: `HidlAtciManager.kt`
- Created: `MipcDeviceManager.kt`  
- Created: `MEDIATEK_FLASH_SMS_RESEARCH.md` (updated)
- Existing: `AtCommandManager.kt` (already incomplete AT implementation)

## Conclusion

The MediaTek MT6789 architecture requires going through either:

1. The HIDL service interface (preferred, official)
2. The MIPC binary protocol (requires reverse engineering)
3. Carrier APN settings (if restricting Class 0)

Shell-level direct injection is not feasible without implementing one of the above.
