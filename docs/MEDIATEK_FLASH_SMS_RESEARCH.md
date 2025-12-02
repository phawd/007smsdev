# MediaTek MT6789 Flash SMS - Comprehensive Testing Report

## Device Information

- Device: Ulefone Armor 21
- OS: Android 13 (API 33)
- SoC: MediaTek MT6789 (Dimensity 6020/Helio G99)
- Modem: MOLY.LR13.R2.MP.V101.4.P2
- RIL: mtkfusionrild (PID 8715)

## Discovered Architecture

### AT Command Flow

```
RIL_ATCI_READER Thread 
  └── Receives: AT+EOPS?, AT+ECSQ (signal), etc.
  └── Response Thread: tid:533555232000

RIL_ATCI2_READER Thread 
  └── Receives: AT+EOPS?, AT+ECSQ, etc.
  └── Response Thread: tid:533297048832

ATCI Daemon (atcid)
  └── PID: 4243 (system user)
  └── PID: 12324 (root user, started after daemon-u command)
  └── Service: vendor.mediatek.hardware.atci@1.0::IAtcid/default
  └── Socket: /dev/socket/adb_atci_socket (srw-rw---- radio:system)
```

### Device Paths Tested

#### 1. /dev/ttyCMIPC0-9 (MediaTek Internal Protocol Communication)

- **Major**: 496
- **Minors**: 41-50
- **Status**: Exist, permissions allow access (major 496 = radio:radio)
- **Result**: Writes appear to succeed but no response from modem
- **Notes**: atcid strings indicate "fail to open mipc socket", suggesting different interface needed

#### 2. /dev/socket/rild-atci

- **Permissions**: srw-rw---- root:radio
- **Status**: Exists, owned by root:radio
- **Result**: Connection denied even with root

#### 3. /dev/socket/adb_atci_socket

- **Permissions**: srw-rw---- radio:system
- **Status**: Created by atcid daemon
- **Result**: Connection denied when attempting netcat

#### 4. /dev/radio/pttycmd1

- **Resolution**: Symlink to /dev/pts/5
- **Permissions**: crw-rw-rw- (136,5)
- **Result**: Writes appear successful but no visible output

#### 5. /dev/pts/5 (PTY)

- **Permissions**: crw-rw-rw- u:object_r:devpts:s0
- **Result**: Both write and read attempts show no data flow

### Key Findings

1. **AT Command Polling**: RIL_ATCI_READER threads are clearly polling AT+EOPS every 7 seconds:

   ```
   11-30 04:02:35.308  8715  8765 I AT : [0] AT> AT+EOPS? (RIL_ATCI_READER tid:533537418496)
   11-30 04:02:35.313  8715  8764 I AT : [0] AT< +EOPS: 0,2,"310260",4096 (RIL_ATCI_READER, tid:533555232000)
   11-30 04:02:35.313  8715  8764 I AT : [0] AT< OK (RIL_ATCI_READER, tid:533555232000)
   ```

2. **ATCI Binary Insights**: Strings from /vendor/bin/atcid show:
   - "fail to open mipc socket. errno:%d"
   - "sendDataToMeta"
   - "ATCI COMMAND"
   - Support for AT+CTSA, AT+CPMS, +VZWATCICFG
   - References to "cmdline config"

3. **SELinux Status**: Set to Permissive mode - not blocking access

4. **HIDL Service**: vendor.mediatek.hardware.atci@1.0::IAtcid/default (PID 16612)
   - Cannot be called via `service call` command
   - Requires HIDL client interface (not available from shell)

## Methods Tested (All Failed)

### Direct Device Write Methods

```bash
# Attempt 1: Echo via device
echo "AT" > /dev/ttyCMIPC2
→ "Permission denied" (even with root)

# Attempt 2: Cat pipeline
printf 'AT\r\n' | cat > /dev/ttyCMIPC2
→ Appears to succeed but modem doesn't respond

# Attempt 3: DD copy
printf 'AT\r\n' | dd of=/dev/ttyCMIPC2
→ Records appear in output but no modem response

# Attempt 4: PTY direct write
printf 'AT\r\n' > /dev/pts/5
→ Exit code 1, no output

# Attempt 5: Read-write combo
(printf 'AT\r\n' > /dev/pts/5) & sleep 0.5; cat < /dev/pts/5
→ Only reads echo of command, no modem response
```

### Socket Methods

```bash
# Attempt 1: Netcat to rild-atci
echo "AT" | nc -U /dev/socket/rild-atci
→ "Permission denied"

# Attempt 2: Netcat to adb_atci_socket as root
su -c "echo 'AT' | nc -U /dev/socket/adb_atci_socket"
→ Hangs or connection refused

# Attempt 3: Netcat as radio user
su radio -c "echo -e 'AT\r\n' | nc -w 2 -U /dev/socket/adb_atci_socket"
→ No output, timeout
```

## Current Understanding

### Why Direct Writes Don't Work

1. **MIPC Protocol**: MediaTek uses proprietary MIPC (Internal Protocol Communication) with:
   - Start byte: 0xA0
   - Length header
   - Command ID (2 bytes)
   - Payload
   - Checksum
   - End byte: 0xA1
   - Raw ASCII AT commands won't work

2. **ATCI Daemon Role**: atcid acts as intermediary:
   - Opens MIPC sockets internally
   - Receives AT commands from multiple sources
   - Routes them to modem via MIPC protocol
   - Manages responses

3. **RIL Integration**: mtkfusionrild (RIL) has dedicated ATCI threads:
   - RIL_ATCI_READER: Reads AT responses
   - Regularly polls AT+EOPS for network status
   - Suggests internal message queue

### Why Standard API Works

- SmsManager uses RIL abstraction layer
- RIL translates to AT+CMGS or AT+CMGW
- Atci daemon handles protocol conversion

### Why Direct Injection Fails

- Bypasses ATCI daemon entirely
- MIPC expects binary frame format
- /dev/ttyCMIPC* devices expect MIPC not raw AT
- Socket connections require HIDL or specific protocol handshake

## Next Steps for Success

### Option 1: Reverse Engineer MIPC

- Capture existing MIPC traffic with strace/tcpdump
- Identify SMS-related command IDs
- Build proper MIPC frame for AT+CSMP
- Send via MIPC device with correct format

### Option 2: Use ATCI Daemon API

- Understand adb_atci_socket protocol
- Implement HIDL client interface
- Call IAtcid methods directly from app

### Option 3: RIL Extension

- Modify RIL to add flash SMS capability
- May require recompiling mtkfusionrild

### Option 4: Wait for Carrier/OEM Update

- Flash SMS (Class 0) support varies by carrier
- Some carriers block via network settings
- Check network APN settings for SMS class support

## Recommendations

1. **Priority**: Capture MIPC traffic while app does normal SMS
   - Use strace on mtkfusionrild
   - Use tcpdump/netcat on MIPC devices
   - Identify command structure for SMS

2. **Testing**: Once MIPC format identified:
   - Build proper frames with AT+CSMP
   - Send to /dev/ttyCMIPC devices as root
   - Monitor logcat for ATCI_READER response

3. **Fallback**: If direct MIPC fails:
   - Implement HIDL client for vendor.mediatek.hardware.atci@1.0
   - Call sendAtCmd method (if available)
   - Would require JNI/native code

## Files Created

- `HidlAtciManager.kt`: HIDL service investigation
- `MipcDeviceManager.kt`: MIPC protocol communication (binary frame building)
- `AtCommandManager.kt`: Existing AT command implementation (incomplete)
