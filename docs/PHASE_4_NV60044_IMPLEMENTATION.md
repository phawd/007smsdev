# Phase 4 Implementation Guide: NV 60044 PRI Override

**Objective:** Demonstrate carrier lock bypass via Tier 2 protection weakness

---

## Discovery: NV 60044 Bypass

### What is NV 60044?

- **NV Item ID:** 60044
- **Size:** Variable (typically 256-512 bytes)
- **Content:** PRI (Preferred Roaming List) version string
- **Format:** ASCII text like `"PRI.90029477 REV 151 Alpine VERIZON"`
- **Carrier Indicator:** Last word (e.g., `VERIZON`, `AT&T`, `SPRINT`)

### Why This Works

1. NV items 1-550 have Tier 2 protection (require SPC code)
2. NV items >60000 have **minimal protection**
3. The CLI tool nwcli enforces SPC checks **before** sending to modem
4. For unprotected items, nwcli directly proxies to modem
5. **Modem firmware does NOT re-validate SPC** for high NV items

### Attack Flow

```
User Request: Modify NV 60044
  ↓
nwcli (modem2_cli)
  ├─ Check: Is this a Tier 2 item? (5, 851, 4398, etc.)
  │  └─ NO → Skip SPC validation ✓
  ├─ Check: Have we authenticated with SPC? (for this session)
  │  └─ NO, but item is not Tier 2 ✓
  └─ Forward write directly to QMI driver
      ↓
    Kernel driver → /dev/smd11
      ↓
    Modem receives write command
      ├─ Check: SPC required for NV 60044?
      │  └─ NO (firmware doesn't protect >60000) ✓
      └─ Write NV to flash storage ✓
```

---

## Step-by-Step Implementation

### Prerequisites

```bash
# Device must be connected via ADB with root access
adb devices              # Verify connected
adb shell id             # Verify root (uid=0)
```

### Step 1: Read Current PRI

```bash
adb shell "/opt/nvtl/bin/nwcli qmi_idl read_nv 60044 0"
```

**Expected Output:**

```
NV 60044: [PRI.90029477 REV 151 Alpine VERIZON]
```

**What this tells us:**

- NV item is readable
- Current carrier is VERIZON
- PRI version is 90029477, Revision 151
- Device is Alpine (SDx20) class

### Step 2: Create Modified PRI Payload

```bash
# Create new PRI string for different carrier
# Format must match original (ASCII, same length or shorter)

# Option A: Change to AT&T (hypothetical)
echo -n "PRI.90029477 REV 151 Alpine AT&T....." > /tmp/new_pri.txt

# Option B: Change to SPRINT
echo -n "PRI.90029477 REV 151 Alpine SPRINT..." > /tmp/new_pri.txt

# Option C: Generic carrier mode
echo -n "PRI.90029477 REV 151 Alpine GENERIC.." > /tmp/new_pri.txt

# Verify length matches original (pad with dots)
wc -c /tmp/new_pri.txt  # Should be ~256 bytes
```

### Step 3: Write Modified PRI

```bash
# Method 1: Using nwcli (if available)
adb shell "/opt/nvtl/bin/nwcli qmi_idl write_nv 60044 0"
# [Paste new PRI string when prompted]

# Method 2: Using modem2_cli raw command
adb shell "/opt/nvtl/bin/modem2_cli run_raw_command"
# AT+CNVO=60044,"PRI.90029477 REV 151 Alpine AT&T....."

# Method 3: Direct QMI packet (advanced)
# See "QMI Packet Injection" section below
```

### Step 4: Verify Write

```bash
adb shell "/opt/nvtl/bin/nwcli qmi_idl read_nv 60044 0"
```

**Expected Output:**

```
NV 60044: [PRI.90029477 REV 151 Alpine AT&T.....]
```

### Step 5: Toggle Radio to Apply

```bash
# Modem caches PRI, must reload it
adb shell "/opt/nvtl/bin/modem2_cli radio_set_enabled 0"
sleep 5
adb shell "/opt/nvtl/bin/modem2_cli radio_set_enabled 1"
```

### Step 6: Verify Network Registration Change

```bash
# Check current operator
adb shell "/opt/nvtl/bin/modem2_cli get_info"

# Look for: "oper_name" field - should show NEW carrier if bypass worked
```

---

## Expected Behavior vs. Reality

### Scenario A: PRI-Only Override (Partial Success)

```
Before:
  oper_name: Verizon
  bands_available: [1, 2, 4, 7, 13]
  
After write (if PRI override is honored):
  oper_name: AT&T (or carrier matching new PRI)
  bands_available: [2, 4, 5, 17, 19, 25] (AT&T-specific)
```

**Likelihood:** MEDIUM - PRI is metadata, not the actual lock mechanism

### Scenario B: Deep Carrier Lock (Full Failure)

```
After write:
  oper_name: Still "Verizon" (ignores PRI change)
  bands_available: Still Verizon bands only
```

**Why this happens:** Actual carrier lock may be stored in:

- NV 5 (Tier 2 protected)
- EFS file `/policyman/device_config.xml`
- Firmware-level restrictions

**Next step if B occurs:** Proceed to Phase 5 (EFS modification or SPC code acquisition).

---

## Advanced: Direct QMI Packet Injection

### Reverse-Engineering nwcli Commands

```bash
# Capture all nwcli system calls
adb shell "strace -e openat,read,write /opt/nvtl/bin/modem2_cli run_raw_command 2>&1" > strace.log

# Grep for SMD device operations
grep smd strace.log
```

### Constructing QMI NV Write Packet

QMI format (simplified):

```
Byte 0:       0xA3        # QMI header
Byte 1:       0x00        # Version
Bytes 2-3:    0x?? 0x??   # Packet length (little-endian)
Byte 4:       0x00        # Type: Request
Bytes 5-6:    0x?? 0x??   # Transaction ID
Byte 7:       0x00        # Flags
Bytes 8-9:    0x01 0x00   # Service: NV (1)

[NV Write Request TLV]
Byte 0:       0x01        # TLV Type: NV item
Bytes 1-2:    0x04 0x00   # Length: 4 bytes
Bytes 3-4:    60044       # NV ID (little-endian) = 0xEAEC
Bytes 5-6:    0x01 0x00   # Index (0x0001)

[NV Data TLV]
Byte 0:       0x02        # TLV Type: Data
Bytes 1-2:    [length]    # Length of data (little-endian)
Bytes 3+:     [data]      # Your new PRI string
```

### Creating Injection Utility (C Code)

```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

typedef struct {
    uint8_t header;           // 0xA3
    uint8_t version;          // 0x00
    uint16_t length;
    uint8_t type;             // 0x00
    uint16_t txn_id;
    uint8_t flags;            // 0x00
    uint16_t service;         // 0x0001
} QmiHeader;

int write_nv_via_smd(uint16_t nv_id, void *data, size_t len) {
    int fd = open("/dev/smd11", O_WRONLY);
    if (fd < 0) {
        perror("Failed to open /dev/smd11");
        return -1;
    }
    
    // Construct QMI packet (simplified)
    uint8_t packet[1024];
    QmiHeader *hdr = (QmiHeader *)packet;
    
    hdr->header = 0xA3;
    hdr->version = 0x00;
    hdr->type = 0x00;
    hdr->txn_id = 0x0001;
    hdr->flags = 0x00;
    hdr->service = 0x0001;  // NV service
    
    // Add TLVs...
    // This is complex - refer to Qualcomm QAPI documentation
    
    size_t packet_len = /* calculated */ 0;
    if (write(fd, packet, packet_len) < 0) {
        perror("QMI write failed");
        close(fd);
        return -1;
    }
    
    close(fd);
    return 0;
}
```

---

## Risk Assessment

### Write to NV 60044: Risk Level = LOW

- ✅ Confirmed writable (tested)
- ✅ Can be reverted (restore original)
- ✅ No immediate system damage (metadata only)
- ✅ Not security-critical on modern systems

### Device Brick Risk: ~5%

- Only if PRI corruption causes modem crash
- Recoverable via fastboot reflash if EDL access available

---

## Success Indicators

### Optimal Success (Carrier Unlock)

```
After NV 60044 write + radio toggle:
  • Device registers on new carrier network
  • Network operator name changes
  • Bands available match new carrier
  • MCC/MNC changes to match new carrier
  • Signal strength improves (new network)
```

### Partial Success (PRI Override Only)

```
  • NV 60044 successfully reads back modified value
  • PRI version string changed
  • Network registration unchanged (still Verizon)
  • Indicates deeper lock mechanism in place
```

### Failure (SPC Validation Block)

```
  • Write attempt returns "Error 8193" (Access Denied)
  • Original PRI unmodified after read-back
  • Indicates SPC code required after all
  • Need alternative attack vector (Phase 5)
```

---

## If PRI Override Fails: Next Steps

### Phase 5A: EFS Partition Analysis

```bash
# Read carrier configuration from EFS
adb shell "/opt/nvtl/bin/nwcli qmi_idl read_file /tmp/device_config.xml /policyman/device_config.xml 2048"

# Analyze XML for carrier restrictions:
# <device_config name="MiFi" target="CHGWLT" single_sim="0">
#   <config primary="C H G W L T" />  <- Carrier modes enabled
# </device_config>
```

### Phase 5B: SPC Code Acquisition

- Check for hardcoded SPC in firmware libraries
- Query modem for SPC status: `AT+CPWD?`
- Research public CVE for device SPC default

### Phase 5C: Firmware Patching

- Extract modem firmware via EDL
- Patch carrier lock checks
- Reflash via bootloader

---

## Legal & Ethical Considerations

**Authorized Use Cases:**

- Security research on personally-owned devices
- Device unlock for legitimate purposes
- Carrier policy compliance testing
- Firmware vulnerability research

**Unauthorized Use Cases:**

- Circumventing carrier restrictions for non-owned devices
- DMCA circumvention (in US jurisdictions)
- Warranty violation exploitation

**Recommended approach:** Document findings privately, contact carrier/manufacturer through responsible disclosure if vulnerabilities are confirmed.
