#!/usr/bin/env python3
"""
MiFi 8800L Comprehensive Controller
===================================

Full automation script for Inseego MiFi 8800L device control.
Supports IMEI modification, carrier config, band enable, roaming, APN,
and more.

Author: ZeroSMS Project
License: MIT

PROPRIETARY FUNCTIONS DOCUMENTED:
================================

modem2_cli Functions (libmodem2_api.so):
----------------------------------------
  get_info              - Get IMEI, IMSI, ICCID, firmware version
  get_state             - Get connection state, signal, operator
  get_signal            - Get RSSI, RSRP, RSRQ, SINR, bars
  get_carrier_unlock    - Get carrier lock status (State 0 = unlocked)
  unlock_carrier        - Unlock carrier with NCK code
  validate_spc          - Validate SPC code (default: 000000)
  roam_get_enabled      - Get roaming status
  roam_set_enabled      - Enable/disable roaming (1/0)
  roam_get_intl_enabled - Get international roaming status
  roam_set_intl_enabled - Enable/disable international roaming
  enabled_tech_get      - Get enabled radio technologies (bitmask)
  enabled_tech_set      - Set enabled technologies (GSM,UMTS,CDMA,EVDO,LTE)
  lte_band_get_enabled  - Get enabled LTE bands
  lte_band_set_enabled  - Set enabled LTE bands
  band_class_get_enabled- Get band class status
  band_class_set_enabled- Set band class
  active_band_get       - Get currently active band
  prof_get_pri_tech     - Get PRI APN profile
  prof_set_pri_tech     - Set PRI APN profile (tech, APN, auth, PDP type)
"""

import subprocess
import re
import time
import json
import argparse
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from enum import Enum, IntFlag

# ============================================================================
# CONSTANTS
# ============================================================================

# Keep execution under 2 minutes to avoid interactive hangs
DEFAULT_TIMEOUT = 90


class TechMode(IntFlag):
    """Radio technology bitmask values"""

    GSM = 0x01
    UMTS = 0x02
    CDMA = 0x04
    EVDO = 0x08
    LTE = 0x10
    WIFI = 0x40
    ALL = GSM | UMTS | CDMA | EVDO | LTE


class LTEBand(IntFlag):
    """LTE Band numbers (as bitmask positions)"""

    B1 = 1 << 0
    B2 = 1 << 1
    B3 = 1 << 2
    B4 = 1 << 3
    B5 = 1 << 4
    B7 = 1 << 6
    B8 = 1 << 7
    B12 = 1 << 11
    B13 = 1 << 12
    B14 = 1 << 13
    B17 = 1 << 16
    B20 = 1 << 19
    B25 = 1 << 24
    B26 = 1 << 25
    B28 = 1 << 27
    B29 = 1 << 28
    B30 = 1 << 29
    B38 = 1 << 37
    B39 = 1 << 38
    B40 = 1 << 39
    B41 = 1 << 40
    B66 = 1 << 65
    ALL = 0xFFFFFFFFFFFFFFFF


class CarrierMode(Enum):
    """Valid CertifiedCarrier values"""

    VERIZON = "Verizon"
    SPRINT = "Sprint"
    ATT = "AT&T"
    BELL = "Bell"
    TELUS = "Telus"
    GSM = "GSM"
    AUTO = "AUTO"


# CLI tool paths
MODEM2_CLI = "/opt/nvtl/bin/modem2_cli"
NWCLI = "/opt/nvtl/bin/nwcli"
SMS_CLI = "/opt/nvtl/bin/sms_cli"
USB_CLI = "/opt/nvtl/bin/usb_cli"
WIFI_CLI = "/opt/nvtl/bin/wifi_cli"
GPS_CLI = "/opt/nvtl/bin/gps_cli"
ROUTER_CLI = "/opt/nvtl/bin/router2_cli"

# Config files
SETTINGS_XML = "/sysconf/settings.xml"
FEATURES_XML = "/sysconf/features.xml"

# NV Items
NV_IMEI = 550
NV_SIM_LOCK = 3461
NV_SUBSIDY_LOCK = 4399
NV_PRI_VERSION = 60044

# EFS Paths
EFS_LTE_BANDPREF = "/nv/item_files/modem/mmode/lte_bandpref"
EFS_DEVICE_CONFIG = "/policyman/device_config.xml"

# ============================================================================
# ADB INTERFACE
# ============================================================================


def adb_shell(cmd: str, timeout: int = DEFAULT_TIMEOUT) -> Tuple[str, int]:
    """Execute ADB shell command and return output and return code"""
    full_cmd = f'adb shell "{cmd}"'
    try:
        result = subprocess.run(
            full_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout + result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "ERROR: Command timed out", -1
    except Exception as e:
        return f"ERROR: {e}", -1


def adb_shell_interactive(cmd: str, inputs: List[str], timeout: int = DEFAULT_TIMEOUT) -> Tuple[str, int]:
    """Execute ADB shell command with interactive inputs"""
    input_str = "\n".join(inputs) + "\n"
    full_cmd = f'adb shell "{cmd}"'
    try:
        result = subprocess.run(
            full_cmd,
            shell=True,
            input=input_str,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout + result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "ERROR: Command timed out", -1
    except Exception as e:
        return f"ERROR: {e}", -1

# ============================================================================
# IMEI FUNCTIONS
# ============================================================================


def imei_to_bcd_bytes(imei: str) -> bytes:
    """Encode IMEI to raw bytes (3GPP identity encoding with type nibble)."""

    if len(imei) != 15 or not imei.isdigit():
        raise ValueError("IMEI must be exactly 15 digits")

    b = bytearray()
    b.append(0x08)  # length octet

    # First byte: (digit0 << 4) | 0xA (type indicator for IMEI)
    b.append((int(imei[0]) << 4) | 0x0A)

    # Remaining pairs: (even_index_digit << 4) | odd_index_digit
    for i in range(1, 15, 2):
        odd_digit = int(imei[i])
        even_digit = int(imei[i + 1]) if i + 1 < len(imei) else 0xF
        b.append((even_digit << 4) | odd_digit)

    return bytes(b)


def encode_imei_bcd(imei: str) -> str:
    """Encode IMEI to space-delimited hex string (NV 550 format)."""

    return " ".join([f"{b:02x}" for b in imei_to_bcd_bytes(imei)])


def imei_from_bcd(bcd_hex: str) -> str:
    """Convert BCD hex string to 15-digit IMEI."""

    bytes_list = bcd_hex.strip().split()
    if len(bytes_list) < 2:
        raise ValueError("BCD data too short")

    imei_digits: List[str] = []

    # First byte after length: high nibble = digit0, low nibble = type(0xA)
    first = int(bytes_list[1], 16)
    digit0 = (first >> 4) & 0x0F
    if digit0 <= 9:
        imei_digits.append(str(digit0))

    # Remaining bytes carry odd (low nibble) then even (high nibble)
    for i in range(2, min(len(bytes_list), 9)):
        byte_val = int(bytes_list[i], 16)
        low_nibble = byte_val & 0x0F
        high_nibble = (byte_val >> 4) & 0x0F
        if low_nibble <= 9:
            imei_digits.append(str(low_nibble))
        if high_nibble <= 9:
            imei_digits.append(str(high_nibble))

    return "".join(imei_digits[:15])


def get_current_imei() -> str:
    """Get current IMEI from NV 550"""
    output, rc = adb_shell(f"{NWCLI} qmi_idl read_nv {NV_IMEI} 0")

    # Parse BCD hex output
    lines = output.strip().split("\n")
    for line in lines:
        if line.startswith("08 "):
            return imei_from_bcd(line)

    # Fallback: get from modem2_cli get_info
    output, rc = adb_shell(f"{MODEM2_CLI} get_info")
    match = re.search(r'imei:\[(\d+)\]', output)
    if match:
        return match.group(1)

    return "ERROR: Could not read IMEI"


def calculate_luhn_check(imei_14: str) -> str:
    """Calculate Luhn check digit for 14-digit TAC+Serial"""
    if len(imei_14) != 14 or not imei_14.isdigit():
        raise ValueError("Need exactly 14 digits")

    total = 0
    for i, digit in enumerate(imei_14):
        d = int(digit)
        if i % 2 == 1:  # Double odd positions (0-indexed)
            d *= 2
            if d > 9:
                d -= 9
        total += d

    check = (10 - (total % 10)) % 10
    return imei_14 + str(check)


def set_imei(new_imei: str) -> Tuple[bool, str]:
    """
    Set new IMEI in NV 550.

    WARNING: Changing IMEI may be illegal in your jurisdiction.
    This function is for educational/testing purposes only.

    Args:
        new_imei: 15-digit IMEI (or 14-digit + auto check digit)

    Returns:
        (success, message)
    """
    # Auto-calculate check digit if 14 digits provided
    if len(new_imei) == 14:
        new_imei = calculate_luhn_check(new_imei)
        print(f"Auto-calculated check digit: {new_imei}")

    if len(new_imei) != 15 or not new_imei.isdigit():
        return False, "IMEI must be 15 digits"

    # Encode to binary (9-byte payload: len + IMEI digits)
    payload = imei_to_bcd_bytes(new_imei)
    hex_escapes = "".join([f"\\x{b:02x}" for b in payload])

    # Write payload to temp file on device (keeps under 1–2 min budget)
    adb_shell(f"printf '{hex_escapes}' > /tmp/nv550.bin", timeout=15)

    # Attempt 1: QMI NV write via nwcli (NV 550 index 0)
    out_nv, rc_nv = adb_shell(
        f"{NWCLI} qmi_idl write_nv {NV_IMEI} 0 /tmp/nv550.bin",
        timeout=20,
    )

    if rc_nv == 0 and ("success" in out_nv.lower() or out_nv.strip() == ""):
        time.sleep(2)
        new_read = get_current_imei()
        if new_read == new_imei:
            return True, f"IMEI changed to {new_imei} via write_nv"
        return False, (
            f"NV write returned success but verify shows: {new_read}"
        )

    # Attempt 2: AT fallback (some modems accept EGMR)
    at_cmd = f'AT+EGMR=1,7,"{new_imei}"'
    out_at, _ = adb_shell_interactive(
        f"{MODEM2_CLI} run_raw_command",
        [at_cmd, ""],
        timeout=15,
    )

    if "ok" in out_at.lower() or "success" in out_at.lower():
        time.sleep(2)
        new_read = get_current_imei()
        if new_read == new_imei:
            return True, f"IMEI changed to {new_imei} via AT"
        return False, (
            f"AT reported success but verify shows: {new_read}"
        )

    return False, (
        "IMEI change not confirmed. "
        f"write_nv rc={rc_nv} out={out_nv[:200]} | AT out={out_at[:200]}"
    )

# ============================================================================
# NV ITEM READ/WRITE FUNCTIONS
# ============================================================================


def nv_read(item_id: int, index: int = 0) -> Tuple[bool, str, bytes]:
    """
    Read a single NV item using QMI.

    Args:
        item_id: NV item number (0-65535)
        index: Subscription index (0=primary, 1=secondary)

    Returns:
        Tuple of (success, message, raw_bytes)

    Example:
        success, msg, data = nv_read(550)  # Read IMEI
    """
    output, rc = adb_shell(f"{NWCLI} qmi_idl read_nv {item_id} {index}")

    if rc != 0:
        return False, f"Failed to read NV {item_id}: rc={rc}", b""

    # Parse hex output
    lines = output.strip().split('\n')
    hex_data = []
    for line in lines:
        if not line.strip():
            continue
        # Lines contain hex bytes like "08 9a 09 10 86 87 75 93 78"
        hex_bytes = line.strip().split()
        for hb in hex_bytes:
            try:
                hex_data.append(int(hb, 16))
            except ValueError:
                continue

    raw_bytes = bytes(hex_data)
    return True, f"Read NV {item_id}: {len(raw_bytes)} bytes", raw_bytes


def nv_read_range(
    start: int, end: int, index: int = 0
) -> Dict[int, Tuple[bool, bytes]]:
    """
    Read a range of NV items.

    Args:
        start: Starting NV item number
        end: Ending NV item number (inclusive)
        index: Subscription index (0=primary)

    Returns:
        Dict mapping NV item ID to (success, data)

    Example:
        results = nv_read_range(0, 100)  # Read security range
        for nv_id, (success, data) in results.items():
            if success:
                print(f"NV {nv_id}: {data.hex()}")
    """
    results = {}
    for item_id in range(start, end + 1):
        success, msg, data = nv_read(item_id, index)
        results[item_id] = (success, data)
        # Small delay to avoid overwhelming the device
        time.sleep(0.1)

    return results


def nv_write(item_id: int, index: int, data: bytes) -> Tuple[bool, str]:
    """
    Write a single NV item using QMI.

    ⚠️ WARNING: This uses write_nv which has a known bug!
    Bug: write_nv writes to wrong NV item (550→60044)
    DO NOT USE until bug is fixed via Ghidra analysis!

    Args:
        item_id: NV item number (0-65535)
        index: Subscription index (0=primary, 1=secondary)
        data: Raw bytes to write

    Returns:
        Tuple of (success, message)
    """
    # Write data to temp file
    hex_str = data.hex()
    temp_file = f"/tmp/nv{item_id}.bin"

    # Create binary file on device
    adb_shell(f"echo -n -e '\\x{hex_str}' > {temp_file}")

    # Write using nwcli (⚠️ BUG EXISTS)
    cmd = f"{NWCLI} qmi_idl write_nv {item_id} {index} {temp_file}"
    output, rc = adb_shell(cmd)

    if rc != 0:
        msg = f"Failed to write NV {item_id}: rc={rc}, out={output[:200]}"
        return False, msg

    msg = f"Wrote NV {item_id} (⚠️ WARNING: write_nv bug exists!)"
    return True, msg


# ============================================================================
# CARRIER CONFIG FUNCTIONS
# ============================================================================


def get_certified_carrier() -> str:
    """Get current CertifiedCarrier from settings.xml"""
    output, rc = adb_shell(f"grep CertifiedCarrier {SETTINGS_XML}")
    match = re.search(r'<CertifiedCarrier>([^<]+)</CertifiedCarrier>', output)
    if match:
        return match.group(1)
    return "ERROR: Could not read carrier"


def set_certified_carrier(carrier: str) -> Tuple[bool, str]:
    """
    Set CertifiedCarrier in settings.xml.

    Valid values: Verizon, Sprint, AT&T, Bell, Telus, GSM, AUTO
    """
    valid_carriers = [e.value for e in CarrierMode]
    if carrier not in valid_carriers:
        return False, f"Invalid carrier. Valid: {valid_carriers}"

    current = get_certified_carrier()

    # Use sed to replace
    sed_cmd = f"sed -i 's|<CertifiedCarrier>{current}</CertifiedCarrier>|<CertifiedCarrier>{carrier}</CertifiedCarrier>|' {SETTINGS_XML}"
    output, rc = adb_shell(sed_cmd)

    if rc == 0:
        # Verify
        new_val = get_certified_carrier()
        if new_val == carrier:
            return True, f"Carrier changed from {current} to {carrier}"
        else:
            return False, f"Change failed. Current: {new_val}"

    return False, f"sed command failed: {output}"

# ============================================================================
# BAND ENABLE FUNCTIONS
# ============================================================================


def get_enabled_lte_bands() -> Dict[str, Any]:
    """Get currently enabled LTE bands"""
    # Read from EFS
    output, rc = adb_shell(
        f"{NWCLI} qmi_idl read_file /tmp/bands.bin {EFS_LTE_BANDPREF} 8")

    result = {
        "raw_hex": "",
        "bitmask": 0,
        "bands": []
    }

    # Also get from modem2_cli
    for band in range(1, 72):
        out, _ = adb_shell_interactive(
            f"{MODEM2_CLI} lte_band_get_enabled",
            [str(band)],
            timeout=5
        )
        if "enabled:[1]" in out.lower():
            result["bands"].append(band)

    return result


def enable_all_lte_bands() -> Tuple[bool, str]:
    """
    Enable all LTE bands by writing 0xFF bytes to EFS band preference.
    """
    # Create all-bands file (8 bytes of 0xFF)
    hex_data = "ff " * 8

    # Write binary file
    adb_shell(
        "printf '\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff' > /tmp/all_bands.bin")

    # Write to EFS via QMI
    output, rc = adb_shell(
        f"{NWCLI} qmi_idl write_file /tmp/all_bands.bin {EFS_LTE_BANDPREF}")

    if "success" in output.lower() or rc == 0:
        # Toggle radio to apply
        adb_shell(f"{MODEM2_CLI} radio_set_enabled 0")
        time.sleep(2)
        adb_shell(f"{MODEM2_CLI} radio_set_enabled 1")
        time.sleep(3)
        return True, "All LTE bands enabled. Radio cycled."

    return False, f"EFS write failed: {output}"


def set_lte_band(band: int, enabled: bool) -> Tuple[bool, str]:
    """Enable or disable specific LTE band"""
    val = "1" if enabled else "0"
    output, rc = adb_shell_interactive(
        f"{MODEM2_CLI} lte_band_set_enabled",
        [str(band), val],
        timeout=10
    )

    if "success" in output.lower():
        return True, f"Band {band} {'enabled' if enabled else 'disabled'}"
    return False, output


# ============================================================================
# ROAMING FUNCTIONS
# ============================================================================


def get_roaming_status() -> Dict[str, bool]:
    """Get roaming enable status"""
    domestic, _ = adb_shell(f"{MODEM2_CLI} roam_get_enabled")
    intl, _ = adb_shell(f"{MODEM2_CLI} roam_get_intl_enabled")

    return {
        "domestic": "enabled:[1]" in domestic.lower(),
        "international": "enabled:[1]" in intl.lower()
    }


def set_roaming(
    enabled: bool,
    international: bool = False,
) -> Tuple[bool, str]:
    """Enable or disable roaming"""
    val = "1" if enabled else "0"

    if international:
        output, rc = adb_shell_interactive(
            f"{MODEM2_CLI} roam_set_intl_enabled",
            [val],
            timeout=10
        )
    else:
        output, rc = adb_shell_interactive(
            f"{MODEM2_CLI} roam_set_enabled",
            [val],
            timeout=10
        )

    if "success" in output.lower():
        label = "International " if international else ""
        state = "enabled" if enabled else "disabled"
        return True, f"{label}Roaming {state}"
    return False, output

# ============================================================================
# TECHNOLOGY MODE FUNCTIONS
# ============================================================================


def get_enabled_tech() -> Dict[str, Any]:
    """Get enabled radio technologies"""
    output, rc = adb_shell(f"{MODEM2_CLI} enabled_tech_get")

    result: Dict[str, Any] = {
        "raw": output,
        "bitmask": 0,
        "technologies": []
    }

    match = re.search(r'tech modes:\[(\d+)\]', output.lower())
    if match:
        bitmask = int(match.group(1))
        result["bitmask"] = bitmask

        if bitmask & TechMode.GSM:
            result["technologies"].append("GSM")
        if bitmask & TechMode.UMTS:
            result["technologies"].append("UMTS")
        if bitmask & TechMode.CDMA:
            result["technologies"].append("CDMA")
        if bitmask & TechMode.EVDO:
            result["technologies"].append("EVDO")
        if bitmask & TechMode.LTE:
            result["technologies"].append("LTE")

    return result


def set_enabled_tech(technologies: List[str]) -> Tuple[bool, str]:
    """
    Set enabled radio technologies.

    Args:
        technologies: List of tech names (GSM, UMTS, CDMA, EVDO, LTE)
    """
    tech_str = ",".join(technologies)
    output, rc = adb_shell_interactive(
        f"{MODEM2_CLI} enabled_tech_set",
        [tech_str],
        timeout=15
    )

    if "success" in output.lower():
        return True, f"Technologies set: {tech_str}"
    return False, output

# ============================================================================
# APN PROFILE FUNCTIONS
# ============================================================================


@dataclass
class APNProfile:
    """APN Profile configuration"""
    tech: int  # 0=LTE, 1=UMTS, etc
    apn: str
    auth_type: int  # 0=None, 1=PAP, 2=CHAP, 3=PAP/CHAP
    pdp_type: int  # 0=IPv4, 1=IPv6, 2=IPv4v6, 3=v4v6
    username: str = ""
    password: str = ""


# Common carrier APNs
CARRIER_APNS = {
    "att": APNProfile(0, "broadband", 2, 3),
    "verizon": APNProfile(0, "vzwinternet", 0, 3),
    "tmobile": APNProfile(0, "fast.t-mobile.com", 0, 3),
    "sprint": APNProfile(0, "cinet.spcs", 2, 3),
}


def get_apn_profile() -> Dict[str, Any]:
    """Get current APN profile"""
    output, rc = adb_shell(f"{MODEM2_CLI} prof_get_pri_tech")

    result: Dict[str, Any] = {
        "raw": output,
        "tech": None,
        "apn": None,
        "auth": None,
        "pdp_type": None
    }

    # Parse output
    for line in output.split("\n"):
        if "tech" in line.lower():
            match = re.search(r':\[(\d+)\]', line)
            if match:
                result["tech"] = int(match.group(1))
        elif "apn" in line.lower():
            match = re.search(r':\[([^\]]*)\]', line)
            if match:
                result["apn"] = match.group(1)

    return result


def set_apn_profile(profile: APNProfile) -> Tuple[bool, str]:
    """Set APN profile"""
    inputs = [
        str(profile.tech),
        profile.apn,
        str(profile.auth_type),
        str(profile.pdp_type)
    ]

    if profile.username:
        inputs.append(profile.username)
    if profile.password:
        inputs.append(profile.password)

    output, rc = adb_shell_interactive(
        f"{MODEM2_CLI} prof_set_pri_tech",
        inputs,
        timeout=15
    )

    if "success" in output.lower():
        return True, f"APN set to {profile.apn}"
    return False, output


def set_carrier_apn(carrier: str) -> Tuple[bool, str]:
    """Set APN for known carrier"""
    carrier_lower = carrier.lower()
    if carrier_lower not in CARRIER_APNS:
        return False, f"Unknown carrier. Known: {list(CARRIER_APNS.keys())}"

    return set_apn_profile(CARRIER_APNS[carrier_lower])

# ============================================================================
# POWER SETTINGS FUNCTIONS
# ============================================================================


def set_power_mode(mode: str) -> Tuple[bool, str]:
    """
    Set power mode.

    Args:
        mode: "max" for maximum power, "save" for power save
    """
    if mode == "max":
        # Disable power save
        output, rc = adb_shell_interactive(
            f"{MODEM2_CLI} powersave",
            ["0"],  # 0 = disable power save
            timeout=10
        )

        # Also enable carrier aggregation for max throughput
        adb_shell_interactive(
            f"{MODEM2_CLI} ca_set_enabled", ["1"], timeout=10
        )

        if "success" in output.lower():
            return (
                True,
                "Power mode set to maximum (power save disabled, CA enabled)",
            )

    elif mode == "save":
        output, rc = adb_shell_interactive(
            f"{MODEM2_CLI} powersave",
            ["1"],  # 1 = enable power save
            timeout=10
        )

        if "success" in output.lower():
            return True, "Power save mode enabled"

    return False, f"Unknown mode: {mode}. Use 'max' or 'save'"


def get_tx_power() -> Dict[str, Any]:
    """Get current TX power info from signal stats"""
    output, rc = adb_shell(f"{MODEM2_CLI} get_signal")

    result: Dict[str, Any] = {
        "raw": output,
        "tx_power": None,
        "rssi": None,
        "rsrp": None,
        "rsrq": None,
        "sinr": None
    }

    patterns = {
        "tx_power": r'tx power:\[(-?\d+)\]',
        "rssi": r'rssi:\[(-?\d+)\]',
        "rsrp": r'rsrp:\[(-?\d+)\]',
        "rsrq": r'rsrq:\[(-?\d+)\]',
        "sinr": r'sinr:\[(-?\d+)\]',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output)
        if match:
            result[key] = int(match.group(1))

    return result

# ============================================================================
# NETWORK FUNCTIONS
# ============================================================================


def scan_networks() -> List[Dict[str, Any]]:
    """Scan for available networks"""
    print("Starting network scan (this may take 30-60 seconds)...")

    # Start scan
    adb_shell(f"{MODEM2_CLI} mns_start_scan")

    # Wait for scan
    time.sleep(45)

    # Get results
    output, rc = adb_shell(f"{MODEM2_CLI} mns_get_list")

    networks = []
    # Parse COPS format: (status,"mccmnc","name",tech)
    for match in re.finditer(r'\((\d+),"(\d+)","([^"]*)",(\d+)\)', output):
        status, mccmnc, name, tech = match.groups()
        networks.append({
            "status": int(status),  # 1=available, 2=current, 3=forbidden
            "mccmnc": mccmnc,
            "name": name,
            "tech": int(tech),  # 0=GSM, 2=UMTS, 7=LTE
            "status_text": {
                1: "Available",
                2: "Current",
                3: "Forbidden",
            }.get(int(status), "Unknown"),
        })

    return networks


def select_network(mccmnc: str, tech: int = 7) -> Tuple[bool, str]:
    """
    Manually select network.

    Args:
        mccmnc: MCC+MNC code (e.g., "310410" for AT&T)
        tech: Access technology (0=GSM, 2=UMTS, 7=LTE)
    """
    inputs = [
        "1",  # Enable MNS
        mccmnc,
        str(tech)
    ]

    output, rc = adb_shell_interactive(
        f"{MODEM2_CLI} mns_set_oper",
        inputs,
        timeout=30
    )

    if "success" in output.lower():
        return True, f"Selected network {mccmnc} on tech {tech}"
    return False, output


def connect_to_network(
    carrier: str = "att",
    mccmnc: Optional[str] = None,
    international_roam: bool = True,
) -> Tuple[bool, str]:
    """Apply power/band/APN settings and optionally select a network."""

    steps: List[str] = []

    # Max power and roaming
    set_power_mode("max")
    set_roaming(True, international=international_roam)
    set_enabled_tech(["GSM", "UMTS", "CDMA", "EVDO", "LTE"])
    enable_all_lte_bands()

    if carrier:
        # Skip APN setting - prof_set_pri_tech times out (>90s)
        # Manually set via modem2_cli if needed
        steps.append(f"APN {carrier}: skipped (known timeout issue)")

    if mccmnc:
        ok, msg = select_network(mccmnc)
        steps.append(f"Select {mccmnc}: {'ok' if ok else msg}")

    state = get_connection_state()
    steps.append(f"State: {state}")
    connected = state.get("state", "").lower() in {"online", "connected"}

    summary = "; ".join(steps)
    return connected, summary


def get_connection_state() -> Dict[str, Any]:
    """Get current connection state"""
    output, rc = adb_shell(f"{MODEM2_CLI} get_state")

    result: Dict[str, Any] = {
        "raw": output,
        "state": None,
        "tech": None,
        "operator": None,
        "mccmnc": None,
        "rssi": None,
        "bars": None,
        "roaming": False
    }

    patterns = {
        "state": r'state:\[([^\]]+)\]',
        "tech": r'tech:\[(\d+)\]',
        "operator": r'oper name:\[([^\]]+)\]',
        "mccmnc": r'oper id:\[([^\]]+)\]',
        "rssi": r'rssi:\[(-?\d+)\]',
        "bars": r'bars:\[(\d+)\]',
        "roaming": r'roam:\[(\d+)\]',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output)
        if match:
            val = match.group(1)
            if key == "roaming":
                result[key] = val == "1"
            elif key in ["tech", "rssi", "bars"]:
                result[key] = int(val)
            else:
                result[key] = val

    return result


# ============================================================================
# RADIO CONTROL FUNCTIONS
# ============================================================================


def radio_is_enabled() -> bool:
    """Check if radio is enabled."""
    output, rc = adb_shell(f"{MODEM2_CLI} radio_is_enabled")
    return "enabled" in output.lower() or "[1]" in output


def radio_set_enabled(enabled: bool) -> Tuple[bool, str]:
    """Enable or disable radio."""
    value = "1" if enabled else "0"
    inputs = [value]
    output, rc = adb_shell_interactive(
        f"{MODEM2_CLI} radio_set_enabled",
        inputs,
        timeout=15
    )
    if rc == 0:
        state = "enabled" if enabled else "disabled"
        return True, f"Radio {state}"
    return False, f"Failed to set radio: {output[:200]}"


def active_band_get() -> Dict[str, Any]:
    """Get currently active band."""
    output, rc = adb_shell(f"{MODEM2_CLI} active_band_get")

    result = {"raw": output, "band": None, "channel": None}

    # Parse output like: "Active band: [4] Channel: [1234]"
    band_match = re.search(r'band:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    if band_match:
        result["band"] = int(band_match.group(1))

    chan_match = re.search(r'channel:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    if chan_match:
        result["channel"] = int(chan_match.group(1))

    return result


def get_voice_signal() -> Dict[str, Any]:
    """Get voice signal quality."""
    output, rc = adb_shell(f"{MODEM2_CLI} get_voice_signal")

    result = {"raw": output}

    # Parse signal info - format varies by modem
    patterns = {
        "rssi": r'rssi:\s*\[?(-?\d+)\]?',
        "ecio": r'ecio:\s*\[?(-?\d+)\]?',
        "rscp": r'rscp:\s*\[?(-?\d+)\]?',
        "snr": r'snr:\s*\[?(-?\d+)\]?',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            result[key] = int(match.group(1))

    return result


def get_reject_cause_code() -> Dict[str, Any]:
    """Get network rejection cause code."""
    output, rc = adb_shell(f"{MODEM2_CLI} get_reject_cause_code")

    result = {"raw": output, "cause_code": None, "description": None}

    # Parse cause code
    match = re.search(r'cause:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    if match:
        result["cause_code"] = int(match.group(1))

    # Common cause codes
    cause_codes = {
        2: "IMSI unknown in HLR",
        3: "Illegal MS",
        6: "Illegal ME",
        7: "GPRS services not allowed",
        8: "GPRS and non-GPRS services not allowed",
        11: "PLMN not allowed",
        12: "Location area not allowed",
        13: "Roaming not allowed in this location area",
        15: "No suitable cells in location area",
    }

    if result["cause_code"]:
        result["description"] = cause_codes.get(
            result["cause_code"],
            "Unknown cause"
        )

    return result


def get_oper_info() -> Dict[str, Any]:
    """Get operator information."""
    output, rc = adb_shell(f"{MODEM2_CLI} get_oper_info")

    result = {"raw": output, "mcc": None, "mnc": None, "name": None}

    # Parse MCC/MNC
    mccmnc_match = re.search(r'(\d{5,6})', output)
    if mccmnc_match:
        mccmnc = mccmnc_match.group(1)
        result["mcc"] = mccmnc[:3]
        result["mnc"] = mccmnc[3:]

    # Parse operator name
    name_match = re.search(
        r'operator.*?:\s*\[?([^\]]+)\]?',
        output,
        re.IGNORECASE
    )
    if name_match:
        result["name"] = name_match.group(1).strip()

    return result


def get_service_info() -> Dict[str, Any]:
    """Get service information."""
    output, rc = adb_shell(f"{MODEM2_CLI} get_service_info")

    result = {"raw": output}

    # Parse service info
    patterns = {
        "service_status": r'service.*status:\s*\[?([^\]]+)\]?',
        "roam_status": r'roam.*status:\s*\[?([^\]]+)\]?',
        "data_capabilities": r'data.*cap:\s*\[?([^\]]+)\]?',
        "voice_support": r'voice:\s*\[?([^\]]+)\]?',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            result[key] = match.group(1).strip()

    return result


# ============================================================================
# BAND & TECHNOLOGY INFO FUNCTIONS
# ============================================================================


def band_class_get_enabled() -> Dict[str, Any]:
    """Get enabled band classes."""
    output, rc = adb_shell(f"{MODEM2_CLI} band_class_get_enabled")

    result = {"raw": output, "classes": []}

    # Parse band class list
    # Format varies: "Band classes: [0, 1, 6, 10]" or similar
    match = re.search(r'band.*class.*:\s*\[([^\]]+)\]', output, re.IGNORECASE)
    if match:
        classes_str = match.group(1)
        classes = [
            int(c.strip())
            for c in classes_str.split(',')
            if c.strip().isdigit()
        ]
        result["classes"] = classes

    return result


def band_class_set_enabled(classes: List[int]) -> Tuple[bool, str]:
    """Set enabled band classes."""
    classes_str = ",".join(str(c) for c in classes)
    inputs = [classes_str]

    output, rc = adb_shell_interactive(
        f"{MODEM2_CLI} band_class_set_enabled",
        inputs,
        timeout=15
    )

    if rc == 0 or "success" in output.lower():
        return True, f"Set band classes to {classes_str}"
    return False, f"Failed: {output[:200]}"


def lte_band_get_prior() -> List[int]:
    """Get LTE band priority list."""
    output, rc = adb_shell(f"{MODEM2_CLI} lte_band_get_prior")

    # Parse priority list - format: "Priority: [4, 2, 12, 13, ...]"
    match = re.search(r'priority.*:\s*\[([^\]]+)\]', output, re.IGNORECASE)
    if match:
        bands_str = match.group(1)
        bands = [
            int(b.strip())
            for b in bands_str.split(',')
            if b.strip().isdigit()
        ]
        return bands

    return []


def lte_band_set_prior(bands: List[int]) -> Tuple[bool, str]:
    """Set LTE band priority list."""
    bands_str = ",".join(str(b) for b in bands)
    inputs = [bands_str]

    output, rc = adb_shell_interactive(
        f"{MODEM2_CLI} lte_band_set_prior",
        inputs,
        timeout=15
    )

    if rc == 0 or "success" in output.lower():
        return True, f"Set band priority to {bands_str}"
    return False, f"Failed: {output[:200]}"


def active_tech_get() -> str:
    """Get currently active radio technology."""
    output, rc = adb_shell(f"{MODEM2_CLI} active_tech_get")

    # Parse technology - format: "Active tech: [LTE]" or "tech:[10]"
    tech_names = {
        0: "Unknown", 1: "CDMA", 2: "GSM", 3: "HDR",
        4: "WCDMA", 5: "EHRPD", 6: "LTE", 7: "TDSCDMA",
        8: "1xRTT", 9: "EVDO", 10: "LTE"
    }

    match = re.search(r'tech.*:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    if match:
        tech_num = int(match.group(1))
        return tech_names.get(tech_num, f"Unknown ({tech_num})")

    match = re.search(r'tech.*:\s*\[?([A-Z]+)\]?', output, re.IGNORECASE)
    if match:
        return match.group(1).upper()

    return "Unknown"


def get_network_time() -> Dict[str, Any]:
    """Get network time from cellular tower."""
    output, rc = adb_shell(f"{MODEM2_CLI} get_network_time")

    result = {"raw": output, "time": None, "timezone": None}

    # Parse time - format varies by network
    time_match = re.search(
        r'time.*:\s*\[?([^\]]+)\]?',
        output,
        re.IGNORECASE
    )
    if time_match:
        result["time"] = time_match.group(1).strip()

    tz_match = re.search(
        r'timezone.*:\s*\[?([^\]]+)\]?', output, re.IGNORECASE
    )
    if tz_match:
        result["timezone"] = tz_match.group(1).strip()

    return result


def get_cached_time() -> Dict[str, Any]:
    """Get cached network time (faster than get_network_time)."""
    output, rc = adb_shell(f"{MODEM2_CLI} get_cached_time")

    result = {"raw": output, "time": None}

    time_match = re.search(
        r'time.*:\s*\[?([^\]]+)\]?',
        output,
        re.IGNORECASE
    )
    if time_match:
        result["time"] = time_match.group(1).strip()

    return result


def get_sup_tech() -> List[str]:
    """Get list of supported radio technologies."""
    output, rc = adb_shell(f"{MODEM2_CLI} get_sup_tech")

    tech_names = {
        1: "GSM", 2: "UMTS", 4: "CDMA", 8: "EVDO", 16: "LTE",
        32: "TDSCDMA", 64: "WIFI"
    }

    techs = []

    # Try to parse bitmask
    match = re.search(r'tech.*:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    if match:
        bitmask = int(match.group(1))
        for bit, name in tech_names.items():
            if bitmask & bit:
                techs.append(name)
        return techs

    # Try to parse name list
    for name in tech_names.values():
        if name in output.upper():
            techs.append(name)

    return techs


# ============================================================================
# CARRIER AGGREGATION (CA) FUNCTIONS
# ============================================================================


def ca_get_enabled() -> bool:
    """Check if Carrier Aggregation is enabled."""
    output, rc = adb_shell(f"{MODEM2_CLI} ca_get_enabled")
    match = re.search(r'enabled:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    return match.group(1) == "1" if match else False


def ca_set_enabled(enabled: bool) -> Tuple[bool, str]:
    """Enable or disable Carrier Aggregation."""
    value = "1" if enabled else "0"
    inputs = [value]

    output, rc = adb_shell_interactive(
        f"{MODEM2_CLI} ca_set_enabled",
        inputs,
        timeout=15
    )

    if rc == 0 or "success" in output.lower():
        state = "enabled" if enabled else "disabled"
        return True, f"CA {state}"
    return False, f"Failed: {output[:200]}"


def ca_bands_get_enabled() -> Dict[str, Any]:
    """Get enabled CA band combinations."""
    output, rc = adb_shell(f"{MODEM2_CLI} ca_bands_get_enabled")

    result = {"raw": output, "combinations": []}

    # Parse band combinations - format: "CA bands: [4+12, 2+4, ...]"
    match = re.search(r'ca.*bands?.*:\s*\[([^\]]+)\]', output, re.IGNORECASE)
    if match:
        combos_str = match.group(1)
        result["combinations"] = [
            combo.strip() for combo in combos_str.split(',')
        ]

    return result


def ca_bands_set_enabled(combinations: List[str]) -> Tuple[bool, str]:
    """Set enabled CA band combinations."""
    combos_str = ",".join(combinations)
    inputs = [combos_str]

    output, rc = adb_shell_interactive(
        f"{MODEM2_CLI} ca_bands_set_enabled",
        inputs,
        timeout=15
    )

    if rc == 0 or "success" in output.lower():
        return True, f"Set CA bands to {combos_str}"
    return False, f"Failed: {output[:200]}"


def ca_tri_bands_get_enabled() -> Dict[str, Any]:
    """Get enabled 3-band CA combinations (e.g., B2+B4+B12)."""
    output, rc = adb_shell(f"{MODEM2_CLI} ca_tri_bands_get_enabled")

    result = {"raw": output, "combinations": []}

    match = re.search(r'tri.*bands?.*:\s*\[([^\]]+)\]', output, re.IGNORECASE)
    if match:
        combos_str = match.group(1)
        result["combinations"] = [
            combo.strip() for combo in combos_str.split(',')
        ]

    return result


def ca_tri_bands_set_enabled(combinations: List[str]) -> Tuple[bool, str]:
    """Set enabled 3-band CA combinations."""
    combos_str = ",".join(combinations)
    inputs = [combos_str]

    output, rc = adb_shell_interactive(
        f"{MODEM2_CLI} ca_tri_bands_set_enabled",
        inputs,
        timeout=15
    )

    if rc == 0 or "success" in output.lower():
        return True, f"Set tri-band CA to {combos_str}"
    return False, f"Failed: {output[:200]}"


def check_lte_ca_status() -> Dict[str, Any]:
    """Check current LTE CA status (active, bands, bandwidth)."""
    output, rc = adb_shell(f"{MODEM2_CLI} check_lte_ca_status")

    result = {"raw": output, "active": False, "bands": [], "bandwidth": None}

    # Parse CA status
    if "active" in output.lower():
        result["active"] = True

    # Parse active bands
    match = re.search(r'bands?.*:\s*\[([^\]]+)\]', output, re.IGNORECASE)
    if match:
        bands_str = match.group(1)
        result["bands"] = [b.strip() for b in bands_str.split(',')]

    # Parse bandwidth
    bw_match = re.search(r'bandwidth.*:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    if bw_match:
        result["bandwidth"] = int(bw_match.group(1))

    return result


def get_autonomous_gap_enabled() -> bool:
    """Check if autonomous gap is enabled (inter-frequency search)."""
    output, rc = adb_shell(f"{MODEM2_CLI} get_autonomous_gap_enabled")
    match = re.search(r'enabled:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    return match.group(1) == "1" if match else False


def set_autonomous_gap_enabled(enabled: bool) -> Tuple[bool, str]:
    """Enable/disable autonomous gap (inter-frequency search)."""
    value = "1" if enabled else "0"
    inputs = [value]

    output, rc = adb_shell_interactive(
        f"{MODEM2_CLI} set_autonomous_gap_enabled",
        inputs,
        timeout=15
    )

    if rc == 0 or "success" in output.lower():
        state = "enabled" if enabled else "disabled"
        return True, f"Autonomous gap {state}"
    return False, f"Failed: {output[:200]}"


# ============================================================================
# MANUAL NETWORK SELECTION (MNS) EXTENDED FUNCTIONS
# ============================================================================


def mns_get_info() -> Dict[str, Any]:
    """Get information about manual network selection."""
    output, rc = adb_shell(f"{MODEM2_CLI} mns_get_info")

    result = {
        "raw": output,
        "mode": None,  # Auto or Manual
        "current": None,  # Current network
        "available": []  # Available networks
    }

    # Parse mode
    mode_match = re.search(r'mode.*:\s*\[?([^\]]+)\]?', output, re.IGNORECASE)
    if mode_match:
        result["mode"] = mode_match.group(1).strip()

    # Parse current network
    curr_match = re.search(
        r'current.*:\s*\[?([^\]]+)\]?',
        output,
        re.IGNORECASE
    )
    if curr_match:
        result["current"] = curr_match.group(1).strip()

    return result


def mns_clear_list() -> Tuple[bool, str]:
    """Clear the manual network selection list."""
    output, rc = adb_shell(f"{MODEM2_CLI} mns_clear_list")

    if rc == 0 or "success" in output.lower() or "cleared" in output.lower():
        return True, "MNS list cleared"
    return False, f"Failed: {output[:200]}"


def mns_validate() -> Tuple[bool, str]:
    """Validate current network selection."""
    output, rc = adb_shell(f"{MODEM2_CLI} mns_validate")

    result = {"raw": output, "valid": False, "reason": None}

    if "valid" in output.lower() or "success" in output.lower():
        return True, "Network selection valid"

    # Try to extract reason
    reason_match = re.search(
        r'reason.*:\s*\[?([^\]]+)\]?', output, re.IGNORECASE)
    if reason_match:
        reason = reason_match.group(1).strip()
        return False, f"Invalid: {reason}"

    return False, f"Invalid: {output[:200]}"


# ============================================================================
# SMS FUNCTIONS
# ============================================================================


def send_sms(phone: str, message: str) -> Tuple[bool, str]:
    """Send SMS message"""
    # sms_cli send is interactive
    output, rc = adb_shell_interactive(
        f"{SMS_CLI} send",
        [phone, message],
        timeout=30
    )

    if "success" in output.lower() or "sent" in output.lower():
        return True, f"SMS sent to {phone}"
    return False, output


def get_sms_list() -> List[Dict[str, Any]]:
    """Get list of SMS messages"""
    output, rc = adb_shell(f"{SMS_CLI} get_list")

    messages: List[Dict[str, Any]] = []
    # Parse output format (implementation depends on actual format)
    # This is a placeholder - actual parsing needed

    return messages

# ============================================================================
# AT COMMAND FUNCTIONS
# ============================================================================


def send_at_command(command: str) -> Tuple[str, bool]:
    """Send raw AT command via modem port"""
    output, rc = adb_shell_interactive(
        f"{MODEM2_CLI} run_raw_command",
        [command, ""],
        timeout=15
    )

    success = "OK" in output or "success" in output.lower()
    return output, success

# ============================================================================
# SIM MANAGEMENT FUNCTIONS (NEWLY DISCOVERED)
# ============================================================================


def sim_get_carrier() -> str:
    """Get SIM carrier identifier (e.g., SIM_CARRIER_ATT, SIM_CARRIER_VZW)"""
    output, _ = adb_shell(f"{MODEM2_CLI} sim_get_carrier")
    match = re.search(r'carrier is:\[([^\]]+)\]', output)
    return match.group(1) if match else "Unknown"


def sim_get_gid1() -> str:
    """Get SIM Group Identifier 1 (GID1) - carrier grouping"""
    output, _ = adb_shell(f"{MODEM2_CLI} sim_get_gid1")
    match = re.search(r'gid1:\[([^\]]+)\]', output)
    return match.group(1) if match else ""


def sim_get_gid2() -> str:
    """Get SIM Group Identifier 2 (GID2) - sub-carrier grouping"""
    output, _ = adb_shell(f"{MODEM2_CLI} sim_get_gid2")
    match = re.search(r'gid2:\[([^\]]+)\]', output)
    return match.group(1) if match else ""


def sim_get_mnc_length() -> int:
    """Get MNC (Mobile Network Code) length from SIM"""
    output, _ = adb_shell(f"{MODEM2_CLI} sim_get_mnc_length")
    match = re.search(r'mnc_length:\[(\d+)\]', output)
    return int(match.group(1)) if match else 2


def sim_pin_get_status() -> Dict[str, Any]:
    """Get SIM PIN lock status"""
    output, _ = adb_shell(f"{MODEM2_CLI} sim_pin_get_status")
    result = {"enabled": False, "verified": False, "retries": 3}

    if "enabled" in output.lower():
        result["enabled"] = True
    if "verified" in output.lower():
        result["verified"] = True

    match = re.search(r'retries.*?(\d+)', output, re.IGNORECASE)
    if match:
        result["retries"] = int(match.group(1))

    return result


def sim_change_pin(old_pin: str, new_pin: str) -> Tuple[bool, str]:
    """Change SIM PIN (requires current PIN)"""
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} sim_change_pin",
        [old_pin, new_pin],
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def sim_enable_pin(enable: bool, pin: str) -> Tuple[bool, str]:
    """Enable or disable SIM PIN lock"""
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} sim_enable_pin",
        ["1" if enable else "0", pin],
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def sim_unlock_pin(pin: str) -> Tuple[bool, str]:
    """Unlock SIM with PIN"""
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} sim_unlock_pin",
        [pin],
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def sim_unlock_puk(puk: str, new_pin: str) -> Tuple[bool, str]:
    """Unlock SIM with PUK and set new PIN"""
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} sim_unlock_puk",
        [puk, new_pin],
        timeout=10
    )
    success = "success" in output.lower()
    return success, output

# ============================================================================
# VOLTE / IMS FUNCTIONS (NEWLY DISCOVERED)
# ============================================================================


def volte_get_enabled() -> bool:
    """Check if VoLTE is enabled"""
    output, _ = adb_shell(f"{MODEM2_CLI} volte_get_enabled")
    match = re.search(r'enabled:\[(\d+)\]', output)
    return match.group(1) == "1" if match else False


def volte_set_enabled(enable: bool) -> Tuple[bool, str]:
    """Enable or disable VoLTE"""
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} volte_set_enabled",
        ["1" if enable else "0"],
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def volte_get_hd_voice() -> bool:
    """Check if HD Voice is enabled"""
    output, _ = adb_shell(f"{MODEM2_CLI} volte_get_hd_voice_enab")
    match = re.search(r'enabled:\[(\d+)\]', output)
    return match.group(1) == "1" if match else False


def volte_set_hd_voice(enable: bool) -> Tuple[bool, str]:
    """Enable or disable HD Voice"""
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} volte_set_hd_voice_enab",
        ["1" if enable else "0"],
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def ims_get_sip_data() -> str:
    """Get IMS SIP configuration data"""
    output, _ = adb_shell(f"{MODEM2_CLI} ims_get_sip_data")
    return output


def ims_get_sms_data() -> str:
    """Get SMS over IMS configuration"""
    output, _ = adb_shell(f"{MODEM2_CLI} ims_get_sms_data")
    return output


def ims_lvc_get_enabled() -> bool:
    """Check if IMS LVC (LTE Voice Call) is enabled"""
    output, _ = adb_shell(f"{MODEM2_CLI} ims_lvc_get_enabled")
    match = re.search(r'enabled:\[(\d+)\]', output)
    return match.group(1) == "1" if match else False


# ============================================================================
# VOLTE ADVANCED FUNCTIONS
# ============================================================================


def volte_get_amr_mode() -> int:
    """Get VoLTE AMR (Adaptive Multi-Rate) codec mode."""
    output, _ = adb_shell(f"{MODEM2_CLI} volte_get_amr_mode")
    match = re.search(r'mode:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    return int(match.group(1)) if match else 0


def volte_set_amr_mode(mode: int) -> Tuple[bool, str]:
    """Set VoLTE AMR codec mode (0-7)."""
    inputs = [str(mode)]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} volte_set_amr_mode",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def volte_get_amr_wb_mode() -> int:
    """Get VoLTE AMR-WB (Wideband) codec mode."""
    output, _ = adb_shell(f"{MODEM2_CLI} volte_get_amr_wb_mode")
    match = re.search(r'mode:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    return int(match.group(1)) if match else 0


def volte_set_amr_wb_mode(mode: int) -> Tuple[bool, str]:
    """Set VoLTE AMR-WB codec mode (0-8)."""
    inputs = [str(mode)]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} volte_set_amr_wb_mode",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def volte_get_dcmo_timer() -> int:
    """Get DCMO (Device Configuration Management Object) timer value."""
    output, _ = adb_shell(f"{MODEM2_CLI} volte_get_dcmo_timer")
    match = re.search(r'timer:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    return int(match.group(1)) if match else 0


def volte_set_dcmo_timer(seconds: int) -> Tuple[bool, str]:
    """Set DCMO timer value in seconds."""
    inputs = [str(seconds)]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} volte_set_dcmo_timer",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def volte_get_dcmo_tdelay() -> int:
    """Get DCMO transition delay."""
    output, _ = adb_shell(f"{MODEM2_CLI} volte_get_dcmo_tdelay")
    match = re.search(r'delay:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    return int(match.group(1)) if match else 0


def volte_set_dcmo_tdelay(milliseconds: int) -> Tuple[bool, str]:
    """Set DCMO transition delay in milliseconds."""
    inputs = [str(milliseconds)]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} volte_set_dcmo_tdelay",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def volte_get_hys() -> int:
    """Get VoLTE hysteresis value."""
    output, _ = adb_shell(f"{MODEM2_CLI} volte_get_hys")
    match = re.search(r'hys:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    return int(match.group(1)) if match else 0


def volte_set_hys(value: int) -> Tuple[bool, str]:
    """Set VoLTE hysteresis value."""
    inputs = [str(value)]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} volte_set_hys",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def volte_get_rcl_max_entries() -> int:
    """Get VoLTE RCL (Redial Call List) maximum entries."""
    output, _ = adb_shell(f"{MODEM2_CLI} volte_get_rcl_max_entries")
    match = re.search(r'entries:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    return int(match.group(1)) if match else 0


def volte_set_rcl_max_entries(count: int) -> Tuple[bool, str]:
    """Set VoLTE RCL maximum entries."""
    inputs = [str(count)]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} volte_set_rcl_max_entries",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def volte_get_sess_config() -> Dict[str, Any]:
    """Get VoLTE session configuration."""
    output, _ = adb_shell(f"{MODEM2_CLI} volte_get_sess_config")

    result = {"raw": output}

    # Parse session config parameters
    patterns = {
        "timer_t1": r't1:\s*\[?(\d+)\]?',
        "timer_t2": r't2:\s*\[?(\d+)\]?',
        "timer_t4": r't4:\s*\[?(\d+)\]?',
        "session_expires": r'expires:\s*\[?(\d+)\]?',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            result[key] = int(match.group(1))

    return result


def volte_set_sess_config(
    t1: int = 500, t2: int = 4000, t4: int = 5000, expires: int = 1800
) -> Tuple[bool, str]:
    """Set VoLTE session configuration timers."""
    inputs = [str(t1), str(t2), str(t4), str(expires)]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} volte_set_sess_config",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def volte_get_silent_redial() -> bool:
    """Check if VoLTE silent redial is enabled."""
    output, _ = adb_shell(f"{MODEM2_CLI} volte_get_silent_redial")
    match = re.search(r'enabled:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    return match.group(1) == "1" if match else False


def volte_set_silent_redial(enabled: bool) -> Tuple[bool, str]:
    """Enable/disable VoLTE silent redial."""
    inputs = ["1" if enabled else "0"]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} volte_set_silent_redial",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def volte_get_src_thttle() -> int:
    """Get VoLTE source throttle value."""
    output, _ = adb_shell(f"{MODEM2_CLI} volte_get_src_thttle")
    match = re.search(r'throttle:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    return int(match.group(1)) if match else 0


def volte_set_src_thttle(value: int) -> Tuple[bool, str]:
    """Set VoLTE source throttle value."""
    inputs = [str(value)]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} volte_set_src_thttle",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def volte_get_tlte_911fail() -> int:
    """Get VoLTE LTE 911 failure timer."""
    output, _ = adb_shell(f"{MODEM2_CLI} volte_get_tlte_911fail")
    match = re.search(r'timer:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    return int(match.group(1)) if match else 0


def volte_set_tlte_911fail(seconds: int) -> Tuple[bool, str]:
    """Set VoLTE LTE 911 failure timer in seconds."""
    inputs = [str(seconds)]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} volte_set_tlte_911fail",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


# ============================================================================
# IMS ADVANCED FUNCTIONS
# ============================================================================


def ims_set_sip_timer(timer_name: str, value: int) -> Tuple[bool, str]:
    """Set IMS SIP timer value."""
    inputs = [timer_name, str(value)]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} ims_set_sip_timer",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def ims_pres_get_config() -> Dict[str, Any]:
    """Get IMS presence configuration."""
    output, _ = adb_shell(f"{MODEM2_CLI} ims_pres_get_config")

    result = {"raw": output}

    # Parse presence config
    patterns = {
        "enabled": r'enabled:\s*\[?(\d+)\]?',
        "publish_timer": r'publish.*timer:\s*\[?(\d+)\]?',
        "capability_poll_interval": r'poll.*interval:\s*\[?(\d+)\]?',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            if key == "enabled":
                result[key] = match.group(1) == "1"
            else:
                result[key] = int(match.group(1))

    return result


def ims_pres_set_config(
    enabled: bool, publish_timer: int = 1200, poll_interval: int = 3600
) -> Tuple[bool, str]:
    """Set IMS presence configuration."""
    inputs = ["1" if enabled else "0", str(publish_timer), str(poll_interval)]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} ims_pres_set_config",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def ims_reg_set_delay(milliseconds: int) -> Tuple[bool, str]:
    """Set IMS registration delay in milliseconds."""
    inputs = [str(milliseconds)]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} ims_reg_set_delay",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


# ============================================================================
# DIAGNOSTIC FUNCTIONS (NEWLY DISCOVERED)
# ============================================================================


def get_diag_info() -> str:
    """Get diagnostic information"""
    output, _ = adb_shell(f"{MODEM2_CLI} get_diag_info")
    return output


def lifetime_counters_get() -> Dict[str, int]:
    """Get device lifetime usage counters"""
    output, _ = adb_shell(f"{MODEM2_CLI} lifetime_counters_get")
    counters = {}

    # Parse counters from output
    for match in re.finditer(r'(\w+):\[?(\d+)\]?', output):
        key, val = match.groups()
        counters[key] = int(val)

    return counters


def get_activation_date() -> str:
    """Get device activation date"""
    output, _ = adb_shell(f"{MODEM2_CLI} get_activation_date")
    match = re.search(r'date:\[([^\]]+)\]', output)
    return match.group(1) if match else "Unknown"


def get_refurb_info() -> Dict[str, Any]:
    """Get refurbishment information"""
    output, _ = adb_shell(f"{MODEM2_CLI} get_refurb_info")
    info = {}

    for match in re.finditer(r'(\w+):\[([^\]]+)\]', output):
        key, val = match.groups()
        info[key] = val

    return info


# ============================================================================
# EFS FILE OPERATIONS (NEWLY DISCOVERED)
# ============================================================================


def efs_delete_file(path: str) -> Tuple[bool, str]:
    """Delete EFS file"""
    output, _ = adb_shell(
        f"{MODEM2_CLI} delete_efs_file",
        timeout=15
    )
    # Command is interactive - needs path input
    # This is a placeholder - needs interactive implementation
    success = "success" in output.lower()
    return success, output


def efs_write_large_file(local_path: str, efs_path: str) -> Tuple[bool, str]:
    """Write large file to EFS (>1KB)"""
    # Push file to device first
    subprocess.run(["adb", "push", local_path, "/tmp/efs_upload.bin"],
                   capture_output=True, timeout=30)

    output, _ = adb_shell(
        f"{MODEM2_CLI} write_efs_large_file",
        timeout=30
    )
    success = "success" in output.lower()
    return success, output


# ============================================================================
# eHRPD FUNCTIONS (Batch 5 - Session 7)
# ============================================================================


def ehrpd_get_enabled() -> bool:
    """Check if eHRPD is enabled."""
    output, _ = adb_shell(f"{MODEM2_CLI} ehrpd_get_enabled")
    match = re.search(r'enabled:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    return match.group(1) == "1" if match else False


def ehrpd_set_enabled(enabled: bool) -> Tuple[bool, str]:
    """Enable/disable eHRPD (evolved High Rate Packet Data)."""
    inputs = ["1" if enabled else "0"]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} ehrpd_set_enabled",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def ehrpd_get_state() -> Dict[str, Any]:
    """Get eHRPD state information."""
    output, _ = adb_shell(f"{MODEM2_CLI} ehrpd_get_state")

    result = {"raw": output}

    # Parse eHRPD state
    patterns = {
        "state": r'state:\s*\[?(\w+)\]?',
        "session_active": r'session:\s*\[?(\d+)\]?',
        "meid": r'meid:\s*\[?([0-9A-Fa-f]+)\]?',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            if key == "session_active":
                result[key] = match.group(1) == "1"
            else:
                result[key] = match.group(1)

    return result


def ehrpd_set_state(state: str) -> Tuple[bool, str]:
    """Set eHRPD state (e.g., 'active', 'dormant', 'disabled')."""
    inputs = [state]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} ehrpd_set_state",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


# ============================================================================
# 1xRTT/CDMA FUNCTIONS (Batch 5 - Session 7)
# ============================================================================


def rtt_1x_get_ext_timer() -> int:
    """Get 1xRTT extended timer value (seconds)."""
    output, _ = adb_shell(f"{MODEM2_CLI} 1xrtt_get_ext_timer")
    match = re.search(r'timer:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    return int(match.group(1)) if match else 0


def rtt_1x_set_ext_timer(seconds: int) -> Tuple[bool, str]:
    """Set 1xRTT extended timer (0-3600 seconds)."""
    inputs = [str(seconds)]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} 1xrtt_set_ext_timer",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def get_bsr_timers() -> Dict[str, int]:
    """Get BSR (Burst Signaling Rate) timers."""
    output, _ = adb_shell(f"{MODEM2_CLI} get_bsr_timers")

    timers = {}
    patterns = {
        "t1": r't1:\s*\[?(\d+)\]?',
        "t2": r't2:\s*\[?(\d+)\]?',
        "t3": r't3:\s*\[?(\d+)\]?',
        "t4": r't4:\s*\[?(\d+)\]?',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            timers[key] = int(match.group(1))

    return timers


def set_bsr_timers(t1: int, t2: int, t3: int, t4: int) -> Tuple[bool, str]:
    """Set BSR timers (T1, T2, T3, T4 in milliseconds)."""
    inputs = [str(t1), str(t2), str(t3), str(t4)]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} set_bsr_timers",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def get_cai_rev() -> int:
    """Get CAI (Common Air Interface) revision level."""
    output, _ = adb_shell(f"{MODEM2_CLI} get_cai_rev")
    match = re.search(r'revision:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    return int(match.group(1)) if match else 0


def set_cai_rev(revision: int) -> Tuple[bool, str]:
    """Set CAI revision level (0-7, typically 6 for IS-95B)."""
    inputs = [str(revision)]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} set_cai_rev",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def get_ddtm_state() -> Dict[str, Any]:
    """Get DDTM (Data Dedicated Transmission Mode) state."""
    output, _ = adb_shell(f"{MODEM2_CLI} get_ddtm_state")

    result = {"raw": output}

    # Parse DDTM state
    patterns = {
        "enabled": r'enabled:\s*\[?(\d+)\]?',
        "mode": r'mode:\s*\[?(\w+)\]?',
        "so_list": r'so.*list:\s*\[?([0-9,]+)\]?',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            if key == "enabled":
                result[key] = match.group(1) == "1"
            elif key == "so_list":
                result[key] = [int(x) for x in match.group(1).split(',')]
            else:
                result[key] = match.group(1)

    return result


def set_ddtm_state(enabled: bool, mode: str = "auto") -> Tuple[bool, str]:
    """Set DDTM state (enabled/disabled, mode: auto/manual)."""
    inputs = ["1" if enabled else "0", mode]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} set_ddtm_state",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


# ============================================================================
# PROFILE FUNCTIONS (Batch 6 - Session 7)
# ============================================================================


def prof_get_act_tech() -> str:
    """Get active technology profile."""
    output, _ = adb_shell(f"{MODEM2_CLI} prof_get_act_tech")
    match = re.search(r'tech:\s*\[?(\w+)\]?', output, re.IGNORECASE)
    return match.group(1) if match else "unknown"


def prof_set_act_tech(tech: str) -> Tuple[bool, str]:
    """Set active technology profile (e.g., 'LTE', 'CDMA', 'UMTS')."""
    inputs = [tech]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} prof_set_act_tech",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def prof_get_cust_tech() -> Dict[str, Any]:
    """Get custom technology profile settings."""
    output, _ = adb_shell(f"{MODEM2_CLI} prof_get_cust_tech")

    result = {"raw": output}

    patterns = {
        "tech": r'tech:\s*\[?(\w+)\]?',
        "apn": r'apn:\s*\[?([^\]]+)\]?',
        "auth_type": r'auth.*type:\s*\[?(\w+)\]?',
        "username": r'user.*:\s*\[?([^\]]+)\]?',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            result[key] = match.group(1)

    return result


def prof_set_cust_tech(
        tech: str, apn: str, auth: str = "NONE",
        username: str = "", password: str = "") -> Tuple[bool, str]:
    """Set custom technology profile."""
    inputs = [tech, apn, auth, username, password]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} prof_set_cust_tech",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def prof_get_tech() -> str:
    """Get current technology profile."""
    output, _ = adb_shell(f"{MODEM2_CLI} prof_get_tech")
    match = re.search(r'tech:\s*\[?(\w+)\]?', output, re.IGNORECASE)
    return match.group(1) if match else "unknown"


def prof_set_tech(tech: str) -> Tuple[bool, str]:
    """Set technology profile (e.g., 'LTE', '3G', '4G', 'AUTO')."""
    inputs = [tech]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} prof_set_tech",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


# Note: prof_get_pri_tech and prof_set_pri_tech already implemented
# (lines ~800-850 in original file)


# ============================================================================
# CALL CONTROL FUNCTIONS (Batch 6 - Session 7)
# ============================================================================


def start_call(phone_number: str) -> Tuple[bool, str]:
    """Initiate voice call to phone number."""
    inputs = [phone_number]
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} start_call",
        inputs,
        timeout=15
    )
    success = "success" in output.lower() or "call" in output.lower()
    return success, output


def stop_call() -> Tuple[bool, str]:
    """End current voice call."""
    output, _ = adb_shell(f"{MODEM2_CLI} stop_call", timeout=10)
    success = "success" in output.lower() or "ended" in output.lower()
    return success, output


def get_call_status() -> Dict[str, Any]:
    """Get current call status and information."""
    output, _ = adb_shell(f"{MODEM2_CLI} get_call_status")

    result = {"raw": output}

    patterns = {
        "active": r'active:\s*\[?(\d+)\]?',
        "state": r'state:\s*\[?(\w+)\]?',
        "number": r'number:\s*\[?([^\]]+)\]?',
        "duration": r'duration:\s*\[?(\d+)\]?',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            if key == "active":
                result[key] = match.group(1) == "1"
            elif key == "duration":
                result[key] = int(match.group(1))
            else:
                result[key] = match.group(1)

    return result


# ============================================================================
# SMS MANAGEMENT FUNCTIONS (Session 7/8 - NEW)
# ============================================================================

SMS_CLI = "/opt/nvtl/bin/sms_cli"


def sms_send(phone: str, message: str) -> Tuple[bool, str]:
    """Send SMS message."""
    inputs = [phone, message]
    output, _ = adb_shell_interactive(
        f"{SMS_CLI} send",
        inputs,
        timeout=15
    )
    success = "success" in output.lower() or "sent" in output.lower()
    return success, output


def sms_read(msg_id: int) -> Dict[str, Any]:
    """Read SMS message by ID."""
    output, _ = adb_shell(f"{SMS_CLI} read {msg_id}")

    result = {"raw": output, "id": msg_id}

    patterns = {
        "from": r'from:\s*\[?([^\]]+)\]?',
        "date": r'date:\s*\[?([^\]]+)\]?',
        "message": r'message:\s*\[?([^\]]+)\]?',
        "read": r'read:\s*\[?(\d+)\]?',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            if key == "read":
                result[key] = match.group(1) == "1"
            else:
                result[key] = match.group(1)

    return result


def sms_delete(msg_id: int) -> Tuple[bool, str]:
    """Delete SMS message."""
    output, _ = adb_shell(f"{SMS_CLI} delete {msg_id}", timeout=10)
    success = "success" in output.lower() or "deleted" in output.lower()
    return success, output


def sms_get_list() -> List[Dict[str, Any]]:
    """Get list of all SMS messages."""
    output, _ = adb_shell(f"{SMS_CLI} get_list")

    messages = []
    # Parse message list (format: id, from, date, preview)
    for match in re.finditer(
            r'(\d+)\s*\|\s*([^\|]+)\s*\|\s*([^\|]+)\s*\|\s*([^\n]+)',
            output):
        msg_id, from_num, date, preview = match.groups()
        messages.append({
            "id": int(msg_id),
            "from": from_num.strip(),
            "date": date.strip(),
            "preview": preview.strip()
        })

    return messages


def sms_get_unread_count() -> int:
    """Get count of unread messages."""
    output, _ = adb_shell(f"{SMS_CLI} get_unread")
    match = re.search(r'unread:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    return int(match.group(1)) if match else 0


def sms_set_state(enabled: bool) -> Tuple[bool, str]:
    """Enable/disable SMS service."""
    inputs = ["1" if enabled else "0"]
    output, _ = adb_shell_interactive(
        f"{SMS_CLI} set_state",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


# Address Book Functions

def sms_ab_add_entry(name: str, phone: str) -> Tuple[bool, str]:
    """Add address book entry."""
    inputs = [name, phone]
    output, _ = adb_shell_interactive(
        f"{SMS_CLI} ab_add_entry",
        inputs,
        timeout=10
    )
    success = "success" in output.lower() or "added" in output.lower()
    return success, output


def sms_ab_del_entry(entry_id: int) -> Tuple[bool, str]:
    """Delete address book entry."""
    output, _ = adb_shell(f"{SMS_CLI} ab_del_entry {entry_id}", timeout=10)
    success = "success" in output.lower() or "deleted" in output.lower()
    return success, output


def sms_ab_edit_entry(
        entry_id: int, name: str, phone: str) -> Tuple[bool, str]:
    """Edit address book entry."""
    inputs = [str(entry_id), name, phone]
    output, _ = adb_shell_interactive(
        f"{SMS_CLI} ab_edit_entry",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def sms_ab_get_entry(entry_id: int) -> Dict[str, Any]:
    """Get address book entry by ID."""
    output, _ = adb_shell(f"{SMS_CLI} ab_get_entry {entry_id}")

    result = {"raw": output, "id": entry_id}

    patterns = {
        "name": r'name:\s*\[?([^\]]+)\]?',
        "phone": r'phone:\s*\[?([^\]]+)\]?',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            result[key] = match.group(1)

    return result


def sms_ab_get_entry_by_phone(phone: str) -> Dict[str, Any]:
    """Get address book entry by phone number."""
    output, _ = adb_shell(f"{SMS_CLI} ab_get_entry_addr {phone}")

    result = {"raw": output, "phone": phone}

    patterns = {
        "id": r'id:\s*\[?(\d+)\]?',
        "name": r'name:\s*\[?([^\]]+)\]?',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            if key == "id":
                result[key] = int(match.group(1))
            else:
                result[key] = match.group(1)

    return result


def sms_ab_get_entry_by_name(name: str) -> Dict[str, Any]:
    """Get address book entry by name."""
    output, _ = adb_shell(f"{SMS_CLI} ab_get_entry_name {name}")

    result = {"raw": output, "name": name}

    patterns = {
        "id": r'id:\s*\[?(\d+)\]?',
        "phone": r'phone:\s*\[?([^\]]+)\]?',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            if key == "id":
                result[key] = int(match.group(1))
            else:
                result[key] = match.group(1)

    return result


def sms_ab_get_list() -> List[Dict[str, Any]]:
    """Get all address book entries."""
    output, _ = adb_shell(f"{SMS_CLI} ab_get_list")

    entries = []
    # Parse entry list (format: id | name | phone)
    for match in re.finditer(
            r'(\d+)\s*\|\s*([^\|]+)\s*\|\s*([^\n]+)', output):
        entry_id, name, phone = match.groups()
        entries.append({
            "id": int(entry_id),
            "name": name.strip(),
            "phone": phone.strip()
        })

    return entries


# ============================================================================
# GPS MANAGEMENT FUNCTIONS (Session 7/8 - NEW)
# ============================================================================

GPS_CLI = "/opt/nvtl/bin/gps_cli"


def gps_start() -> Tuple[bool, str]:
    """Start GPS acquisition."""
    output, _ = adb_shell(f"{GPS_CLI} gps_start", timeout=10)
    success = "success" in output.lower() or "started" in output.lower()
    return success, output


def gps_stop() -> Tuple[bool, str]:
    """Stop GPS."""
    output, _ = adb_shell(f"{GPS_CLI} gps_stop", timeout=10)
    success = "success" in output.lower() or "stopped" in output.lower()
    return success, output


def gps_get_status() -> Dict[str, Any]:
    """Get GPS status (satellites, SNR, fix quality)."""
    output, _ = adb_shell(f"{GPS_CLI} gps_status")

    result = {"raw": output}

    patterns = {
        "fix": r'fix:\s*\[?(\d+)\]?',
        "satellites": r'satellites:\s*\[?(\d+)\]?',
        "snr": r'snr:\s*\[?([0-9.]+)\]?',
        "latitude": r'lat.*:\s*\[?([0-9.\-]+)\]?',
        "longitude": r'lon.*:\s*\[?([0-9.\-]+)\]?',
        "altitude": r'alt.*:\s*\[?([0-9.\-]+)\]?',
        "accuracy": r'acc.*:\s*\[?([0-9.]+)\]?',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            if key in ["fix", "satellites"]:
                result[key] = int(match.group(1))
            else:
                result[key] = float(match.group(1))

    return result


def gps_get_last_fix() -> Dict[str, Any]:
    """Get last GPS fix data."""
    output, _ = adb_shell(f"{GPS_CLI} get_last_fix")

    result = {"raw": output}

    patterns = {
        "timestamp": r'time.*:\s*\[?([^\]]+)\]?',
        "latitude": r'lat.*:\s*\[?([0-9.\-]+)\]?',
        "longitude": r'lon.*:\s*\[?([0-9.\-]+)\]?',
        "altitude": r'alt.*:\s*\[?([0-9.\-]+)\]?',
        "accuracy": r'acc.*:\s*\[?([0-9.]+)\]?',
        "speed": r'speed:\s*\[?([0-9.]+)\]?',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            if key == "timestamp":
                result[key] = match.group(1)
            else:
                result[key] = float(match.group(1))

    return result


def gps_set_agps_mode(mode: str) -> Tuple[bool, str]:
    """Set A-GPS mode (MS-Based, MS-Assisted, Standalone)."""
    inputs = [mode]
    output, _ = adb_shell_interactive(
        f"{GPS_CLI} agps_mode_set",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def gps_force_xtra() -> Tuple[bool, str]:
    """Force download of XTRA satellite data."""
    output, _ = adb_shell(f"{GPS_CLI} force_xtra", timeout=30)
    success = "success" in output.lower() or "download" in output.lower()
    return success, output


def gps_get_mode() -> str:
    """Get current GPS mode."""
    output, _ = adb_shell(f"{GPS_CLI} get_mode")
    match = re.search(r'mode:\s*\[?(\w+)\]?', output, re.IGNORECASE)
    return match.group(1) if match else "unknown"


def gps_get_active() -> bool:
    """Check if GPS is active."""
    output, _ = adb_shell(f"{GPS_CLI} get_active")
    match = re.search(r'active:\s*\[?(\d+)\]?', output, re.IGNORECASE)
    return match.group(1) == "1" if match else False


def gps_set_active(enabled: bool) -> Tuple[bool, str]:
    """Set GPS active state."""
    inputs = ["1" if enabled else "0"]
    output, _ = adb_shell_interactive(
        f"{GPS_CLI} set_active",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def gps_enable_powersave(enabled: bool) -> Tuple[bool, str]:
    """Enable/disable GPS power saving mode."""
    inputs = ["1" if enabled else "0"]
    output, _ = adb_shell_interactive(
        f"{GPS_CLI} enable_powersave_mode",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def gps_get_nmea_tcp() -> Dict[str, Any]:
    """Get NMEA TCP streaming configuration."""
    output, _ = adb_shell(f"{GPS_CLI} get_nmea_tcp")

    result = {"raw": output}

    patterns = {
        "enabled": r'enabled:\s*\[?(\d+)\]?',
        "host": r'host:\s*\[?([^\]]+)\]?',
        "port": r'port:\s*\[?(\d+)\]?',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            if key == "enabled":
                result[key] = match.group(1) == "1"
            elif key == "port":
                result[key] = int(match.group(1))
            else:
                result[key] = match.group(1)

    return result


def gps_set_nmea_tcp(
        host: str, port: int, enabled: bool = True) -> Tuple[bool, str]:
    """Set NMEA TCP streaming (for real-time location apps)."""
    inputs = ["1" if enabled else "0", host, str(port)]
    output, _ = adb_shell_interactive(
        f"{GPS_CLI} set_nmea_tcp",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def gps_get_privacy() -> Dict[str, Any]:
    """Get location privacy settings."""
    output, _ = adb_shell(f"{GPS_CLI} get_privacy")

    result = {"raw": output}

    patterns = {
        "enabled": r'enabled:\s*\[?(\d+)\]?',
        "mode": r'mode:\s*\[?(\w+)\]?',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            if key == "enabled":
                result[key] = match.group(1) == "1"
            else:
                result[key] = match.group(1)

    return result


def gps_set_privacy(enabled: bool, mode: str = "user") -> Tuple[bool, str]:
    """Set location privacy (enabled, mode: user/network)."""
    inputs = ["1" if enabled else "0", mode]
    output, _ = adb_shell_interactive(
        f"{GPS_CLI} set_privacy",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


def gps_update_wan_connection(connected: bool) -> Tuple[bool, str]:
    """Update WAN connection status for A-GPS."""
    inputs = ["1" if connected else "0"]
    output, _ = adb_shell_interactive(
        f"{GPS_CLI} update_wan_connection",
        inputs,
        timeout=10
    )
    success = "success" in output.lower()
    return success, output


# ============================================================================
# MOBILE IP / DATA FUNCTIONS (NEWLY DISCOVERED)
# ============================================================================


def mip_get_profile() -> Dict[str, Any]:
    """Get Mobile IP profile"""
    output, _ = adb_shell(f"{MODEM2_CLI} mip_get_profile")
    profile = {}

    for match in re.finditer(r'(\w+):\[([^\]]+)\]', output):
        key, val = match.groups()
        profile[key] = val

    return profile


def mip_get_settings() -> Dict[str, Any]:
    """Get Mobile IP settings"""
    output, _ = adb_shell(f"{MODEM2_CLI} mip_get_settings")
    settings = {}

    for match in re.finditer(r'(\w+):\[([^\]]+)\]', output):
        key, val = match.groups()
        settings[key] = val

    return settings


def pdn_get_ext_params() -> Dict[str, Any]:
    """Get PDN (Packet Data Network) extended parameters"""
    output, _ = adb_shell(f"{MODEM2_CLI} pdn_get_ext_params")
    params = {}

    for match in re.finditer(r'(\w+):\[([^\]]+)\]', output):
        key, val = match.groups()
        params[key] = val

    return params


def network_attach() -> Tuple[bool, str]:
    """Force network attach (LTE registration)"""
    output, _ = adb_shell(f"{MODEM2_CLI} network_attach", timeout=30)
    success = "success" in output.lower() or "attached" in output.lower()
    return success, output

# ============================================================================
# FACTORY / PROVISIONING FUNCTIONS (NEWLY DISCOVERED - USE WITH CAUTION)
# ============================================================================


def factory_reset_device() -> Tuple[bool, str]:
    """
    Factory reset device - DESTRUCTIVE!
    Requires user confirmation.
    """
    print("WARNING: This will erase all data!")
    confirm = input("Type 'FACTORY_RESET' to confirm: ")
    if confirm != "FACTORY_RESET":
        return False, "Factory reset cancelled"

    output, _ = adb_shell(f"{MODEM2_CLI} factory_reset", timeout=60)
    success = "success" in output.lower()
    return success, output


def mdn_min_set(mdn: str, min1: str, min2: str) -> Tuple[bool, str]:
    """
    Set MDN/MIN for CDMA provisioning - REQUIRES SPC!
    WARNING: Incorrect values may deactivate device.
    """
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} mdn_min_set",
        [mdn, min1, min2],
        timeout=20
    )
    success = "success" in output.lower()
    return success, output


def get_carrier_unlock_status() -> Tuple[bool, Dict[str, Any]]:
    """
    Get carrier unlock status
    Returns state, carrier_block, verify_retries, unblock_retries

    State: 0=unlocked, 1=locked
    Carrier block: 0=not blocked, 1=blocked
    Verify retries: Remaining NCK attempts
    Unblock retries: Remaining unblock attempts
    """
    output, _ = adb_shell(f"{MODEM2_CLI} get_carrier_unlock", timeout=10)

    # Parse output like:
    # State:[0] Carrier block:[0] Verify retries:[0] Unblock retries:[0]
    import re
    state_match = re.search(r'State:\[(\d+)\]', output)
    block_match = re.search(r'Carrier block:\[(\d+)\]', output)
    verify_match = re.search(r'Verify retries:\[(\d+)\]', output)
    unblock_match = re.search(r'Unblock retries:\[(\d+)\]', output)

    status = {
        'state': int(state_match.group(1)) if state_match else None,
        'carrier_block': int(block_match.group(1)) if block_match else None,
        'verify_retries': int(verify_match.group(1)) if verify_match else None,
        'unblock_retries': (
            int(unblock_match.group(1)) if unblock_match else None
        ),
        'unlocked': state_match and int(state_match.group(1)) == 0,
        'raw': output
    }

    success = state_match is not None
    return success, status


def unlock_carrier_lock(nck_code: str) -> Tuple[bool, str]:
    """
    Unlock carrier lock with NCK (Network Control Key)
    WARNING: Wrong code may permanently lock device!

    This function submits an NCK code directly to modem2_cli.
    For Sierra Wireless algorithm-based unlock, use unlock_carrier_sierra().

    ⚠️ CRITICAL WARNINGS:
    - Check unlock status first with get_carrier_unlock_status()
    - Verify retry counter is not 0 (device will be permanently locked!)
    - Wrong NCK code decrements retry counter
    - After 0 retries, device is PERMANENTLY LOCKED
    - Always backup device state before attempting unlock

    Args:
        nck_code: Network Control Key (typically 8-16 hex digits)

    Returns:
        (success, output)
    """
    print("⚠️  WARNING: Attempting carrier unlock!")
    print("⚠️  Wrong NCK code may permanently lock device!")

    # Check retry counter first
    status_ok, status = get_carrier_unlock_status()
    if status_ok and status.get('verify_retries') == 0:
        return (
            False,
            "ERROR: No unlock attempts remaining! "
            "Device will be permanently locked!"
        )

    if status_ok:
        print(
            f"ℹ️  Remaining attempts: "
            f"{status.get('verify_retries', 'unknown')}")

    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} unlock_carrier_lock",
        [nck_code],
        timeout=20
    )
    success = "success" in output.lower() or "unlocked" in output.lower()
    return success, output


def unlock_carrier_sierra(challenge: Optional[str] = None,
                          devicegeneration: str = "SDX20") -> Tuple[bool, str]:
    """
    Unlock carrier using Sierra Wireless algorithm (EXPERIMENTAL!)

    This function uses B.Kerler's Sierra Wireless unlock algorithms adapted
    for Inseego MiFi devices. Algorithm compatibility with Qualcomm SDX20 is
    UNCERTAIN - Sierra algorithms are designed for Sierra Wireless chipsets
    (MDM8200/9200/9x15/9x30/9x40/9x50/SDX55/65/75), not Qualcomm SDX20.

    ⚠️ EXTREME RISK WARNINGS:
    - Algorithm may NOT work on Qualcomm SDX20 (MiFi 8800L chipset)
    - Wrong response will decrement unlock retry counter
    - After 0 retries, device is PERMANENTLY LOCKED
    - Test on non-critical device first!
    - Always backup device state before attempting
    - Get unlock status first to verify retry counter > 0

    Process:
    1. Query modem for unlock challenge
    2. Calculate response using Sierra algorithm
    3. Submit response to modem
    4. If correct, device unlocks; if wrong, retry counter decrements

    Args:
        challenge: Optional pre-obtained challenge (hex string)
                   If None, will query modem for challenge
        devicegeneration: Device generation for algorithm selection
                          Default: "SDX20" (MiFi 8800L)
                          Options: MDM8200, MDM9200, MDM9x15, MDM9x30,
                                   MDM9x40, MDM9x50, SDX55, SDX65, SDX20

    Returns:
        (success, output)

    Example:
        >>> # Check unlock status first
        >>> ok, status = get_carrier_unlock_status()
        >>> if status['verify_retries'] > 0:
        ...     success, output = unlock_carrier_sierra()
        ... else:
        ...     print("No unlock attempts remaining!")
    """
    try:
        # Import Sierra adapter
        from sierra_adapter import (
            calculate_unlock_response,
            get_algorithm_info
        )
    except ImportError:
        return (
            False,
            "ERROR: sierra_adapter.py not found! "
            "Run from tools/ directory."
        )

    print("=" * 70)
    print("⚠️  SIERRA WIRELESS ALGORITHM UNLOCK (EXPERIMENTAL)")
    print("=" * 70)
    print()
    print("CRITICAL WARNINGS:")
    print("  - Algorithm compatibility with SDX20 (MiFi 8800L) is UNCERTAIN")
    print(
        "  - Sierra algorithms designed for Sierra chipsets, "
        "not Qualcomm SDX20"
    )
    print("  - Wrong response will PERMANENTLY reduce unlock attempts")
    print("  - Device may be PERMANENTLY LOCKED after failed attempts")
    print("  - This is EXPERIMENTAL and may brick your device!")
    print()

    # Check unlock status
    status_ok, status = get_carrier_unlock_status()
    if not status_ok:
        return False, "ERROR: Could not get unlock status from modem"

    if status.get('unlocked'):
        return True, "Device is already unlocked (state=0)"

    verify_retries = status.get('verify_retries', 0)
    if verify_retries == 0:
        return (
            False,
            "ERROR: No unlock attempts remaining! "
            "Device permanently locked!"
        )

    print("ℹ️  Device unlock status:")
    print(f"   State: {'Locked' if status.get('state') == 1 else 'Unlocked'}")
    print(f"   Remaining attempts: {verify_retries}")
    print()

    # Show algorithm info
    algo_info = get_algorithm_info(devicegeneration)
    if algo_info:
        print(f"ℹ️  Algorithm parameters for {devicegeneration}:")
        print(f"   Key index: {algo_info.get('openlock')}")
        print(f"   Challenge length: {algo_info.get('clen')} bytes")
        print()

    # Get challenge if not provided
    if challenge is None:
        print("📡 Querying modem for unlock challenge...")
        # Try to get challenge from modem2_cli
        # NOTE: This may not work - modem2_cli may not return
        # challenge in parseable format
        output, _ = adb_shell(f"{MODEM2_CLI} unlock_carrier_lock", timeout=10)

        # Try to parse challenge from output
        import re
        challenge_match = re.search(
            r'challenge[:\s]+([0-9A-Fa-f]{8,16})', output, re.IGNORECASE)
        if not challenge_match:
            # Try alternate format
            challenge_match = re.search(r'([0-9A-Fa-f]{16})', output)

        if challenge_match:
            challenge = challenge_match.group(1)
            print(f"   Challenge: {challenge}")
        else:
            print("   Could not parse challenge from modem output:")
            print(f"   {output}")
            print()
            challenge = input(
                "   Enter challenge manually (16 hex digits): ").strip()
            if not challenge:
                return False, "ERROR: No challenge provided"
    else:
        print(f"📡 Using provided challenge: {challenge}")

    # Validate challenge
    if not challenge:
        return False, "ERROR: No challenge available"

    if len(challenge) < 8 or len(challenge) > 16:
        return (
            False,
            f"ERROR: Invalid challenge length: {len(challenge)} "
            f"(expected 8-16 hex digits)"
        )

    try:
        int(challenge, 16)
    except ValueError:
        return False, f"ERROR: Invalid hex challenge: {challenge}"

    print()
    print("🔐 Calculating unlock response...")

    # Calculate response
    try:
        response = calculate_unlock_response(
            challenge, devicegeneration, unlock_type=0)
        print(f"   Response: {response}")
    except Exception as e:
        return False, f"ERROR: Algorithm failed: {e}"

    print()
    print("⚠️  FINAL WARNING:")
    print(
        f"   About to submit response to modem "
        f"(attempts left: {verify_retries})")
    print(f"   Wrong response will reduce attempts to {verify_retries - 1}")
    print(f"   Device generation: {devicegeneration}")
    print()

    confirm = input("Type 'UNLOCK' to confirm (anything else to cancel): ")
    if confirm != "UNLOCK":
        return False, "Unlock cancelled by user"

    print()
    print("📤 Submitting unlock response to modem...")

    # Submit response to modem
    output, _ = adb_shell_interactive(
        f"{MODEM2_CLI} unlock_carrier_lock",
        [response],
        timeout=20
    )

    success = "success" in output.lower() or "unlocked" in output.lower()

    if success:
        print()
        print("✓ SUCCESS: Device unlocked!")
        print()
    else:
        print()
        print("✗ FAILED: Unlock unsuccessful")
        print(f"   Output: {output}")
        print()

        # Check remaining attempts
        status_ok, new_status = get_carrier_unlock_status()
        if status_ok:
            new_retries = new_status.get('verify_retries', 0)
            print(f"   Remaining attempts: {new_retries}")
            if new_retries == 0:
                print(
                    "   ⚠️  DEVICE PERMANENTLY LOCKED! "
                    "No attempts remaining!"
                )

    return success, output

# ============================================================================
# STATUS FUNCTIONS
# ============================================================================


def get_full_status() -> Dict[str, Any]:
    """Get comprehensive device status"""
    status: Dict[str, Any] = {
        "device_info": {},
        "connection": {},
        "signal": {},
        "carrier_unlock": {},
        "roaming": {},
        "technologies": {},
        "apn": {},
        "sim": {}
    }

    # Device info
    output, _ = adb_shell(f"{MODEM2_CLI} get_info")
    for key in ["imei", "imsi", "iccid", "mdn", "Model", "FW Version"]:
        match = re.search(rf'{key.lower()}:\[([^\]]*)\]', output.lower())
        if match:
            status["device_info"][key] = match.group(1)

    # Connection state
    status["connection"] = get_connection_state()

    # Signal
    status["signal"] = get_tx_power()

    # Carrier unlock
    output, _ = adb_shell(f"{MODEM2_CLI} get_carrier_unlock")
    match = re.search(r'State:\[(\d+)\]', output)
    if match:
        status["carrier_unlock"]["state"] = int(match.group(1))
        status["carrier_unlock"]["unlocked"] = match.group(1) == "0"

    # Roaming
    status["roaming"] = get_roaming_status()

    # Technologies
    status["technologies"] = get_enabled_tech()

    # APN
    status["apn"] = get_apn_profile()

    # SIM
    output, _ = adb_shell(f"{MODEM2_CLI} sim_get_status")
    status["sim"]["raw"] = output

    # Certified carrier
    status["certified_carrier"] = get_certified_carrier()

    return status

# ============================================================================
# CLI INTERFACE
# ============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="MiFi 8800L Comprehensive Controller",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s status                    # Show full device status
  %(prog)s imei                      # Show current IMEI
  %(prog)s imei-set 352099001761481  # Change IMEI
  %(prog)s carrier AUTO              # Set carrier mode to AUTO
  %(prog)s bands all                 # Enable all LTE bands
  %(prog)s roaming on                # Enable roaming
  %(prog)s roaming intl on           # Enable international roaming
  %(prog)s tech GSM,UMTS,LTE         # Set enabled technologies
  %(prog)s apn broadband             # Set APN
  %(prog)s apn-carrier att           # Set AT&T APN profile
  %(prog)s power max                 # Maximum power mode
  %(prog)s network scan              # Scan for networks
  %(prog)s network select 310410     # Select network by MCCMNC
  %(prog)s sms +15551234567 "Hello"  # Send SMS
  %(prog)s at "AT+CSQ"               # Send AT command
"""
    )

    subparsers = parser.add_subparsers(
        dest="command", help="Command to execute")

    # Status
    subparsers.add_parser("status", help="Show full device status")

    # IMEI
    subparsers.add_parser("imei", help="Show current IMEI")
    imei_set = subparsers.add_parser("imei-set", help="Change IMEI")
    imei_set.add_argument(
        "new_imei", help="New 15-digit IMEI (or 14 + auto check digit)")

    # Carrier
    carrier = subparsers.add_parser("carrier", help="Set CertifiedCarrier")
    carrier.add_argument(
        "mode",
        choices=[
            "AUTO",
            "GSM",
            "Verizon",
            "Sprint",
            "AT&T",
            "Bell",
            "Telus",
        ],
    )

    # Bands
    bands = subparsers.add_parser("bands", help="LTE band control")
    bands.add_argument("action", choices=["all", "get", "set"])
    bands.add_argument("--band", type=int, help="Band number for set")
    bands.add_argument("--enable", type=int,
                       choices=[0, 1], help="Enable (1) or disable (0)")

    # Roaming
    roaming = subparsers.add_parser("roaming", help="Roaming control")
    roaming.add_argument("action", choices=["on", "off", "intl", "status"])
    roaming.add_argument("intl_action", nargs="?", choices=["on", "off"])

    # Technology
    tech = subparsers.add_parser("tech", help="Set enabled technologies")
    tech.add_argument("modes", help="Comma-separated: GSM,UMTS,CDMA,EVDO,LTE")

    # APN
    apn = subparsers.add_parser("apn", help="Set APN")
    apn.add_argument("name", help="APN name")

    apn_carrier = subparsers.add_parser(
        "apn-carrier", help="Set carrier APN profile")
    apn_carrier.add_argument("carrier", choices=list(CARRIER_APNS.keys()))

    # Power
    power = subparsers.add_parser("power", help="Power mode control")
    power.add_argument("mode", choices=["max", "save"])

    # Network
    network = subparsers.add_parser("network", help="Network control")
    network.add_argument("action", choices=["scan", "select", "status"])
    network.add_argument("mccmnc", nargs="?", help="MCCMNC for select")

    connect = subparsers.add_parser(
        "connect", help="Max power + bands + APN + optional network select"
    )
    connect.add_argument(
        "--carrier", default="att", choices=list(CARRIER_APNS.keys())
    )
    connect.add_argument("--mccmnc", help="Optional MCCMNC for manual select")
    connect.add_argument(
        "--no-intl",
        action="store_true",
        help="Skip enabling international roaming",
    )

    # SMS
    sms = subparsers.add_parser("sms", help="Send SMS")
    sms.add_argument("phone", help="Phone number")
    sms.add_argument("message", help="Message text")

    # AT command
    at = subparsers.add_parser("at", help="Send AT command")
    at.add_argument("command", help="AT command")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Execute command
    if args.command == "status":
        status = get_full_status()
        print(json.dumps(status, indent=2, default=str))

    elif args.command == "imei":
        imei = get_current_imei()
        print(f"Current IMEI: {imei}")

    elif args.command == "imei-set":
        success, msg = set_imei(args.new_imei)
        print(f"{'SUCCESS' if success else 'FAILED'}: {msg}")

    elif args.command == "carrier":
        success, msg = set_certified_carrier(args.mode)
        print(f"{'SUCCESS' if success else 'FAILED'}: {msg}")

    elif args.command == "bands":
        if args.action == "all":
            success, msg = enable_all_lte_bands()
            print(f"{'SUCCESS' if success else 'FAILED'}: {msg}")
        elif args.action == "get":
            bands = get_enabled_lte_bands()
            print(json.dumps(bands, indent=2))
        elif args.action == "set":
            if args.band is None or args.enable is None:
                print("ERROR: --band and --enable required for set")
            else:
                success, msg = set_lte_band(args.band, args.enable == 1)
                print(f"{'SUCCESS' if success else 'FAILED'}: {msg}")

    elif args.command == "roaming":
        if args.action == "status":
            status = get_roaming_status()
            print(json.dumps(status, indent=2))
        elif args.action == "on":
            success, msg = set_roaming(True)
            print(f"{'SUCCESS' if success else 'FAILED'}: {msg}")
        elif args.action == "off":
            success, msg = set_roaming(False)
            print(f"{'SUCCESS' if success else 'FAILED'}: {msg}")
        elif args.action == "intl":
            if args.intl_action:
                success, msg = set_roaming(
                    args.intl_action == "on", international=True)
                print(f"{'SUCCESS' if success else 'FAILED'}: {msg}")
            else:
                print("ERROR: Specify 'on' or 'off' for international roaming")

    elif args.command == "tech":
        techs = [t.strip() for t in args.modes.split(",")]
        success, msg = set_enabled_tech(techs)
        print(f"{'SUCCESS' if success else 'FAILED'}: {msg}")

    elif args.command == "apn":
        profile = APNProfile(0, args.name, 0, 3)  # LTE, no auth, IPv4v6
        success, msg = set_apn_profile(profile)
        print(f"{'SUCCESS' if success else 'FAILED'}: {msg}")

    elif args.command == "apn-carrier":
        success, msg = set_carrier_apn(args.carrier)
        print(f"{'SUCCESS' if success else 'FAILED'}: {msg}")

    elif args.command == "power":
        success, msg = set_power_mode(args.mode)
        print(f"{'SUCCESS' if success else 'FAILED'}: {msg}")

    elif args.command == "network":
        if args.action == "scan":
            networks = scan_networks()
            print(json.dumps(networks, indent=2))
        elif args.action == "select":
            if not args.mccmnc:
                print("ERROR: MCCMNC required for select")
            else:
                success, msg = select_network(args.mccmnc)
                print(f"{'SUCCESS' if success else 'FAILED'}: {msg}")
        elif args.action == "status":
            state = get_connection_state()
            print(json.dumps(state, indent=2))

    elif args.command == "connect":
        success, msg = connect_to_network(
            args.carrier,
            args.mccmnc,
            international_roam=not args.no_intl,
        )
        print(f"{'SUCCESS' if success else 'FAILED'}: {msg}")

    elif args.command == "sms":
        success, msg = send_sms(args.phone, args.message)
        print(f"{'SUCCESS' if success else 'FAILED'}: {msg}")

    elif args.command == "at":
        output, success = send_at_command(args.command)
        print(f"{'SUCCESS' if success else 'FAILED'}:\n{output}")


if __name__ == "__main__":
    main()
