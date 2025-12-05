#!/usr/bin/env python3
"""
MiFi 8800L SPC Calculator and Carrier Unlock Utility
=====================================================

Phase 6A: SPC Algorithm Reversal - Code Artifact

Based on reverse engineering analysis of:
- libmal_qct.so (QMI modem abstraction layer)
- libmodem2_api.so (Modem2 API library)

FINDINGS:
---------
The MiFi 8800L uses a STATIC DEFAULT SPC (000000), not an
IMEI-derived algorithm. The SPC is validated at the Qualcomm baseband
processor level via QMI DMS protocol.

USAGE:
------
    python spc_calculator.py --test          # Validate default SPC on device
    python spc_calculator.py --unlock        # Attempt carrier unlock
    python spc_calculator.py --status        # Check unlock status
    python spc_calculator.py --info          # Get device info
"""

import subprocess
import argparse
import re
import sys
from typing import Dict, Tuple
from dataclasses import dataclass


# ==============================================================================
# SPC CONSTANTS (from reverse engineering)
# ==============================================================================

# Default SPC for Qualcomm devices (validated via XDA research +
# device testing)
DEFAULT_SPC = "000000"

# Unlock password (12 hex F's) - used with some unlock tools
UNLOCK_PASSWORD = "FFFFFFFFFFFF"

# Known SPC codes for various carriers/devices
KNOWN_SPC_CODES: Dict[str, str] = {
    'default': '000000',
    'qualcomm_test': '000000',
    'verizon_mifi': '000000',
    'sprint': '000000',
    'att': '000000',
    'tmobile': '000000',
}

# NV Items related to SPC/unlock (from Qualcomm documentation)
NV_ITEMS = {
    550: "UE_IMEI",              # Device IMEI (BCD encoded)
    3461: "SIM_LOCK_STATUS",     # SIM lock state
    4398: "SUBSIDY_LOCK",        # Primary carrier lock (PROTECTED)
    4399: "SUBSIDY_LOCK_2",      # Secondary lock indicator
    6828: "PERSO_STATUS",        # Personalization status
    6830: "CARRIER_INFO",        # Carrier ID (10 = Verizon)
    34821: "MAX_SPC_ATTEMPTS",   # Maximum SPC validation attempts
    60044: "PRI_VERSION",        # Carrier PRI version string
}


# ==============================================================================
# DATA CLASSES
# ==============================================================================

@dataclass
class DeviceInfo:
    """Device information structure"""
    imei: str = ""
    imsi: str = ""
    iccid: str = ""
    firmware: str = ""
    pri_version: str = ""
    carrier_id: int = 0
    
    
@dataclass
class UnlockStatus:
    """Carrier unlock status structure"""
    state: int = -1
    carrier_block: int = -1
    verify_retries: int = 0
    unblock_retries: int = 0
    is_unlocked: bool = False


# ==============================================================================
# SPC FUNCTIONS
# ==============================================================================

def get_default_spc() -> str:
    """
    Returns the default SPC for MiFi 8800L devices.
    
    The SPC validation mechanism sends the provided code to the
    Qualcomm baseband via QMI DMS protocol. The baseband compares
    against a stored value in secure NV storage.
    
    For MiFi 8800L with Verizon PRI:
    - Default SPC: 000000
    - Unlock password: FFFFFFFFFFFF (12 hex F's)
    
    Returns:
        str: The default SPC code (000000)
    """
    return DEFAULT_SPC


def get_unlock_password() -> str:
    """
    Returns the unlock password for carrier unlock operations.
    
    Returns:
        str: 12-character hex password (FFFFFFFFFFFF)
    """
    return UNLOCK_PASSWORD


def validate_spc_format(spc: str) -> bool:
    """
    Validate SPC format (6 numeric digits).
    
    Args:
        spc: SPC code to validate
        
    Returns:
        bool: True if valid format, False otherwise
    """
    return len(spc) == 6 and spc.isdigit()


def calculate_luhn_checksum(imei_without_check: str) -> int:
    """
    Calculate Luhn checksum for IMEI validation.
    
    Note: This is NOT used for SPC calculation on MiFi 8800L,
    but included for reference as some devices derive SPC from IMEI.
    
    Args:
        imei_without_check: 14-digit IMEI without check digit
        
    Returns:
        int: Check digit (0-9)
    """
    digits = [int(d) for d in imei_without_check]
    
    # Double every second digit from right
    for i in range(len(digits) - 2, -1, -2):
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9
    
    total = sum(digits)
    return (10 - (total % 10)) % 10


# ==============================================================================
# DEVICE COMMUNICATION (via ADB)
# ==============================================================================

def run_adb_command(cmd: str, timeout: int = 30) -> Tuple[bool, str]:
    """
    Execute ADB shell command on device.
    
    Args:
        cmd: Command to execute
        timeout: Timeout in seconds
        
    Returns:
        Tuple of (success, output)
    """
    try:
        result = subprocess.run(
            ['adb', 'shell', cmd],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = result.stdout + result.stderr
        success = result.returncode == 0 or 'success' in output.lower()
        return success, output.strip()
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except FileNotFoundError:
        return False, "ADB not found in PATH"
    except Exception as e:
        return False, str(e)


def validate_spc_on_device(spc: str = DEFAULT_SPC) -> Tuple[bool, str]:
    """
    Validate SPC code on connected MiFi device.
    
    Args:
        spc: SPC code to validate (default: 000000)
        
    Returns:
        Tuple of (success, message)
    """
    if not validate_spc_format(spc):
        return False, f"Invalid SPC format: {spc}"
    
    # Use echo to provide input to validate_spc command
    cmd = f'echo "{spc}" | /opt/nvtl/bin/modem2_cli validate_spc'
    success, output = run_adb_command(cmd)
    
    if 'success' in output.lower():
        return True, f"SPC {spc} validated successfully"
    else:
        return False, f"SPC validation failed: {output}"


def get_carrier_unlock_status() -> UnlockStatus:
    """
    Get carrier unlock status from device.
    
    Returns:
        UnlockStatus: Current unlock status
    """
    status = UnlockStatus()
    
    success, output = run_adb_command('/opt/nvtl/bin/modem2_cli get_carrier_unlock')
    
    if not success and 'State' not in output:
        return status
    
    # Parse output
    state_match = re.search(r'State:\[(\d+)\]', output)
    block_match = re.search(r'Carrier block:\[(\d+)\]', output)
    verify_match = re.search(r'Verify retries:\[(\d+)\]', output)
    unblock_match = re.search(r'Unblock retries:\[(\d+)\]', output)
    
    if state_match:
        status.state = int(state_match.group(1))
    if block_match:
        status.carrier_block = int(block_match.group(1))
    if verify_match:
        status.verify_retries = int(verify_match.group(1))
    if unblock_match:
        status.unblock_retries = int(unblock_match.group(1))
    
    # State 0 = Unlocked at modem level
    status.is_unlocked = (status.state == 0 and status.carrier_block == 0)
    
    return status


def get_device_info() -> DeviceInfo:
    """
    Get device information from MiFi.
    
    Returns:
        DeviceInfo: Device information structure
    """
    info = DeviceInfo()
    
    success, output = run_adb_command('/opt/nvtl/bin/modem2_cli get_info')
    
    if not success:
        return info
    
    # Parse output (format varies by firmware)
    for line in output.split('\n'):
        line = line.strip()
        if 'IMEI' in line.upper():
            match = re.search(r'(\d{15})', line)
            if match:
                info.imei = match.group(1)
        elif 'IMSI' in line.upper():
            match = re.search(r'(\d{15})', line)
            if match:
                info.imsi = match.group(1)
        elif 'firmware' in line.lower() or 'version' in line.lower():
            info.firmware = line.split(':')[-1].strip() if ':' in line else line
    
    return info


def attempt_carrier_unlock(spc: str = DEFAULT_SPC) -> Tuple[bool, str]:
    """
    Attempt carrier unlock operation.
    
    WARNING: This operation may have permanent effects.
    
    Args:
        spc: SPC code (must be validated first)
        
    Returns:
        Tuple of (success, message)
    """
    # First validate SPC
    valid, msg = validate_spc_on_device(spc)
    if not valid:
        return False, f"SPC validation required first: {msg}"
    
    # Attempt unlock
    cmd = '/opt/nvtl/bin/modem2_cli unlock_carrier'
    success, output = run_adb_command(cmd, timeout=60)
    
    return success, output


# ==============================================================================
# MAIN CLI
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='MiFi 8800L SPC Calculator and Unlock Utility',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python spc_calculator.py --test           # Test default SPC (000000)
  python spc_calculator.py --status         # Check unlock status
  python spc_calculator.py --info           # Get device information
  python spc_calculator.py --validate 123456  # Test custom SPC
        """
    )
    
    parser.add_argument('--test', action='store_true',
                        help='Test default SPC (000000) on device')
    parser.add_argument('--validate', metavar='SPC',
                        help='Validate specific SPC code')
    parser.add_argument('--status', action='store_true',
                        help='Get carrier unlock status')
    parser.add_argument('--info', action='store_true',
                        help='Get device information')
    parser.add_argument('--unlock', action='store_true',
                        help='Attempt carrier unlock (requires SPC)')
    parser.add_argument('--show-default', action='store_true',
                        help='Show default SPC code')
    
    args = parser.parse_args()
    
    if args.show_default:
        print(f"Default SPC: {get_default_spc()}")
        print(f"Unlock Password: {get_unlock_password()}")
        return 0
    
    if args.test:
        print(f"Testing default SPC ({DEFAULT_SPC})...")
        success, msg = validate_spc_on_device()
        print(f"Result: {'✓ SUCCESS' if success else '✗ FAILED'}")
        print(f"Message: {msg}")
        return 0 if success else 1
    
    if args.validate:
        spc = args.validate
        print(f"Validating SPC: {spc}")
        if not validate_spc_format(spc):
            print("ERROR: Invalid SPC format (must be 6 digits)")
            return 1
        success, msg = validate_spc_on_device(spc)
        print(f"Result: {'✓ SUCCESS' if success else '✗ FAILED'}")
        print(f"Message: {msg}")
        return 0 if success else 1
    
    if args.status:
        print("Getting carrier unlock status...")
        status = get_carrier_unlock_status()
        print(f"State: {status.state}")
        print(f"Carrier Block: {status.carrier_block}")
        print(f"Verify Retries: {status.verify_retries}")
        print(f"Unblock Retries: {status.unblock_retries}")
        print(f"Is Unlocked: {'✓ YES' if status.is_unlocked else '✗ NO'}")
        return 0
    
    if args.info:
        print("Getting device information...")
        info = get_device_info()
        print(f"IMEI: {info.imei or 'N/A'}")
        print(f"IMSI: {info.imsi or 'N/A'}")
        print(f"Firmware: {info.firmware or 'N/A'}")
        return 0
    
    if args.unlock:
        print("WARNING: Carrier unlock operation")
        print("This may have permanent effects on the device.")
        confirm = input("Type 'YES' to proceed: ")
        if confirm != 'YES':
            print("Aborted.")
            return 1
        success, msg = attempt_carrier_unlock()
        print(f"Result: {'✓ SUCCESS' if success else '✗ FAILED'}")
        print(f"Message: {msg}")
        return 0 if success else 1
    
    # Default: show help
    parser.print_help()
    return 0


if __name__ == '__main__':
    sys.exit(main())
