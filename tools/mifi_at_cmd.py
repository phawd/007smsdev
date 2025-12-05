#!/usr/bin/env python3
"""
MiFi AT Command Interface
=========================

Direct AT command interface for MiFi 8800L using /dev/at_mdm0 device.
Bypasses modem2_cli interactive mode limitations.

Usage:
    python mifi_at_cmd.py "AT"              # Basic AT test
    python mifi_at_cmd.py "AT+CGSN"         # Get IMEI
    python mifi_at_cmd.py "AT+EGMR?"        # Check EGMR support
    python mifi_at_cmd.py "AT+EGMR=1,7,\"352099001761481\""  # Change IMEI
"""

import subprocess
import sys
import re

AT_DEVICE = "/dev/at_mdm0"
TIMEOUT = 5


def send_at_command(command: str, timeout: int = TIMEOUT) -> tuple[str, bool]:
    """
    Send AT command to modem via ADB.
    
    Args:
        command: AT command string (without trailing CR)
        timeout: Response timeout in seconds
        
    Returns:
        (response_text, success)
    """
    # Simple direct approach - echo and read
    direct_cmd = (
        f'echo -e "{command}\\r" > {AT_DEVICE}; '
        f'sleep 1; '
        f'dd if={AT_DEVICE} bs=256 count=1 2>/dev/null || true'
    )

    try:
        result = subprocess.run(
            ['adb', 'shell', direct_cmd],
            capture_output=True,
            text=True,
            timeout=timeout + 5
        )
        output = result.stdout + result.stderr
        success = (
            "OK" in output or "CGSN" in output or
            command.split('+')[0] in output
        )
        return output.strip(), success
        
    except subprocess.TimeoutExpired:
        return "TIMEOUT", False
    except Exception as e:
        return f"ERROR: {e}", False


def test_at_connection() -> bool:
    """Test basic AT connection"""
    response, success = send_at_command("AT")
    return success or "OK" in response


def get_imei_at() -> str:
    """Get IMEI via AT command"""
    response, success = send_at_command("AT+CGSN")
    
    # Parse IMEI from response
    for line in response.split('\n'):
        line = line.strip()
        if line.isdigit() and len(line) == 15:
            return line
    
    return f"Could not parse IMEI from: {response}"


def check_egmr_support() -> tuple[bool, str]:
    """Check if AT+EGMR is supported"""
    response, _ = send_at_command("AT+EGMR=?")
    supported = "ERROR" not in response.upper() and "CME" not in response.upper()
    return supported, response


def change_imei_egmr(new_imei: str) -> tuple[bool, str]:
    """
    Attempt to change IMEI via AT+EGMR command.
    
    WARNING: IMEI modification may be illegal in your jurisdiction.
    
    Args:
        new_imei: New 15-digit IMEI
        
    Returns:
        (success, response)
    """
    if len(new_imei) != 15 or not new_imei.isdigit():
        return False, "IMEI must be 15 digits"
    
    # Check if EGMR is supported first
    supported, test_resp = check_egmr_support()
    if not supported:
        return False, f"AT+EGMR not supported: {test_resp}"
    
    # AT+EGMR=1,7,"IMEI" - write IMEI to slot 1
    cmd = f'AT+EGMR=1,7,"{new_imei}"'
    response, success = send_at_command(cmd)
    
    return success, response


def get_signal_at() -> dict:
    """Get signal quality via AT+CSQ"""
    response, success = send_at_command("AT+CSQ")
    
    result = {"raw": response, "rssi": None, "ber": None}
    
    # Parse +CSQ: rssi,ber
    match = re.search(r'\+CSQ:\s*(\d+),(\d+)', response)
    if match:
        rssi_raw = int(match.group(1))
        ber_raw = int(match.group(2))
        
        # Convert RSSI (0-31 scale to dBm)
        if rssi_raw == 99:
            result["rssi"] = "Unknown"
        else:
            result["rssi"] = -113 + (rssi_raw * 2)
        result["ber"] = ber_raw
    
    return result


def get_network_info_at() -> dict:
    """Get network info via AT commands"""
    result = {}
    
    # Operator
    resp, _ = send_at_command("AT+COPS?")
    match = re.search(r'\+COPS:\s*\d+,\d+,"([^"]+)"', resp)
    if match:
        result["operator"] = match.group(1)
    
    # Registration status
    resp, _ = send_at_command("AT+CREG?")
    match = re.search(r'\+CREG:\s*\d+,(\d+)', resp)
    if match:
        reg_status = int(match.group(1))
        result["registration"] = {
            0: "Not registered",
            1: "Registered, home",
            2: "Searching",
            3: "Registration denied",
            4: "Unknown",
            5: "Registered, roaming"
        }.get(reg_status, f"Unknown ({reg_status})")
    
    return result


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="MiFi AT Command Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s "AT"                    # Test connection
  %(prog)s "AT+CGSN"               # Get IMEI
  %(prog)s "AT+CSQ"                # Signal quality
  %(prog)s --imei                  # Get IMEI (parsed)
  %(prog)s --signal                # Get signal info
  %(prog)s --network               # Get network info
  %(prog)s --set-imei 352099001761481  # Change IMEI (WARNING!)
"""
    )
    
    parser.add_argument("command", nargs="?", help="AT command to send")
    parser.add_argument("--imei", action="store_true", help="Get IMEI")
    parser.add_argument("--signal", action="store_true", help="Get signal info")
    parser.add_argument("--network", action="store_true", help="Get network info")
    parser.add_argument(
        "--set-imei", metavar="IMEI", help="Change IMEI (15 digits)"
    )
    parser.add_argument("--test", action="store_true", help="Test AT connection")
    parser.add_argument(
        "--timeout", type=int, default=5, help="Command timeout"
    )
    
    args = parser.parse_args()
    
    global TIMEOUT
    TIMEOUT = args.timeout
    
    if args.test:
        if test_at_connection():
            print("AT connection OK")
        else:
            print("AT connection FAILED")
            sys.exit(1)
    
    elif args.imei:
        print(f"IMEI: {get_imei_at()}")
    
    elif args.signal:
        import json
        print(json.dumps(get_signal_at(), indent=2))
    
    elif args.network:
        import json
        print(json.dumps(get_network_info_at(), indent=2))
    
    elif args.set_imei:
        print("WARNING: IMEI modification may be illegal!")
        success, response = change_imei_egmr(args.set_imei)
        print(f"{'SUCCESS' if success else 'FAILED'}: {response}")
    
    elif args.command:
        response, success = send_at_command(args.command)
        print(f"Response ({'' if success else 'possibly '}OK):")
        print(response)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
