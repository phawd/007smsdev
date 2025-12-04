#!/usr/bin/env python3
"""
Helper CLI for enabling Qualcomm diagnostic ports and sending SMS via AT commands
using adb + root access. This mirrors the ZeroSMS in-app functionality for users who
prefer a desktop workflow.
"""

import argparse
import base64
import json
import os
import platform
import shutil
import shlex
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple

try:
    from serial.tools import list_ports
except Exception:  # pyserial optional
    list_ports = None

DIAG_PROPERTIES = [
    "persist.vendor.usb.config",
    "persist.sys.usb.config",
    "sys.usb.config",
]

DIAG_PROFILES = {
    "generic": {
        "label": "Generic Snapdragon (diag + serial)",
        "variants": [
            "diag,serial_cdev,rmnet,dpl,qdss,adb",
            "diag,serial_cdev,rmnet,adb",
        ],
    },
    "inseego-m2000": {
        "label": "Inseego MiFi M2000/M2100 (diag_mdm)",
        "variants": [
            "diag,diag_mdm,adb",
        ],
    },
    "inseego-8000": {
        "label": "Inseego 5G MiFi 8000 (serial-only)",
        "variants": [
            "diag,serial_cdev,adb",
            "diag,adb",
        ],
    },
}

DEFAULT_TTY_PATHS = [
    "/dev/smd0",
    "/dev/smd11",
    "/dev/smd7",
    "/dev/ttyUSB0",
    "/dev/ttyUSB1",
    "/dev/ttyUSB2",
    "/dev/ttyACM0",
    "/dev/ttyACM1",
]

DEEP_TTY_PATHS = DEFAULT_TTY_PATHS + [
    "/dev/ttyUSB3",
    "/dev/ttyUSB4",
    "/dev/ttyACM2",
    "/dev/ttyMT0",
    "/dev/ttyMT1",
    "/dev/ttyHS0",
    "/dev/ttyHSL0",
    "/dev/at_mdm0",
    "/dev/diag",
]


@dataclass
class ProbeResult:
    path: str
    exists: bool
    accessible: bool
    responded: bool
    response: str


USE_ROOT = True


def check_prerequisites() -> None:
    if shutil.which("adb") is None:
        sys.exit("adb is not available on PATH. Install Android Platform Tools first.")
    if platform.system().lower() == "windows":
        # Warn about missing pyserial for COM scan on Windows
        if list_ports is None:
            print(
                "[!] pyserial not installed; COM port scanning will be unavailable.",
                file=sys.stderr,
            )


def run_adb_command(args: List[str]) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["adb"] + args,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        msg = proc.stderr.strip() or proc.stdout.strip()
        raise RuntimeError(f"adb {' '.join(args)} failed: {msg}")
    return proc


def run_shell(command: str) -> subprocess.CompletedProcess:
    return run_adb_command(["shell", command])


def run_root(command: str) -> subprocess.CompletedProcess:
    if not USE_ROOT:
        return run_shell(command)
    safe = command.replace('"', r"\"")
    return run_shell(f'su -c "{safe}"')


def get_baud_for_device(device: str) -> int:
    lower = device.lower()
    if "smd" in lower or "qmi" in lower:
        return 9600
    return 115200


def send_at_command(device: str, command: str, timeout: int = 3) -> str:
    baud = get_baud_for_device(device)
    escaped_arg = shlex.quote(command)
    shell_cmd = (
        f"stty -F {device} {baud} cs8 -cstopb -parenb raw -echo; "
        f"printf '%s\\r\\n' {escaped_arg} > {device}; "
        f"timeout {timeout} cat {device}"
    )
    result = run_root(shell_cmd)
    return result.stdout.strip()


def send_text_payload(device: str, message: str, timeout: int = 10) -> str:
    baud = get_baud_for_device(device)
    payload = message.encode("utf-8") + b"\x1a"
    encoded = base64.b64encode(payload).decode("ascii")
    shell_cmd = (
        f"stty -F {device} {baud} cs8 -cstopb -parenb raw -echo; "
        f"printf '%s' '{encoded}' | base64 -d > {device}; "
        f"timeout {timeout} cat {device}"
    )
    result = run_root(shell_cmd)
    return result.stdout.strip()


def enable_diag(profile_key: str) -> bool:
    if profile_key not in DIAG_PROFILES:
        valid = ", ".join(DIAG_PROFILES.keys())
        raise ValueError(f"Unknown profile '{profile_key}'. Valid profiles: {valid}")

    profile = DIAG_PROFILES[profile_key]
    variants = profile["variants"]
    print(f"[+] Enabling diag profile '{profile_key}' ({profile['label']})...")
    for variant in variants:
        for prop in DIAG_PROPERTIES:
            print(f"    setprop {prop} {variant}")
            run_root(f"setprop {prop} {variant}")
        # Check sys.usb.config to confirm
        current = run_shell("getprop sys.usb.config").stdout.strip()
        if variant.split(",")[0] in current:
            print(f"[+] Active USB config: {current}")
            return True
        print(f"[!] sys.usb.config still {current}, trying next variant...")
    return False


def enable_diag_ai() -> None:
    print("[+] AI diag probing: cycling through all known presets")
    for key in DIAG_PROFILES.keys():
        try:
            if enable_diag(key):
                print(f"[+] Successfully enabled diag using profile '{key}'")
                return
        except Exception as exc:
            print(f"[!] Profile {key} failed: {exc}")
    raise RuntimeError(
        "AI diag probing failed for all presets. Try manual --profile selection."
    )


def send_sms_via_at(device: str, destination: str, message: str) -> None:
    print(f"[+] Using modem device {device}")
    response = send_at_command(device, "AT")
    print(f"AT -> {response}")

    response = send_at_command(device, "ATE0")
    print(f"ATE0 -> {response}")

    response = send_at_command(device, "AT+CMGF=1")
    if "OK" not in response:
        raise RuntimeError(f"Failed to switch to text mode: {response}")
    print("CMGF -> OK")

    cmgs_cmd = f'AT+CMGS="{destination}"'
    response = send_at_command(device, cmgs_cmd)
    print(f"CMGS -> {response}")
    if ">" not in response:
        raise RuntimeError("Modem did not provide '>' prompt for message input.")

    response = send_text_payload(device, message)
    print(f"Payload response:\n{response}")
    if "OK" not in response and "+CMGS" not in response:
        raise RuntimeError("SMS send failed; check modem logs.")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ZeroSMS desktop helper for enabling Qualcomm diag and sending SMS via AT commands.",
    )
    parser.add_argument(
        "--adb-non-root",
        action="store_true",
        help="Run adb shell commands without invoking su",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    diag_parser = subparsers.add_parser(
        "diag", help="Enable Qualcomm diagnostic USB mode via adb root"
    )
    diag_parser.add_argument(
        "--profile",
        choices=DIAG_PROFILES.keys(),
        default="generic",
        help="Diag preset to apply (default: %(default)s)",
    )
    diag_parser.add_argument(
        "--ai",
        action="store_true",
        help="Try all known profiles until one succeeds",
    )

    sms_parser = subparsers.add_parser(
        "sms", help="Send SMS via AT commands over adb root"
    )
    sms_parser.add_argument(
        "destination", help="E.164 destination number, e.g. +15551234567"
    )
    sms_parser.add_argument("message", help="Message body to send (text mode)")
    sms_parser.add_argument(
        "--device",
        default=None,
        help=f"Modem device file (default: first available from {', '.join(DEFAULT_TTY_PATHS)})",
    )
    sms_parser.add_argument(
        "--auto",
        action="store_true",
        help="AI probing: scan all modem nodes for a responsive AT port before sending",
    )
    sms_parser.add_argument(
        "--deep",
        action="store_true",
        help="Include deep-probing paths (MediaTek/Samsung) when auto-scanning",
    )

    probe_parser = subparsers.add_parser(
        "probe", help="Deep probe modem nodes for AT/SMS capability"
    )
    probe_parser.add_argument(
        "--deep",
        action="store_true",
        help="Include extended chipset paths (MediaTek, Samsung, diag) during probe",
    )
    probe_parser.add_argument(
        "--include-response",
        action="store_true",
        help="Show the first AT response line for each device",
    )

    usb_parser = subparsers.add_parser(
        "usb", help="List USB devices (vendor/product IDs)"
    )
    usb_parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON instead of text",
    )

    usb_switch_parser = subparsers.add_parser(
        "usb-switch", help="Run usb_modeswitch to flip a USB device"
    )
    usb_switch_parser.add_argument(
        "--vendor", "-v", required=True, help="Vendor ID (hex, e.g. 0x05c6)"
    )
    usb_switch_parser.add_argument(
        "--product", "-p", required=True, help="Product ID (hex, e.g. 0x90b4)"
    )
    usb_switch_parser.add_argument(
        "--message", "-M", help="Message content (hex string) for usb_modeswitch"
    )
    usb_switch_parser.add_argument(
        "--config", "-c", help="Path to usb_modeswitch config file"
    )

    com_parser = subparsers.add_parser(
        "comscan", help="Enumerate desktop serial/COM ports using pyserial"
    )
    com_parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON list of ports",
    )

    return parser


def resolve_device_path(device_arg: Optional[str], deep: bool = False) -> str:
    if device_arg:
        return device_arg
    for result in probe_modems(deep=deep):
        if result.exists and result.accessible and result.responded:
            return result.path
    raise RuntimeError(
        "No modem devices found. Pass --device explicitly once diag mode exposes /dev/smd*."
    )


def probe_modems(deep: bool = False) -> List[ProbeResult]:
    candidates = DEEP_TTY_PATHS if deep else DEFAULT_TTY_PATHS
    seen = set()
    results: List[ProbeResult] = []
    for path in candidates:
        if path in seen:
            continue
        seen.add(path)
        exists = (
            run_root(f"if [ -c {path} ]; then echo EXISTS; fi").stdout.strip()
            == "EXISTS"
        )
        if not exists:
            results.append(ProbeResult(path, False, False, False, "missing"))
            continue
        accessible = (
            run_root(
                f"if [ -r {path} ] && [ -w {path} ]; then echo ACCESS; fi"
            ).stdout.strip()
            == "ACCESS"
        )
        if not accessible:
            results.append(ProbeResult(path, True, False, False, "perm denied"))
            continue
        try:
            response = send_at_command(path, "AT")
            responded = "OK" in response.upper()
            snippet = response.splitlines()[0] if response else ""
        except Exception as exc:
            responded = False
            snippet = str(exc)
        results.append(ProbeResult(path, True, True, responded, snippet))
    return results


def list_usb_devices() -> List[dict]:
    devices: List[dict] = []
    system = platform.system().lower()

    # Linux: prefer lsusb, fall back to sysfs
    if system == "linux" and shutil.which("lsusb"):
        proc = subprocess.run(["lsusb"], capture_output=True, text=True, check=False)
        for line in proc.stdout.splitlines():
            parts = line.split()
            if "ID" in parts:
                idx = parts.index("ID")
                vid_pid = parts[idx + 1]
                description = " ".join(parts[idx + 2 :]) if len(parts) > idx + 2 else ""
                bus = parts[1] if len(parts) > 1 else "??"
                device = parts[3].strip(":") if len(parts) > 3 else "??"
                vid, pid = vid_pid.split(":") if ":" in vid_pid else ("0000", "0000")
                devices.append(
                    {
                        "bus": bus,
                        "device": device,
                        "vid": vid,
                        "pid": pid,
                        "description": description,
                    }
                )
        return devices

    if system == "darwin":
        proc = subprocess.run(
            ["system_profiler", "SPUSBDataType", "-json"],
            capture_output=True,
            text=True,
            check=False,
        )
        try:
            data = json.loads(proc.stdout)
            items = data.get("SPUSBDataType", [])
            for item in _flatten_spusb(items):
                devices.append(item)
        except Exception:
            pass
        return devices

    if system == "windows":
        ps = [
            "Get-PnpDevice -PresentOnly | Where-Object {$_.InstanceId -like 'USB*'} | "
            "Select-Object InstanceId,Class,DeviceID,Name | ConvertTo-Json"
        ]
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps[0]],
            capture_output=True,
            text=True,
            check=False,
        )
        try:
            entries = json.loads(proc.stdout)
            if isinstance(entries, dict):
                entries = [entries]
            for entry in entries or []:
                instance = entry.get("InstanceId", "")
                vid, pid = _extract_vid_pid(instance)
                devices.append(
                    {
                        "bus": "USB",
                        "device": entry.get("DeviceID", ""),
                        "vid": vid,
                        "pid": pid,
                        "description": entry.get("Name") or entry.get("Class") or "",
                    }
                )
        except Exception:
            pass
        return devices

    # Other/unknown OS: try adb shell/sysfs to detect attached USB devices on phone
    try:
        proc = run_shell("ls /sys/bus/usb/devices")
        for item in proc.stdout.split():
            desc = run_shell(
                f"cat /sys/bus/usb/devices/{item}/product 2>/dev/null"
            ).stdout.strip()
            vid = run_shell(
                f"cat /sys/bus/usb/devices/{item}/idVendor 2>/dev/null"
            ).stdout.strip()
            pid = run_shell(
                f"cat /sys/bus/usb/devices/{item}/idProduct 2>/dev/null"
            ).stdout.strip()
            if vid and pid:
                devices.append(
                    {
                        "bus": item,
                        "device": item,
                        "vid": vid,
                        "pid": pid,
                        "description": desc,
                    }
                )
    except Exception:
        pass
    return devices


def _flatten_spusb(items) -> List[dict]:
    flattened: List[dict] = []
    for entry in items:
        vid = entry.get("vendor_id", "0000")
        pid = entry.get("product_id", "0000")
        desc = entry.get("_name", entry.get("device_name", "USB Device"))
        flattened.append(
            {
                "bus": entry.get("_name", ""),
                "device": entry.get("bsd_name", ""),
                "vid": vid,
                "pid": pid,
                "description": desc,
            }
        )
        children = entry.get("_items", [])
        flattened.extend(_flatten_spusb(children))
    return flattened


def _extract_vid_pid(identifier: str) -> Tuple[str, str]:
    vid = "0000"
    pid = "0000"
    identifier_upper = identifier.upper()
    if "VID_" in identifier_upper:
        vid = identifier_upper.split("VID_")[1][:4]
    if "PID_" in identifier_upper:
        pid = identifier_upper.split("PID_")[1][:4]
    return vid, pid


def run_usb_modeswitch(
    vendor: str, product: str, message: Optional[str], config: Optional[str]
) -> None:
    if shutil.which("usb_modeswitch") is None:
        raise RuntimeError(
            "usb_modeswitch binary not found. Install usb-modeswitch package first."
        )
    args = ["usb_modeswitch", "-v", _sanitize_hex(vendor), "-p", _sanitize_hex(product)]
    if message:
        args += ["-M", message]
    if config:
        args += ["-c", config]
    print(f"[+] Running: {' '.join(args)}")
    subprocess.run(args, check=True)


def _sanitize_hex(value: str) -> str:
    value = value.lower().strip()
    if value.startswith("0x"):
        value = value[2:]
    return f"0x{value}"


def list_com_ports() -> List[dict]:
    if list_ports is None:
        raise RuntimeError(
            "pyserial is required for COM port scanning. Install with `pip install pyserial`."
        )
    ports_info = []
    for port in list_ports.comports():
        ports_info.append(
            {"device": port.device, "description": port.description, "hwid": port.hwid}
        )
    return ports_info


def main() -> None:
    check_prerequisites()
    parser = build_arg_parser()
    args = parser.parse_args()
    global USE_ROOT
    USE_ROOT = not args.adb_non_root

    if args.command == "diag":
        if args.ai:
            enable_diag_ai()
        else:
            if not enable_diag(args.profile):
                raise RuntimeError(
                    "Selected profile did not activate diag mode. Try --ai."
                )
    elif args.command == "sms":
        device = resolve_device_path(args.device, deep=args.deep or args.auto)
        print(f"[+] Detected modem device: {device}")
        send_sms_via_at(device, args.destination, args.message)
    elif args.command == "probe":
        results = probe_modems(deep=args.deep)
        if not results:
            print("No modem paths evaluated.")
        for result in results:
            status = (
                "OK"
                if result.responded
                else (
                    "ACCESS"
                    if result.accessible
                    else ("MISSING" if not result.exists else "NO RESPONSE")
                )
            )
            line = f"{result.path:<18} {status}"
            if args.include_response and result.response:
                line += f" :: {result.response}"
            print(line)
    elif args.command == "usb":
        devices = list_usb_devices()
        if args.json:
            print(json.dumps(devices, indent=2))
        else:
            for dev in devices:
                print(
                    f"{dev['bus']}:{dev['device']} {dev['vid']}:{dev['pid']} {dev['description']}"
                )
    elif args.command == "usb-switch":
        run_usb_modeswitch(args.vendor, args.product, args.message, args.config)
    elif args.command == "comscan":
        ports = list_com_ports()
        if args.json:
            print(json.dumps(ports, indent=2))
        else:
            for port in ports:
                print(f"{port['device']:<15} {port['description']} ({port['hwid']})")
    else:
        parser.error("Unsupported command")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("Aborted by user.")
    except Exception as exc:
        sys.exit(f"Error: {exc}")
