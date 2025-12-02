
import sys
import serial
import time
import serial.tools.list_ports

import subprocess

def enable_diag_port(device_type):
    print(f"\n[INFO] Attempting to enable diagnostic/AT ports for {device_type} device...")
    if device_type == "qualcomm":
        print("- Qualcomm: You can enable diag/AT ports with:")
        print("  adb shell su -c 'setprop persist.sys.usb.config diag,serial_cdev,rmnet,adb'")
        print("  (You may need to reboot or replug USB)")
        try:
            subprocess.run(["adb", "shell", "su", "-c", "setprop persist.sys.usb.config diag,serial_cdev,rmnet,adb"], check=False)
        except Exception:
            pass
    elif device_type == "mtk":
        print("- MediaTek: Use AT+EUSBAUDIO or AT+ESWUL to enable diagnostic/AT ports (varies by model)")
        print("  Example: Send 'AT+EUSBAUDIO=2' or 'AT+ESWUL=1' via AT command interface.")
        print("  Some devices require engineering mode apps or special USB drivers.")
    elif device_type == "samsung":
        print("- Samsung: Use *#0808# in dialer to set USB config, or use Samsung USB diagnostic tools.")
    else:
        print("- Generic: Refer to device documentation or try enabling serial/diag via AT commands or system properties.")
    print()

def list_serial_ports():
    print("Available serial ports:")
    ports = serial.tools.list_ports.comports()
    for idx, port in enumerate(ports):
        info = f"{port.device}"
        if port.vid and port.pid:
            info += f" (VID: {hex(port.vid)}, PID: {hex(port.pid)})"
        if port.manufacturer:
            info += f" [{port.manufacturer}]"
        if port.product:
            info += f" [{port.product}]"
        print(f"  [{idx}] {info}")
    if not list(ports):
        print("  No serial ports found.")
    print()
    return list(ports)

# Example usage: python qualcomm_modem_access.py /dev/smd0 "AT+CSQ"

def send_at_command(device_path, command, baudrate=115200, timeout=2, wait=0.5):
    try:
        with serial.Serial(device_path, baudrate, timeout=timeout) as ser:
            ser.write((command + "\r").encode())
            time.sleep(wait)
            response = ser.read_all().decode(errors="ignore")
            return response
    except Exception as e:
        return f"Error: {e}"

def initialize_modem(device_path, modem_type, baudrate=115200):
    # Basic initialization for different modem types
    if modem_type == "qualcomm":
        print("[INFO] Initializing Qualcomm modem...")
        print(send_at_command(device_path, "ATE0", baudrate))  # Echo off
        print(send_at_command(device_path, "AT+CMEE=2", baudrate))  # Verbose errors
    elif modem_type == "mtk":
        print("[INFO] Initializing MediaTek modem...")
        print(send_at_command(device_path, "ATE0", baudrate))
        print(send_at_command(device_path, "AT+CMEE=2", baudrate))
    else:
        print("[INFO] Initializing generic modem...")
        print(send_at_command(device_path, "ATE0", baudrate))

def send_sms(device_path, modem_type, phone_number, message, baudrate=115200):
    print(f"[INFO] Sending SMS to {phone_number} via {modem_type} modem...")
    # Set text mode
    print(send_at_command(device_path, "AT+CMGF=1", baudrate))
    # Set character set (optional, for UCS2)
    # print(send_at_command(device_path, "AT+CSCS=\"UCS2\"", baudrate))
    # Send SMS
    try:
        with serial.Serial(device_path, baudrate, timeout=5) as ser:
            ser.write(b'AT+CMGF=1\r')
            time.sleep(0.5)
            ser.write(f'AT+CMGS="{phone_number}"\r'.encode())
            time.sleep(0.5)
            ser.write((message + chr(26)).encode())  # Ctrl+Z to send
            time.sleep(2)
            response = ser.read_all().decode(errors="ignore")
            print(response)
    except Exception as e:
        print(f"Error: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python qualcomm_modem_access.py <device_path> <AT_command|'sms'> [args...]")
        print("\nExamples:")
        print("  python qualcomm_modem_access.py /dev/smd0 AT+CSQ")
        print("  python qualcomm_modem_access.py /dev/ttyUSB0 sms <modem_type> <phone_number> <message>")
        print("  python qualcomm_modem_access.py scan   # List all serial ports and USB IDs")
        print("  python qualcomm_modem_access.py enable <device_type>   # Enable diag/AT ports (qualcomm, mtk, samsung, generic)")
        sys.exit(1)

    if sys.argv[1].lower() == "scan":
        list_serial_ports()
        sys.exit(0)

    if sys.argv[1].lower() == "enable":
        if len(sys.argv) < 3:
            print("Usage: python qualcomm_modem_access.py enable <device_type>")
            print("  device_type: qualcomm | mtk | samsung | generic")
            sys.exit(1)
        device_type = sys.argv[2].lower()
        enable_diag_port(device_type)
        sys.exit(0)

    device_path = sys.argv[1]
    action = sys.argv[2] if len(sys.argv) > 2 else None
    baudrate = 115200
    if not action:
        print("No command specified. Use 'scan' to list ports or provide AT command/SMS arguments.")
        sys.exit(1)
    if action.lower() == "sms":
        if len(sys.argv) < 6:
            print("Usage: python qualcomm_modem_access.py <device_path> sms <modem_type> <phone_number> <message>")
            sys.exit(1)
        modem_type = sys.argv[3].lower()  # qualcomm, mtk, generic
        phone_number = sys.argv[4]
        message = sys.argv[5]
        initialize_modem(device_path, modem_type, baudrate)
        send_sms(device_path, modem_type, phone_number, message, baudrate)
    else:
        command = action
        if len(sys.argv) > 3:
            try:
                baudrate = int(sys.argv[3])
            except Exception:
                pass
        print(f"Sending '{command}' to {device_path} at {baudrate} baud...")
        result = send_at_command(device_path, command, baudrate)
        print("Response:\n" + result)

if __name__ == "__main__":
    main()
