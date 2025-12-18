#!/bin/sh
# Restart script for usb_serial prog
echo -n "killing usb_serial"
killall usb_serial
echo -n "Restarting usb_serial"
/usr/bin/usb_serial &
