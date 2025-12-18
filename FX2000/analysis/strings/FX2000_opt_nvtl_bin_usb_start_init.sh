#!/bin/sh
# INIT script for usb_start.sh - start usb_start.sh in background
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
		echo -n "Starting usb_start.sh: "
		/usr/bin/usb_serial &
		/opt/nvtl/bin/usb_start.sh &
		echo "done"
		echo "Usage: $0 { start }" >&2
		exit 1
