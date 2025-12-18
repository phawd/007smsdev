#!/bin/sh
# usb_start.sh
# Wait for usb.sh to be running, then execute usb_cli start using the current runlevel.
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
get_start_mode()
	runlevel=`runlevel | awk '{ print $2 }'`
	case $runlevel in
		start_mode=LPM
		start_mode=FTM
		start_mode=Online
		start_mode=LTM
		logger -p local1.crit -t usb_start.sh "runlevel=$runlevel not supported"
		exit 1
wait_for_usbd()
	while true ; do
		usb_cli is_running &> /dev/null
		if [ $? -eq 0 ]; then
			break
		sleep 1
wait_for_usbd
usb_cli stop
if [ $rc -ne 0 ]; then
	logger -p local1.crit -t usb_start.sh "'usb_cli stop' failed with $rc"
get_start_mode
usb_cli start $start_mode
if [ $rc -eq 0 ]; then
	logger -p local1.crit -t usb_start.sh "USB started in $start_mode"
	logger -p local1.crit -t usb_start.sh "'usb_cli start $start_mode' failed with $rc"
