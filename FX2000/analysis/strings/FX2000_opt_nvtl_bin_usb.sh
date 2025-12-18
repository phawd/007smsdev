#!/bin/sh
# INIT script for usbd
USB=usbd
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
mount_adb()
	if [ -d /sys/class/android_usb/android0/f_ffs ]; then
		echo adb > /sys/class/android_usb/android0/f_ffs/aliases &> /dev/null
		mkdir -p /dev/usb-ffs/adb
		mkdir -p /system/bin
		ln -sf /bin/sh  /system/bin/sh &> /dev/null
		# Only mount this once
		mount | grep functionfs &> /dev/null
		if [ $? -ne 0 ]; then
			mount -o uid=2000,gid=2000 -t functionfs adb /dev/usb-ffs/adb
               	fi
case $1 in
		echo -n "Starting $USB: "
		mount_adb
		start-stop-daemon -S -b -a /opt/nvtl/bin/$USB
		echo "done"
		echo -n "Stopping $USB: "
		start-stop-daemon -K -x /opt/nvtl/bin/$USB
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $USB { start | stop | restart}" >&2
		exit 1
