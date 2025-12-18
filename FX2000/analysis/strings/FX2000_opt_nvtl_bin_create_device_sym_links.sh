#!/bin/sh
# Copyright (C) 2016 Novatel Wireless, Inc.  All Rights Reserved.
# Script used to load kernel drivers for Rooney (MDM9x40 based MiFi).
# It should be executed during the beginng of rcS.
# If executed with the 'start' argument (e.g. from rcS) all of the modules
# will be loaded.
export PATH=$PATH:/opt/nvtl/bin:/opt/nvtl/bin/tests LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
# These device instances change based on the kernel configuration.
# Create a symlink that can be user by other user space code.
create_device_sym_links()
	DEVICES_DIR=/opt/nvtl/devices
	rm -rf $DEVICES_DIR
	mkdir -p $DEVICES_DIR
	for device in lcd
		dir=`ls -d /sys/devices/platform/*$device*`
		ls -d $dir &> /dev/null
		if [ $? -ne 0 ]; then
			logger -p local1.crit -t $SCRIPT_NAME "could not find sysfs base directory for $device"
			ln -s $dir $DEVICES_DIR/$device
	for device in `ls /sys/bus/i2c/devices/*/name`
		cat $device | grep cyttsp5_i2c_adapter &> /dev/null
		if [ $? -eq 0 ]; then
			touch_i2c_dir=`dirname $device`
			ln -s $touch_i2c_dir $DEVICES_DIR/touch
SCRIPT_NAME=`basename $0`
echo "[MIFI_TIMESTAMP] - $SCRIPT_NAME: started" > /dev/kmsg
case $1 in
		create_device_sym_links
		echo "usage: $SCRIPT_NAME { start }"
		exit 1
logger -p local1.crit -t $SCRIPT_NAME "done"
echo "[MIFI_TIMESTAMP] - $SCRIPT_NAME: done" > /dev/kmsg
