#!/bin/sh
# Copyright (C) 2016 Novatel Wireless, Inc.  All Rights Reserved.
# Script used to load kernel drivers for Moretti (SDX55 based MiFi).
# It should be executed during the beginng of rcS.
# If executed with the 'start' argument (e.g. from rcS) all of the modules
# will be loaded.
export PATH=$PATH:/opt/nvtl/bin:/opt/nvtl/bin/tests LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
# load touchscreen drivers
load_touch()
	# Load the touch drivers if the HW is present
	/opt/nvtl/bin/tests/i2c_test  -a 0x24 -m read -s 8 -o 0 &> /dev/null
	if [ $? -ne 0 ]; then
		/opt/nvtl/bin/tests/i2c_test  -a 0x24 -m read -s 8 -o 0 &> /dev/null
		if [ $? -ne 0 ]; then
			return
	echo "$SCRIPT_NAME: loading touch drivers cyttsp5.ko, cyttsp5_device_access.ko, cyttsp5_loader.ko, cyttsp5_i2c.ko" > /dev/kmsg
	insmod /lib/modules/`uname -r`/kernel/drivers/input/touchscreen/cyttsp5/cyttsp5.ko
	insmod /lib/modules/`uname -r`/kernel/drivers/input/touchscreen/cyttsp5/cyttsp5_device_access.ko
	insmod /lib/modules/`uname -r`/kernel/drivers/input/touchscreen/cyttsp5/cyttsp5_loader.ko
	insmod /lib/modules/`uname -r`/kernel/drivers/input/touchscreen/cyttsp5/cyttsp5_i2c.ko
# load qualcomm modules required by QMI/Wlan
load_qcom_prereq()
	insmod /lib/modules/`uname -r`/extra/q6_notifier_dlkm.ko
	insmod /lib/modules/`uname -r`/extra/apr_dlkm.ko
	insmod /lib/modules/`uname -r`/extra/adsp_loader_dlkm.ko
	insmod /lib/modules/`uname -r`/extra/q6_dlkm.ko
	insmod /lib/modules/`uname -r`/extra/platform_dlkm.ko
	insmod /lib/modules/`uname -r`/extra/native_dlkm.ko
	insmod /lib/modules/`uname -r`/extra/swr_dlkm.ko
	insmod /lib/modules/`uname -r`/extra/shortcut-fe.ko
	insmod /lib/modules/`uname -r`/extra/shortcut-fe-ipv6.ko
	insmod /lib/modules/`uname -r`/extra/shortcut-fe-cm.ko
	insmod /lib/modules/`uname -r`/extra/mbhc_dlkm.ko
	insmod /lib/modules/`uname -r`/extra/swr_ctrl_dlkm.ko
	insmod /lib/modules/`uname -r`/extra/embms_kernel.ko
load_all()
	# The order is important - don't change it.
	# load_qcom_prereq
	load_touch
SCRIPT_NAME=`basename $0`
echo "[MIFI_TIMESTAMP] - $SCRIPT_NAME: started" > /dev/kmsg
case $1 in
		load_all
		create_device_sym_links.sh start
		echo "usage: $SCRIPT_NAME { start }"
		exit 1
logger -p local1.crit -t $SCRIPT_NAME "done"
echo "[MIFI_TIMESTAMP] - $SCRIPT_NAME: done" > /dev/kmsg
