#!/bin/sh
# ctrlxfer.sh - script used to process control transfers from the android gadget driver
# This script is executed by the UDEV rule /etc/udev/rules.d/10-ctrlxfer.rules:
#   SUBSYSTEM=="android_usb"
#   ACTION=="change"
#   DEVPATH=="/devices/virtual/android_usb/android0"
# Before the UDEV event is generated the android gadget driver sets these sysfs variables:
#   /sys/devices/virtual/android_usb/android0/ctrlxfer_event/ctrlxfer_bRequest
#   /sys/devices/virtual/android_usb/android0/ctrlxfer_event/ctrlxfer_wIndex
#   /sys/devices/virtual/android_usb/android0/ctrlxfer_event/ctrlxfer_wValue
# This feature is used by the umts_pst_cli.exe tool and the mode switch code that
# is provided with the Verizon Dashboard App.
# write a message to the /opt/nvtl/tmp/usb/ctrlxferlog
tmplog()
	echo $* >> $LOGFILE
# Initialize variables used by the android gadget driver
# (defined in kernel/include/linux/usb/nvtl/composite.h)
init_gadget_variables()
	# ctrlxfer_wValue
	USB_VAL_NVTL_SWITCH_TO_DEBUG_MODE=0000
	USB_VAL_NVTL_SWITCH_TO_END_USER_MODE=0002
	USB_VAL_NVTL_TOGGLE_MODE=0003
	USB_VAL_NVTL_SWITCH_TO_ENTERPRISE_MODE_WIN=0004
	USB_VAL_NVTL_SWITCH_TO_ENTERPRISE_MODE_MAC=0005
	USB_VAL_NVTL_SET_RL_0=0100
	USB_VAL_NVTL_SET_RL_1=0101
	USB_VAL_NVTL_SET_RL_2=0102
	USB_VAL_NVTL_SET_RL_3=0103
	USB_VAL_NVTL_SET_RL_4=0104
	USB_VAL_NVTL_SET_RL_5=0105
	USB_VAL_NVTL_SET_RL_6=0106
	USB_VAL_NVTL_SSH_ENABLE_MAKE_TEMP=0201
	USB_VAL_NVTL_SSH_ENABLE_MAKE_PERM=0203
	USB_VAL_NVTL_SSH_DISABLE_MAKE_TEMP=0200
	USB_VAL_NVTL_SSH_DISABLE_MAKE_PERM=0202
	USB_VAL_NVTL_USB_CONSOLE_RESTART=0204
	USB_VAL_NVTL_UART_CONSOLE_RESTART=0208
	USB_VAL_NVTL_SWITCH_TO_DEBUG_MODE_03=0301
	USB_VAL_NVTL_SWITCH_TO_END_USER_MODE_03=0302
	USB_VAL_NVTL_TOGGLE_MODE_03=0303
	USB_VAL_NVTL_LOGGING_STORE_LOGS_TO_FLASH=0901
	USB_VAL_NVTL_ENTER_APPSBOOT=0B00
	USB_VAL_NVTL_ENTER_RECOVERY=0B01
	USB_VAL_NVTL_IGNORE=FF00
	# ctrlxfer_wIndex
	USB_IDX_NVTL_REBOOT_AFTER_SWITCH=0000
	USB_IDX_NVTL_REENUM_AFTER_SWITCH=0001
	USB_IDX_NVTL_REBOOT=0002
	USB_IDX_NVTL_REENUM=0003
	USB_IDX_NVTL_IGNORE=00FF
	USB_REQ_NVTL_VENDOR_COMMAND=FE
	SYSFSPATH=/sys/devices/virtual/android_usb/android0/ctrlxfer_event
clear_req()
	echo 0 > $SYSFSPATH/ctrlxfer_bRequest
	echo 0 > $SYSFSPATH/ctrlxfer_bRequestType
	echo 0 > $SYSFSPATH/ctrlxfer_wLength
	echo 0 > $SYSFSPATH/ctrlxfer_wIndex
	echo 0 > $SYSFSPATH/ctrlxfer_wValue
reboot_device()
	nvtl_log -p 1 -m USBUTIL -l notice -s "ctrlxfer.sh: running: 'dsm_cli reset_device 1'"
	dsm_cli reset_device 1
# Use the usb_cli to switch modes
usb_cli_mode_switch()
	tmplog "usb_cli_mode_switch: $1"
	usb_cli mode_switch $1 0
	if [ $rc -ne 0 ]; then
		tmplog "'usb_cli mode_switch $1 0' failed with $rc"
		nvtl_log -p 1 -m USBUTIL -l err -s "ctrlxfer.sh: 'usb_cli mode_switch $1 0' failed with $rc"
toggle_mode()
	tmplog "toggle_mode: +++"
	mode_changed=1
	if [ "$usb_default_mode" == "[1][EUM]" ]; then
		usb_cli_mode_switch DBG
		usb_cli_mode_switch EUM
	tmplog "toggle_mode: ---"
switch_to_debug_mode()
	tmplog "switch_to_debug_mode: +++"
	if [ "$usb_default_mode" != "[0][Debug]" ]; then
		mode_changed=1
		dsm_cli set_default_usb_mode 0
		usb_cli_mode_switch DBG
	tmplog "wait for security mode switching from eum to debug ---"
	sleep 18
	tmplog "switch_to_debug_mode: ---"
switch_to_eum()
	tmplog "switch_to_eum: +++"
	if [ "$usb_default_mode" != "[1][EUM]" ]; then
		mode_changed=1
		dsm_cli set_default_usb_mode 1
		usb_cli_mode_switch EUM
	tmplog "wait for switching from debug to eum ---"
	sleep 10
	tmplog "switch_to_eum: ---"
# Since auto detect is being used there's no distinction between MacOS and Windows
switch_to_enterprise_mode()
	enterprise_mode_enabled=`usb_cli get_state | grep enterprise_mode_enabled | awk -F '='  '{print $2}'`
	if [ "$enterprise_mode_enabled" == "[1]" ]; then
		tmplog "enterprise mode already enabled"
		mode_changed=1
		usb_cli_mode_switch ENT
switch_to_enterprise_mode_windows()
	tmplog "switch_to_enterprise_mode_windows: +++"
	switch_to_enterprise_mode
	tmplog "switch_to_enterprise_mode_windows: ---"
switch_to_enterprise_mode_mac()
	tmplog "switch_to_enterprise_mode_mac: +++"
	switch_to_enterprise_mode
	tmplog "switch_to_enterprise_mode_mac: ---"
process_mode_switch()
	tmplog "process_mode_switch: wValue=$wValue"
	mode_changed=0
	case $wValue in
	$USB_VAL_NVTL_SWITCH_TO_END_USER_MODE)
		switch_to_eum
	$USB_VAL_NVTL_SWITCH_TO_END_USER_MODE_03)
		switch_to_eum
	$USB_VAL_NVTL_SWITCH_TO_ENTERPRISE_MODE_WIN)
		switch_to_enterprise_mode_windows
	$USB_VAL_NVTL_SWITCH_TO_ENTERPRISE_MODE_MAC)
		switch_to_enterprise_mode_mac
	$USB_VAL_NVTL_SWITCH_TO_DEBUG_MODE)
		switch_to_debug_mode
	$USB_VAL_NVTL_SWITCH_TO_DEBUG_MODE_03)
		switch_to_debug_mode
	$USB_VAL_NVTL_TOGGLE_MODE)
		toggle_mode
	$USB_VAL_NVTL_TOGGLE_MODE_03)
		toggle_mode
	$USB_VAL_NVTL_IGNORE)
		tmplog "No wValue action"
		tmplog "Invalid wValue=$wValue"
	tmplog "mode_changed=$mode_changed"
	tmplog "process_mode_switch: ---"
process_set_rl()
	tmplog "process_set_rl: +++"
	case $wValue in
	$USB_VAL_NVTL_SET_RL_0)
		# Shutdown requested - add message to persistent log file
		nvtl_log -p 1 -m USBUTIL -l notice -s "ctrlxfer.sh: running: 'dsm_cli shutdown_device 1'"
		dsm_cli shutdown_device 1
	$USB_VAL_NVTL_SET_RL_1)
		tmplog "running: 'dsm_cli set_persistent_mode 1'"
		dsm_cli set_persistent_mode 1
	$USB_VAL_NVTL_SET_RL_2)
		tmplog "running: 'dsm_cli set_persistent_mode 2'"
		dsm_cli set_persistent_mode 2
	$USB_VAL_NVTL_SET_RL_3)
		tmplog "running: 'dsm_cli set_persistent_mode 3'"
		dsm_cli set_persistent_mode 3
	$USB_VAL_NVTL_SET_RL_4)
		tmplog "running: 'dsm_cli set_persistent_mode 4'"
		dsm_cli set_persistent_mode 4
	$USB_VAL_NVTL_SET_RL_5)
		tmplog "running: 'dsm_cli set_persistent_mode 5'"
		dsm_cli set_persistent_mode 5
	$USB_VAL_NVTL_SET_RL_6)
		# Reboot requested - add message to persistent log file
		reboot_device
	tmplog "process_set_rl: ---"
kill_getty()
	tmplog "kill_getty: +++"
	tmplog "kill getty on $tty and hope that inittab would respawn"
	gettyps=`ps | grep getty | grep $tty`
	tmplog "gettyps=$gettyps"
	kill -9  `ps | grep getty | grep $tty | awk '{print $1}'`
	gettyps=`ps | grep getty | grep $tty`
	tmplog "gettyps=$gettyps"
	tmplog "kill_getty: ---"
process_set_ssh()
	tmplog "process_set_ssh: +++"
	case $wValue in
	$USB_VAL_NVTL_SSH_ENABLE_MAKE_TEMP)
		tmplog "enable ssh"
		killall dropbear
		/etc/init.d/dropbear restart
	$USB_VAL_NVTL_SSH_ENABLE_MAKE_PERM)
		tmplog "enable ssh, persist"
		/etc/init.d/dropbear start always
	$USB_VAL_NVTL_SSH_DISABLE_MAKE_TEMP)
		tmplog "disable ssh"
		/etc/init.d/dropbear stop
	$USB_VAL_NVTL_SSH_DISABLE_MAKE_PERM)
		tmplog "disable ssh, persist"
		/etc/init.d/dropbear stop always
	$USB_VAL_NVTL_USB_CONSOLE_RESTART)
		kill_getty ttyGS0
	$USB_VAL_NVTL_UART_CONSOLE_RESTART)
		kill_getty ttyHSL0
	tmplog "process_set_ssh: ---"
store_logs()
	tmplog "store_logs: $1"
	# default directory for storing logs
	logdir=$1
	mkdir -p $logdir
	/opt/nvtl/bin/storelogs.sh
	mv /opt/nvtl/tmp/*log.tgz $logdir/.
	sync; sync
	tmplog "store_logs: ---"
process_rw_logs()
	tmplog "process_rw_logs: +++"
	case $wValue in
	$USB_VAL_NVTL_LOGGING_STORE_LOGS_TO_FLASH)
		tmplog "storing to NAND"
		store_logs /opt/nvtl/log/debuglogs
	tmplog "process_rw_logs: ---"
process_reboot_fastboot()
	target=`cat /target`
	case $target in
	mdm9640)
		sys_reboot bootloader
		sys_reboot bootloader
		sys_reboot_fastboot.sh
process_enter_appsboot()
	tmplog "process_enter_appsboot: +++"
	case $wValue in
	$USB_VAL_NVTL_ENTER_APPSBOOT)
		# need to log something here
		echo "[USBUTIL]:[notice] - ctrlxfer.sh: running: 'sys_reboot bootloader'" >> /opt/nvtl/log/system_log
		sync; sync; sync
		process_reboot_fastboot
	$USB_VAL_NVTL_ENTER_RECOVERY)
		echo "[USBUTIL]:[notice] - ctrlxfer.sh: running: 'sys_reboot recovery'" >> /opt/nvtl/log/system_log
		sync; sync; sync
		sys_reboot recovery
	tmplog "process_enter_appsboot: ---"
restart_usb()
	tmplog "restart_usb: +++"
	tmplog "running: 'usb_cli stop'"
	usb_cli stop
	# TODO: Not sure about this logic.
	#       Maybe we should just bail if not in RL 3.
	RUNLEVEL=`runlevel | awk '{print $2}'`
	if [ $RUNLEVEL -ne 3 ]; then
		tmplog "running: 'dsm_cli set_persistent_mode 3"
		dsm_cli set_persistent_mode 3
	tmplog "running: 'usb_cli start Online'"
	usb_cli start Online
	tmplog "restart_usb: ---"
# Process the SYSFSPATH/ctrlxfer_wIndex value
process_windex()
	tmplog "process_windex: wIndex=$wIndex"
	case $wIndex in
	$USB_IDX_NVTL_REENUM_AFTER_SWITCH)
		if [ $mode_changed == 1 ]; then
			restart_usb
	$USB_IDX_NVTL_REBOOT_AFTER_SWITCH)
		if [ $mode_changed == 1 ]; then
			reboot_device
	$USB_IDX_NVTL_REENUM)
		restart_usb
	$USB_IDX_NVTL_REBOOT)
		reboot_device
	$USB_IDX_NVTL_IGNORE)
		tmplog "No wIndex action"
		tmplog "Invalid wIndex=$wIndex"
	tmplog "process_windex: ---"
	LOGDIR=/opt/nvtl/tmp/usb
	LOGFILE=$LOGDIR/ctrlxferlog
	mkdir -p $LOGDIR
	tmplog "$0: +++"
	init_gadget_variables
	# Uncomment to log the udev environment
	# set 2>1 >> $LOGFILE
	bRequest=`cat $SYSFSPATH/ctrlxfer_bRequest`
	tmplog "$SYSFSPATH/ctrlxfer_bRequest=$bRequest"
	# Exit if the UDEV event is not for us
	if [ "$bRequest" != "$USB_REQ_NVTL_VENDOR_COMMAND" ]; then
		tmplog "Not our event - exiting script"
		exit 0
	# Get the other 2 values then clear the sysfs entries
	wIndex=`cat $SYSFSPATH/ctrlxfer_wIndex`
	wValue=`cat $SYSFSPATH/ctrlxfer_wValue`
	tmplog "wIndex=$wIndex wValue=$wValue"
	clear_req
	# Add a log message to the persistent system log
	nvtl_log -p 1 -m USBUTIL -l notice -s "ctrlxfer.sh: bRequest=$bRequest wIndex=$wIndex wValue=$wValue"
	usb_default_mode=`usb_cli get_state | grep usb_default_mode | awk -F '='  '{print $2}'`
	tmplog "usb_default_mode=$usb_default_mode"
	process_mode_switch
	process_set_rl
	process_set_ssh
	process_rw_logs
	process_enter_appsboot
	process_windex
	tmplog "$0: --- "
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
