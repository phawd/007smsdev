#!/bin/sh
# init.d script for the wifi listed
WIFI=wifid
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
export KERNEL=`uname -r`
MODULE_BASE=/lib/modules/$KERNEL/extra
WIFI_ETC_LIB=/opt/nvtl/etc/wifi
WIFI_DAT_LIB=/opt/nvtl/data/wifi
WIFI_INI_FILE='/etc/misc/wifi/WCNSS_qcom_cfg.ini'
WIFI_FW_PATH='/firmware/image'
BDF_PATH='/lib/firmware/wlan/qca_cld'
TARGET_PATH='/firmware/image'
BDF_OTP_PATH='/opt/nvtl/data/wifi'
WIFI_INI_BK_FILE='/etc/misc/wifi/WCNSS_qcom_cfg.ini.bk'
mkdir -p $WIFI_DAT_LIB
export RETRY_LIMIT=5
# Default Country will be USA
country="US"
runlevel=`runlevel | cut -b 3`
log () {
	nvtl_log -p 1 -m "WIFI" -l $2 -s "wifi.sh:$1"
log "is invoked [$0] [$1] [$2] [$3] [$4] [$5]" "notice"
unload_wifi_driver() {
	ifconfig wlan1 down   > /dev/null 2>&1
	ifconfig wlan0 down  > /dev/null 2>&1
	rmmod wlan
# mount /firmware file system
mount_copy() {
	local dev_country=$1
case "$country" in
		BDF_NAME="bdwlan_AU_duvel.elf"
		BDF_NAME="bdwlan_GB_duvel.elf"
# ToDo: Correct once we have proper JP BDF
		BDF_NAME="bdwlan_JP_duvel.elf"
		BDF_NAME="bdwlan_US_duvel.elf"
	__="$BDF_PATH/$BDF_NAME"
# BDF copied at /lib/firmware/wlan/qca_cld shall be in country wise name like bdwlan_AU/US/GB.elf 
	log "copy bdf $BDF_NAME" "notice"
	mount -o rw,remount /firmware
	time sleep 0.25
	COPYPATH=${__}
	cp $COPYPATH $TARGET_PATH/bdwlan.elf
	chmod -R 777 $TARGET_PATH/bdwlan.elf
	mount -o ro,remount /firmware
	time sleep 0.50 
# replace correct WCNSS_qcom_cfg ini
replace_ini() {
	local INI_PATH='/etc/misc/wifi'
	# if bk present then else no need
	if [ -e ${WIFI_INI_BK_FILE} ]; then
		cp  ${WIFI_INI_BK_FILE} ${WIFI_INI_FILE}
		if [ $? != 0 ]; then
			log "Copy WCNSS_qcom_cfg_bk.ini failed code: $?" "notice"
			log "Copy WCNSS_qcom_cfg_bk.ini Successful" "notice"
# this function will enable/disable flags in WCNSS_qcom_cfg.ini based on country
set_flags() {
	local country=$1
	local gEnableTxSUBeamformer=1
	local etsi13_srd_chan_in_master_mode=1
	local gEnableDFSMasterCap=0
	local gindoor_channel_support=1
	log "country code = ${country}" "notice"
	if [ "CA" = "$country" ]; then
		gEnableTxSUBeamformer=1
		etsi13_srd_chan_in_master_mode=0
		gEnableDFSMasterCap=0
		gindoor_channel_support=0
	elif [ "JP" = "$country" ]; then
		gEnableTxSUBeamformer=1
		etsi13_srd_chan_in_master_mode=0
		gEnableDFSMasterCap=0
		gindoor_channel_support=1
	elif [ "GB" = "$country" ]; then
		gEnableTxSUBeamformer=1
		etsi13_srd_chan_in_master_mode=1
		gEnableDFSMasterCap=0
		gindoor_channel_support=1
	elif [ "AU" = "$country" ]; then
		gEnableTxSUBeamformer=1
		etsi13_srd_chan_in_master_mode=0
		gEnableDFSMasterCap=0
		gindoor_channel_support=1
		gEnableTxSUBeamformer=1
		etsi13_srd_chan_in_master_mode=0
		gEnableDFSMasterCap=0
		gindoor_channel_support=0
    for key in gindoor_channel_support gEnableDFSMasterCap etsi13_srd_chan_in_master_mode gEnableTxSUBeamformer
        sed -i "s/^\($key\).*/\1 $(eval echo = \${$key})/" $WIFI_INI_FILE
    done
load_wifi_driver() {
	    insmod $MODULE_BASE/wlan.ko 
	    c=1
                sleep 1                               
		ifconfig wlan0 up 169.254.1.1 netmask 255.255.255.0 2>  /dev/null
			rc=$?
	       	while [ $rc -ne 0 -a $c -le $RETRY_LIMIT ]; do
            		sleep 1
            		ifconfig wlan0 up 169.254.1.1 netmask 255.255.255.0 2> /dev/null
            		rc=$?
            		c=`expr $c + 1`
		done		
#               sleep 5                               
		if [ $2 == 2 ] ; then
			iw dev wlan0 interface add wlan1 type managed
#			ip link set dev wlan1 address $1
			ifconfig wlan1 up 169.254.2.1 netmask 255.255.255.0 2>  /dev/null
#			ifconfig wlan1 txqueuelen 5000
			rc=$?
		       	while [ $rc -ne 0 -a $c -le $RETRY_LIMIT ]; do
		 		sleep 1
		    		ifconfig wlan1 up 169.254.2.1 netmask 255.255.255.0 2>  /dev/null
		    		rc=$?
		    		c=`expr $c + 1`
case $1 in
		log "Starting $WIFI" "debug"
		if [ $runlevel == 2 ]; then
			/opt/nvtl/bin/wifi_diag.sh 1
			start-stop-daemon -S -b -a /opt/nvtl/bin/$WIFI
		log "Wifi up in runlevel $runlevel" "debug"
		log  "Stopping $WIFI: " "debug"
		start-stop-daemon -K -x /opt/nvtl/bin/$WIFI
		log "Stopping Wifi done" "debug"
	unload_driver)
		log "Unloading Wifi driver: " "debug"
		unload_wifi_driver
		log "Unloading Wifi driver done" "debug"
	load_driver)
		log "Loading Wifi driver: " "notice"
		unload_wifi_driver
		time sleep 0.5
		country=$(grep '<Country' /sysconf/settings.xml | cut -f2 -d">"|cut -f1 -d"<")
		if [ "$country" = "US" ]; then
 	 		log "No changes needed for $country" "notice"
			replace_ini
			set_flags $country
		mount_copy $country
		time sleep 0.5
		load_wifi_driver $mac2 $4 $5
		log "Loading Wifi driver done" "debug"
	restart)
		$0 stop
		$0 start
		log "Usage: $WIFI { start | stop | restart| load_driver | unload_driver }" "notice"
		exit 1
