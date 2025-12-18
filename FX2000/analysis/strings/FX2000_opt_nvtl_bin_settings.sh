#!/bin/sh
# init.d script for the sub-system listed
SETTINGS=settingsd
BLUETOOTH_SCRIPT_FILE="/opt/nvtl/bin/bluetooth.sh"
CARRIER_INIT_COOKIE="/opt/nvtl/data/branding/carrier_init_done"
FOTA_SUCCESS_COOKIE="/opt/nvtl/data/fota/staging/result_success"
CARRIER_INIT_COOKIE_DELETED="/tmp/carrier_init_done_deleted"
BRANDING_IPK="/opt/nvtl/data/branding/branding.ipk"
BRANDING_TAR="/opt/nvtl/data/branding/branding.tgz"
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
do_wait_for_carrier_init()
    COUNTER=0   
    while [ $COUNTER -lt 60 ]
    	if [ -e "$CARRIER_INIT_COOKIE" ]; then
    		break
    	else
    		/opt/nvtl/bin/nvtl_log -p 0 -m SETTINGS -l notice -s "waiting for carrier initialization..."
    		sleep 1
        let COUNTER=COUNTER+1
    done
case $1 in
		echo -n "Starting $SETTINGS: "
		if [ -f $BLUETOOTH_SCRIPT_FILE ]; then
			$BLUETOOTH_SCRIPT_FILE bt_chip_check
		if [ -e "$FOTA_SUCCESS_COOKIE" ]; then
			/opt/nvtl/bin/nvtl_log -p 1 -m SETTINGS -l notice -s "FOTA_SUCCESS_COOKIE found"
			if [ ! -e "$CARRIER_INIT_COOKIE_DELETED" ]; then
				/opt/nvtl/bin/nvtl_log -p 1 -m SETTINGS -l notice -s "Delete CARRIER_INIT_COOKIE."
				rm -rf $CARRIER_INIT_COOKIE
				touch $CARRIER_INIT_COOKIE_DELETED
				/opt/nvtl/bin/nvtl_log -p 1 -m SETTINGS -l notice -s "current branding-version:[$(/usr/bin/ipkg-cl info branding | grep Version | awk '{print $2}')]"
				/opt/nvtl/bin/nvtl_log -p 1 -m SETTINGS -l notice -s "Carrier initialization already done."
		start-stop-daemon -S -b -a /opt/nvtl/bin/$SETTINGS
		do_wait_for_carrier_init
		if [ -e "$CARRIER_INIT_COOKIE" ]; then
			if [ -e "$BRANDING_IPK" ]; then
				/opt/nvtl/bin/nvtl_log -p 1 -m SETTINGS -l notice -s "Delete ${BRANDING_IPK}"
				rm -rf $BRANDING_IPK
			if [ -e "$BRANDING_TAR" ]; then
				/opt/nvtl/bin/nvtl_log -p 1 -m SETTINGS -l notice -s "Delete ${BRANDING_TAR}"
				rm -rf $BRANDING_TAR
		echo "done"
		echo -n "Stopping $SETTINGS: "
		start-stop-daemon -K -x /opt/nvtl/bin/$SETTINGS
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $SETTINGS { start | stop | restart}" >&2
		exit 1
