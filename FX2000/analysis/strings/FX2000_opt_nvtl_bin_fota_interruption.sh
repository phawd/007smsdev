#!/bin/sh
# init.d script for fota upgrade interruption
export PATH=$PATH:/opt/nvtl/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
FOTA_DATA=/opt/nvtl/data/fota
DLPKG_STAGING_DIR=$FOTA_DATA/staging
FOTA_STAGING_FULL_UPDATE_PRE_INSTALL=$DLPKG_STAGING_DIR/update_pre_full_fota_install
FOTA_STAGING_UPDATE_PRE_INSTALL=$DLPKG_STAGING_DIR/update_pre_install
FOTA_STAGING_UPDATE_POST_INSTALL=$DLPKG_STAGING_DIR/update_post_install
FOTA_LOG_FILE=$FOTA_DATA/update_log
INTERRUPTION_COUNT=$FOTA_DATA/interruption_count
jump_to_rl5=0
case "$1" in
  start)
        echo "FOTA_INTERRUPTION: Checking if upgrade got interrupted"
	if [ -f $FOTA_STAGING_UPDATE_PRE_INSTALL ]; then
		jump_to_rl5=1
		echo "FOTA_INTERRUPTION: Found FOTA_STAGING_UPDATE_PRE_INSTALL" | tee -a $FOTA_LOG_FILE
	elif [ -f $FOTA_STAGING_UPDATE_POST_INSTALL ] ; then
		jump_to_rl5=1
		echo "FOTA_INTERRUPTION: Found FOTA_STAGING_UPDATE_POST_INSTALL" | tee -a $FOTA_LOG_FILE
	if [ "$jump_to_rl5" == "1" ]; then
		if [ -f $INTERRUPTION_COUNT ] ; then
			Y=`cat $INTERRUPTION_COUNT`
		Y=`expr $Y + 1`
		echo $Y > $INTERRUPTION_COUNT
		if [ $Y -lt 5 ] ; then
			echo "FOTA_INTERRUPTION: Going to RL 5, Intr count:$Y" | tee -a $FOTA_LOG_FILE
			telinit 5
        echo "FOTA_INTERRUPTION: done"
        ;;
        ;;
  restart)
        $0 stop
        $0 start
        ;;
        echo "FOTA_INTERRUPTION: Usage fota upgrade { start | stop | restart}" >&2
        exit 1
        ;;
