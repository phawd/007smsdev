#!/bin/sh
# INIT script for mifi_omadm_pri_watchdog.sh.
# All this is for is to run the mifi_omadm_pri_watchdog.sh script in background.
export PATH=$PATH:/opt/nvtl/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
NVTL_LOG=/opt/nvtl/bin/nvtl_log
FOTA_DATA=/opt/nvtl/data/fota
DLPKG_STAGING_DIR=$FOTA_DATA/staging
FOTA_STAGING_UPDATE_POST_INSTALL=$DLPKG_STAGING_DIR/update_post_install
# Only start the watchdog script when the PRI update is occurring.
if [ -f $FOTA_STAGING_UPDATE_POST_INSTALL ]; then
	$NVTL_LOG -p 1 -m FOTA -l notice -s "FOTA_PMODE_WATCHDOG: Starting"
	fota_pmode_watchdog.sh &
	$NVTL_LOG -p 1 -m FOTA -l notice -s "FOTA_PMODE_WATCHDOG: Not started"	
