#!/bin/sh
# Watchdog script for monitoring the MiFi FOTA programming mode, PRI update procedure.
# Occasionally the PRI update process will hang while updating the modem PRI.
# This script will wait for 90 seconds and check whether the process is still running.
# If it's running it will kill it, then kill the PRI update process. 
# Tries total of 3 times, and gives up. 
export PATH=$PATH:/opt/nvtl/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
NVTL_LOG=/opt/nvtl/bin/nvtl_log
max_count=3
counter=0
while [ $counter -lt $max_count ]; do
	if [ $counter -gt 0 ]; then
		# Try again
		sleep 1
		/etc/rc5.d/S98fota_pmode5 start &
	# Give the PRI update process time to complete
	sleep 380
	# Get the pid of the PRI update process INIT script
	pid=`ps | grep S98fota_pmode5 | grep -v grep | awk '{print $1}'`
	if [ -n "$pid" ]; then
		# Process is still running - kill it and try again		
		$NVTL_LOG -p 1 -m FOTA -l err -s "FOTA_PMODE_WATCHDOG: S98fota_pmode5 process still running after 90 seconds"
		# Kill the script process
		kill $pid
		# Check for the pri_diff_process
		pid=`pidof pri_diff_process`
		if [ -n "$pid" ]; then
			$NVTL_LOG -p 1 -m FOTA -l err -s "FOTA_PMODE_WATCHDOG: pri_diff_process process still running after 90 seconds"
			killall pri_diff_process &> /dev/null 
		echo 100 > /var/log/fota_progress
		sleep 1
		killall mifi_upi_disp &> /dev/null 
		# All done
		$NVTL_LOG -p 1 -m FOTA -l notice -s "FOTA_PMODE_WATCHDOG: OK"		 
		exit 0
	let counter=counter+1
# We keep getting stuck - reboot the device.
$NVTL_LOG -p 1 -m FOTA -l err -s "FOTA_PMODE_WATCHDOG: S98fota_pmode5 failed 3 times - rebooting device"
telinit 6
