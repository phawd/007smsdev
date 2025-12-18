#!/bin/sh
# init.d script for the omadm started for DM restore functionality
OMADM=omadmd
OMADM_RESTORE=/tmp/omadmd_restore
export SHELL=/bin/sh PATH=/opt/nvtl/data/branding/bin:$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=/opt/nvtl/data/branding/lib:$LD_LIBRARY_PATH:/opt/nvtl/lib
if [ ! -e "/opt/nvtl/data/branding/bin/$OMADM" ]; then
	/opt/nvtl/bin/nvtl_log -p 1 -m OMADM -l err "/opt/nvtl/data/branding/bin/$OMADM not found"
	if [ ! -e "/opt/nvtl/bin/$OMADM" ]; then
		/opt/nvtl/bin/nvtl_log -p 1 -m OMADM -l err "/opt/nvtl/bin/$OMADM not found .. exiting."
		exit 2
		cp /opt/nvtl/bin/$OMADM $OMADM_RESTORE
	cp /opt/nvtl/data/branding/bin/$OMADM $OMADM_RESTORE
case $1 in
	start) 
		echo -n "Starting $OMADM_RESTORE: "
		start-stop-daemon -S -b -a $OMADM_RESTORE -- restore
		echo "done"
		echo -n "Stopping $OMADM_RESTORE: "
		start-stop-daemon -K -x $OMADM_RESTORE
		echo "done"
	restart)
		$0 stop
		sleep 2
		$0 start
		echo "Usage: $OMADM_RESTORE { start | stop | restart}" >&2
		exit 1
