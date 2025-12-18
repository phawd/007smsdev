#!/bin/sh
# init.d script for the omadm_wap_proxy listed
OMADM=omadm_wap_proxyd
OMADM_PATH="/opt/nvtl/bin"
export SHELL=/bin/sh PATH=/opt/nvtl/data/branding/bin:$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=/opt/nvtl/data/branding/lib:$LD_LIBRARY_PATH:/opt/nvtl/lib
if [ ! -e "/opt/nvtl/data/branding/bin/$OMADM" ]; then
	/opt/nvtl/bin/nvtl_log -p 1 -m OMADM -l err "/opt/nvtl/data/branding/bin/$OMADM not found"
	if [ ! -e "/opt/nvtl/bin/$OMADM" ]; then
		/opt/nvtl/bin/nvtl_log -p 1 -m OMADM -l err "/opt/nvtl/bin/$OMADM not found .. exiting."
		exit 2
	OMADM_PATH="/opt/nvtl/data/branding/bin"
case $1 in
		echo -n "Starting $OMADM: "
		start-stop-daemon -S -b -a $OMADM_PATH/$OMADM
		echo "done"
		echo -n "Stopping $OMADM: "
		start-stop-daemon -K -x $OMADM_PATH/$OMADM
		echo "done"
	restart)
		$0 stop
		sleep 2
		$0 start
		echo "Usage: $OMADM { start | stop | restart}" >&2
		exit 1
