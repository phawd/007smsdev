#!/bin/sh
# init.d script for the cbsd listed
CBSD=cbsdd
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
		echo -n "Starting $CBSD: "
		if [ ! -d "/opt/nvtl/data/cbsd" ];then
			mkdir -p /opt/nvtl/data/cbsd
			mkdir -p /opt/nvtl/data/cbsd/cpi
			mkdir -p /opt/nvtl/data/cbsd/certificates
		start-stop-daemon -S -b -a /opt/nvtl/bin/$CBSD
		echo "done"
		echo -n "Stopping $CBSD: "
		start-stop-daemon -K -x /opt/nvtl/bin/$CBSD
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $CBSD { start | stop | restart}" >&2
		exit 1
