#!/bin/sh
# init.d script for the fota listed
FOTA=fotad
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
		echo -n "Starting $FOTA: "
		start-stop-daemon -S -b -a /opt/nvtl/bin/$FOTA
		echo "done"
		echo -n "Stopping $FOTA: "
		start-stop-daemon -K -x /opt/nvtl/bin/$FOTA
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $FOTA { start | stop | restart}" >&2
		exit 1
