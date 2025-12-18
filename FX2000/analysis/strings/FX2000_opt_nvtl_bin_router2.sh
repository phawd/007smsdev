#!/bin/sh
# init.d script for the router2 listed
ROUTER2=router2d
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
		echo -n "Starting $ROUTER2: "
		start-stop-daemon -S -b -a /opt/nvtl/bin/$ROUTER2
		echo "done"
		echo -n "Stopping $ROUTER2: "
		start-stop-daemon -K -x /opt/nvtl/bin/$ROUTER2
		sleep 1
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $ROUTER2 { start | stop | restart}" >&2
		exit 1
