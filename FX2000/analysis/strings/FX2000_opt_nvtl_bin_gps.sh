#!/bin/sh
# init.d script for the gps listed
GPS=gpsd
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
		echo -n "Starting $GPS: "
		start-stop-daemon -S -b -a /opt/nvtl/bin/$GPS
		echo "done"
		echo -n "Stopping $GPS: "
		start-stop-daemon -K -x /opt/nvtl/bin/$GPS
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $GPS { start | stop | restart}" >&2
		exit 1
