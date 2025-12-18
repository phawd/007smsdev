#!/bin/sh
# init.d script for the dsm listed
DSM=dsmd
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
		echo -n "Starting $DSM: "
		start-stop-daemon -S -b -a /opt/nvtl/bin/$DSM
		echo "done"
		echo -n "Stopping $DSM: "
		start-stop-daemon -K -x /opt/nvtl/bin/$DSM
		echo "done"
	restart)
		$0 stop
                sleep 4
		$0 start
		echo "Usage: $DSM { start | stop | restart}" >&2
		exit 1
