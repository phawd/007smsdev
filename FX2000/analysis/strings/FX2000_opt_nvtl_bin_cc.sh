#!/bin/sh
# init.d script for the cc listed
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
		echo -n "Starting $CC: "
		start-stop-daemon -S -b -a /opt/nvtl/bin/$CC
		echo "done"
		echo -n "Stopping $CC: "
		start-stop-daemon -K -x /opt/nvtl/bin/$CC
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $CC { start | stop | restart}" >&2
		exit 1
