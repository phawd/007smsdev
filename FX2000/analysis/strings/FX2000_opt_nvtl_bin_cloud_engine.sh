#!/bin/sh
# init.d script for the cloud_engine
APP=cloud_engined
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
		echo "Starting $APP: "
		start-stop-daemon -S -b -a /opt/nvtl/bin/$APP
		echo "Stopping $APP: "
		start-stop-daemon -K -x /opt/nvtl/bin/$APP
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $APP { start | stop | restart}" >&2
		exit 1
