#!/bin/sh
# init.d script for the nua listed
NUA=nuad
NUA_WATCHDOG=nua_timer_watchdogd
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
		#echo "Starting nua_cli listen"
		#/opt/nvtl/bin/nua_cli listen &
		echo -n "Starting $NUA: "
		start-stop-daemon -S -b -a /opt/nvtl/bin/$NUA
		echo -n "Starting $NUA_WATCHDOG: "
		/opt/nvtl/bin/$NUA_WATCHDOG &
		echo -n "Stopping $NUA: "
		start-stop-daemon -K -x /opt/nvtl/bin/$NUA
		echo -n "Stopping $NUA_WATCHDOG"
		killall $NUA_WATCHDOG
		#echo -n "Stopping nua_cli"
		#killall nua_cli
		echo "done"
	restart)
		$0 stop
		sleep 2
		$0 start
		echo "Usage: $NUA { start | stop | restart}" >&2
		exit 1
