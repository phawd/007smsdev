#!/bin/sh
# init.d script for the mifi_health listed
MIFI_HEALTH=mifi_healthd
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
		echo -n "Starting $MIFI_HEALTH: "
		start-stop-daemon -S -b -a /opt/nvtl/bin/$MIFI_HEALTH
		echo "done"
		echo -n "Stopping $MIFI_HEALTH: "
		start-stop-daemon -K -x /opt/nvtl/bin/$MIFI_HEALTH
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $MIFI_HEALTH { start | stop | restart}" >&2
		exit 1
