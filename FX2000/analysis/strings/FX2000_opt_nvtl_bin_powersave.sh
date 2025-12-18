#!/bin/sh
# init.d script for the powersave listed
POWERSAVE=powersaved
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
RUNLEVEL=`runlevel | awk '{print $2}'`
case $1 in
		echo -n "Starting $POWERSAVE: "
		start-stop-daemon -S -b -a /opt/nvtl/bin/power_config.sh
		start-stop-daemon -S -b -a /opt/nvtl/bin/$POWERSAVE
		echo "done"
		echo -n "Stopping $POWERSAVE: "
		start-stop-daemon -K -x /opt/nvtl/bin/$POWERSAVE
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $POWERSAVE { start | stop | restart}" >&2
		exit 1
