#!/bin/sh
# init.d script for the longship listed
LONGSHIP=longshipd
NVTL_LOG="/opt/nvtl/bin/nvtl_log"
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
if [ -f "/opt/nvtl/data/longship/new/bin/longship_new.sh" ]; then
	$NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "Found longship_new"
	if [ ! -x "/opt/nvtl/data/longship/new/bin/longship_new.sh" ]; then
		chmod +x /opt/nvtl/data/longship/new/bin/longship_new.sh
	/opt/nvtl/data/longship/new/bin/longship_new.sh $1
case $1 in
		echo -n "Starting $LONGSHIP: "
		start-stop-daemon -S -b -a /opt/nvtl/bin/$LONGSHIP
		echo "done"
		echo -n "Stopping $LONGSHIP: "
		killall zmon_datausage.sh 	
		start-stop-daemon -K -x /opt/nvtl/bin/$LONGSHIP
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $LONGSHIP { start | stop | restart}" >&2
		exit 1
