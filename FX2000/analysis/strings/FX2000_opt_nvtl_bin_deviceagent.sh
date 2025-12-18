#!/bin/sh
# init.d script for the deviceagent listed
DEVAGENT=deviceagentd
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
        PID=`pidof $DEVAGENT`
        if [ -z "$PID" ]
        then
            echo -n "Starting $DEVAGENT: "
		    chmod u+s /opt/nvtl/bin/deviceagent_startstop
		    start-stop-daemon -S -b -a /opt/nvtl/bin/$DEVAGENT
		    echo "done"
        else
            echo "$DEVAGENT is already running"
        fi
		echo -n "Stopping $DEVAGENT: "
		start-stop-daemon -K -q -s TERM --exec /opt/nvtl/bin/$DEVAGENT
		sleep 5
		start-stop-daemon -K -q -s KILL --exec /opt/nvtl/bin/$DEVAGENT
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $DEVAGENT { start | stop | restart}" >&2
		exit 1
