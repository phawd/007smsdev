#!/bin/sh
# init.d script for the bckrst listed
BCKRST=bckrstd
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
		echo -n "Starting $BCKRST: "
		start-stop-daemon -S -b -a /opt/nvtl/bin/$BCKRST
		echo "done"
		echo -n "Stopping $BCKRST: "
		start-stop-daemon -K -x /opt/nvtl/bin/$BCKRST
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $BCKRST { start | stop | restart}" >&2
		exit 1
