#!/bin/sh
# init.d script for the factory_reset listed
FACTORY_RESET=factory_resetd
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
		echo -n "Starting $FACTORY_RESET: "
		start-stop-daemon -S -b -a /opt/nvtl/bin/$FACTORY_RESET
		echo "done"
		echo -n "Stopping $FACTORY_RESET: "
		start-stop-daemon -K -x /opt/nvtl/bin/$FACTORY_RESET
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $FACTORY_RESET { start | stop | restart}" >&2
		exit 1
