#!/bin/sh
# init.d script for the tr069 listed
TR069=tr069d
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
		echo -n "Starting $TR069: "
		start-stop-daemon -S -b -a /opt/nvtl/bin/$TR069
		echo "done"
		echo -n "Stopping $TR069: "
		start-stop-daemon -K -x /opt/nvtl/bin/$TR069
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $TR069 { start | stop | restart}" >&2
		exit 1
