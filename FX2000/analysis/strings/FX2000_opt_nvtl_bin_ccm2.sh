#!/bin/sh
# init.d script for the ccm2 listed
CCM2=ccm2d
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
		echo -n "Starting $CCM2: "
		start-stop-daemon -S -b -a /opt/nvtl/bin/$CCM2
		echo "done"
		echo -n "Stopping $CCM2: "
		start-stop-daemon -K -x /opt/nvtl/bin/$CCM2
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $CCM2 { start | stop | restart}" >&2
		exit 1
