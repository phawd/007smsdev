#!/bin/sh
# init.d script for the vpn listed
VPN=vpnd
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
		echo -n "Starting $VPN: "
		start-stop-daemon -S -b -a /opt/nvtl/bin/$VPN
		echo "done"
		echo -n "Stopping $VPN: "
		start-stop-daemon -K -x /opt/nvtl/bin/$VPN
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $VPN { start | stop | restart}" >&2
		exit 1
