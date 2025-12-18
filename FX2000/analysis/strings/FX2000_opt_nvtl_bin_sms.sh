#!/bin/sh
# init.d script for the sms listed
SMS=smsd
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
		echo -n "Starting $SMS: "
		start-stop-daemon -S -b -a /opt/nvtl/bin/$SMS
		echo "done"
		echo -n "Stopping $SMS: "
		start-stop-daemon -K -x /opt/nvtl/bin/$SMS
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $SMS { start | stop | restart}" >&2
		exit 1
