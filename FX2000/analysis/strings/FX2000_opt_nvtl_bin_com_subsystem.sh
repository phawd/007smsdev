#!/bin/sh
# init.d script for the com_subsystem listed
COM_SUBSYSTEM=com_subsystemd
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
		echo -n "Starting $COM_SUBSYSTEM: "
		/opt/nvtl/bin/ipq_com_ip.sh start
		start-stop-daemon -S -b -a /opt/nvtl/bin/$COM_SUBSYSTEM
		echo -n "Stopping $COM_SUBSYSTEM: "
		/opt/nvtl/bin/ipq_com_ip.sh stop
		start-stop-daemon -K -x /opt/nvtl/bin/$COM_SUBSYSTEM
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $COM_SUBSYSTEM { start | stop | restart}" >&2
		exit 1
