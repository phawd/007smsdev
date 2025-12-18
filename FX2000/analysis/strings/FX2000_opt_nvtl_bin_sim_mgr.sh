#!/bin/sh
# init.d script for the sim_mgr listed
SIM_MGR=sim_mgrd
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
		echo -n "Starting $SIM_MGR: "
		start-stop-daemon -S -b -a /opt/nvtl/bin/$SIM_MGR
		echo "done"
		echo -n "Stopping $SIM_MGR: "
		start-stop-daemon -K -x /opt/nvtl/bin/$SIM_MGR
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $SIM_MGR { start | stop | restart}" >&2
		exit 1
