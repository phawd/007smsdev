#!/bin/sh
# init.d script for the wan_mgr listed
WAN_MGR=wan_mgrd
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
   start)
       echo -n "Starting $WAN_MGR: "
       start-stop-daemon -S -b -a /opt/nvtl/bin/$WAN_MGR
       echo "done"
       ;;
   stop)
       echo -n "Stopping $WAN_MGR: "
       start-stop-daemon -K -x /opt/nvtl/bin/$WAN_MGR
       sleep 1
       echo "done"
       ;;
   restart)
       $0 stop
       $0 start
       ;;
       echo "Usage: $WAN_MGR { start | stop | restart}" >&2
       exit 1
       ;;
