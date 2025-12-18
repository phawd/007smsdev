#!/bin/sh
# INIT script for mifi_debugd
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
DEBUG_CONF_FILE=/opt/nvtl/data/logging/mifi_dbg.conf
DEFAULT_DEBUG_CONF_FILE=/opt/nvtl/etc/logging/mifi_dbg.conf
case "$1" in
  start)
	if [ ! -f $DEBUG_CONF_FILE ]; then
		cp $DEFAULT_DEBUG_CONF_FILE $DEBUG_CONF_FILE
        echo -n "Starting mifi_debugd: "
        start-stop-daemon -S -b -a /opt/nvtl/bin/mifi_debugd
        echo "done"
        ;;
        echo -n "Stopping mifi_debugd: "
        start-stop-daemon -K -n mifi_debugd
        echo "done"
        ;;
  restart)
        $0 stop
        $0 start
        ;;
        echo "Usage mifi_debugd { start | stop | restart}" >&2
        exit 1
        ;;
