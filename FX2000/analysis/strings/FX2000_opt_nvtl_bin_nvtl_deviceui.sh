#!/bin/sh
# init.d script for the webui listed
DEVUI_FRAMEWORK=devuid
DEVUI_LOG_VERSION_COMMAND="devuid -version"
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib:/opt/nvtl/data/branding/lib
case $1 in
		echo -n "Starting $DEVUI_FRAMEWORK: "
		$DEVUI_LOG_VERSION_COMMAND
		start-stop-daemon -S -b -a /opt/nvtl/bin/$DEVUI_FRAMEWORK
		echo "done"
		echo -n "Stopping $DEVUI_FRAMEWORK: "
		start-stop-daemon -K -x /opt/nvtl/bin/$DEVUI_FRAMEWORK
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $DEVUI_FRAMEWORK { start | stop | restart}" >&2
		exit 1
