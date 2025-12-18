#!/bin/sh
# init.d script for the file_sharing listed
FILE_SHARING=file_sharingd
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
		echo -n "Starting $FILE_SHARING: "
		start-stop-daemon -S -b -a /opt/nvtl/bin/$FILE_SHARING
		echo "done"
		echo -n "Stopping $FILE_SHARING: "
		start-stop-daemon -K -x /opt/nvtl/bin/$FILE_SHARING
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $FILE_SHARING { start | stop | restart}" >&2
		exit 1
