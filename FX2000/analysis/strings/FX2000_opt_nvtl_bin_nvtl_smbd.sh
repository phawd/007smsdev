#!/bin/sh
# nvtl_smbd.sh <start | stop>
# Start / stop smbd
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
export PATH=$PATH:/opt/nvtl/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
DAEMON_SMB=/usr/sbin/smbd
LOG=$LOGDIR/sambalog
do_stop()
	PID=`pidof $1` >> $LOG
	if [ -n "$PID" ]; then
		echo "Stopping $1,  pid = $PID" >> $LOG
		nvtl_log -p 1 -m FILE_SHARING -l notice -s "Stopping $1: pid=$PID"
		killall $1 >> $LOG
	COUNTER=0
	while [ $COUNTER -lt 10 ]; do
		PID=`pidof $1` >> $LOG
		if [ -n "$PID" ]; then
			echo "waiting for $1 to die..." >> $LOG
			kill -1 $PID >> $LOG
			sleep 1
			break
		let COUNTER=COUNTER+1
	if [ $COUNTER -ge 10 ]; then
		echo "$1 did not die, force killing" >> $LOG
		nvtl_log -p 1 -m FILE_SHARING -l notice -s "$1 did not die, force killing"
		kill -9 $PID >> $LOG
		echo "$1 has stopped" >> $LOG
		nvtl_log -p 0 -m FILE_SHARING -l notice -s "$1 has stopped"
case "$1" in
  start)
	echo -n "Starting $DAEMON_SMB: "
	start-stop-daemon -S -x "$DAEMON_SMB" -- -D
	echo "done"
	echo -n "Stopping $DAEMON_SMB: "
	do_stop smbd
	echo "done"
	echo "Usage: $0 {start | stop}"
