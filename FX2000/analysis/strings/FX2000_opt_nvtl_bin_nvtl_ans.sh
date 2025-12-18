#!/bin/sh
# init.d script for ans
export PATH=$PATH:/opt/nvtl/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
APP=ansd
APPDIR=/opt/nvtl/bin
do_start()
    PID=`pidof $APP`
    if [ -z "$PID" ]
    then
	    echo "Starting $APP"
   	    ${APPDIR}/${APP} &
    else
        echo "$APP is already running"
do_stop()
    PID=`pidof $APP`
    if [ -n "$PID" ]
    then
  	    echo "Stopping $APP,  pid = $PID"
	    kill $PID
	COUNTER=0   
    while [ $COUNTER -lt 10 ]
        PID=`pidof $APP`
        if [ -n "$PID" ] 
        then
            echo "waiting for $APP to die..."
            sleep 1
        else
            break
        fi
        let COUNTER=COUNTER+1
    done
    if [ $COUNTER -ge 10 ] 
    then
        echo "$APP did not die, force killing"
        kill -9 $PID
    else
        echo "$APP has stopped"
case $1 in
    	do_start
        ;;
    stop)
        do_stop
	restart)
		do_stop
		do_start
		echo "Invalid script action"
		exit 1
