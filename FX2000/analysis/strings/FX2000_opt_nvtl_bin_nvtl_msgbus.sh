#!/bin/sh
ACTION=$1
APP="msgbusd"
NVTL_BIN="/opt/nvtl/bin"
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
    #Try polite shutdown
    PID=`pidof $APP`
    if [ -n "$PID" ] 
    then
        echo "stopping $APP" 
        killall $APP
    #wait for graceful termination
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
    #force kill if needed
    if [ $COUNTER -ge 10 ] 
    then
        echo "$APP did not die, force killing"
        kill -9 $PID
    else
        echo "$APP has stopped"
start() 
    PID=`pidof $APP`
    if [ -z "$PID" ]
    then
        echo "starting $APP"
        $NVTL_BIN/$APP &
    else
        echo "$APP is already started"
case $1 in
    start)
        start
        ;;
    restart)
        stop
        start
        ;;
    stop)
        stop
        ;;
	echo "Invalid service paramter"
        ;;
