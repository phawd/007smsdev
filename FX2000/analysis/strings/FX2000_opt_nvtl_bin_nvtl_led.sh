#!/bin/sh
# init.d script for LED subsystem.
export PATH=$PATH:/opt/nvtl/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
APP=ledd
APPDIR=/opt/nvtl/bin
###########################################################################
# Function to start the application.
###########################################################################
do_start()
    PID=`pidof $APP`
    if [ -z "$PID" ]
    then
	    echo "Starting $APP"
   	    ${APPDIR}/${APP} &
    else
        echo "$APP is already running"
###########################################################################
# Function to stop the application.
###########################################################################
do_stop()
    PID=`pidof $APP`
    if [ -n "$PID" ]
    then
  	    echo "Stopping $APP,  pid = $PID"
	    killall $APP
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
        killall -s 9 $APP
    else
        echo "$APP has stopped"
###########################################################################
# Execute user command. Starts in run level 3 or 4. 
# else kills for all other run levels
###########################################################################
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
#End of the script
