#!/bin/sh
# init.d script for memory compaction.
export PATH=$PATH:/opt/nvtl/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
APP=nvtl_mem_diag.sh
APPDIR=/opt/nvtl/bin
ARG="daemon $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13"
###########################################################################
do_start()
    PID=`pidof $APP`
    if [ -z "$PID" ]
    then
            echo "Starting $APP"
            ${APPDIR}/${APP} ${ARG} &
    else
        echo "$APP is already running"
###########################################################################
do_stop()
    PID=`pidof $APP`
    if [ -n "$PID" ]
    then
            echo "Stopping $APP,  pid = $PID"
            killall $APP
###########################################################################
# Execute user command. Starts in run level 3 or 4.
# else kills for all other run levels
###########################################################################
case $1 in
        start)
                do_start
                ;;
        stop)
                do_stop
                ;;
        restart)
                do_stop
                do_start
                ;;
        *)
                echo "Invalid script action"
                exit 1
                ;;
#End of the script
