#!/bin/sh
# init.d script for the omadm listed
LWM2M_WATCHDOG=lwm2m_watchdogd
LWM2M_APP_START=lwm2m_app_start
LWM2M_APP=lwm2md
LWM2M_CLI="lwm2m_model_cli"
LWM2M_APP_SH=lwm2m_app.sh
LWM2M_PATH="/opt/nvtl/bin"
LWM2M_APP_SH_PID=`pidof $LWM2M_APP_SH`
export SHELL=/bin/sh PATH=/opt/nvtl/data/branding/bin:$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=/opt/nvtl/data/branding/lib:$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
    start)  
        if [ -z "$LWM2M_APP_SH_PID" ]
        then
            echo -n "Starting $LWM2M_APP_START: "
            ${LWM2M_PATH}/${LWM2M_APP_START} &
            echo "done"
        fi
        echo -n "Starting $LWM2M_WATCHDOG: "
        ${LWM2M_PATH}/${LWM2M_WATCHDOG} &
        echo "done"
        ;;
    stop)
        echo -n "Stopping $LWM2M_WATCHDOG: "
        killall $LWM2M_WATCHDOG
        echo "done"
        LWM2M_APP_PID=`pidof $LWM2M_APP`
        if [ -n "$LWM2M_APP_PID" ]
        then
            echo -n "Stopping $LWM2M_APP: "
            kill -9 $LWM2M_APP_PID
        fi
        killall $LWM2M_APP_START
        sleep 1
        SPID=`pidof $LWM2M_APP_SH`
        if [ -n "$SPID" ]
        then
            kill -9 $SPID
        fi
        sleep 2
        ${LWM2M_PATH}/${LWM2M_CLI} dm_call_stop
        sleep 1
        ${LWM2M_PATH}/${LWM2M_CLI} dm_call_stop
        sleep 1
        rm -rf /tmp/lwm2m_socket_connection_recv_time
        rm -rf /tmp/lwm2m_socket_connection_send_time
        rm -rf /tmp/lwm2m_socket_connection_send_failed
        rm -rf /tmp/lwm2m_application_started
        rm -rf /tmp/watch_lwm2m_application
        rm -rf /tmp/kill_lwm2m_app
        sync
        sync
        sleep 1
        echo "done"
        ;;
    restart)
        $0 stop
        sleep 2
        $0 start
        ;;
        echo "Usage: lwm2m_watchdog.sh { start | stop | restart}" >&2
        exit 1
        ;;
