#!/bin/sh
# init.d script for the omadm listed
LWM2M=lwm2m_modeld
LWM2M_APP_BIN=lwm2md
LWM2M_WATCHDOG_SH=lwm2m_watchdog.sh
LWM2M_APP_START=lwm2m_app_start
LWM2M_LOG_SH=lwm2m_logger.sh
LWM2M_APP_SH=lwm2m_app.sh
LWM2M_DATA_DIR="/opt/nvtl/data/lwm2m"
LWM2M_CLI=lwm2m_model_cli
LWM2M_PATH="/opt/nvtl/bin"
export SHELL=/bin/sh PATH=/opt/nvtl/data/branding/bin:$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=/opt/nvtl/data/branding/lib:$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
        start)
                echo -n "Starting $LWM2M: "
                if [ ! -d ${LWM2M_DATA_DIR} ]; then
                        mkdir -p ${LWM2M_DATA_DIR}
                fi
                ${LWM2M_PATH}/${LWM2M_LOG_SH} &
                start-stop-daemon -S -b -a $LWM2M_PATH/$LWM2M
                echo "done"
                echo -n "Starting $LWM2M_WATCHDOG_SH: "
                ${LWM2M_PATH}/${LWM2M_WATCHDOG_SH} start
                echo "done"
                ;;
        stop)
                echo -n "Stopping $LWM2M: "
                PID=`pidof $LWM2M_LOG_SH`
                if [ -n "$PID" ]
                then
                        kill -9 $PID
                fi
                ${LWM2M_PATH}/${LWM2M_CLI} dm_call_stop
                sleep 1
                ${LWM2M_PATH}/${LWM2M_CLI} dm_call_stop
                sleep 1
                start-stop-daemon -K -x $LWM2M_PATH/$LWM2M
                echo -n "Stopping $LWM2M_WATCHDOG_SH: "
                ${LWM2M_PATH}/${LWM2M_WATCHDOG_SH} stop
                sleep 1
                killall $LWM2M_APP_START
                sleep 1
                killall $LWM2M_APP_BIN
                sleep 1
                SPID=`pidof $LWM2M_APP_SH`
		if [ -n "$SPID" ]
			kill -9 $SPID
                sleep 2
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
        *)
                echo "Usage: lwm2m.sh { start | stop | restart}" >&2
                exit 1
                ;;
