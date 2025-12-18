#!/bin/sh
# init.d script for webserver
export PATH=$PATH:/usr/sbin:/opt/nvtl/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib:/opt/nvtl/data/branding/lib
APP=lighttpd
APPDIR=/usr/sbin
APPOPTIONS="-f /etc/lighttpd/lighttpd.conf"
WEBUI_LOG_VERSION_COMMAND="/opt/nvtl/bin/webuid -version"
SUPPORTED_LOCALES_DIR="/opt/nvtl/webui/public"
SYSSER_FCGI="/opt/nvtl/bin/sysser.fcgi"
HOSTSFILE="/etc/hosts"
UPLOADDATADIR="/opt/nvtl/data/webui/uploads"
WEBUI_CONFIG_FILE="/opt/nvtl/etc/webui/config.xml"
WEBUI_BRANDING_CONFIG_FILE="/opt/nvtl/data/branding/etc/webui/config.xml"
SSLDIR="/opt/nvtl/data/webui/ssl"
LIGHTTPDSSLCONFIGFILE="/opt/nvtl/data/webui/ssl/lighttpd_ssl.conf"
LIGHTTPDREMOTEADMINCONFIGFILE="/opt/nvtl/data/webui/ssl/nvtl_wan_ip_redirect.sh"
if [ -f $WEBUI_BRANDING_CONFIG_FILE ]; then
    CONFIG_FILE=$WEBUI_BRANDING_CONFIG_FILE
    CONFIG_FILE=$WEBUI_CONFIG_FILE
WEBUI_COMMAND="/opt/nvtl/bin/webuid -c $CONFIG_FILE -m /opt/nvtl/etc/webui/menu_layout.json -r /etc/lighttpd/mod_rewrite.conf -p /etc/lighttpd/mod_proxy.conf"
LOG_TO_FILE=1
function log()
    echo "$1"
    if [ $LOG_TO_FILE -eq 1 ]
    then
	    echo "$(date) : $1 " 2>&1 >> /tmp/webuilog
function clearLog()
    >/tmp/webuilog
do_wait_for_webui_init()
    log "BEGIN do_wait_for_webui_init..."
    COUNTER=0   
    while [ $COUNTER -lt 15 ]
        if msgbus_cli MsgBusGet webui.ready | grep "data:\[1\]" > /dev/null 2>&1 ; then
	    break
        else
            #echo "waiting for webui initialization..."
	    log "waiting for webui initialization...$COUNTER"
	    nvtl_log -p 0 -m WEBUI -l debug -s "waiting for webui initialization..."
            sleep 1
        fi
        let COUNTER=COUNTER+1
    done
    log "END do_wait_for_webui_init..."
do_wait_for_hosts_file()
    log "BEGIN do_wait_for_hosts_file..."
    COUNTER=0   
    while [ $COUNTER -lt 10 ]
        if [ -e "$HOSTSFILE" ]; then
            log "$HOSTSFILE file exists"
	    LINECOUNT=$(wc -l $HOSTSFILE | awk '{print $1}')
            if [ $LINECOUNT -gt 1 ]; then
                break
            else
		log "Waiting for Router to update the $HOSTSFILE file..."
                nvtl_log -p 0 -m WEBUI -l debug -s "waiting for router to update $HOSTSFILE file..."
                sleep 1
            fi
        else
	    log "waiting for $HOSTSFILE file..."
	    nvtl_log -p 0 -m WEBUI -l debug -s "waiting for $HOSTSFILE file..."
            sleep 1
        fi
        let COUNTER=COUNTER+1
    done
    if [ $COUNTER = 10 ]; then
        log "END hosts_file do not exit. The web server might not start or start properly..."
    log "END do_wait_for_hosts_file..."
do_create_ssl_dir()
    log "BEGIN do_create_ssl_dir..."
    if [ ! -x "${LIGHTTPDSSLCONFIGFILE}" ]; then
	log "$LIGHTTPDSSLCONFIGFILE file does not exist, creating file and setting executable permission."
        mkdir -p ${SSLDIR}
        echo "#!/bin/sh" > ${LIGHTTPDSSLCONFIGFILE}
        chmod 744 ${LIGHTTPDSSLCONFIGFILE}
    else
	log "$LIGHTTPDSSLCONFIGFILE file exists."
    if [ ! -x "${LIGHTTPDREMOTEADMINCONFIGFILE}" ]; then
	log "$LIGHTTPDREMOTEADMINCONFIGFILE file does not exist, creating file and setting executable permission."
        mkdir -p ${SSLDIR}
        echo "#!/bin/sh" > ${LIGHTTPDREMOTEADMINCONFIGFILE}
        chmod 744 ${LIGHTTPDREMOTEADMINCONFIGFILE}
    else
	log "$LIGHTTPDREMOTEADMINCONFIGFILE file exists."
    log "END do_create_ssl_dir..."
do_start()
    log "BEGIN do_start"
    PID=`pidof $APP`
    if [ -z "$PID" ]
    then
	    do_wait_for_hosts_file
	    do_wait_for_webui_init
            if [ ! -d ${UPLOADDATADIR} ]; then
                mkdir -p ${UPLOADDATADIR}
            fi
	    #echo "Setting permissions for upload dir"
	    log "Setting permissions for upload dir"
	    chown lighttpd:lighttpd ${UPLOADDATADIR}
	    #echo "Clearing upload dir"
	    log "Clearing upload dir"
	    rm -rf ${UPLOADDATADIR}/*
	    #echo "Starting $APP"
	    log "Starting $APP"
	    nvtl_log -p 0 -m WEBUI -l debug -s "Starting $APP"
   	    ${APPDIR}/${APP} ${APPOPTIONS} 2>&1 >> /tmp/webuilog
    else
        #echo "$APP is already running"
	log "$APP is already running"
	nvtl_log -p 0 -m WEBUI -l debug -s "$APP is already running"
    log "END do_start"   
do_log_webui_version()
    log "BEGIN do_log_webui_version"
    ${WEBUI_LOG_VERSION_COMMAND}
    log "END do_log_webui_version"
do_generate_layout_rewrite()
	log "BEGIN do_generate_layout_rewrite"
	while read locale; do
  		WEBUI_COMMAND="$echo $WEBUI_COMMAND -l $locale"
		log "Command:$WEBUI_COMMAND"
	done < $SUPPORTED_LOCALES_DIR/supported_locales
	$WEBUI_COMMAND
	log "END do_generate_layout_rewrite"
do_check_webserver()
	log "BEGIN do_check_webserver"
	# Run in background so the rest of the processes in this runlevel can be started
	nvtl_check_webserver.sh $LOG_TO_FILE &
	log "END do_check_webserver"
do_stop()
    log "BEGIN do_stop"
    PID=`pidof $APP`
    if [ -n "$PID" ]
    then
	    log "Stopping $APP,  pid = $PID"
	    nvtl_log -p 1 -m WEBUI -l info -s "Stopping $APP,  pid = $PID"
	    kill $PID
    COUNTER=0   
    while [ $COUNTER -lt 10 ]
        PID=`pidof $APP`
        if [ -n "$PID" ] 
        then
	    log "waiting for $APP to die..."
	    nvtl_log -p 0 -m WEBUI -l debug -s "waiting for $APP to die..."
            sleep 1
        else
            break
        fi
        let COUNTER=COUNTER+1
    done
    if [ $COUNTER -ge 10 ] 
    then
	log "$APP did not die, force killing"
	nvtl_log -p 1 -m WEBUI -l info -s "$APP did not die, force killing"
        kill -9 $PID
    else
	log "$APP has stopped"
	nvtl_log -p 0 -m WEBUI -l debug -s "$APP has stopped"
    # Kill the webuid process
    log "Stopping webuid: "
    start-stop-daemon -K -x /opt/nvtl/bin/webuid
    log "done"
    # Kill the sysser process
    sysser_pid=`pidof $(basename $SYSSER_FCGI)`
    if [ -n "$sysser_pid" ]
    then
	log "Stopping $SYSSER_FCGI, pid = $sysser_pid "
	nvtl_log -p 1 -m WEBUI -l info -s "Stopping $SYSSER_FCGI,  pid = $sysser_pid"
	kill $sysser_pid
    COUNTER=0
    while [ $COUNTER -lt 10 ]
	sysser_pid=`pidof $(basename $SYSSER_FCGI)`
	if [ -n "$sysser_pid" ]
        then
	    log "waiting for $SYSSER_FCGI to die..."
	    nvtl_log -p 0 -m WEBUI -l debug -s "waiting for $SYSSER_FCGI to die..."
            sleep 1
        else
            break
        fi
        let COUNTER=COUNTER+1
    done
    if [ $COUNTER -ge 10 ]
    then
        log " did not die, force killing"
    	nvtl_log -p 1 -m WEBUI -l info -s "$SYSSER_FCGI did not die, force killing"
        kill -9 $sysser_pid
    else
        log "$SYSSER_FCGI has stopped"
    	nvtl_log -p 0 -m WEBUI -l debug -s "$SYSSER_FCGI has stopped"
do_status()
    log "BEGIN do_status"
    PID=`pidof $APP`
    if [ -n "$PID" ]; then
        log "$APP running, PID = $PID"
	nvtl_log -p 0 -m WEBUI -l debug -s "$APP running, PID = $PID"
    else
        log "$APP is not running"
	nvtl_log -p 1 -m WEBUI -l notice -s "$APP is not running"
case $1 in
    start)
	clearLog
	do_create_ssl_dir
    	do_generate_layout_rewrite
    	do_log_webui_version
    	do_start
	do_check_webserver
        ;;
    stop)
        do_stop
    restart)
	clearLog
	do_stop
	do_create_ssl_dir
    	do_generate_layout_rewrite
    	do_log_webui_version
    	do_start
	do_check_webserver
    status)
        do_status
	echo "usage: $0 {start,stop,restart,status}"
	nvtl_log -p 0 -m WEBUI -l debug -s "usage: $0 {start,stop,restart,status}"
