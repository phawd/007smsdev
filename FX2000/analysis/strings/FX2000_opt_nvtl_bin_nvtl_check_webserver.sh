#!/bin/sh
# Script used by the INIT script - nvtl_webserver.sh
# Log whether the webserver is working or not
#set -xv
export PATH=$PATH:/usr/sbin:/opt/nvtl/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
LOG_TO_FILE=$1
function log()
    echo "$1"
    if [ $LOG_TO_FILE -eq 1 ]
    then
	    echo "$(date) : $1 " 2>&1 >> /tmp/webuilog
do_check_webserver()
	log "BEGIN do_check_webserver"
	COUNTER=0
	curl_rc=0   
    	while [ $COUNTER -lt 10 ]
		echo "temp"
                webui_cli get_https_enabled > /dev/null
                rc=$?
                if [ $rc -eq 0 ]; then
                        enabled=$(webui_cli get_https_enabled | grep "enabled:" | awk -F ":" '{printf("%s", $2); }' | sed 's/\[//g' | sed 's/\]//g')
                        #http or https check
                        if [ $enabled -eq 0 ]; then
                                log "http found, checking with http request"
                                curl --silent http://webapi.nvtl > /dev/null
                                curl_rc=$?
                        else
                                port=$(webui_cli get_https_port | grep "port:" | awk -F ":" '{printf("%s", $2); }' | sed 's/\[//g' | sed 's/\]//g')
                                if [ $port -eq 443 ]; then
                                        log "https at default port found, checking with https request"
                                        curl --silent https://webapi.nvtl -k > /dev/null
                                        curl_rc=$?
                                else
                                        log "https at port $port found, checking with https request"
                                        curl --silent https://webapi.nvtl:$port -k > /dev/null
                                        curl_rc=$?
                                fi
                        fi
                else
                        log "webui_cli get_https_enabled failed"
                        $curl_rc=-1
                fi
        	if [ $curl_rc -eq 0  ]; then
	    		break
        	else
			log "waiting for webserver to start..."
			nvtl_log -p 0 -m WEBUI -l debug -s "waiting for webserver to start..."
            		sleep 1
        	fi
        	let COUNTER=COUNTER+1
    	done
	if [[ $curl_rc != 0 ]]
		log "Webserver launch failed. Webserver not reachable."
		nvtl_log -p 1 -m WEBUI -l err -s "Webserver launch failed. Webserver not reachable. Check webserver configuration files."
		log "Webserver launched successfully."
		nvtl_log -p 1 -m WEBUI -l info -s "Webserver launched successfully."
	log "END do_check_webserver"
do_check_webserver
