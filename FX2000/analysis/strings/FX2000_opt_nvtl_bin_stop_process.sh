#!/bin/sh
log () {
    nvtl_log -p 1 -m "ROUTER2" -l "$2" -s "stop_process.sh:$1"
PID=`pidof $APP`
if [ -n "$PID" ] ; then
	log "Stopping $APP,  pid = $PID" "debug"
	kill $PID
	COUNTER=0
	while [ $COUNTER -lt 10 ]
		PID=`pidof $APP`
		if [ -n "$PID" ] ; then
			log "waiting for $APP to die..." "debug"
			sleep 1
			break
		let COUNTER=COUNTER+1
	if [ $COUNTER -ge 10 ] ; then
		log "$APP did not die, force killing" "debug"
		kill -9 $PID
		log "$APP has stopped" "debug"
