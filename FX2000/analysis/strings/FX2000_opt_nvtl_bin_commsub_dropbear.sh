#!/bin/sh
# INIT script for starting dropbear for communication subsystem
case "$1" in
  start)
        echo -n "Starting dropbear: "
        start-stop-daemon -S -b -a /usr/sbin/dropbear -- -r /etc/dropbear/dropbear_rsa_key 
        echo "done"
        ;;
        echo -n "Stopping dropbear: "
        start-stop-daemon -K -n dropbear
        echo "done"
        ;;
  restart)
        $0 stop
        $0 start
        ;;
        echo "Usage $0 { start | stop | restart } { always | once } " >&2
        exit 1
        ;;
