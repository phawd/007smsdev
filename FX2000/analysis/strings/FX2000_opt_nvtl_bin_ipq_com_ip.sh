#!/bin/sh
# INIT script for starting ipq ip communcation
case "$1" in
  start)
        echo -n "Starting ipq ip communication: "
        ifconfig mhi_swip0 10.10.10.3 up && ifconfig mhi_swip0
        ip neigh add 10.10.10.7 lladdr 70:71:aa:4b:29:77 nud permanent dev mhi_swip0
        echo "done"
        ;;
        ;;
  restart)
        $0 stop
        $0 start
        ;;
        echo "Usage syslogd { start | stop | restart}" >&2
        exit 1
        ;;
