#!/bin/sh
# INIT script for starting diag_read 
export SHELL=/bin/sh
export PATH=$PATH:/opt/nvtl/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
CHKDIAG=`ls /sys/kernel/config/usb_gadget/g1/functions | grep -q diag`
case "$1" in
  start)
        # check if diag port is present or not before starting
        # diag_read app
        if $CHKDIAG ; then
                echo -n "Starting diag_read: "
                nvtl_log -p 1 -m DIAGREAD -l notice -s "Starting diag_read"
                start-stop-daemon -S diag_read -a /opt/nvtl/bin/diag_read --oknodo
                if [ $? -eq 0 ]; then
                        echo "done"
                else
                        echo "error $? starting daemon!"
                fi
        else
                echo "Not starting diag_read"
                nvtl_log -p 1 -m DIAGREAD -l notice -s "Not starting diag_read"
        fi
        ;;
        echo -n "Stopping diag_read: "
        start-stop-daemon -K -n diag_read
        echo "done"
        ;;
  restart)
        $0 stop
        $0 start
        ;;
        echo "Usage diag_read { start | stop | restart}" >&2
        exit 1
        ;;
