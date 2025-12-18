#! /bin/sh
#Copyright (c) 2014 Qualcomm Technologies, Inc.  All Rights Reserved.
#Qualcomm Technologies Proprietary and Confidential.
# qmi_ip   init.d script to start the Data Software's qmi_ip daemon
case "$1" in
  start)
	echo -n "Starting qmi_ip: "
        cp /etc/qmi_ip_cfg.xml /data/qmi_ip_cfg.xml
        start-stop-daemon -S -b -a qrtr-ns
        start-stop-daemon -S -b -a irsc_util
        if [ ! -d /data/data_qcmap ]
        then
                mkdir -p /data/data_qcmap
        fi
        if [ -d /data/data_qcmap/qti ]
        then
                rm -rf /data/data_qcmap/qti
        fi
        start-stop-daemon -S -b -a qti
        start-stop-daemon -S -b -a qmi_ip_multiclient /data/qmi_ip_cfg.xml
        echo "done"
        ;;
        echo -n "Stopping qmi_ip: "
        start-stop-daemon -K -n qmi_ip_multiclient
        echo "done"
        ;;
  restart)
        $0 stop
        $0 start
        ;;
        echo "Usage qmi_ip_multiclient { start | stop | restart}" >&2
        exit 1
        ;;
