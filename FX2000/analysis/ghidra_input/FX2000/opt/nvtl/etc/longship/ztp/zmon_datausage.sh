#!/bin/sh
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
DBFILE="/opt/nvtl/data/longship/ztp/datausage"
TUNNELFILE="/opt/nvtl/data/longship/ztp/tunnelStatus.txt"
TMPDBFILE="/opt/nvtl/data/longship/ztp/datausage.tmp"
BOOTUPDB="/tmp/longship/db_bootup_snapshot"

period=$1
if [ ! -d "/tmp/longship" ]; then
        mkdir -p /tmp/longship
fi

date_str="`date`"
if [ -f "/tmp/longship/data_usage_monitor" ]; then
	echo "$date_str: $0 already running!!. This should never happend!!!" >>/tmp/longship/data_usage_monitor
	exit 1
else
	echo "$date_str: $0 Started" >> /tmp/longship/data_usage_monitor
fi

cp $DBFILE $BOOTUPDB
while true
do
	if [ -f $TMPDBFILE ]; then 
		rm -f $TMPDBFILE
	fi
	longship_cli update_data_usage $DBFILE $TUNNELFILE $TMPDBFILE 0 >>/tmp/longship/data_usage_monitor.log
	if [ -f $TMPDBFILE ]; then
		mv $TMPDBFILE $DBFILE
	fi 
        sleep $period
	rm -f /tmp/longship/data_usage_monitor.log
done
rm -f /tmp/longship/data_usage_monitor

