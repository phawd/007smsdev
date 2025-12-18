#!/bin/sh
export LD_LIBRARY_PATH=/opt/nvtl/lib:$LD_LIBRARY_PATH
tunnelDetails="/opt/nvtl/data/longship/ztp/TunnelDetails.txt"
miscDetails="/opt/nvtl/data/longship/ztp/MiscDetails.txt"
NVTL_LOG="/opt/nvtl/bin/nvtl_log"

longshipStartZabbix()
{
    serverIP="`sed -n 's/serverIP=//p' $tunnelDetails`"
    zHostName="`sed -n 's/zHostName=//p' $miscDetails`"    	
    if [ -z "$zHostName" ]; then
	$NVTL_LOG -p1 -m "LONGSHIP" -l err -s "Missing zHostName!!"
        exit 1
    fi
    cp /etc/zabbix_agentd.conf /opt/nvtl/data/longship/ztp/zabbix_agentd.conf
    sed -i 's/# User=.*/User='longmifisd'/' /opt/nvtl/data/longship/ztp/zabbix_agentd.conf
    sed -i 's/Server=.*/Server='$serverIP'/' /opt/nvtl/data/longship/ztp/zabbix_agentd.conf
    sed -i 's/Hostname=.*/Hostname='$zHostName'/' /opt/nvtl/data/longship/ztp/zabbix_agentd.conf
    sed -i 's/ServerActive=.*/ServerActive='$serverIP'/' /opt/nvtl/data/longship/ztp/zabbix_agentd.conf
    sed -i 's/# AllowRoot=.*/AllowRoot='1'/' /opt/nvtl/data/longship/ztp/zabbix_agentd.conf
    sed -i 's/# Timeout=.*/Timeout='20'/' /opt/nvtl/data/longship/ztp/zabbix_agentd.conf
    sed -i 's/# Include=\/usr\/local\/etc\/zabbix_agentd.conf.d\/\*\.conf/Include=\/etc\/zabbix_agentd.conf.d\//' /opt/nvtl/data/longship/ztp/zabbix_agentd.conf
    /bin/zabbix_agentd --config /opt/nvtl/data/longship/ztp/zabbix_agentd.conf
}

longshipStopZabbix()
{
   killall zabbix_agentd
}

if [ "$1" == "start" ]; then
    longshipStartZabbix
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "ZTP Zabbix Started!!"
elif [ "$1" == "stop" ]; then
    longshipStopZabbix
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "ZTP Zabbix Stopped!!"
fi
	
exit 0
