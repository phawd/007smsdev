#!/bin/sh
export LD_LIBRARY_PATH=/opt/nvtl/lib:$LD_LIBRARY_PATH
tunnelDetails="/opt/nvtl/data/longship/ztp/TunnelDetails.txt"
longshipPass="/opt/nvtl/data/longship/ztp/ztp_user.txt"
dropbearRSAKey="/opt/nvtl/data/longship/ztp/dropbear_rsa_host_key"
NVTL_LOG="/opt/nvtl/bin/nvtl_log"

Port=$2

longshipSSHCreateKey()
{
    dropbearkey -t rsa -f $dropbearRSAKey
}

longshipSSHStart()
{
    tunnelIP="`sed -n 's/tunnelIP=//p' $tunnelDetails`"
    pid=`pgrep -n dropbear`
    if [ ! -z $pid ]; then # If there is already running process
       kill $pid
    fi
    /usr/sbin/dropbear -r /etc/dropbear/dropbear_rsa_key -p $tunnelIP:$Port
    $NVTL_LOG -p1 -m "monitoring dropbear"
    sh /opt/nvtl/etc/longship/ztp/zmonitor_dropbear.sh $tunnelIP $Port &	
}

longshipSSHStop()
{
if [ -e "/tmp/monitor_dropbear" ]; then
   rm /tmp/monitor_dropbear
fi
   killall dropbear
}

if [ "$1" == "rsa" ]; then
    longshipSSHCreateKey
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "ZTP RSA created!!"
elif [ "$1" == "start" ]; then
    longshipSSHStart
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "ZTP SSH Started!!"
elif [ "$1" == "stop" ]; then
   longshipSSHStop 
   $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "ZTP SSH Stopped!!"
fi
	
exit 0
