#!/bin/sh

ROUTER_CMD_LOGS=/opt/nvtl/tmp/router2/router2-log 

print_if_failed () 
{ 
    if [ `wc -l $ROUTER_CMD_LOGS | cut -d ' ' -f1` -gt 3000 ]; then 
        echo "$(tail -n 500 $ROUTER_CMD_LOGS)" > $ROUTER_CMD_LOGS 
        printf '.....TRUNCATED....\n' >> $ROUTER_CMD_LOGS 
    fi 
    printf "`date |tr -s ' '|cut -d ' ' -f1,3,4` CMD: "%s" from "%s". \n" "$*"  "$0" >>$ROUTER_CMD_LOGS 
    $@ 2>> $ROUTER_CMD_LOGS && return  
    st=$? 
    cmd="$*" 
    printf 'Command: "%s" FAILED with status %d from "%s" Please Fix \n' "$*" "$st" "$0" >>$ROUTER_CMD_LOGS 
    nvtl_log -p 1 -m "ROUTER" -l "error" -s "Command: $cmd, FAILED with status $st from "$0"." 
    return $st 
}

print_command () 
{ 
    printf 'Executing cmd: "%s" from "%s". \n' "$*"  "$0" >> $ROUTER_CMD_LOGS 
}

if [ -d /sys/devices/virtual/net/br0/brif/ ]; then 
    print_if_failed ls /sys/devices/virtual/net/br0/brif/ >/opt/nvtl/tmp/router2/br_ifc
    list_of_ifc=`cat /opt/nvtl/tmp/router2/br_ifc` 
    print_command "list_of_ifc=`cat /opt/nvtl/tmp/router2/br_ifc`" 
fi 
ifc=`ifconfig -a |grep wlan1|tr -s ' ' | cut -d ' ' -f1`
print_command "ifc=`ifconfig -a |grep wlan1|tr -s ' ' | cut -d ' ' -f1`" 
if [ $ifc == "wlan1" ] ; then 
	print_if_failed brctl addif br0 wlan1
fi 

if [ -f /root/router_test_bridge_insert.sh ]
then
	print_if_failed source /root/router_test_bridge_insert.sh wlan1
fi

mac=`ifconfig |grep wlan0|tr -s ' ' |cut -d ' ' -f5`
if [ -z "$mac" ] ; then 
   print_if_failed echo "We failed to find the MAC address of wlan0 interface." 
   mac=`ifconfig |grep 'ecm0\|rndis0'|tr -s ' ' |cut -d ' ' -f5`
fi 
   print_if_failed ifconfig br0 hw ether $mac 
print_if_failed sh /opt/nvtl/tmp/router2/deinit_dhcpd.sh
is_radvd_running=`pidof radvd` 
print_command is_radvd_running=\`pidof radvd\` 
if [ -z "$is_radvd_running"  ] ; then 
	print_if_failed echo "radvd is not running " 
else 
	print_if_failed killall -SIGHUP radvd
fi 
print_if_failed exit 0
