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

# Reset the linux routing stack of previous configurations.
print_if_failed iptables --flush -t filter
print_if_failed iptables --flush -t mangle
print_if_failed iptables --flush -t nat
# Setup bridge.
print_if_failed brctl addbr br0
print_if_failed brctl setfd br0 0
print_if_failed ifconfig br0 192.168.11.1 up
print_if_failed ifconfig br0 netmask 255.255.255.0

echo "0" > /proc/sys/net/ipv4/ip_forward 
print_command echo "0" \> /proc/sys/net/ipv4/ip_forward 
echo "0" > /proc/sys/net/ipv6/conf/all/forwarding
print_command echo "0" \> /proc/sys/net/ipv6/conf/all/forwarding
echo "0" > /proc/sys/net/ipv6/conf/all/proxy_ndp
print_command echo "0" \> /proc/sys/net/ipv6/conf/all/proxy_ndp
print_command iptables -t nat -I PREROUTING -p tcp -i br0 -d 192.168.11.1 --dport 80 -j DNAT --to 192.168.11.1 
print_command sh /opt/nvtl/tmp/router2/init_internet_block.sh
# start dhcp server.
print_if_failed touch /opt/nvtl/tmp/router2/dhcpd.leases
print_if_failed sh /opt/nvtl/tmp/router2/init_dhcpd.sh

# Test script hooks for debugging only.
if [ -f /root/router_test_init.sh ]
then
    source /root/router_test_init.sh
fi
print_if_failed exit 0
