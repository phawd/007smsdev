#!/bin/sh
ROUTER_CMD_LOGS=/opt/nvtl/tmp/router2/router2-log 
touch $ROUTER_CMD_LOGS 
chmod 0664 $ROUTER_CMD_LOGS 
print_if_failed () 
    if [ `wc -l $ROUTER_CMD_LOGS | cut -d ' ' -f1` -gt 10000 ]; then 
        echo "$(tail -n 1000 $ROUTER_CMD_LOGS)" > $ROUTER_CMD_LOGS 
        printf '.....TRUNCATED....\n' >> $ROUTER_CMD_LOGS 
    printf "`date |tr -s ' '|cut -d ' ' -f1,3,4` CMD: "%s" from "%s". \n" "$*"  "$0" >>$ROUTER_CMD_LOGS 
    $@ 2>> $ROUTER_CMD_LOGS && return  
    st=$? 
    cmd="$*" 
    printf 'Command: "%s" FAILED with status %d from "%s" Please Fix \n' "$*" "$st" "$0" >>$ROUTER_CMD_LOGS 
    nvtl_log -p 1 -m "ROUTER" -l "error" -s "Command: $cmd, FAILED with status $st from "$0"." 
    return $st 
print_command () 
    printf 'Executing cmd: "%s" from "%s". \n' "$*"  "$0" >> $ROUTER_CMD_LOGS 
# Reset the linux routing stack of previous configurations.
print_if_failed iptables -w --flush -t filter
print_if_failed iptables -w --flush -t mangle
print_if_failed iptables -w --flush -t nat
# Setup bridge.
print_if_failed brctl addbr bridge0
print_if_failed brctl setfd bridge0 0
print_if_failed ifconfig bridge0 10.14.0.1 up
print_if_failed ifconfig bridge0 netmask 255.255.255.0
echo "0" > /proc/sys/net/ipv4/ip_forward 
print_command echo "0" \> /proc/sys/net/ipv4/ip_forward 
echo "0" > /proc/sys/net/ipv6/conf/all/forwarding
print_command echo "0" \> /proc/sys/net/ipv6/conf/all/forwarding
echo "0" > /proc/sys/net/ipv6/conf/all/proxy_ndp
print_command echo "0" \> /proc/sys/net/ipv6/conf/all/proxy_ndp
print_if_failed iptables -w -t filter -N INSEEGO_FILTER_INPUT 
print_if_failed iptables -w -t filter -A INPUT -j INSEEGO_FILTER_INPUT 
print_if_failed iptables -w -t filter -N INSEEGO_FILTER_OUTPUT 
print_if_failed iptables -w -t filter -A OUTPUT -j INSEEGO_FILTER_OUTPUT 
print_if_failed iptables -w -t filter -N INSEEGO_FILTER_FORWARD 
print_if_failed iptables -w -t filter -A FORWARD -j INSEEGO_FILTER_FORWARD 
print_if_failed iptables -w -t mangle -N INSEEGO_MANGLE_PREROUTING 
print_if_failed iptables -w -t mangle -I PREROUTING -j INSEEGO_MANGLE_PREROUTING 
print_if_failed iptables -w -t mangle -N INSEEGO_MANGLE_POSTROUTING 
print_if_failed iptables -w -t mangle -I POSTROUTING -j INSEEGO_MANGLE_POSTROUTING 
print_if_failed iptables -w -t nat -N INSEEGO_NAT_PREROUTING 
print_if_failed iptables -w -t nat -I PREROUTING -j INSEEGO_NAT_PREROUTING 
print_if_failed iptables -w -t nat -N INSEEGO_NAT_POSTROUTING 
print_if_failed iptables -w -t nat -I POSTROUTING -j INSEEGO_NAT_POSTROUTING 
print_if_failed iptables -w -t filter -N INSEEGO_MNGACCS_INPUT 
print_if_failed iptables -w -t filter -N INSEEGO_MNGACCS_OUTPUT 
print_if_failed iptables -w -t filter -N INSEEGO_MNGACCS_FORWARD 
print_if_failed iptables -w -t nat -N INSEEGO_MNGACCS_PREROUTING 
print_if_failed iptables -w -t nat -N INSEEGO_MNGACCS_POSTROUTING 
print_if_failed iptables -w -t nat -N INSEEGO_MNGACCS_INPUT 
print_if_failed iptables -w -t nat -N INSEEGO_MNGACCS_OUTPUT 
print_if_failed iptables -w -t nat -N CUSTOMER_DNS_OVERRIDE 
print_if_failed ip6tables -w -t filter -N INSEEGO_FILTER_INPUT 
print_if_failed ip6tables -w -t filter -I INPUT -j INSEEGO_FILTER_INPUT 
print_if_failed ip6tables -w -t filter -N INSEEGO_FILTER_OUTPUT 
print_if_failed ip6tables -w -t filter -I OUTPUT -j INSEEGO_FILTER_OUTPUT 
print_if_failed ip6tables -w -t filter -N INSEEGO_FILTER_FORWARD 
print_if_failed ip6tables -w -t filter -I FORWARD -j INSEEGO_FILTER_FORWARD 
print_if_failed ip6tables -w -t mangle -N INSEEGO_MANGLE_POSTROUTING 
print_if_failed ip6tables -w -t mangle -A POSTROUTING -j INSEEGO_MANGLE_POSTROUTING 
print_if_failed ip6tables -w -t mangle -N INSEEGO_MANGLE_PREROUTING 
print_if_failed ip6tables -w -t mangle -A PREROUTING -j INSEEGO_MANGLE_PREROUTING 
print_if_failed ip6tables -w -t filter -N INSEEGO_MNGACCS_INPUT 
print_if_failed ip6tables -w -t filter -N INSEEGO_MNGACCS_OUTPUT 
print_if_failed ip6tables -w -t filter -N INSEEGO_MNGACCS_FORWARD 
print_if_failed ip6tables -w -t nat -N INSEEGO_MNGACCS_PREROUTING 
print_if_failed ip6tables -w -t nat -N INSEEGO_MNGACCS_POSTROUTING 
print_if_failed ip6tables -w -t nat -N INSEEGO_MNGACCS_INPUT 
print_if_failed ip6tables -w -t nat -N INSEEGO_MNGACCS_OUTPUT 
print_if_failed ip6tables -w -t nat -N CUSTOMER_DNS_OVERRIDE 
print_if_failed ip6tables -w -t nat -N INSEEGO_NAT_PREROUTING 
print_if_failed ip6tables -w -t nat -I PREROUTING -j INSEEGO_NAT_PREROUTING 
print_if_failed ip6tables -w -t nat -N INSEEGO_NAT_POSTROUTING 
print_if_failed ip6tables -w -t nat -I POSTROUTING -j INSEEGO_NAT_POSTROUTING 
print_command sh /opt/nvtl/tmp/router2/init_internet_block.sh
/usr/sbin/avahi-daemon -f /opt/nvtl/tmp/router2/avahi_daemon.conf -D# start dhcp server.
print_if_failed touch /opt/nvtl/tmp/router2/dhcpd.leases
print_if_failed sh /opt/nvtl/tmp/router2/init_dhcpd.sh
# Test script hooks for debugging only.
if [ -f /root/router_test_init.sh ]
    source /root/router_test_init.sh
print_if_failed exit 0
