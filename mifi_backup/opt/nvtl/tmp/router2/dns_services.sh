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

nvtl_log -p 1 -m "ROUTER" -l "notice" -s "/opt/nvtl/tmp/router2/dns_services.sh: stopping dnsmasq" 
print_if_failed /opt/nvtl/bin/stop_process.sh dnsmasq
print_if_failed iptables -t nat -D PREROUTING -i br0 -p tcp --dport 80 -d 192.168.11.1 -j DNAT --to 192.168.11.1 
nvtl_log -p 1 -m "ROUTER" -l "notice" -s "/opt/nvtl/tmp/router2/dns_services.sh: starting nvtl_dnsd" 
nvtl_dnsd br0 53 /etc/dns_cache.txt &
print_if_failed iptables -t nat -A PREROUTING -i br0 -p tcp --dport 80  -d 0/0 -j DNAT --to 192.168.11.1 
print_if_failed exit 0
