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

print_if_failed ebtables -I INPUT -s 00:15:ff:85:73:98 -p IPv4 --ip-dst ! 192.168.11.1 -j CONTINUE
print_if_failed ebtables -I INPUT -s 00:15:ff:85:73:98 -p IPv6 --ip6-dst ! fe80::44f0:f9ff:fefa:66ef -j CONTINUE
print_if_failed ebtables -I OUTPUT -p IPv4 -d 00:15:ff:85:73:98 --ip-src ! 192.168.11.1 -j CONTINUE
print_if_failed ebtables -I OUTPUT -p IPv6 -d 00:15:ff:85:73:98 --ip6-src ! fe80::44f0:f9ff:fefa:66ef -j CONTINUE
print_if_failed exit 0
