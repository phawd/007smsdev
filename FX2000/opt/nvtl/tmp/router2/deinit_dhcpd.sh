#!/bin/sh

ROUTER_CMD_LOGS=/opt/nvtl/tmp/router2/router2-log 

touch $ROUTER_CMD_LOGS 
chmod 0664 $ROUTER_CMD_LOGS 
print_if_failed () 
{ 
    if [ `wc -l $ROUTER_CMD_LOGS | cut -d ' ' -f1` -gt 10000 ]; then 
        echo "$(tail -n 1000 $ROUTER_CMD_LOGS)" > $ROUTER_CMD_LOGS 
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

nvtl_log -p 1 -m "ROUTER" -l "notice" -s "/opt/nvtl/tmp/router2/deinit_dhcpd.sh: stopping dhcpd " 
print_if_failed /opt/nvtl/bin/stop_process.sh dhcpd
print_if_failed exit 0
