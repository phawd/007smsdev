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

LOGFILE='/opt/nvtl/tmp/router2/set_dns_filter.log'
BLACK_LIST='/opt/nvtl/tmp/router2/dns_black_list'
WHITE_LIST='/opt/nvtl/tmp/router2/dns_white_list'
DNSMASQ_CONF_FILE='/etc/dnsmasq.conf'
if ([ $# -lt 1 ] || [ $# -gt 3 ]);then
        echo "Bad arguments passed:Argc - $# " > $LOGFILE
        echo "Usage: sh dns_filter.sh <Delete:0>" >> $LOGFILE
        echo "OR  sh dns_filter.sh <Add:1>  <Black-list:1 or White-list:0> "<URL-list>"" >> $LOGFILE
        exit 1
fi
if [ -f /etc/dnsmasq.conf ];then

        start_var=`grep  -n -m1 "#DNS_FILTERING:BEGIN" $DNSMASQ_CONF_FILE | cut -f1 -d':'`
        end_var=`grep  -n -m1 "#DNS_FILTERING:END" $DNSMASQ_CONF_FILE | cut -f1 -d':'`
        # Delete existing DNS FILTER CONFIGURATION and ADD either Black or White list
        [ ! -z "$start_var" ] && [ ! -z "$end_var" ] && sed -i "${start_var},${end_var}d" $DNSMASQ_CONF_FILE
        if [ $1 == '0' ];then
                echo "DNS Filter Servers Configuration is removed." >> $LOGFILE
                rm -f $BLACK_LIST > /dev/null 2>&1
                rm -f $WHITE_LIST > /dev/null 2>&1
                sh /opt/nvtl/tmp/router2/dns_services.sh
                exit 1
        fi
        URL=`echo $3 | sed "s/[]'[]//g"`
        IFS=','
        if ([ $2 == '0' ] && [ ! -z "$URL" ]);then
                echo "#DNS_FILTERING:BEGIN" > $WHITE_LIST ; > $BLACK_LIST
                    for url in $URL; do
			url=`echo $url | sed "s/^ *//g" | sed "s/ *$//g"`
                       echo "server=/$url/#" >> $WHITE_LIST
                done
                echo "server=/#/" >> $WHITE_LIST
                echo "#DNS_FILTERING:END" >> $WHITE_LIST

                echo "Update white list DNS Servers Configuration." >> $LOGFILE
                cat $WHITE_LIST >> $DNSMASQ_CONF_FILE
        elif ([ $2 == '1' ] && [ ! -z "$URL" ]);then
                echo "#DNS_FILTERING:BEGIN" > $BLACK_LIST ; > $WHITE_LIST
                    for url in $URL; do
			url=`echo $url | sed "s/^ *//g" | sed "s/ *$//g"`
                       echo "server=/$url/" >> $BLACK_LIST
                done
                echo "#DNS_FILTERING:END" >> $BLACK_LIST

                echo "Update white list DNS Servers Configuration." >> $LOGFILE
                cat $BLACK_LIST >> $DNSMASQ_CONF_FILE

        else
                echo "Invalid arguments are passed." >> LOGFILE
                echo "Usage: sh dns_filter.sh <1-black-list , 0 - white-list>." >> $LOGFILE
        fi
 fi
 sh /opt/nvtl/tmp/router2/dns_services.sh
 exit 0
