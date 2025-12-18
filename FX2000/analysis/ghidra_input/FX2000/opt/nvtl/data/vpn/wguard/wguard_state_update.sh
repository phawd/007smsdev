#Script to update WGuard current connection status.
#Usage- sh <script-name> <conn-name>
#Return connection status.
#!/bin/sh

WGUARD_CMD_LOGS=/opt/nvtl/tmp/vpn/wguard/wgvpn-log
state_cmd="wg show wg$1"
wgshow=$($state_cmd)
date_str=$(date)
printf "${date_str} :\n ${wgshow}
" >> $WGUARD_CMD_LOGS
if [ -z "$wgshow" ] ; then
  date_str=$(date)
  printf "${date_str} :wg$1 - NOT CONNECTED\n" >> $WGUARD_CMD_LOGS
  cur_state=0 #VPN_STATE_NOTCONNECTED
else
  handshake=$($state_cmd | grep "latest handshake:")
  if [ -z "$handshake" ] ; then
    date_str=$(date)
    printf "${date_str} : wg$1: Running, still not connected. Please check network connectivity.\n" >> $WGUARD_CMD_LOGS
    cur_state=4 #VPN_STATE_CONNECT_FAILED
  else
    inhour=$($state_cmd | grep "latest handshake:" | grep -i "hour")
    if [ ! -z "$inhour" ] ; then
      date_str=$(date)
      printf "${date_str} : wg$1: Running, network might be down.\n" >> $WGUARD_CMD_LOGS
      cur_state=5 #VPN_STATE_STALE_HANDSHAKE
    else
      inmin=$($state_cmd | grep "latest handshake:" | grep -i "minute")
      if [ -z "$inmin" ] ; then
        date_str=$(date)
        printf "${date_str} : wg$1: Running and Connected.\n" >> $WGUARD_CMD_LOGS
        cur_state=2 #VPN_STATE_CONNECTED
      else
        min=$($state_cmd | grep "latest handshake:" | cut -f2 -d':' | cut -f2 -d' ')
        #min=`echo $min | sed -e 's/ //g'`
        date_str=$(date)
        if [[ $min -gt 2 ]] ; then
          printf "${date_str} : wg$1: Running, but not active from more than ${min} minutes.\n" >> $WGUARD_CMD_LOGS
          cur_state=5 #VPN_STATE_STALE_HANDSHAKE
        else
          printf "${date_str} : wg$1: Running and Connected.\n" >> $WGUARD_CMD_LOGS
          cur_state=2 #VPN_STATE_CONNECTED
        fi
      fi
    fi
  fi
fi
echo $cur_state
