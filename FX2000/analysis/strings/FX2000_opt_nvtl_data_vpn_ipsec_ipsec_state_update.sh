#Script to update IPSec current connection status.
#Usage- sh <script-name> <conn-name>
#Return connection status.
#!/bin/sh
state_cmd="ipsec status $1"
var=`eval $state_cmd | grep -i established`
if [[ "$var" == "" ]]; then
var=`eval $state_cmd | grep -vi security | grep CONNECTING`
  if [[ "$var" == "" ]]; then
    #DISCONNECTED
    cur_state=3
    if [ -f /opt/nvtl/data/vpn/ipsec/ipsec_failure_update.sh ]; then
      fail=`sh /opt/nvtl/data/vpn/ipsec/ipsec_failure_update.sh $2`
      if [ $fail -ne "0" ]; then
        #CONNECTION_FAILED
        cur_state=4
      fi
    #CONNECTING
    cur_state=1
    #CONNECTED
    cur_state=2
echo $cur_state
