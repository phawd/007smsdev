#Script to update IPSec Connection Failure Reason.
#Usage- sh <script-name> <tun_idx>
#Return Connection Failure Reason.
#!/bin/sh

LOG="/opt/nvtl/tmp/vpn/ipsec/ipsec_conn$1_log"
state_cmd="establishing IKE_SA failed, peer not responding"
var=`grep -i "$state_cmd" $LOG`
if [ ! -z "$var" ]; then
  echo 7
else
  state_cmd="received NO_PROPOSAL_CHOSEN notify error"
  var=`grep -i "$state_cmd" $LOG`
  if [ ! -z "$var" ]; then
    echo 8
  else
    echo 0
  fi
fi