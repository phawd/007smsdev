#!/bin/sh
ip=$1
port=$2

tmpfile='/tmp/monitor_dropbear'

touch $tmpfile

while [ 1 ]; do
  sleep 5
  pid=`pgrep -n dropbear`
  if [ -z $pid ]; then # If there is none
    /usr/sbin/dropbear -r /etc/dropbear/dropbear_rsa_key -p $ip:$port
  else
    sleep 10           # Else wait.
  fi
  if [[ ! -e ${tmpfile} ]]; then #If file does not exit, exit from monitoring
      exit 0
  fi
done;
