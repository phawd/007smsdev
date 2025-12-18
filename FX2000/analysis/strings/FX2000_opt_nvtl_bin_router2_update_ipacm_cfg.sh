#!/bin/sh
IPA_FILE_PATH=/etc/data/ipa/IPACM_cfg.xml 
LOG_FILE_PATH=/opt/nvtl/tmp/router2/log_ipa.txt 
silencer()
    if [ -z "$debug" -o "$debug" == "0" ]; then
        $* > /dev/null 2>&1
        else
        $*
       fi
mode=`cat "$IPA_FILE_PATH" | grep IPPassthroughMode | cut -f 2 -d '>' | cut -f 1 -d '<'`
mac=`cat  "$IPA_FILE_PATH" | grep IPPassthroughMacAddr | cut -f 2 -d '>' | cut -f 1 -d '<'`
subnet=`cat "$IPA_FILE_PATH" | grep SubnetAddress | cut -f 2 -d '>' | cut -f 1 -d '<'`
netmask=`cat "$IPA_FILE_PATH" | grep SubnetMask | cut -f 2 -d '>' | cut -f 1 -d '<'`
touch $LOG_FILE_PATH
chmod 664 $LOG_FILE_PATH
ippasstrough_enable(){
	echo "Enable ippt function IPPT:$1 previous mode $mode" >> "$LOG_FILE_PATH"
if [ "$mode" == "$1" ];then
    echo "Input mode equal to existing mode" >> "$LOG_FILE_PATH"	
	sed -i "s/<IPPassthroughMacAddr>"$mac"/<IPPassthroughMacAddr>0/g" "$IPA_FILE_PATH"
	sed -i "s/<IPPassthroughMode>"$mode"/<IPPassthroughMode>$1/g" "$IPA_FILE_PATH"
	sed -i "s/<IPPassthroughMacAddr>"$mac"/<IPPassthroughMacAddr>0/g" "$IPA_FILE_PATH"
mac_update(){
	echo "mac_update MAC:$1 previous mac $mac" >> "$LOG_FILE_PATH"
if [ "$mac" == "$1" ];then
        echo "both macs are equal" >> "$LOG_FILE_PATH"
	sed -i "s/<IPPassthroughMacAddr>"$mac"/<IPPassthroughMacAddr>"$1"/g" "$IPA_FILE_PATH"
subnet_update(){
echo "subnet_update SUBNET:$1 NETMASK:$2 previous subnet $subnet previous netmask $netmask" >> "$LOG_FILE_PATH"
if  [ "$subnet" == "$1" ]  && [ "$netmask" == "$2" ];then
        echo "Input subnet equal to existing subnet" >> "$LOG_FILE_PATH"
sed -i "s/<SubnetAddress>"$subnet"/<SubnetAddress>$1/g" "$IPA_FILE_PATH"
sed -i "s/<SubnetMask>"$netmask"/<SubnetMask>$2/g" "$IPA_FILE_PATH"
ippt_subnet_enable(){
echo "Reboot: " >> "$LOG_FILE_PATH"
echo "ippt_subnet_enable IPPT:$1 previous mode $mode" >> "$LOG_FILE_PATH"
if [ "$mode" == "$1" ];then
    echo "Input mode equal to existing mode" >> "$LOG_FILE_PATH"
        else
         sed -i "s/<IPPassthroughMode>"$mode"/<IPPassthroughMode>$1/g" "$IPA_FILE_PATH"
echo "ippt_subnet_enable SUBNET:$2 NETMASK:$3 previous subnet $subnet previous netmask $netmask" >> "$LOG_FILE_PATH"
if  [ "$subnet" == "$2" ]  && [ "$netmask" == "$3" ];then
        echo "Input subnet equal to existing subnet" >> "$LOG_FILE_PATH"
sed -i "s/<SubnetAddress>"$subnet"/<SubnetAddress>$2/g" "$IPA_FILE_PATH"
sed -i "s/<SubnetMask>"$netmask"/<SubnetMask>$3/g" "$IPA_FILE_PATH"
case $1 in
         ippasstrough_enable) silencer ippasstrough_enable $2 $3;;
	 mac_update) silencer mac_update $2;;
	 subnet_update) silencer subnet_update $2 $3;;
	 ippt_subnet_enable) silencer ippt_subnet_enable $2 $3 $4;;
