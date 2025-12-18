#!/bin/sh
export LD_LIBRARY_PATH=/opt/nvtl/lib:$LD_LIBRARY_PATH
NVTL_LOG="/opt/nvtl/bin/nvtl_log"
ztpKey="/opt/nvtl/data/longship/ztp/ztpKey.txt"
longshipPass="/opt/nvtl/data/longship/ztp/ztp_user.txt"
tunnelDetails="/opt/nvtl/data/longship/ztp/TunnelDetails.txt"
miscDetails="/opt/nvtl/data/longship/ztp/MiscDetails.txt"
DeviceInfo="/opt/nvtl/data/longship/ztp/DeviceInfo.txt"
certFile="/etc/ssl/certs/cacerts.pem"
hostDetails="/opt/nvtl/data/longship/ztp/hostDetails.txt"
debugTrace="$1"
md5sum="2efbc8704df69db8e7f1242933eb3ffb"
if [ "$debugTrace" == "1" ]; then
mkdir "/tmp/longship"
debugTrace="--trace-ascii /tmp/longship/zdevinfo.txt"
encData()
   local data=$1
   encdata=`echo $data | openssl aes-256-cbc -a -salt -pass pass:$md5sum -pbkdf2`
   echo $encdata | tr -d ' '
sendDeviceInfo()
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "Send Info to Management Appliance..!!"
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "Fetching LAN IP of the Device..!!"
    dLanIP=`ifconfig bridge0 | grep "inet addr" | cut -d ":" -f2 | cut -d " " -f1`
    dLanMask=`ifconfig bridge0 | grep "inet addr" | cut -d ":" -f4 | cut -d " " -f3`
    dLanSubnet=`ipcalc.sh $dLanIP $dLanMask | grep "PREFIX" | cut  -d "=" -f2`
    dLanNetwork=`ipcalc.sh $dLanIP $dLanMask | grep "NETWORK" | cut  -d "=" -f2`
    dLanCidr=$dLanNetwork/$dLanSubnet
    if [ -z $dLanIP ]; then
        dLanIP="null"
    dGuestIP="null"
    echo "$deviceMac" >$DeviceInfo
    echo "$userName" >>$DeviceInfo
    echo "$password" >>$DeviceInfo
    echo "$dLanIP" >>$DeviceInfo
    echo "$dLanCidr" >>$DeviceInfo
    echo "$dGuestIP" >>$DeviceInfo
encUserName=$(encData $userName)
encPassword=$(encData $password)
    curl $debugTrace --cacert $certFile $no_cert_check --max-time 120 --connect-timeout 60 --retry 3 --retry-delay 5  --location --request POST $mgmtProto$mgmtURL/api-device/device/init --header  'Authorization: '"$Key"'' --header 'Content-Type: application/json' --data-raw '{"device_mac":"'$deviceMac'","device_username":"'$encUserName'","device_ctunnel_ip":"'$tunnelIP'","device_password":"'$encPassword'","device_lan_ip":"'$dLanIP'","device_lan_cidr":"'$dLanCidr'","device_guest_ip":"'$dGuestIP'"}'
    curl_ret="$?"
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "Sent details, curl ret=$curl_ret"	
    echo "\ncurl_ret=$curl_ret" >>$DeviceInfo
userName="longmifisd"
password="`cat $longshipPass`"
mgmtProto="`sed -n 's/mgmtProto=//p' $hostDetails`"
if [ -z "$mgmtProto" ]; then
    exit 1
mgmtURL="`sed -n 's/mgmtURL=//p' $hostDetails`"
if [ -z "$mgmtURL" ]; then
    exit 1
no_cert_check="`sed -n 's/no_cert_check=//p' $hostDetails`"
tunnelIP="`sed -n 's/tunnelIP=//p' $tunnelDetails`"
serverIP="`sed -n 's/serverIP=//p' $tunnelDetails`"
deviceMac="`sed -n 's/deviceMac=//p' $miscDetails`"
if [ -z "$deviceMac" ]; then
    deviceMac="`ifconfig | grep bridge0 | awk '{print $5}'`";
    echo "deviceMac=$deviceMac" >>$miscDetails
/opt/nvtl/etc/longship/ztp/accessToken.sh
accessKey=`cat /opt/nvtl/data/longship/ztp/accessKey`
Key="Bearer ${accessKey}"
sendDeviceInfo
