#!/bin/sh
export LD_LIBRARY_PATH=/opt/nvtl/lib:$LD_LIBRARY_PATH
NVTL_LOG="/opt/nvtl/bin/nvtl_log"
ztpKey="/opt/nvtl/data/longship/ztp/ztpKey.txt"
HandshakeInfo="/opt/nvtl/data/longship/ztp/HandshakeInfo.txt"
HandshakeResp="/opt/nvtl/data/longship/ztp/HandshakeResp.txt"
miscDetails="/opt/nvtl/data/longship/ztp/MiscDetails.txt"
hostDetails="/opt/nvtl/data/longship/ztp/hostDetails.txt"
certFile="/etc/ssl/certs/cacerts.pem"
supportedFeatureList=`cat /opt/nvtl/etc/longship/ztp/supported_templates.json`
model=$2
serialID=$3
fw_version=$4
md5sum=$5
debugTrace="$6"
if [ "$debugTrace" == "1" ]; then
mkdir "/tmp/longship"
debugTrace="--trace-ascii /tmp/longship/zhandshake.txt"
handShakeAPI()
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "Fetching WAN IP of the Device..!!"
    dWanIP=`ifconfig eth2 | grep "inet addr" | cut -d ":" -f2 | cut -d " " -f1`
    if [ -z $dWanIP ]; then
        dWanIP="null"
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "Fetching 5G IP of the Device..!!"
    d5gIP=`ifconfig rmnet_data0 | grep "inet addr" | cut -d ":" -f2 | cut -d " " -f1`
    if [ -z $d5gIP ]; then
        d5gIP="null"
    devicePublicKey=`cat /opt/nvtl/data/longship/ztp/devicePublicKey`
    deviceDataPublicKey=`cat /opt/nvtl/data/longship/ztp/dTWireguardKey | awk 'NR==1{print $2; exit}'`
    if [ -f "/opt/nvtl/data/longship/ztp/deleteStatus" ]; then
        is_deleted=`cat /opt/nvtl/data/longship/ztp/deleteStatus`  
    else
	is_deleted=0
    echo "deviceMac=$deviceMac" >$HandshakeInfo
    echo "device_serial=$serialID" >>$HandshakeInfo
    echo "dHostName=$dHostName" >>$HandshakeInfo
    echo "model=$model" >>$HandshakeInfo
    echo "dWanIP=$dWanIP" >>$HandshakeInfo
    echo "d5gIP=$d5gIP" >>$HandshakeInfo
    echo "md5sum=$md5sum" >>$HandshakeInfo
    echo "imei=$imei" >>$HandshakeInfo
    echo "fw_version=$fw_version" >>$HandshakeInfo
    echo "is_deleted=$is_deleted" >>$HandshakeInfo
    echo "dHostName=$dHostName" >>$HandshakeInfo	
    echo "zHostName=$zHostName" >>$HandshakeInfo		
    resp=`curl $debugTrace --cacert $certFile $no_cert_check --max-time 120 --connect-timeout 60 --retry 3 --retry-delay 5  --location --request POST $mgmtProto$mgmtURL/api-device/device/connectDevice \
          --header  'Authorization: '"$Key"'' --header 'Content-Type: application/json' \
          --data-raw '{"device_mac":"'$deviceMac'","device_serial":"'$serialID'","hostname":"'$dHostName'","device_model":"'$model'","device_wan_ip":"'$dWanIP'","device_5g_ip":"'$d5gIP'","wg_pubkey":"'$devicePublicKey'","device_public_data_key":"'$deviceDataPublicKey'","md5_sum":"'$md5sum'","device_imei":"'$imei'","fw_version":"'$fw_version'","is_deleted":"'$is_deleted'","zabbix_template_version":"1","zHostname":"'$zHostName'","supported_templates":'$supportedFeatureList'}' | jq -r .message`
    echo "Resp: $resp" >>$HandshakeInfo
    echo "$resp" >$HandshakeResp	
    echo $resp
mgmtProto="`sed -n 's/mgmtProto=//p' $hostDetails`"
if [ -z "$mgmtProto" ]; then
    $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "mgmtProto missing"
    exit 1
mgmtURL="`sed -n 's/mgmtURL=//p' $hostDetails`"
if [ -z "$mgmtURL" ]; then
    $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "mgmtURL missing"
    exit 1
no_cert_check="`sed -n 's/no_cert_check=//p' $hostDetails`"
deviceMac="`sed -n 's/deviceMac=//p' $miscDetails`"
if [ -z "$deviceMac" ]; then
    deviceMac="`ifconfig | grep bridge0 | awk '{print $5}'`";
    echo "deviceMac=$deviceMac" >>$miscDetails
dHostName="`sed -n 's/dHostName=//p' $miscDetails`"
zHostName="`sed -n 's/zHostName=//p' $miscDetails`"
if [ -z "$dHostName" ]; then
    dHostName=$model-$(echo $deviceMac | cut -d: -f5- | tr -d ":")
    echo "dHostName=$dHostName" >>$miscDetails
if [ -z "$zHostName" ]; then
    zHostName=$model-$(echo $((1000 + RANDOM % 9999)))-$(echo $deviceMac | cut -d: -f5- | tr -d ":")	
    echo "zHostName=$zHostName" >>$miscDetails	
$NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "Initiate Handshake API"
/opt/nvtl/etc/longship/ztp/accessToken.sh
accessKey=`cat /opt/nvtl/data/longship/ztp/accessKey`
Key="Bearer ${accessKey}"
hresp=$(handShakeAPI)
$NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "Handshake resp:$hresp"
