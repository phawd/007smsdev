#!/bin/sh
export LD_LIBRARY_PATH=/opt/nvtl/lib:$LD_LIBRARY_PATH
NVTL_LOG="/opt/nvtl/bin/nvtl_log"
ztpKey="/opt/nvtl/data/longship/ztp/ztpKey.txt"
miscDetails="/opt/nvtl/data/longship/ztp/MiscDetails.txt"
certFile="/etc/ssl/certs/cacerts.pem"
hostDetails="/opt/nvtl/data/longship/ztp/hostDetails.txt"
debugTrace="$1"
if [ "$debugTrace" == "1" ]; then
mkdir "/tmp/longship"
debugTrace="--trace-ascii /tmp/longship/zreq_template.txt"
ztp_default_template_api()                                                                   
    factoryoperid="`cat /opt/nvtl/data/longship/ztp/factory_reset_opr_id`"
    if [ -z "$factoryoperid" ]; then 
	echo "factoryoperid=$factoryoperid not found, Assume zero"
        factoryoperid=""
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "Requesting default templates - Opr ID=$factoryoperid"    
    curl $debugTrace --cacert $certFile $no_cert_check --max-time 120 --connect-timeout 60 --retry 3 --retry-delay 5  --location --request POST $mgmtProto$mgmtURL/api-device/device/applyDefaultZTPconfig \
        --header  'Authorization: '"$Key"'' --header 'Content-Type: application/json' --data-raw '{ "device_mac":"'$deviceMac'","operation_id":"'$factoryoperid'" }' | jq . > /opt/nvtl/data/longship/ztp/app_temp.json
    curl_ret="$?"
    if [ "$curl_ret" == "0" ]; then 
	rm -rf /opt/nvtl/data/longship/ztp/factory_reset_opr_id
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "Request sent - curl_ret=$curl_ret"                                                                                
mgmtProto="`sed -n 's/mgmtProto=//p' $hostDetails`"
if [ -z "$mgmtProto" ]; then
    $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "zreq_template: Error mgmtProto missing"
    exit 1
mgmtURL="`sed -n 's/mgmtURL=//p' $hostDetails`"
if [ -z "$mgmtURL" ]; then
    $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "zreq_template: Error mgmtURL missing"
    exit 1
no_cert_check="`sed -n 's/no_cert_check=//p' $hostDetails`"
deviceMac="`sed -n 's/deviceMac=//p' $miscDetails`"
if [ -z "$deviceMac" ]; then
    deviceMac="`ifconfig | grep bridge0 | awk '{print $5}'`";
    echo "deviceMac=$deviceMac" >>$miscDetails
/opt/nvtl/etc/longship/ztp/accessToken.sh
accessKey=`cat /opt/nvtl/data/longship/ztp/accessKey`
Key="Bearer ${accessKey}"
ztp_default_template_api
