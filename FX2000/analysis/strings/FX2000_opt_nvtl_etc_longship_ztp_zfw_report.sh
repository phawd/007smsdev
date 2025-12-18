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
debugTrace="--trace-ascii /tmp/longship/zfw_report.txt"
fw_send_report_api()                                                                   
    fota_opr_id="`cat /opt/nvtl/data/longship/ztp/fota_opr_id`"
    if [ -z "$fota_opr_id" ]; then 
	echo "fota_opr_id not found, exit"
	$NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "fota_opr_id=$fota_opr_id not found, exit"
    severity="`cat /opt/nvtl/data/longship/ztp/fota_severity`"
    if [ -z "$severity" ]; then 
	echo "severity not found, exit"
	$NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "severity not found, exit"
    remarks="`cat /opt/nvtl/data/longship/ztp/fota_remarks`"
    if [ -z "$remarks" ]; then 
	echo "remarks not found, exit"
	$NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "remarks not found, exit"
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "Sending FW report: OprID=[$fota_opr_id], severity=[$severity], remarks=[$remarks]"    
    curl $debugTrace --cacert $certFile $no_cert_check --max-time 120 --connect-timeout 60 --retry 3 --retry-delay 5  --location --request POST $mgmtProto$mgmtURL/api-device/device/firmwareUpgradeStatus \
	--header  'Authorization: '"$Key"'' --header 'Content-Type:application/json' --data-raw  '{"operation_id":"'$fota_opr_id'","severity":"'$severity'","remarks":"'$remarks'"}' | jq -r 
.message
    curl_ret="$?"
    if [ "$curl_ret" == "0" ]; then 
	rm -f /opt/nvtl/data/longship/ztp/fota_opr_id
	rm -f /opt/nvtl/data/longship/ztp/fota_severity
	rm -f /opt/nvtl/data/longship/ztp/fota_remarks
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "FW report sent - curl_ret=$curl_ret"                                                                                
mgmtProto="`sed -n 's/mgmtProto=//p' $hostDetails`"
if [ -z "$mgmtProto" ]; then
    $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "zfw_report: Missing mgmtProto"
    exit 1
mgmtURL="`sed -n 's/mgmtURL=//p' $hostDetails`"
if [ -z "$mgmtURL" ]; then
    $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "zfw_report: Missing mgmtURL"
    exit 1
no_cert_check="`sed -n 's/no_cert_check=//p' $hostDetails`"
/opt/nvtl/etc/longship/ztp/accessToken.sh
accessKey=`cat /opt/nvtl/data/longship/ztp/accessKey`
Key="Bearer ${accessKey}"
fw_send_report_api
