#!/bin/sh
export LD_LIBRARY_PATH=/opt/nvtl/lib:$LD_LIBRARY_PATH
NVTL_LOG="/opt/nvtl/bin/nvtl_log"
certFile="/etc/ssl/certs/cacerts.pem"
pkg_req_func()                                                                   
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "Requesting ZTP pkg from Host=[$mgmtProto$mgmtURL]"    
    rm -f "/tmp/longship/ztp_ency_key.zip"
    curl $debugTrace --max-time 120 --connect-timeout 60 --retry 3 --retry-delay 5   --cacert $certFile $no_cert_check --location --output /tmp/longship/ztp_ency_key.zip $mgmtProto$mgmtURL/ztpkey/ztp_ency_key.zip
    curl_ret="$?"
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "Request sent - curl_ret=$curl_ret"
    if [ -f "/tmp/longship/ztp_ency_key.zip" ]; then
       $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "ZTP pkg downloaded successfully"
       exit 0
    else 
       $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "Failed to download ZTP pkg"
       exit 1
    fi    	
debugTrace="$1"
mgmtURL="$2"
mgmtProto="$3"
no_cert_check="$4"
if [ "$debugTrace" == "1" ]; then
    debugTrace="--trace-ascii /tmp/longship/zpkg_req.txt"
mkdir -p "/tmp/longship"
pkg_req_func
