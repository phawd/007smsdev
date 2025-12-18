#!/bin/sh
export LD_LIBRARY_PATH=/opt/nvtl/lib:$LD_LIBRARY_PATH
NVTL_LOG="/opt/nvtl/bin/nvtl_log"
filePath="$1"
md5sum="$2"
mgmtURL="$3"
mgmtProto="$4"
no_cert_check="$5"
tmpZtpKey="/tmp/ztpKey.txt"
fileDetails="/opt/nvtl/data/longship/ztp/ztpKey.txt"
hostDetails="/opt/nvtl/data/longship/ztp/hostDetails.txt"
if [ ! -f $filePath ]; then
    $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "ZTP Pkg file not present"	
    exit 1
unzip -o -d "/tmp" -P $md5sum $filePath
ret=`echo $?`
if [ $ret -ne 0 ]; then
    $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "Couldn't extract zip file, ret=$ret"	
    exit 2
if [ -z "$mgmtProto" ]; then
    $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "EM Proto missing"
    exit 3
if [ -z "$mgmtURL" ]; then
    $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "EM Host or IP is missing"  
    exit 4
if [ -d "/opt/nvtl/data/longship/ztp" ]; then
    rm -rf /opt/nvtl/data/longship/ztp/*
    mkdir -p "/opt/nvtl/data/longship/ztp" 
mv $tmpZtpKey $fileDetails
echo "mgmtProto=$mgmtProto" >>$hostDetails
echo "mgmtURL=$mgmtURL" >>$hostDetails
echo "no_cert_check=$no_cert_check" >>$hostDetails
sync; sync
