#!/bin/sh
# Access key genreration using Login API
export LD_LIBRARY_PATH=/opt/nvtl/lib:$LD_LIBRARY_PATH
NVTL_LOG="/opt/nvtl/bin/nvtl_log"
fileDetails="/opt/nvtl/data/longship/ztp/ztpKey.txt"
hostDetails="/opt/nvtl/data/longship/ztp/hostDetails.txt"
mgmtProto="`sed -n 's/mgmtProto=//p' $hostDetails`"
if [ -z "$mgmtProto" ]; then
   $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "accessToken: Error mgmtProto missing"
   exit 1
mgmtURL="`sed -n 's/mgmtURL=//p' $hostDetails`"
if [ -z "$mgmtURL" ]; then
   $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "accessToken: Error mgmtURL missing"
   exit 1
no_cert_check="`sed -n 's/no_cert_check=//p' $hostDetails`"
mgmtUser=`cat $fileDetails | cut -d "&" -f1`                                                                           
if [ -z "$mgmtUser" ]; then
   $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "accessToken: Error mgmtUser missing"
   exit 1                                                                                                                                    
                                                                                                        
mgmtPass=`cat $fileDetails | cut -d "&" -f2`                                                              
if [ -z "$mgmtPass" ]; then
   $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "accessToken: Error mgmtPass missing"    
    exit 1                                                                                                
# Decode the encoded password
mgmtPass=`echo -n "$mgmtPass" | base64 -d`
# Encode the decoded password with username
encuser=$(echo -n "$mgmtUser:$mgmtPass" | base64)                                                             
key=`curl --max-time 120 --connect-timeout 60 --retry 3 --retry-delay 5 $no_cert_check --location --request POST $mgmtProto$mgmtURL/api-user/login/ --header "Authorization: Basic $encuser" | jq -r .access`
# Access Token generated
if [ -z "$key" ]; then
    $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "accessToken: Unable to get the key"        
    exit 1
echo $key > /opt/nvtl/data/longship/ztp/accessKey
