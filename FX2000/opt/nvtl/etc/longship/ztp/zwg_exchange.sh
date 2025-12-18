#!/bin/sh
export LD_LIBRARY_PATH=/opt/nvtl/lib:$LD_LIBRARY_PATH
NVTL_LOG="/opt/nvtl/bin/nvtl_log"
ztpKey="/opt/nvtl/data/longship/ztp/ztpKey.txt"
miscDetails="/opt/nvtl/data/longship/ztp/MiscDetails.txt"
tunnelDetails="/opt/nvtl/data/longship/ztp/TunnelDetails.txt"
certFile="/etc/ssl/certs/cacerts.pem"
hostDetails="/opt/nvtl/data/longship/ztp/hostDetails.txt"

debugTrace="$1"
if [ "$debugTrace" == "1" ]; then
mkdir "/tmp/longship"
debugTrace="--trace-ascii /tmp/longship/zwg_exchange.txt"
fi

wireguardTunnelEstablishment()
{
    deviceMac="`sed -n 's/deviceMac=//p' $miscDetails`"
    if [ -z "$deviceMac" ]; then
        deviceMac="`ifconfig | grep bridge0 | awk '{print $5}'`";
        echo "deviceMac=$deviceMac" >>$miscDetails
    fi	
    devicePublicKeyInfo=`cat /opt/nvtl/data/longship/ztp/devicePublicKey`
    devicePrivateKeyInfo=`cat /opt/nvtl/data/longship/ztp/devicePrivateKey`    	
    deviceDataPublicKeyInfo=`cat /opt/nvtl/data/longship/ztp/dTWireguardKey | awk 'NR==1{print $2; exit}'`
  
    curl $debugTrace --cacert $certFile $no_cert_check --max-time 120 --connect-timeout 60 --retry 3 --retry-delay 5  --header  'Authorization: '"$Key"'' --header "Content-Type: application/json" --request POST --data \
        '{"device_public_key": "'$devicePublicKeyInfo'","device_public_data_key":"'$deviceDataPublicKeyInfo'", "device_token": "'$deviceMac'"}' \
        $mgmtProto$mgmtURL/api-device/device/WgKeyExchange | jq . > /opt/nvtl/data/longship/ztp/iss.json

     #Send the Wireguard key Information to EM
     curl $debugTrace --cacert $certFile $no_cert_check --max-time 120 --connect-timeout 60 --retry 3 --retry-delay 5  --location --request POST $mgmtProto$mgmtURL/api-device/device/deviceWireguardInfo \
	--header  'Authorization: '"$Key"'' --header 'Content-Type: application/json' \
	--data-raw '{"device_mac":"'$deviceMac'","device_public_key":"'$deviceDataPublicKeyInfo'"}' | jq . > /tmp/wg_tmp.json


    serverPubkey=`jq -r .wg_public_key /opt/nvtl/data/longship/ztp/iss.json`
    tunnelIP=`jq -r .wg_private_ip /opt/nvtl/data/longship/ztp/iss.json`
    serverIP=`jq -r .server_ip /opt/nvtl/data/longship/ztp/iss.json`
    serverPort=`jq -r .server_port /opt/nvtl/data/longship/ztp/iss.json` 
    
    if [ -z "$serverPubkey" -o -z "$tunnelIP" -o -z "$serverIP" ]; then
	$NVTL_LOG -p1 -m "LONGSHIP" -l err -s "Empty response (tunnelIP:$tunnelIP,serverIP:$serverIP)"
        exit 1
    fi
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "WG exchnage (tunnelIP:$tunnelIP,serverIP:$serverIP,serverPort:$serverPort)"
    echo "serverPubkey=$serverPubkey" >$tunnelDetails
    echo "tunnelIP=$tunnelIP" >>$tunnelDetails
    echo "serverIP=$serverIP" >>$tunnelDetails
    echo "devicePublicKeyInfo=$devicePublicKeyInfo" >>$tunnelDetails
    echo "devicePrivateKeyInfo=$devicePrivateKeyInfo" >>$tunnelDetails
    echo "serverPubkey=$serverPubkey" >>$tunnelDetails
    echo "mgmtProto=$mgmtProto" >>$tunnelDetails
    echo "mgmtURL=$mgmtURL" >>$tunnelDetails
    wget -T 10 $mgmtURL 2>/tmp/longship/wget_output
    endIP="`awk 'BEGIN { FS = "(" } ; { print $2 }' /tmp/longship/wget_output |  awk -F '[:]' '{printf $1}'`"
    if [ ! -z "$endIP" ]; then
        echo "mgmtURL=$endIP" >>$tunnelDetails
	echo "Endpoint=$endIP"
    else
        echo "mgmtURL=invalid url" >>$tunnelDetails
	echo "Ping Failed"
        exit 1
    fi
    if [ -z "$serverPort" -o "$serverPort" == "null" ]; then
    	echo "wgPort=51820" >>$tunnelDetails
    else
        echo "wgPort=$serverPort" >>$tunnelDetails
    fi    
    echo "keepAlive=25" >>$tunnelDetails	
}

mgmtProto="`sed -n 's/mgmtProto=//p' $hostDetails`"
if [ -z "$mgmtProto" ]; then
    $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "zwg_exchange: Error mgmtProto missing"
    exit 1
fi
mgmtURL="`sed -n 's/mgmtURL=//p' $hostDetails`"
if [ -z "$mgmtURL" ]; then
    $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "zwg_exchange: Error mgmtURL missing"
    exit 1
fi
no_cert_check="`sed -n 's/no_cert_check=//p' $hostDetails`"

$NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "Exchange WG info"
/opt/nvtl/etc/longship/ztp/accessToken.sh
accessKey=`cat /opt/nvtl/data/longship/ztp/accessKey`
Key="Bearer ${accessKey}"

wireguardTunnelEstablishment

exit 0

