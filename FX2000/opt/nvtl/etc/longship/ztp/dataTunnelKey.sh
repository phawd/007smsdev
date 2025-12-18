#******************************************************************************#
# @file          : dataTunnelKey.sh
# @brief         : This file contains source code for Wireguard Key genaration
#                  for data tunnel.
#******************************************************************************#
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
logoutAPI() {
        #refreshKey=`jq -r .refresh /opt/nvtl/data/longship/ztp/accessKey`
        curl $debugTrace --cacert $certFile $no_cert_check --max-time 120 --connect-timeout 60 --retry 3 --retry-delay 5  --location --request POST $mgmtProto$mgmtURL/api-user/logout/ \
                --header  'Authorization: '"$Key"'' \
                -F refresh=$accessKey | jq . > /tmp/logOut.json
        $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "dataTunnelKey: Done logout"
        rm -f /tmp/logOut.json > /dev/null 2>&1
}

generate_next_pub_key() {
                privateKey=`wg genkey`
                publicKey=`echo $privateKey | wg pubkey`
                echo "$privateKey $publicKey" >>/opt/nvtl/data/longship/ztp/dTWireguardKey

                $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "dataTunnelKey: device_mac:$deviceMac, new:$publicKey"

                #Send the Wireguard key Information to EM
                curl $debugTrace --cacert $certFile $no_cert_check --max-time 120 --connect-timeout 60 --retry 3 --retry-delay 5  --location --request POST $mgmtProto$mgmtURL/api-device/device/deviceWireguardInfo \
                --header  'Authorization: '"$Key"'' --header 'Content-Type: application/json' \
                --data-raw '{"device_mac":"'$deviceMac'","device_public_key":"'$publicKey'"}' | jq . > /tmp/wg_tmp.json

                $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "dataTunnelKey: deviceWireguardInfo response: $(cat /tmp/wg_tmp.json)"
                resp=`jq -r .success /tmp/wg_tmp.json`
                rm -f /tmp/wg_tmp.json > /dev/null 2>&1

                if [ "$resp" == "false" ]; then
                        $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "dataTunnelKey: Next DT key response Failed...!!"
                fi

}

mgmtProto="`sed -n 's/mgmtProto=//p' $hostDetails`"
if [ -z "$mgmtProto" ]; then
    $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "dataTunnelKey: Error mgmtProto missing"
    exit 1
fi
mgmtURL="`sed -n 's/mgmtURL=//p' $hostDetails`"
if [ -z "$mgmtURL" ]; then
    $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "dataTunnelKey: Error mgmtURL missing"
    exit 1
fi
no_cert_check="`sed -n 's/no_cert_check=//p' $hostDetails`"
deviceMac="`sed -n 's/deviceMac=//p' $miscDetails`"

/opt/nvtl/etc/longship/ztp/accessToken.sh
accessKey=`cat /opt/nvtl/data/longship/ztp/accessKey`
Key="Bearer ${accessKey}"

#Get the total count of key's to be generated from EM
keyCount=$2
$NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "dataTunnelKey: Logged in, Keycount=$keyCount"
if [ -z $keyCount ]; then 
   keyCount=0
fi

if [ $keyCount -gt 0 ]
then
        $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "dataTunnelKey: Key's to be generated is $keyCount"
        pubKeyList=`echo "["`
        for i in $(seq 1 $keyCount)
	do
                privateKey=`wg genkey`
                publicKey=`echo $privateKey | wg pubkey`
                echo "$privateKey $publicKey" >> /opt/nvtl/data/longship/ztp/dTWireguardKey
                pubKeyList=`echo "$pubKeyList'$publicKey',"`
        done
        pubKeyList=`echo $pubKeyList | sed '$s/,$//'`
        pubKeyList=`echo "$pubKeyList]"`
        echo "$pubKeyList"
        $NVTL_LOG -p0 -m "LONGSHIP" -l notice -s "dataTunnelKey: Generated_Key(s):$pubKeyList"
else
	$NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "dataTunnelKey: Create next key"
        generate_next_pub_key
fi

logoutAPI

exit 0
