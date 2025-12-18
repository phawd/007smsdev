#!/bin/sh
#******************************************************************************#
# @file          : keyRotation.sh                                                   
# @brief         : This script id responsible for performing key rotation 
#                  configuration for control and data tunnel.        
#******************************************************************************#

certFile="/etc/ssl/certs/cacerts.pem"
hostDetails="/opt/nvtl/data/longship/ztp/hostDetails.txt"


#Fetch the file name for logging
cur_file=`basename "$0" | cut -d "." -f1`
NVTL_LOG="/opt/nvtl/bin/nvtl_log"

tunnel_name=$1
psk=$2
opr_id=$3

#******************************************************************************#
# @function      : loginAPI
# @param         : (none)                                                
# @brief         : This function is used for API Authorization login.        
#******************************************************************************#
loginAPI() {
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "$cur_file : Generate  Token for login..!!"
    /opt/nvtl/etc/longship/ztp/accessToken.sh
    accessKey=`cat /opt/nvtl/data/longship/ztp/accessKey`
    if [ -z "$accessKey" -o "$accessKey" = "null" ]
    then
        $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "$cur_file" "Login API response failed: AccessKey - $accessKey"
        exit
    fi
    access_Key="Bearer ${accessKey}"
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "$cur_file :  AccessKey - $accessKey"
}

#******************************************************************************#
# @function      : logoutAPI
# @param         : (none)                                                
# @brief         : This function is used for API Authorization logout.        
#******************************************************************************#
logoutAPI() {
        curl $debugTrace --cacert $certFile $no_cert_check --max-time 120 --connect-timeout 60 --retry 3 --retry-delay 5  --location --request POST $mgmtProto$mgmtURL/api-user/logout/ \
                --header  'Authorization: '"$Key"'' \
                -F refresh=$accessKey | jq . > /tmp/logOut.json
        $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "$cur_file : logged out"
        rm -f /tmp/logOut.json > /dev/null 2>&1
}

#Key Rotation configuration
if [[ $tunnel_name == "controlTunnel" ]]; then
  interface="wg0"
else
  interface=$4
fi

peer=`wg show $interface peers`
prev_psk=`wg show $interface preshared-keys` | awk '{print $2}'
echo $psk > /opt/nvtl/data/longship/ztp/"$interface"_psk
wg set $interface peer $peer preshared-key /opt/nvtl/data/longship/ztp/"$interface"_psk

$NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "$cur_file : Key Rotation is set for tunnel interface:$interface"

if [[ $tunnel_name == "controlTunnel" ]]; then
    #Fetch the EM details from ztp key 
    
    mgmtProto="`sed -n 's/mgmtProto=//p' $hostDetails`" 
    if [ -z "$mgmtProto" ]; then 
      $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "Control Tunnel Key Rotation: Error mgmtProto missing" 
      exit 1 
    fi 
    
    mgmtURL="`sed -n 's/mgmtURL=//p' $hostDetails`" 
    if [ -z "$mgmtURL" ]; then 
      $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "Control Tunnel Key Rotation: Error mgmtURL missing" 
      exit 1 
    fi

    loginAPI
    
    if [[ `wg show wg0 preshared-keys | awk '{print $2}'` == $psk ]]; then
        curl --cacert $certFile $no_cert_check  --max-time 120 --connect-timeout 60 --retry 3 --retry-delay 5 --location --request POST $mgmtProto$mgmtURL/api-device/device/controlTunnelKeyRotationStatus \
        --header  'Authorization: '"$access_Key"'' --header 'Content-Type: application/json' \
        --data-raw '{"operation_uuid":"'$opr_id'","operation_status":"successful","remarks":"Preshared Key is configured successfully"}' \
        | jq . > /tmp/KeyRot.json

        $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "$cur_file" "Key Rotation Response: $(cat /tmp/KeyRot.json)"
        resp=`jq -r .Success /tmp/KeyRot.json`

        if [[ $resp == "false" ]]; then
            echo $prev_psk > /opt/nvtl/data/longship/ztp/"$interface"_psk
            wg set $interface peer $peer preshared-key /opt/nvtl/data/longship/ztp/"$interface"_psk

            $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "$cur_file: Control Tunnel Key Rotation Response - FAILED. Use previous Preshared-key."
        elif [[ $resp == "true" ]]; then
            $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "$cur_file: Control Tunnel Key Rotation Response - SUCCESSFUL"
        fi
    else        
        curl --cacert /etc/ssl/cert.pem  --max-time 120 --connect-timeout 60 --retry 3 --retry-delay 5  --location --request POST $mgmtProto$mgmtUrl/api-device/device/controlTunnelKeyRotationStatus \
        --header  'Authorization: '"$access_Key"'' --header 'Content-Type: application/json' \
        --data-raw '{"operation_uuid":"'$opr_id'","operation_status":"failed","remarks":"Preshared Key is not configured successfully"}' \
        | jq . > /tmp/KeyRot.json

        $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "$cur_file: Control Tunnel Key Rotation Response: $(cat /tmp/KeyRot.json)"
        $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "$cur_file: Control Tunnel Key Rotation - CONFIGURATION FAILED"
    fi
    rm -f /tmp/KeyRot.json
    logoutAPI
else
    if [[ `wg show $interface preshared-keys | awk '{print $2}'` == $psk ]]; then
        $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "$cur_file: Data Tunnel Key Rotation:Interface-$interface - CONFIGURATION SUCCESSFULL"
    else
        echo $prev_psk > /opt/nvtl/data/longship/ztp/"$interface"_psk 
        wg set $interface peer $peer preshared-key /opt/nvtl/data/longship/ztp/"$interface"_psk 
        $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "$cur_file: Data Tunnel Key Rotation:Interface-$interface - CONFIGURATION FAILED"
    fi
fi
#!/bin/sh
#******************************************************************************#
# @file          : keyRotation.sh                                                   
# @brief         : This script id responsible for performing key rotation 
#                  configuration for control and data tunnel.        
#******************************************************************************#

certFile="/etc/ssl/certs/cacerts.pem"
hostDetails="/opt/nvtl/data/longship/ztp/hostDetails.txt"


#Fetch the file name for logging
cur_file=`basename "$0" | cut -d "." -f1`
NVTL_LOG="/opt/nvtl/bin/nvtl_log"

tunnel_name=$1
psk=$2
opr_id=$3

#******************************************************************************#
# @function      : loginAPI
# @param         : (none)                                                
# @brief         : This function is used for API Authorization login.        
#******************************************************************************#
loginAPI() {
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "$cur_file : Generate  Token for login..!!"
    /opt/nvtl/etc/longship/ztp/accessToken.sh
    accessKey=`cat /opt/nvtl/data/longship/ztp/accessKey`
    if [ -z "$accessKey" -o "$accessKey" = "null" ]
    then
        $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "$cur_file" "Login API response failed: AccessKey - $accessKey"
        exit
    fi
    access_Key="Bearer ${accessKey}"
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "$cur_file :  AccessKey - $accessKey"
}

#******************************************************************************#
# @function      : logoutAPI
# @param         : (none)                                                
# @brief         : This function is used for API Authorization logout.        
#******************************************************************************#
logoutAPI() {
        curl $debugTrace --cacert $certFile $no_cert_check --max-time 120 --connect-timeout 60 --retry 3 --retry-delay 5  --location --request POST $mgmtProto$mgmtURL/api-user/logout/ \
                --header  'Authorization: '"$Key"'' \
                -F refresh=$accessKey | jq . > /tmp/logOut.json
        $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "$cur_file : logged out"
        rm -f /tmp/logOut.json > /dev/null 2>&1
}

#Key Rotation configuration
if [[ $tunnel_name == "controlTunnel" ]]; then
  interface="wg0"
else
  interface=$4
fi

peer=`wg show $interface peers`
prev_psk=`wg show $interface preshared-keys` | awk '{print $2}'
echo $psk > /opt/nvtl/data/longship/ztp/"$interface"_psk
wg set $interface peer $peer preshared-key /opt/nvtl/data/longship/ztp/"$interface"_psk

$NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "$cur_file : Key Rotation is set for tunnel interface:$interface"

if [[ $tunnel_name == "controlTunnel" ]]; then
    #Fetch the EM details from ztp key 
    
    mgmtProto="`sed -n 's/mgmtProto=//p' $hostDetails`" 
    if [ -z "$mgmtProto" ]; then 
      $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "Control Tunnel Key Rotation: Error mgmtProto missing" 
      exit 1 
    fi 
    
    mgmtURL="`sed -n 's/mgmtURL=//p' $hostDetails`" 
    if [ -z "$mgmtURL" ]; then 
      $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "Control Tunnel Key Rotation: Error mgmtURL missing" 
      exit 1 
    fi

    loginAPI
    
    if [[ `wg show wg0 preshared-keys | awk '{print $2}'` == $psk ]]; then
        curl --cacert $certFile $no_cert_check  --max-time 120 --connect-timeout 60 --retry 3 --retry-delay 5  --location --request POST $mgmtProto$mgmtURL/api-device/device/controlTunnelKeyRotationStatus \
        --header  'Authorization: '"$access_Key"'' --header 'Content-Type: application/json' \
        --data-raw '{"operation_uuid":"'$opr_id'","operation_status":"successful","remarks":"Preshared Key is configured successfully"}' \
        | jq . > /tmp/KeyRot.json

        $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "$cur_file" "Key Rotation Response: $(cat /tmp/KeyRot.json)"
        resp=`jq -r .Success /tmp/KeyRot.json`

        if [[ $resp == "false" ]]; then
            echo $prev_psk > /opt/nvtl/data/longship/ztp/"$interface"_psk
            wg set $interface peer $peer preshared-key /opt/nvtl/data/longship/ztp/"$interface"_psk

            $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "$cur_file: Control Tunnel Key Rotation Response - FAILED. Use previous Preshared-key."
        elif [[ $resp == "true" ]]; then
            $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "$cur_file: Control Tunnel Key Rotation Response - SUCCESSFUL"
        fi
    else        
        curl --cacert /etc/ssl/cert.pem  --max-time 120 --connect-timeout 60 --retry 3 --retry-delay 5  --location --request POST $mgmtProto$mgmtUrl/api-device/device/controlTunnelKeyRotationStatus \
        --header  'Authorization: '"$access_Key"'' --header 'Content-Type: application/json' \
        --data-raw '{"operation_uuid":"'$opr_id'","operation_status":"failed","remarks":"Preshared Key is not configured successfully"}' \
        | jq . > /tmp/KeyRot.json

        $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "$cur_file: Control Tunnel Key Rotation Response: $(cat /tmp/KeyRot.json)"
        $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "$cur_file: Control Tunnel Key Rotation - CONFIGURATION FAILED"
    fi
    rm -f /tmp/KeyRot.json
    logoutAPI
else
    if [[ `wg show $interface preshared-keys | awk '{print $2}'` == $psk ]]; then
        $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "$cur_file: Data Tunnel Key Rotation:Interface-$interface - CONFIGURATION SUCCESSFULL"
    else
        echo $prev_psk > /opt/nvtl/data/longship/ztp/"$interface"_psk 
        wg set $interface peer $peer preshared-key /opt/nvtl/data/longship/ztp/"$interface"_psk 
        $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "$cur_file: Data Tunnel Key Rotation:Interface-$interface - CONFIGURATION FAILED"
    fi
fi
