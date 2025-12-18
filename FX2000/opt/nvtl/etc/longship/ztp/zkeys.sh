#!/bin/sh
export LD_LIBRARY_PATH=/opt/nvtl/lib:$LD_LIBRARY_PATH
NVTL_LOG="/opt/nvtl/bin/nvtl_log"

generateKey()
{
    if [ ! -f "/opt/nvtl/data/longship/ztp/devicePrivateKey" ]; then 
        devicePrivateKey="$(wg genkey)"
        echo $devicePrivateKey > /opt/nvtl/data/longship/ztp/devicePrivateKey
        devicePublicKey=`echo $devicePrivateKey | wg pubkey`
        echo $devicePublicKey > /opt/nvtl/data/longship/ztp/devicePublicKey
    fi

    if [ ! -f "/opt/nvtl/data/longship/ztp/deviceDataPrivateKey" ]; then
        deviceDataPrivateKey="$(wg genkey)"
        deviceDataPublicKey=`echo $deviceDataPrivateKey | wg pubkey`
        echo "$deviceDataPrivateKey $deviceDataPublicKey" > /opt/nvtl/data/longship/ztp/dTWireguardKey
        $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "ZTP Keys created!"
    fi
}

generateKey
exit 0
