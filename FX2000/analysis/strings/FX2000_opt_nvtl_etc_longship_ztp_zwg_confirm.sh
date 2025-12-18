#!/bin/sh
export LD_LIBRARY_PATH=/opt/nvtl/lib:$LD_LIBRARY_PATH
NVTL_LOG="/opt/nvtl/bin/nvtl_log"
waitForTunnelEstablishment()
    count=0
    res=1
    while [ $res -eq 1 ]
        wg show wg0 | grep "latest handshake"
        res=`echo $?`
        if [ $res eq 0 ]; then
           $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "WG Handshake successful!!"
           exit 0
        else
           $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "WG waiting for Handshake!!"
           count=$(( $count + 1 ))
	   if [ $count eq $try ]; then
               exit 1 
           fi
           sleep 2
        fi
    done
wireguardTunnelEstablishment
