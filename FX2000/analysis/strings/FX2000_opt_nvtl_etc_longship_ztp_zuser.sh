#!/bin/sh
export LD_LIBRARY_PATH=/opt/nvtl/lib:$LD_LIBRARY_PATH
longshipPassFile="/opt/nvtl/data/longship/ztp/ztp_user.txt"
NVTL_LOG="/opt/nvtl/bin/nvtl_log"
longshipUserAdd()
    longshipPass="`date +%s | sha256sum | base64 | head -c 32`"
    echo $longshipPass >$longshipPassFile
    sed -i '/longmifisd/d' /etc/passwd
    echo "longmifisd:x:0:0:root:/root:/bin/sh" >> /etc/passwd
    #sudo adduser -D -H -G root longmifisd
    `echo "longmifisd:$longshipPass" | chpasswd`	
longshipUserDel()
   sed -i '/longmifisd/d' /etc/passwd
if [ "$1" == "add" ]; then
    longshipUserAdd
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "ZTP User added!!"
elif [ "$1" == "del" ]; then
    longshipUserDel
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "ZTP User Deleted!"
