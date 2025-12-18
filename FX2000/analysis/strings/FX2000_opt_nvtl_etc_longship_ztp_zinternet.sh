#!/bin/sh
export LD_LIBRARY_PATH=/opt/nvtl/lib:$LD_LIBRARY_PATH
NVTL_LOG="/opt/nvtl/bin/nvtl_log"
timeout="$1"
mgmtURL="$2"
mgmtPort="$3"
internetCheck()
    nc -w$timeout $mgmtURL $mgmtPort -e"/bin/echo"
    ret=$?
    if [ "$ret" != "0" ]; then
    	$NVTL_LOG -p0 -m "LONGSHIP" -l notice -s "Connect failed - Host=[$mgmtURL:$mgmtPort]!!"
        exit 1;		    	
    $NVTL_LOG -p0 -m "LONGSHIP" -l notice -s "Connect success - Host=[$mgmtURL:$mgmtPort]!!"	
internetCheck
