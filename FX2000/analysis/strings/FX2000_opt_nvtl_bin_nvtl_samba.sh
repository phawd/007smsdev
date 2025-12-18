#!/bin/sh
# nvtl_samba.sh <usb_mount_point> <lan_ip_addr> <samba_host_name> <start | stop>
# set -x
# set -e
export PATH=$PATH:/opt/nvtl/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
USB_MOUNT=$1
LAN_IP=$2
SAMBA_HOST_NAME=$3
LOGDIR=/opt/nvtl/tmp/file_sharing
LOG=$LOGDIR/sambalog
HOSTS_FILE="/etc/hosts"
HOST_ENTRY="${LAN_IP} ${SAMBA_HOST_NAME}"
IS_THERE=`grep "${HOST_ENTRY}" ${HOSTS_FILE}`
add_host_name()
    echo "IS_THERE = ${IS_THERE}"
    if [ ! -n "${IS_THERE}" ]; then
    echo "Adding ${HOST_ENTRY} to ${HOSTS_FILE}"
    nvtl_log -p 0 -m FILE_SHARING -l notice -s "Adding ${HOST_ENTRY} to ${HOSTS_FILE}"	
    echo "${HOST_ENTRY}" >> ${HOSTS_FILE}
remove_host_name()
    echo "IS_THERE = ${IS_THERE}"
    if [ -n "${IS_THERE}" ]; then
    echo "Removing ${HOST_ENTRY} from ${HOSTS_FILE}"
        nvtl_log -p 0 -m FILE_SHARING -l notice -s "Removing ${HOST_ENTRY} from ${HOSTS_FILE}"		
    sed '/'${LAN_IP}' '${SAMBA_HOST_NAME}'/d' ${HOSTS_FILE} > "${HOSTS_FILE}.tmp"
    mv "${HOSTS_FILE}.tmp" ${HOSTS_FILE}
stop_samba()
    nvtl_log -p 1 -m FILE_SHARING -l notice -s "Stopping Samba"	
    /opt/nvtl/bin/nvtl_smbd.sh stop >> $LOG
    /opt/nvtl/bin/nvtl_nmbd.sh stop >> $LOG
    # cleanup config
    rm -rf /etc/samba/*.tdb  >> $LOG
    remove_host_name
    # Removing the service file so that avahi doesn't advertise on a restart    
    rm -f /etc/avahi/services/smb.service
start_samba() 
    # Copying the service file so that avahi advertises on a restart    
    mkdir -p /etc/avahi/services
    cp -f /etc/avahi/smb.service /etc/avahi/services/
    if [ ! -d ${USB_MOUNT} ]; then
        echo "USB card is not mounted at ${USB_MOUNT}"  >> $LOG
	nvtl_log -p 1 -m FILE_SHARING -l err -s "USB card is not mounted at ${USB_MOUNT}"
        exit 1
    add_host_name
    nvtl_log -p 1 -m FILE_SHARING -l notice -s "Starting Samba "
    /opt/nvtl/bin/nvtl_smbd.sh start >> $LOG
    /opt/nvtl/bin/nvtl_nmbd.sh start >> $LOG
mkdir -p $LOGDIR
echo "$0: arg1=$1 arg2=$2 arg3=$3 arg4=$4" >> $LOG
case $4 in
    start)
	start_samba
        ;;
    stop)
        stop_samba
        ;;
        echo "Usage: $0 {start | stop}"
        ;;
