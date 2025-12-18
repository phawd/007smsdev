#!/bin/sh
# set -x
# set -e
export PATH=$PATH:/opt/nvtl/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
LOGDIR=/opt/nvtl/tmp/file_sharing
LOG=$LOGDIR/usb_flash.log
USB_MOUNT=$1
CLI=/opt/nvtl/bin/file_sharing_cli
MTD_DEVICE=/dev/mtdblock12
# It's possible that there are multiple mounts so try to remove all of them
umountAll()
    echo "umountAll called from $2" | tee -a $LOG
    nvtl_log -p 0 -m FILE_SHARING -l notice -s "umountAll called from $2"
    COUNTER=0
    while [ $COUNTER -lt 5 ]; do
        # Can't log this since we need the status code of the command
        umount $USB_MOUNT &> /dev/null
        if [ $? -ne 0 ]; then
            break
        fi
        let COUNTER=COUNTER+1
    done
    $CLI change_usb_state drive_unmounted
    nvtl_log -p 1 -m FILE_SHARING -l notice -s "sending change_usb_state drive_unmounted"
    echo "About to delete  $USB_MOUNT" | tee -a $LOG
    nvtl_log -p 0 -m FILE_SHARING -l notice -s "About to delete $USB_MOUNT"
    rmdir $USB_MOUNT 2>&1 | tee -a $LOG
get_mount_part()
    # There's an override for the mount partition in the config.xml
    grep "<PartitionOverride>" /opt/nvtl/etc/file_sharing/config.xml
    if [ $? -eq 0 ]; then
        mount_part=$(awk -F '[<>]' '/<PartitionOverride>/{print $3}' /opt/nvtl/etc/file_sharing/config.xml)
        nvtl_log -p 1 -m FILE_SHARING -l notice -s "mount partition override from config.xml"
    else
        # Below code will detect the largest parition and
        # it also assumes that flash drive will always be bigger than the NAND.
        mount_part=`cat /proc/partitions | tr -s ' '| cut -d ' ' -f4 | grep -v name | sort -g | sed 'x;$!d'`
        mount_part=$(grep  $mount_part /proc/partitions | tr -s ' ' | cut -d ' ' -f5 | head -1)
mount_USB_drive()
    umountAll "mount_USB_drive"
    # Save some state info in the log file
    cat /proc/partitions | tee -a $LOG
    # First make sure there's a USB flash drive attached.
    cat /proc/partitions | grep sd &> /dev/null
    if [ $? -ne 0 ]; then
        nvtl_log -p 1 -m FILE_SHARING -l notice -s "No flash drive connected"
        $CLI change_usb_state not_detected
        nvtl_log -p 1 -m FILE_SHARING -l notice -s "sending change_usb_state not_detected"
        exit 2
    # Get the mount partition
    get_mount_part
    # Return now if it's already mounted
    mount | grep $mount_part &> /dev/null
    if [ $? -eq 0 ]; then
        nvtl_log -p 1 -m FILE_SHARING -l notice -s "/dev/$mount_part already mounted"
        exit 0
    fs_type=$(blkid /dev/$mount_part | awk -F 'TYPE=' '{print $2}' | cut -d "\"" -f2)
    nvtl_log -p 1 -m FILE_SHARING -l notice -s "mount partition is $mount_part, FS type is $fs_type"
    case "$fs_type" in
    vfat) ;;
    exfat) ;;
    ntfs) ;;
    ext4) ;;
    ext3) ;;
    hfsplus) ;;
        $CLI change_usb_state detected_unsupported_fs
        nvtl_log -p 1 -m FILE_SHARING -l notice -s "sending change_usb_state detected_unsupported_fs: $fs_type"
        exit 1
    esac
    if [ ! -d "$USB_MOUNT" ]; then
        echo "$USB_MOUNT does not exist, creating $USB_MOUNT" | tee -a $LOG
        nvtl_log -p 0 -m FILE_SHARING -l notice -s "does not exist, creating $USB_MOUNT"
        mkdir -p $USB_MOUNT 2>&1 | tee -a $LOG
    else
        echo "$USB_MOUNT already exists" | tee -a $LOG
        nvtl_log -p 0 -m FILE_SHARING -l notice -s "$USB_MOUNT already exists"
    echo "mounting $USB_MOUNT" | tee -a $LOG
    nvtl_log -p 0 -m FILE_SHARING -l notice -s "mounting $USB_MOUNT"
    case "$fs_type" in
    vfat)
        MOUNT_OPTS="fmask=0,dmask=0,dirsync,flush"
        ;;
    exfat)
        MOUNT_OPTS="fmask=0,dmask=0"
        ;;
    ntfs)
        MOUNT_OPTS="ro,fmask=0,dmask=0"
        ;;
    ext4)
        MOUNT_OPTS="rw,errors=remount-ro"
        ;;
    ext3)
        MOUNT_OPTS="rw,errors=remount-ro"
        ;;
    hfsplus)
        MOUNT_OPTS="ro"
        ;;
    esac
    MOUNT_CMD="mount -t $fs_type /dev/$mount_part $USB_MOUNT -o $MOUNT_OPTS"
    nvtl_log -p 0 -m FILE_SHARING -l notice -s "running: $MOUNT_CMD"
    # do not use | or tee command on the following line as it masks the
    # error code from the mount command
    mount -t $fs_type /dev/$mount_part $USB_MOUNT -o $MOUNT_OPTS 2>&1
    rc=$?
    if [ $rc -ne 0 ]; then
        echo "mount /dev/$mount_part $USB_MOUNT failed with $rc" | tee -a $LOG
        nvtl_log -p 1 -m FILE_SHARING -l err -s "mount /dev/$mount_part $USB_MOUNT failed with $rc"
        usleep 100000
        echo "retry mounting $USB_MOUNT" | tee -a $LOG
        nvtl_log -p 1 -m FILE_SHARING -l notice -s "retry mounting $USB_MOUNT"
        nvtl_log -p 0 -m FILE_SHARING -l notice -s "running: $MOUNT_CMD"
        # do not use | or tee command on the following line as it masks the
        # error code from the mount command
        mount -t $fs_type /dev/$mount_part $USB_MOUNT -o $MOUNT_OPTS 2>&1
        rc=$?
        if [ $rc -ne 0 ]; then
            echo "retry mount /dev/$mount_part $USB_MOUNT failed with $rc" | tee -a $LOG
            nvtl_log -p 1 -m FILE_SHARING -l err -s "retry mount /dev/$mount_part $USB_MOUNT failed with $rc"
            umountAll "mount_USB_drive"
        fi
    if [ $rc -eq 0 ]; then
        if [ "exfat" == "$fs_type" ] || [ "vfat" == "$fs_type" ] || [ "ext3" == "$fs_type" ] || [ "ext4" == "$fs_type" ] ; then
            mount | grep "on $USB_MOUNT type $fs_type (rw," 2>&1
            rc=$?
            if [ $rc -eq 0 ]; then
                $CLI change_usb_state detected_mounted
                nvtl_log -p 1 -m FILE_SHARING -l notice -s "sending change_usb_state detected_mounted"
                echo "sending change_usb_state detected_mounted" | tee -a $LOG
            else
                mount | grep "on $USB_MOUNT type $fs_type (ro," 2>&1
                rc=$?
                if [ $rc -eq 0 ]; then
                    $CLI change_usb_state detected_mounted_read_only
                    nvtl_log -p 1 -m FILE_SHARING -l notice -s "sending change_usb_state detected_mounted_read_only"
                    echo "sending change_usb_state detected_mounted_read_only" | tee -a $LOG
                fi
            fi
        else
            if [ "ntfs" == "$fs_type" ] || [ "hfsplus" == "$fs_type" ] ; then
                $CLI change_usb_state detected_mounted_read_only
                nvtl_log -p 1 -m FILE_SHARING -l notice -s "sending change_usb_state detected_mounted_read_only: $fs_type"
                echo "sending change_usb_state detected_mounted_read_only:" | tee -a $LOG
            fi
        fi
        $CLI set_file_system_type $fs_type
        MOUNT_LOG=$(mount |grep $USB_MOUNT)
        nvtl_log -p 1 -m FILE_SHARING -l notice -s "Output of mount command:$MOUNT_LOG" 
    else
        $CLI change_usb_state detected_mount_error
        nvtl_log -p 1 -m FILE_SHARING -l notice -s "sending change_usb_state detected_mount_error"
    exit $rc
unmount_USB_drive()
    if [ -e "$USB_MOUNT" ]; then
        umountAll "unmount_USB_drive"
    else
        $CLI change_usb_state not_detected
        nvtl_log -p 1 -m FILE_SHARING -l notice -s "sending change_usb_state not_detected"
        echo "$USB_MOUNT doesn't exist" | tee -a $LOG
# Create the file_sharing tmp log directory
mkdir -p $LOGDIR
echo "$0: arg1=$1 arg2=$2" >> $LOG
case $2 in
    start)
        echo "+++++++++++++++ start: begin" | tee -a $LOG
        date | tee -a $LOG
        SETTINGSFILE=/sysconf/settings.xml
        if [ ! -f $SETTINGSFILE ]; then
            SETTINGSFILE=/sysconf/settings_def.xml
        fi
        echo "SETTINGSFILE=$SETTINGSFILE"  | tee -a $LOG
        nvtl_log -p 1 -m FILE_SHARING -l notice -s "SETTINGSFILE=$SETTINGSFILE"
        file_sharing_enabled=`xmldata_cli getstring $SETTINGSFILE /Settings/FileSharing/Enabled | grep value | sed "s/[^0-9]//g"`
        if [ "$file_sharing_enabled" == "1" ]; then
            mount_USB_drive
        else
            nvtl_log -p 1 -m FILE_SHARING -l notice -s "Not mounting as file sharing disabled"
        fi
        echo "+++++++++++++++ start: end" | tee -a $LOG
        ;;
    stop)
        echo "--------------- stop: begin" | tee -a $LOG
        date | tee -a $LOG
        unmount_USB_drive
        echo "--------------- stop: end" | tee -a $LOG
        ;;
    restart)
        $0 stop
        $0 start
        ;;
        echo "Usage: { start | stop | restart}" >&2
        exit 1
        ;;
