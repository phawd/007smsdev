#!/bin/sh
# init.d script for fota_upgrade in RL5
export PATH=$PATH:/opt/nvtl/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
FOTA_DATA=/opt/nvtl/data/fota
FOTA_SESSION_LOCK_FILE=$FOTA_DATA/session
DLPKG_STAGING_DIR=$FOTA_DATA/staging
FOTA_STAGING_PKG_DESCRIPTION=$DLPKG_STAGING_DIR/pkg_description
FOTA_SUA_UPDATE_COOKIE=$DLPKG_STAGING_DIR/sua_cookie
FOTA_STAGING_FULL_FOTA=$DLPKG_STAGING_DIR/full_fota
FOTA_STAGING_CURRENT_BOOT_SLOT=$DLPKG_STAGING_DIR/current_slot
FOTA_STAGING_UPDATE_PRE_INSTALL=$DLPKG_STAGING_DIR/update_pre_install
FOTA_STAGING_SYSCONF_BACKUP=$DLPKG_STAGING_DIR/sysconf_bkp.tar.bz2
FOTA_STAGING_UPDATE_POST_INSTALL=$DLPKG_STAGING_DIR/update_post_install
FOTA_STAGING_UPDATE_FAILURE=$DLPKG_STAGING_DIR/result_failure
FOTA_STAGING_UPDATE_SUCCESS=$DLPKG_STAGING_DIR/result_success
FOTA_STAGING_UPDATE_FAILURE_REASON=$DLPKG_STAGING_DIR/result_failure_reason
FOTA_STAGING_PRI_MODEM_SUCCESS=$DLPKG_STAGING_DIR/pri_modem_success
FOTA_STAGING_PRI_MODEM_FAILURE=$DLPKG_STAGING_DIR/pri_modem_failure
FOTA_STAGING_PRI_LINUX_SUCCESS=$DLPKG_STAGING_DIR/pri_linux_success
FOTA_STAGING_PRI_LINUX_FAILURE=$DLPKG_STAGING_DIR/pri_linux_failure
FOTA_STAGING_UPDATE_CLEAR_MCFG=$DLPKG_STAGING_DIR/update_clear_mcfg
FOTA_STAGING_CLR_MCFG_DONE=$DLPKG_STAGING_DIR/clr_mcfg_done
FOTA_STAGING_BRANDING_TGZ=$DLPKG_STAGING_DIR/branding.tgz
FOTA_STAGING_RECOVERY_FILE=$DLPKG_STAGING_DIR/recovery_pkg
FOTA_STAGING_RECOVERY_FILE_SIG=$DLPKG_STAGING_DIR/recovery_pkg.sign
FOTA_CUSTOM_INSTALL=$DLPKG_STAGING_DIR/install.sh
APN_PROFILE=$DLPKG_STAGING_DIR/profile
FOTA_BIN_DIR=/opt/nvtl/bin
FOTA_STAGING_NWCLI=$DLPKG_STAGING_DIR/nwcli
FOTA_STAGING_IPQ_REBOOT_REQUIRED=$DLPKG_STAGING_DIR/ipq_reboot_required
FOTA_BIN_TEST_DIR=/opt/nvtl/bin/tests
FOTA_STANDARD_PRI_UPDATER=$FOTA_BIN_TEST_DIR/pri_diff_process
FOTA_MIFI_MTD_TEST=$FOTA_BIN_TEST_DIR/mifi_mtd_test
FOTA_LINUX_PRI_UPDATER=$FOTA_BIN_DIR/fota_linux_pri.sh
FOTA_LOG_FILE=$FOTA_DATA/update_log
INTERRUPTION_COUNT=$FOTA_DATA/interruption_count
MIFI_UPI_DISP_APP=/opt/nvtl/bin/mifi_upi_disp
MIFI_UPI_DISP_PNG_PREFIX="/opt/nvtl/display/fota/Updating-Software-Less-than-1-min_"
SHUTDOWN_AFTER_INSTALL=$DLPKG_STAGING_DIR/shutdown
LPM_AFTER_INSTALL=$DLPKG_STAGING_DIR/lpm
MAX_LOG_FILE_SIZE=573440 ## 560kb 
NVTL_LOG=/opt/nvtl/bin/nvtl_log
DL_CKSUM_FILE=$DLPKG_STAGING_DIR/dlpkg_cksum
PKG_DESC_FILE=$DLPKG_STAGING_DIR/pkg_description
SRC_VER_FILE=$DLPKG_STAGING_DIR/src_ver
TGT_VER_FILE=$DLPKG_STAGING_DIR/target_ver
UPI_PKG_FILE=$DLPKG_STAGING_DIR/upi_package
SRC_KERNEL_MD5=$DLPKG_STAGING_DIR/src_kernel_md5
SRC_KERNEL_SIZE=$DLPKG_STAGING_DIR/src_kernel_size
VERSION_DIR=/tmp/version
PRI_VER_FILE=$VERSION_DIR/pri
CUSTOM_SCRIPT=$DLPKG_STAGING_DIR/custom_script
CUSTOM_SCRIPT_COOKIE=$DLPKG_STAGING_DIR/custom_script_cookie
PREFERED_TECH=$DLPKG_STAGING_DIR/prefered_tech
get_current_boot_slot()
	if [ ! -f $FOTA_STAGING_CURRENT_BOOT_SLOT ]; then
		echo "FOTA_PMODE: Error did not find current boot slot file in staging directory." | tee -a $FOTA_LOG_FILE
		set_update_failure_and_handle_power_up
	#TODO: get from mtd utility.
	current_slot=`$FOTA_MIFI_MTD_TEST -g | grep -w boot_slot | awk '{print $2}'`
	echo "FOTA_PMODE: Read current boot slot is [$current_slot]" | tee -a $FOTA_LOG_FILE
	if [[ "$current_slot" == "A" ]]; then
		new_slot=B
	elif [[ "$current_slot" == "B" ]]; then
		new_slot=A
		echo "FOTA_PMODE: Error boot slot is [$current_slot] invalid" | tee -a $FOTA_LOG_FILE
		set_update_failure_and_handle_power_up
	staging_current_slot=`cat $FOTA_STAGING_CURRENT_BOOT_SLOT`
	if [ "$staging_current_slot" == "" ]; then
		echo "FOTA_PMODE: Error staginfg current boot slot file value is empty." | tee -a $FOTA_LOG_FILE
		set_update_failure_and_handle_power_up
	if [ "$current_slot" != "$staging_current_slot" ]; then
		echo "FOTA_PMODE: Looks like interruption is occured after setting new boot slot." | tee -a $FOTA_LOG_FILE
		rm -f $FOTA_STAGING_UPDATE_POST_INSTALL
		rm -f $INTERRUPTION_COUNT
		handle_power_up_scenario			
update_boot_slot()
	echo "FOTA_PMODE: Writing next boot slot is [$new_slot]" | tee -a $FOTA_LOG_FILE
	$FOTA_MIFI_MTD_TEST -m $new_slot
backup_update_logs()
	Date=$(date +"%d-%m-%Y_%T")
	update_log_file="$FOTA_DATA/Update_log_$Date.zip"
	file_size=$(ls -l $FOTA_LOG_FILE | awk '{print $5}')
	if [ -z "$file_size" ]; then
		echo "FOTA_PMODE: Update log file is not present" | tee -a $FOTA_LOG_FILE
		if [ $file_size -gt $MAX_LOG_FILE_SIZE ]; then
			zip -j $update_log_file $FOTA_LOG_FILE
			rm $FOTA_LOG_FILE
			#echo "FOTA_PMODE: Backup of the Update log file into $update_log_file" | tee -a $FOTA_LOG_FILE
			count=$(ls -lt $FOTA_DATA | grep "Update_log" | wc -l)
			if [ $count -gt 7 ]; then
				Del_file=$(ls -lt $FOTA_DATA | grep "Update_log" | tail -1 | awk '{print $NF}')
				#echo "Deleting the oldest Update log file [ $Del_file ]" | tee -a $FOTA_LOG_FILE
				rm $FOTA_DATA/$Del_file
log_device_information()
	if [ -f $PKG_DESC_FILE ]; then
		echo -n "FOTA_PMODE: pkg_desc=" | tee -a $FOTA_LOG_FILE		 
		cat $PKG_DESC_FILE | tee -a $FOTA_LOG_FILE
		echo "" | tee -a $FOTA_LOG_FILE 
	if [ -f $SRC_VER_FILE ]; then
		echo -n "FOTA_PMODE: pkg_src_version=" | tee -a $FOTA_LOG_FILE		 
		cat $SRC_VER_FILE | tee -a $FOTA_LOG_FILE
		echo "" | tee -a $FOTA_LOG_FILE 
	if [ -f $TGT_VER_FILE ]; then
		echo -n "FOTA_PMODE: pkg_tgt_version=" | tee -a $FOTA_LOG_FILE		 
		cat $TGT_VER_FILE | tee -a $FOTA_LOG_FILE
		echo "" | tee -a $FOTA_LOG_FILE
	if [ -f $PRI_VER_FILE ]; then
		echo -n "FOTA_PMODE: pri_version=" | tee -a $FOTA_LOG_FILE		 
		cat $PRI_VER_FILE | tee -a $FOTA_LOG_FILE
		echo "" | tee -a $FOTA_LOG_FILE
	if [ -f $DL_CKSUM_FILE ]; then
		echo "FOTA_PMODE: Download file checksums:" | tee -a $FOTA_LOG_FILE		 
		cat $DL_CKSUM_FILE | tee -a $FOTA_LOG_FILE
		echo "" | tee -a $FOTA_LOG_FILE
	if [ -f $UPI_PKG_FILE ]; then
		upi_pkg_md5sum="`md5sum $UPI_PKG_FILE`"
		echo $upi_pkg_md5sum | tee -a $FOTA_LOG_FILE		
create_pri_error_cookie()
	if [ "$1" == "modem_pri" ]; then
		pri_failure_str="Modem-PRI - error=$2"
		echo "$pri_failure_str" >$FOTA_STAGING_PRI_MODEM_FAILURE
	elif [ "$1" == "linux_pri" ]; then
		pri_failure_str="Linux-PRI - error=$2"
		echo "$pri_failure_str" >$FOTA_STAGING_PRI_LINUX_FAILURE
	echo "FOTA_PMODE: $pri_failure_str" | tee -a $FOTA_LOG_FILE
find_403_update_failure_reason()
	diff_list="/tmp/check_md5_diff_result"
	mod_list="/tmp/check_md5_mod_list"
	if [ -f "$diff_list" ]; then
		echo -n "File md5 failure:" >$FOTA_STAGING_UPDATE_FAILURE_REASON
		grep -v -e "---" -e "+++" $diff_list | awk '$1 ~ /^\+/ {print $2}' >$mod_list
		no_of_lines="`wc -l < $mod_list`"
		if [ "$no_of_lines" != "0" ]; then
			file="$mod_list"
			while IFS= read line
				if [ ! -z $line ]; then
					item=`basename $line`
					echo -n " $item" >>$FOTA_STAGING_UPDATE_FAILURE_REASON
					echo "$item"
			done <"$file"
		#Lets check if the issue is with kernel mismatch
		if [ ! -f $SRC_KERNEL_MD5 -o ! -f $SRC_KERNEL_SIZE ]; then
			return
		kernel_md5="`head -n 1 $SRC_KERNEL_MD5 | tr -d '\n'`"
		kernel_size="`head -n 1 $SRC_KERNEL_SIZE | tr -d '\n'`"
		if [ -z kernel_md5 -o -z kernel_size ]; then
			return
		len=$(expr "x$kernel_size" : "x[0-9]*$")
		let len=len-1
		if [ ! $len -gt 0 ]; then
			return
		echo "FOTA_PMODE: src kernel_md5=$kernel_md5, size=$kernel_size" | tee -a $FOTA_LOG_FILE
		rm -f /tmp/kernel_from_nand
		if [ "$target" != "px3" ]; then
			# read boot image from NAND			
			/opt/nvtl/bin/tests/mifi_mtd_test -p boot -r 0 -l $kernel_size -O /tmp/kernel_from_nand
			if [ $? -ne 0 ]; then
				echo "FOTA_PMODE: mifi_mtd_test -p boot -r 0 -l $kernel_size -O /tmp/kernel_from_nand failed" | tee -a $FOTA_LOG_FILE
				return
			fi			
		else 						
			read_image_from_mmc /tmp/kernel_from_nand /dev/mmcblk0p6 $kernel_size
			ret=$?
			if [ $ret -ne 0 ]; then
				echo "FOTA_PMODE: read_image_from_mmc failed to read kernel partition" | tee -a $FOTA_LOG_FILE
				return
		nand_kernel_md5="`md5sum  /tmp/kernel_from_nand | awk '{print $1}'`"
		if [ "$nand_kernel_md5" != "$kernel_md5" ]; then
			echo -n "Kernel md5 failure - [$kernel_md5 != $nand_kernel_md5]" >$FOTA_STAGING_UPDATE_FAILURE_REASON
			#Then some thing wrong with modem image, because it is the only thing left
			echo -n "Modem md5 failure likely" >$FOTA_STAGING_UPDATE_FAILURE_REASON
	print_str="`cat $FOTA_STAGING_UPDATE_FAILURE_REASON`"
	echo "FOTA_PMODE: $print_str" | tee -a $FOTA_LOG_FILE
handle_power_up_scenario()
	if [ -f "$SHUTDOWN_AFTER_INSTALL" ]; then 
		echo "FOTA_PMODE: Found -- $SHUTDOWN_AFTER_INSTALL File" | tee -a $FOTA_LOG_FILE
		echo "FOTA_PMODE: Shutting Off device" | tee -a $FOTA_LOG_FILE
		rm -f $SHUTDOWN_AFTER_INSTALL
		backup_update_logs
		telinit 0
	elif [ -f "$LPM_AFTER_INSTALL" ]; then
		echo "FOTA_PMODE: Found -- $LPM_AFTER_INSTALL File" | tee -a $FOTA_LOG_FILE
		echo "FOTA_PMODE: Will Enter LPM After reboot" | tee -a $FOTA_LOG_FILE 
		backup_update_logs
		rm -f $LPM_AFTER_INSTALL
		telinit 6
		echo "FOTA_PMODE: Default case -- Reboot and enter Online" | tee -a $FOTA_LOG_FILE
		enter_online_after_reboot
enter_online_after_reboot()
	if [ "$target" != "px3" ]; then
		echo "FOTA_PMODE: Setting NV_AUTO_POWER_I to 1" | tee -a $FOTA_LOG_FILE
		nwnvitem -w -e NV_AUTO_POWER_I -d 1
		echo "FOTA_PMODE: enter_online_after_reboot" | tee -a $FOTA_LOG_FILE
	echo "FOTA_PMODE: Restarting from RL5" | tee -a $FOTA_LOG_FILE
	backup_update_logs
	telinit 6
set_update_failure_and_handle_power_up()
	# Set the result code here to failure 
	echo "409" > $FOTA_STAGING_UPDATE_FAILURE
	rm -f $FOTA_STAGING_UPDATE_SUCCESS
	rm -f $FOTA_STAGING_UPDATE_PRE_INSTALL
	rm -f $FOTA_STAGING_UPDATE_POST_INSTALL
	rm -f $INTERRUPTION_COUNT
	# This does not return
	handle_power_up_scenario
read_image_from_mmc()
	filename=$1
	mmcblk=$2
	length=$3
	echo "FOTA_PMODE: read_image_from_mmc: filename=$filename mmcblk=$mmcblk length=$length" | tee -a $FOTA_LOG_FILE
	$NVTL_LOG -p 0 -m FOTA -l notice -s "FOTA_PMODE: read_image_from_mmc: filename=$filename mmcblk=$mmcblk length=$length"
	rm -f $filename
	num_blks=`dc $length 512 / p | awk -F '.' '{print $1}'`
	num_blks=`dc $num_blks 1 + p`
	dd if=$mmcblk of=$filename bs=512 count=$num_blks &> /dev/null
	if [ $rc -ne 0 ]; then
		$NVTL_LOG -p 1 -m FOTA -l notice -s "FOTA_PMODE: dd (read) failed with $rc"
		return 1
	truncate -s $length $filename
	return 0
write_image_to_mmc()
	filename=$1
	mmcblk=$2
	echo "FOTA_PMODE: write_image_to_mmc: filename=$filename mmcblk=$mmcblk" | tee -a $FOTA_LOG_FILE
	$NVTL_LOG -p 0 -m FOTA -l notice -s "FOTA_PMODE: write_image_to_mmc: filename=$filename mmcblk=$mmcblk"
	dd if=$filename of=$mmcblk bs=512 &> /dev/null
	if [ $rc -ne 0 ]; then
		$NVTL_LOG -p 1 -m FOTA -l notice -s "FOTA_PMODE: dd (write) failed with $rc"
		return 1
	return 0
update_partition_mbn()
	PARTITION=mibib
	IMG_PATH=$DLPKG_STAGING_DIR/partition.mbn
	if [ -f "$IMG_PATH" ]; then
		echo "FOTA_PMODE: found partitin.mbn start updating" | tee -a $FOTA_LOG_FILE
		mtd_num=`cat /proc/mtd | grep -w $PARTITION | awk '{print $1}' | sed "s/[^0-9]//g"`
		if [ "$rc" != "0" ]; then
			echo "Get mtd number for $PARTITION failed, rc=$rc" | tee -a $FOTA_LOG_FILE
			return 1
		echo "partition number for $PARTITION is [$mtd_num]" | tee -a $FOTA_LOG_FILE
		image_len=`ls -l $IMG_PATH | awk '{ print $5 }'`
		if [ "$image_len" == "0" ]; then
			echo "$IMG_PATH image length 0" | tee -a $FOTA_LOG_FILE
			return 1
		echo "$IMG_PATH img length=[$image_len]" | tee -a $FOTA_LOG_FILE
		DEV_MTD="/dev/mtd${mtd_num}"
		#Erase the partition
		flash_erase $DEV_MTD 0 0
		if [ "$rc" != "0" ]; then
			echo "Erasing $DEV_MTD partition failed, rc=$rc" | tee -a $FOTA_LOG_FILE
			return 1
		echo "$DEV_MTD flash erase successfull" | tee -a $FOTA_LOG_FILE
		sleep 2
		#Flash paritition with new image
		/opt/nvtl/bin/tests/mifi_mtd_test -p $PARTITION -w 0 -l $image_len -I $IMG_PATH
		if [ "$rc" != "0" ]; then
			echo "Flashing $PARTITION partition is failed, rc=$rc" | tee -a $FOTA_LOG_FILE
			return 1
		sleep 2
		echo "$PARTITION partition flashed successfully" | tee -a $FOTA_LOG_FILE
		sync;sync;
		echo "Removed $IMG_PATH" | tee -a $FOTA_LOG_FILE
		rm -rf $IMG_PATH
		sync;sync;
		echo "Extra reboot before setting fota cookie" | tee -a $FOTA_LOG_FILE
		telinit 6
# Check whether it has branding.tgz and it should verified with it's signature
# This should be verify before starting of upgrade
branding_tgz_verify()
	copy_loca=$1
	echo "FOTA_PMODE: Checking for branding.tgz in the package" | tee -a $FOTA_LOG_FILE
	build_server_pubkey="/opt/nvtl/etc/fota/build_pubkey.pem"
	cd $DLPKG_STAGING_DIR
	fota_pkg=$DLPKG_STAGING_DIR/../upgrade.zip
	found=`unzip -l $fota_pkg | egrep -i "branding.tgz$" | wc -l`
	if [ $found -eq 1 ]; then
		cd /tmp
		# extract branding.tgz from package
		rm -f branding.tgz
		echo "FOTA_PMODE: branding_extract: extracting branding.tgz from zip file" | tee -a $FOTA_LOG_FILE
		unzip -j $fota_pkg branding.tgz -d /tmp
		if [ $? -ne 0 ]; then
			echo "FOTA_PMODE: unzip -j $fota_pkg branding.tgz -d /tmp failed" | tee -a $FOTA_LOG_FILE
			set_update_failure_and_handle_power_up
		echo "FOTA_PMODE: branding_extract: extracting branding.tgz signature from zip file" | tee -a $FOTA_LOG_FILE
		unzip -j $fota_pkg branding.tgz.sign -d /tmp
		if [ $? -ne 0 ]; then
			echo "FOTA_PMODE: unzip -j $fota_pkg branding.tgz.sign -d /tmp failed" | tee -a $FOTA_LOG_FILE
			set_update_failure_and_handle_power_up
		echo "FOTA_PMODE: Verifying the signature for branding.tgz file" | tee -a $FOTA_LOG_FILE
		check=$(openssl dgst -sha256 -verify $build_server_pubkey -signature /tmp/branding.tgz.sign /tmp/branding.tgz)
		if [ "$check" != "Verified OK" ]; then
			echo "FOTA_PMODE: Signature verification failed for branding.tgz" | tee -a $FOTA_LOG_FILE
			set_update_failure_and_handle_power_up
			sleep 10
			echo "FOTA_PMODE: Signature verification successful for branding.tgz" | tee -a $FOTA_LOG_FILE
			if [ "$copy_loca" != " " ]; then
				echo "FOTA_PMODE: copying branding.tgz to $copy_loca" | tee -a $FOTA_LOG_FILE
				cp -f branding.tgz $copy_loca
				sync
				sync
# If the following file is present then update the recovery partition.
# This file is located in the DLPKG_STAGING_DIR directory:
#   recovery.img.tar.bz2: compressed tar file of the recovery kernel image
# This file must be present for the update to occur.
check_recovery_update()
	echo "FOTA_PMODE: Checking for recovery partition udpate from recovery image" | tee -a $FOTA_LOG_FILE
	build_server_pubkey="/opt/nvtl/etc/fota/build_pubkey.pem"
	cd $DLPKG_STAGING_DIR
	fota_pkg=$DLPKG_STAGING_DIR/../upgrade.zip
	#files="recovery.img.tar.bz2"
	#found=1
	#for file in $files; do
	#	if [ -f $file ]; then
	#		chmod +r $file
	#		found=0
	found=`unzip -l $fota_pkg | egrep -i "recovery.img$" | wc -l`
	if [ $found -eq 1 ]; then
		cd /tmp
		# extract recovery image from compressed tar file
		rm -f recovery.img
		#echo "FOTA_PMODE: recovery_extract: extracting recovery image from tar file" | tee -a $FOTA_LOG_FILE
		#tar xvjf $DLPKG_STAGING_DIR/recovery.img.tar.bz2
		echo "FOTA_PMODE: recovery_extract: extracting recovery image from zip file" | tee -a $FOTA_LOG_FILE
		unzip -j $fota_pkg recovery.img -d /tmp
		if [ $? -ne 0 ]; then
			#echo "FOTA_PMODE: tar xvjf $DLPKG_STAGING_DIR/recovery.img.tar.bz2 failed" | tee -a $FOTA_LOG_FILE
			echo "FOTA_PMODE: unzip -j $fota_pkg recovery.img -d /tmp failed" | tee -a $FOTA_LOG_FILE
			set_update_failure_and_handle_power_up
		echo "FOTA_PMODE: recovery_extract: extracting recovery signature from zip file" | tee -a $FOTA_LOG_FILE
		unzip -j $fota_pkg recovery.img.sign -d /tmp
		if [ $? -ne 0 ]; then
			echo "FOTA_PMODE: unzip -j $fota_pkg recovery.img.sign -d /tmp failed" | tee -a $FOTA_LOG_FILE
			set_update_failure_and_handle_power_up
		echo "FOTA_PMODE: Verifying the signature for recovery image file" | tee -a $FOTA_LOG_FILE
		check=$(openssl dgst -sha256 -verify $build_server_pubkey -signature /tmp/recovery.img.sign /tmp/recovery.img)
		if [ "$check" != "Verified OK" ]; then
			echo "FOTA_PMODE: Signature verification failed for recovery image" | tee -a $FOTA_LOG_FILE
			echo "FOTA_PMODE: Failed to upgrade the recovery partition" | tee -a $FOTA_LOG_FILE
			set_update_failure_and_handle_power_up
			sleep 10
			echo "FOTA_PMODE: Signature verification successful for recovery image" | tee -a $FOTA_LOG_FILE
		recovery_len=`ls -l recovery.img | awk '{ print $5 }'`
		if [ "$target" != "px3" ]; then
			# write recovery image to NAND	
			echo "FOTA_PMODE: recovery_write_image: writing recovery image to NAND" | tee -a $FOTA_LOG_FILE
			/opt/nvtl/bin/tests/mifi_mtd_test -p recovery -w 0 -l $recovery_len -I recovery.img
			if [ $? -ne 0 ]; then
				echo "FOTA_PMODE: mifi_mtd_test -p recovery -w 0 -l $recovery_len -I recovery.img failed" | tee -a $FOTA_LOG_FILE
				set_update_failure_and_handle_power_up
			echo "FOTA_PMODE: write_image_to_mmc: writing recovery image to MMC" | tee -a $FOTA_LOG_FILE
			write_image_to_mmc recovery.img /dev/mmcblk0p3
			ret=$?
			if [ $ret -ne 0 ]; then
				echo "FOTA_PMODE:write_image_to_mmc failed to write recovery partition" | tee -a $FOTA_LOG_FILE
				set_update_failure_and_handle_power_up
		rm -f /tmp/recovery_from_nand
		if [ "$target" != "px3" ]; then
			# read recovery image from NAND
			echo "FOTA_PMODE: recovery_read_image_from_nand: reading recovery image from NAND" | tee -a $FOTA_LOG_FILE
			/opt/nvtl/bin/tests/mifi_mtd_test -p recovery -r 0 -l $recovery_len -O /tmp/recovery_from_nand
			if [ $? -ne 0 ]; then
				echo "FOTA_PMODE: mifi_mtd_test -p recovery -r 0 -l $recovery_len -O /tmp/recovery_from_nand failed" | tee -a $FOTA_LOG_FILE
				set_update_failure_and_handle_power_up
			fi			
			echo "FOTA_PMODE: read_image_from_mmc: read recovery image from MMC" | tee -a $FOTA_LOG_FILE			
			read_image_from_mmc /tmp/recovery_from_nand /dev/mmcblk0p3 $recovery_len
			ret=$?
			if [ $ret -ne 0 ]; then
				echo "FOTA_PMODE: read_image_from_mmc failed to read recovery partition" | tee -a $FOTA_LOG_FILE
				set_update_failure_and_handle_power_up
		# compare data read from NAND with original file
		echo "FOTA_PMODE: check_recovery_update_from_recovery_image: comparing images" | tee -a $FOTA_LOG_FILE
		cmp recovery.img /tmp/recovery_from_nand
		if [ $? -ne 0 ]; then
			echo "FOTA_PMODE: cmp recovery.img /tmp/recovery_from_nand failed" | tee -a $FOTA_LOG_FILE
			set_update_failure_and_handle_power_up
		echo "FOTA_PMODE: check_recovery_update_from_recovery_image: success" | tee -a $FOTA_LOG_FILE
		echo "FOTA_PMODE: No recovery partition udpate from recovery image found" | tee -a $FOTA_LOG_FILE
check_recovery_partition()
	# The recovery image has the string "ANDROID!" at the beginning of the header
	if [ "$target" != "px3" ]; then
		$FOTA_MIFI_MTD_TEST -p recovery -r 0 -l 4096 -O /tmp/recovery.img
		if [ $? -ne 0 ]; then
			echo "FOTA_PMODE: $FOTA_MIFI_MTD_TEST -p recovery -r 0 -l 4096 -O /tmp/recovery.img failed" | tee -a $FOTA_LOG_FILE
			set_update_failure_and_handle_power_up
		recovery_str_magic="ANDROID!"
		read_image_from_mmc /tmp/recovery.img /dev/mmcblk0p3 4096
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "FOTA_PMODE: read_image_from_mmc failed to read recovery partition" | tee -a $FOTA_LOG_FILE
			set_update_failure_and_handle_power_up
		recovery_str_magic="KRNL"
	strings /tmp/recovery.img | grep $recovery_str_magic &> /dev/null
	if [ $? -ne 0 ]; then
		echo "FOTA_PMODE: recovery partition does not contain a valid image" | tee -a $FOTA_LOG_FILE
		set_update_failure_and_handle_power_up
	echo "FOTA_PMODE: check_recovery_partition: passed" | tee -a $FOTA_LOG_FILE
ipkg_tgz_apply()
	ipkg_file=$DLPKG_STAGING_DIR/ipkg.tgz
	found=`ls -l $DLPKG_STAGING_DIR | egrep -i "ipkg.tgz$" | wc -l`
	if [ $found -eq 1 ]; then
		echo "FOTA_PMODE: Found the ipkg.tgz" | tee -a $FOTA_LOG_FILE
		tar -xf $ipkg_file -C /usr/lib
		if [ $? -ne 0 ]; then
			echo "FOTA_PMODE: tar -xf $ipkg_file -C /usr/lib failed" | tee -a $FOTA_LOG_FILE
			exit 0
		echo "FOTA_PMODE: Successfully uncompresed the ipkg.tgz to / " | tee -a $FOTA_LOG_FILE
		echo "FOTA_PMODE: The ipkg.tgz not found" | tee -a $FOTA_LOG_FILE
webui_cgi_apply()
	cgi_file=$DLPKG_STAGING_DIR/webui_cgi.tgz
	found=`ls -l $DLPKG_STAGING_DIR | egrep -i "webui_cgi.tgz$" | wc -l`
	if [ $found -eq 1 ]; then
		echo "FOTA_PMODE: Found the webui_cgi.tgz" | tee -a $FOTA_LOG_FILE
		tar -xf $cgi_file -C /opt/nvtl/webui/public
		if [ $? -ne 0 ]; then
			echo "FOTA_PMODE: tar -xf $cgi_file -C /opt/nvtl/webui/public failed" | tee -a $FOTA_LOG_FILE
			exit 0
		echo "FOTA_PMODE: Successfully uncompresed the webui_cgi.tgz to / " | tee -a $FOTA_LOG_FILE
		echo "FOTA_PMODE: The webui_cgi.tgz not found" | tee -a $FOTA_LOG_FILE
save_apn_from_modem()
	model_name=$1
	echo "FOTA_PMODE: Saving APN for device Model = [$model_name]" | tee -a $FOTA_LOG_FILE
	apn_profile=1
	while true; do
		apn_profile_file="$APN_PROFILE$apn_profile.txt"
		backup_profile="$APN_PROFILE$apn_profile.txt.bck"
		if [ -f $FOTA_STAGING_NWCLI ]; then
			echo "FOTA_PMODE: executing the nwcli from FOTA dir" | tee -a $FOTA_LOG_FILE
			chmod 777 $FOTA_STAGING_NWCLI
			$FOTA_STAGING_NWCLI profile_get $apn_profile 1 | tee -a $FOTA_LOG_FILE
			/opt/nvtl/bin/nwcli profile_get $apn_profile 1 | tee -a $FOTA_LOG_FILE
		if [ -f "$apn_profile_file" ]; then
			cp $apn_profile_file $backup_profile
		apn_profile=$((apn_profile+1))
		if [ $apn_profile -eq 5 ];then
			break
clear_mcfg()
	echo "FOTA_PMODE: Executing the AT cmd nwmcfg=7" |  tee -a $FOTA_LOG_FILE                                                                                                   
	if [ -f "/opt/nvtl/bin/read_atcmd" ];then
		cmd=/opt/nvtl/bin/read_atcmd
	elif [ -f "/opt/nvtl/bin/atcmd" ];then
		cmd=/opt/nvtl/bin/atcmd
		echo "FOTA_PMODE: There is no AT command executable" | tee -a $FOTA_LOG_FILE
		return
	$cmd  "at\$nwmcfg=7" /dev/smd7 | tee -a $FOTA_LOG_FILE
	sleep 10
	echo "FOTA_PMODE: Executing the AT cmd nwmcfg?" |  tee -a $FOTA_LOG_FILE                                                                                                   
	$cmd  "at\$nwmcfg?" /dev/smd7 | tee -a $FOTA_LOG_FILE
restore_apn_to_modem()
	model_name=$1
	echo "FOTA_PMODE: Restoring APN for device Model = [$model_name]" | tee -a $FOTA_LOG_FILE
	apn_profile=1
	while true; do
		apn_profile_file="$APN_PROFILE$apn_profile.txt"
		backup_profile="$APN_PROFILE$apn_profile.txt.bck"
		if [ -f  "$backup_profile" ]; then
			cp $backup_profile $apn_profile_file
		if [ -f "$apn_profile_file" ];then
			if [ -f $FOTA_STAGING_NWCLI ]; then
				echo "FOTA_PMODE: executing the nwcli from FOTA dir" | tee -a $FOTA_LOG_FILE
				chmod 777 $FOTA_STAGING_NWCLI
				profile=$($FOTA_STAGING_NWCLI profile_restore $apn_profile 1)
			else 
				profile=$(/opt/nvtl/bin/nwcli profile_restore $apn_profile 1)
			if [ -n "$profile" ]; then 
				valid=$(echo $profile | grep "Failed")
				echo "$profile" | tee -a $FOTA_LOG_FILE
				if [ -z "$valid" ]; then 
					echo "[FOTA_PMODE]: Profile $apn_profile restored successfully" | tee -a $FOTA_LOG_FILE
					apn_profile=$((apn_profile+1))
			apn_profile=$((apn_profile+1))
		if [ $count -eq 20 ];then
			echo "[FOTA_PMODE]: Timeout... Trying to restore the profile" | tee -a $FOTA_LOG_FILE
			while true; do
				apn_profile_file="$APN_PROFILE$apn_profile.txt"
				backup_profile="$APN_PROFILE$apn_profile.txt.bck"
				if [ -f  "$backup_profile" ];then
					cp $backup_profile $apn_profile_file
					sync
					sync
					echo "[FOTA_PMODE]: Trying to restore the profile $apn_profile" | tee -a $FOTA_LOG_FILE	
					if [ -f "$apn_profile_file" ];then
						if [ -f $FOTA_STAGING_NWCLI ];then
							chmod 777 $FOTA_STAGING_NWCLI
							profile=$($FOTA_STAGING_NWCLI profile_restore $apn_profile 1)
						else 
							profile=$(/opt/nvtl/bin/nwcli profile_restore $apn_profile 1)
						fi
						echo "$profile" | tee -a $FOTA_LOG_FILE
				apn_profile=$((apn_profile+1))
				if [ $apn_profile -ge 5 ];then
					break
			break
			count=$((count+1))
			sleep 10
		if [ $apn_profile -ge 5 ];then
			break
save_prefer_tech()
	echo "FOTA_PMODE: Saving Prefered technology" | tee -a $FOTA_LOG_FILE
	if [ -f "/opt/nvtl/bin/read_atcmd" ];then
		cmd=/opt/nvtl/bin/read_atcmd
	elif [ -f "/opt/nvtl/bin/atcmd" ];then
		cmd=/opt/nvtl/bin/atcmd
		echo "FOTA_PMODE: There is no at command executable" | tee -a $FOTA_LOG_FILE
		return
	echo "FOTA_PMODE: AT command executable [$cmd]" | tee -a $FOTA_LOG_FILE
	tech=$($cmd "AT\$NWPREFMODE2?" /dev/smd7 | grep "Mode_Pref" | awk -F':' '{print $2}' | sed -e 's/[[:space:]]*//g')
	if [ -z "$tech" ]; then
		tech=$($cmd "AT\$NWPREFMODE2?" /dev/smd7 | grep "Mode_Pref" | awk -F':' '{print $2}' | sed -e 's/[[:space:]]*//g')
	if [ ! -z "$tech" ]; then	
		echo "FOTA_PMODE: Saved Prefered technology value [ $tech ]" | tee -a $FOTA_LOG_FILE
		echo -n "$tech" > $PREFERED_TECH
		echo "FOTA_PMODE: Error in reading prefer technology value" | tee -a $FOTA_LOG_FILE
		$cmd "AT\$NWPREFMODE2?" /dev/smd7 | tee -a $FOTA_LOG_FILE
restore_prefer_tech()
	echo "FOTA_PMODE: Restoring Prefered technology" | tee -a $FOTA_LOG_FILE
	if [ -f "$PREFERED_TECH" ];then
		if [ -f "/opt/nvtl/bin/read_atcmd" ];then
			cmd=/opt/nvtl/bin/read_atcmd
		elif [ -f "/opt/nvtl/bin/atcmd" ];then
			cmd=/opt/nvtl/bin/atcmd
			echo "FOTA_PMODE: There is no at command executable" | tee -a $FOTA_LOG_FILE
			return
		echo "FOTA_PMODE: AT command executable [$cmd]" | tee -a $FOTA_LOG_FILE
		echo "FOTA_PMODE: Reading the prefer technology before writing Prefered technology value" | tee -a $FOTA_LOG_FILE
		$cmd "AT\$NWPREFMODE2?" /dev/smd7 | tee -a $FOTA_LOG_FILE
		tech=$(cat $PREFERED_TECH)
		echo "FOTA_PMODE: Writing Prefered technology value [ $tech ]" | tee -a $FOTA_LOG_FILE
		if [ -z "$tech" ];then
			echo "FOTA_PMODE: Prefered technology value [ $tech ] is empty" | tee -a $FOTA_LOG_FILE
			return
			$cmd "AT\$NWPREFMODE2=0x$tech" /dev/smd7 | tee -a $FOTA_LOG_FILE
			RET=$?
			if [ "$RET" -ne "0" ]; then 
				echo "FOTA_PMODE: Error in updating Prefered technology value [ $tech ]" | tee -a $FOTA_LOG_FILE
				$cmd "AT\$NWPREFMODE2=0x$tech" /dev/smd7 | tee -a $FOTA_LOG_FILE
				echo "FOTA_PMODE: Successfully updated Prefered technology value [ $tech ]" | tee -a $FOTA_LOG_FILE
do_start()
	date | tee -a $FOTA_LOG_FILE
	target=`cat /target`
	echo "FOTA_PMODE: Target=$target FOTA_CUSTOM_INSTALL=$FOTA_CUSTOM_INSTALL" | tee -a $FOTA_LOG_FILE
	echo "FOTA_PMODE: Arg0=$0" | tee -a $FOTA_LOG_FILE
	# Check for a custom install script if we aren't already running it
	if [ -f $FOTA_CUSTOM_INSTALL ] && [ "$FOTA_CUSTOM_INSTALL" != "$0" ]; then
		echo "FOTA_PMODE: Starting CUSTOM Image / PRI Update process" | tee -a $FOTA_LOG_FILE
		chmod 0777 $FOTA_CUSTOM_INSTALL
		$FOTA_CUSTOM_INSTALL
		rm -f $INTERRUPTION_COUNT		
		echo "FOTA_PMODE: Starting Image / PRI Update process" | tee -a $FOTA_LOG_FILE
		if [ -f $FOTA_STAGING_UPDATE_PRE_INSTALL ]; then			
			date | tee -a $FOTA_LOG_FILE
			echo "FOTA_PMODE: At FOTA_STAGING_UPDATE_PRE_INSTALL" | tee -a $FOTA_LOG_FILE
			$NVTL_LOG -p 1 -m FOTA -l notice -s "FOTA_PMODE: At pre-installation stage"
			# Log necessary device information for future debugging
			log_device_information
			#saving APN profiles
			echo "FOTA_PMODE: saving APN's in PRE-INSTALL stage" | tee -a $FOTA_LOG_FILE
			model_name=$(cat $FOTA_STAGING_PKG_DESCRIPTION | awk '{split($0,a,"_"); print a[1]}')
			save_apn_from_modem $model_name
			sync							
			sleep 5
			#Clearing the content of /opt/nvtl/data/webui/uploads
			if [ -d "/opt/nvtl/data/webui/uploads" ];then
				echo "FOTA_PMODE: Clearing the content in /opt/nvtl/data/webui/uploads path" | tee -a $FOTA_LOG_FILE
				md5sum /opt/nvtl/data/webui/uploads/* | tee -a $FOTA_LOG_FILE
				rm -rf /opt/nvtl/data/webui/uploads/*
			echo "FOTA_PMODE: saving Prefered technology in PRE-INSTALL stage" | tee -a $FOTA_LOG_FILE
			save_prefer_tech
			sync							
			# Check ipkg.tgz
			ipkg_tgz_apply
			# Check cgi.tgz
			webui_cgi_apply
			# Check branding.tgz 
			branding_tgz_verify " "		
			# Check if the recovery partition needs to be updated
			check_recovery_update
			# Make sure the recovery partition is not empty
			check_recovery_partition
			# update partition mbn if avialable
			update_partition_mbn
			echo "FOTA_PMODE: Setting FOTA Cookie to enter recoevery mode" | tee -a $FOTA_LOG_FILE
			RET=0
			if [ "$target" != "px3" ]; then
				if [ -f $FOTA_SUA_UPDATE_COOKIE ]; then
					echo -n "CSddSURA" > /tmp/fotacookie
					$FOTA_MIFI_MTD_TEST -p fotacookie -w 0 -l 8 -I /tmp/fotacookie
				else 
					$FOTA_MIFI_MTD_TEST -c
				RET=$?
				/opt/nvtl/bin/program_fotacookie.sh set
				RET=$?
			if [ "$RET" -ne "0" ]; then 
				echo "FOTA_PMODE: Unable to set the cookie, ret:$RET" | tee -a $FOTA_LOG_FILE
				$NVTL_LOG -p 1 -m FOTA -l err -s "FOTA_PMODE: Error, unable to set cookie"
				# This does not return
				set_update_failure_and_handle_power_up
			else 
				rm -f $FOTA_STAGING_UPDATE_PRE_INSTALL
				rm -f $INTERRUPTION_COUNT
				echo "FOTA_PMODE: Rebooting From RL5 to enter Recovery kernel" | tee -a $FOTA_LOG_FILE
				$NVTL_LOG -p 1 -m FOTA -l notice -s "FOTA_PMODE: Entering recovery mode"
				sync
				sync
				telinit 6
		elif [ -f $FOTA_STAGING_UPDATE_POST_INSTALL ]; then
			echo "FOTA_PMODE: At FOTA_STAGING_UPDATE_POST_INSTALL" | tee -a $FOTA_LOG_FILE
			$NVTL_LOG -p 1 -m FOTA -l notice -s "FOTA_PMODE: At Post installation stage"
			if [ -f "$FOTA_STAGING_UPDATE_SUCCESS" ]; then
				$NVTL_LOG -p 1 -m FOTA -l notice -s "FOTA_PMODE: depmod executing"
				echo "FOTA_PMODE: depmod executing" | tee -a $FOTA_LOG_FILE
				depmod
				sleep 1
				$NVTL_LOG -p 1 -m FOTA -l notice -s "FOTA_PMODE: About to update PRI"
				echo "FOTA_PMODE: Handling Update success case, about to update PRI" | tee -a $FOTA_LOG_FILE
				if [ -f "$MIFI_UPI_DISP_APP" ]; then
					echo "FOTA_PMODE: Starting display app in background" | tee -a $FOTA_LOG_FILE
					$MIFI_UPI_DISP_APP $MIFI_UPI_DISP_PNG_PREFIX 4 350 &			
				sleep 10
				if [ ! -f $FOTA_STAGING_PRI_LINUX_SUCCESS ]; then 
					if [ -f "$DLPKG_STAGING_DIR/pri_delta.xml" -a "$target" != "px3" ]; then 	
						RET=0
						$NVTL_LOG -p 1 -m FOTA -l notice -s "FOTA_PMODE: Starting to update Modem PRI"	
						$FOTA_STANDARD_PRI_UPDATER -f $DLPKG_STAGING_DIR/pri_delta.xml -i 1 >>$FOTA_LOG_FILE 2>&1
						RET=$?
						if [ "$RET" -ne "0" ]; then 
							$NVTL_LOG -p 1 -m FOTA -l err -s "FOTA_PMODE: Error in updating Modem PRI, ret=$RET"
							echo "FOTA_PMODE: Error in Updating Modem PRI, ret:$RET" | tee -a $FOTA_LOG_FILE
							create_pri_error_cookie modem_pri $RET
						else 
							$NVTL_LOG -p 1 -m FOTA -l notice -s "FOTA_PMODE: Success in updating Modem PRI"
							echo "FOTA_PMODE: Success in updating Modem PRI" | tee -a $FOTA_LOG_FILE
							touch $FOTA_STAGING_PRI_MODEM_SUCCESS	
						fi
					else
						echo "FOTA_PMODE: Not updating Modem PRI" | tee -a $FOTA_LOG_FILE	
					$NVTL_LOG -p 1 -m FOTA -l notice -s "FOTA_PMODE: Starting to update Linux PRI"
					RET=0
					$FOTA_LINUX_PRI_UPDATER
					RET=$?
					if [ "$RET" -ne "0" ]; then 
						$NVTL_LOG -p 1 -m FOTA -l err -s "FOTA_PMODE: Error in updating Linux PRI, ret=$RET"
						echo "FOTA_PMODE: Error in updating Linux PRI, ret=$RET" | tee -a $FOTA_LOG_FILE
						create_pri_error_cookie linux_pri $RET
					else 
						$NVTL_LOG -p 1 -m FOTA -l notice -s "FOTA_PMODE: Success in updating Linux PRI"
						echo "FOTA_PMODE: Success in updating Linux PRI" | tee -a $FOTA_LOG_FILE	
						touch $FOTA_STAGING_PRI_LINUX_SUCCESS
					sync
					sync
				fi                                       
				if [ -f "$CUSTOM_SCRIPT" ] && [ ! -f "$CUSTOM_SCRIPT_COOKIE" ];then
					echo "FOTA_PMODE: Custom script found" | tee -a $FOTA_LOG_FILE
					chmod +x $CUSTOM_SCRIPT
					$CUSTOM_SCRIPT "FOTA_PMODE"
					touch $CUSTOM_SCRIPT_COOKIE
					sync
					sync
                                
				echo "FOTA_PMODE: Sleep for 90sec after PRI applied" | tee -a $FOTA_LOG_FILE
				sleep 90
				if [ -f "$FOTA_STAGING_UPDATE_CLEAR_MCFG" ]; then	
					if [ ! -f "$FOTA_STAGING_CLR_MCFG_DONE" ]; then
						clear_mcfg
						touch $FOTA_STAGING_CLR_MCFG_DONE
						sync
						echo "FOTA_PMODE: $FOTA_STAGING_CLR_MCFG_DONE cookie created" | tee -a $FOTA_LOG_FILE
						ls -l $FOTA_STAGING_CLR_MCFG_DONE | tee -a $FOTA_LOG_FILE
						$NVTL_LOG -p 1 -m FOTA -l notice -s "FOTA_PMODE: rebooting the device after clearing mcfg"
						echo "FOTA_PMODE: rebooting the device after clearing mcfg" | tee -a $FOTA_LOG_FILE
						telinit 6
					else
						$NVTL_LOG -p 1 -m FOTA -l notice -s "FOTA_PMODE: First boot after mcfg clear, sleep 30sec for default apn restore by modem"
						echo "FOTA_PMODE: First boot after mcfg clear, sleep 30sec for default apn restore by modem" | tee -a $FOTA_LOG_FILE
						sleep 30
						echo "FOTA_PMODE: Executing the AT cmd nwmcfg?" |  tee -a $FOTA_LOG_FILE
						if [ -f "/opt/nvtl/bin/read_atcmd" ];then
							cmd=/opt/nvtl/bin/read_atcmd
						elif [ -f "/opt/nvtl/bin/atcmd" ];then
							cmd=/opt/nvtl/bin/atcmd
						else
							echo "FOTA_PMODE: There is no at command executable" | tee -a $FOTA_LOG_FILE
						fi
						$cmd  "at\$nwmcfg?" /dev/smd7 | tee -a $FOTA_LOG_FILE
				count=0
				model_name=$(cat $FOTA_STAGING_PKG_DESCRIPTION | awk '{split($0,a,"_"); print a[1]}')
				apn_profile=1
				while true; do	
					time=$(date)
					echo "[$time] :: [FOTA_PMODE]: Reading the profile $apn_profile" | tee -a $FOTA_LOG_FILE
					apn_profile_file="$APN_PROFILE$apn_profile.txt.bck"
					if [ -f "$apn_profile_file" ];then
						if [ -f $FOTA_STAGING_NWCLI ]; then
							chmod 777 $FOTA_STAGING_NWCLI
							profile=$($FOTA_STAGING_NWCLI profile_get $apn_profile 0)
						else
							profile=$(/opt/nvtl/bin/nwcli profile_get $apn_profile 0)
						fi
						if [ -n "$profile" ]; then 
							valid=$(echo $profile | grep "failed")
							echo "$profile" | tee -a $FOTA_LOG_FILE
							if [ -z "$valid" ]; then 
								apn_profile=$((apn_profile+1))
							fi
						fi
					else
						apn_profile=$((apn_profile+1))
					if [ $count -eq 20 ];then
						echo "[$time] :: [FOTA_PMODE]: Timeout... unable to read the profile" | tee -a $FOTA_LOG_FILE
						echo "FOTA_PMODE: Restoring APN to Modem in POST-INSTALL state." | tee -a $FOTA_LOG_FILE
						restore_apn_to_modem $model_name
						break
					else
						count=$((count+1))
						sleep 10
					if [ $apn_profile -eq 5 ];then
						break
				done
				if [ $apn_profile -eq 5 ] && [ $count -ne 20 ];then
					echo "FOTA_PMODE: Restoring APN to Modem in POST-INSTALL state." | tee -a $FOTA_LOG_FILE
					restore_apn_to_modem $model_name
                                
				restore_prefer_tech
				branding_tgz_verify "/opt/nvtl/data/branding"
                                
				if [ -f "$FOTA_STAGING_BRANDING_TGZ" ]; then
 					echo "FOTA_PMODE: Found branding.tgz in the staging directory. So copying to branding directory" | tee -a $FOTA_LOG_FILE
					cp -f $FOTA_STAGING_BRANDING_TGZ /opt/nvtl/data/branding
                                
				$NVTL_LOG -p 1 -m FOTA -l notice -s "FOTA_PMODE: PRI procedure completed"
				if [ -f "$FOTA_STAGING_CLR_MCFG_DONE" ]; then
					rm -f $FOTA_STAGING_CLR_MCFG_DONE
					sync
					echo "FOTA_PMODE: $FOTA_STAGING_CLR_MCFG_DONE cookie removed" | tee -a $FOTA_LOG_FILE
				#echo "FOTA_PMODE: Re-setting the low power mode" | tee -a $FOTA_LOG_FILE
				#/opt/nvtl/bin/nwcli power_mode 1 | tee -a $FOTA_LOG_FILE
				$NVTL_LOG -p 1 -m FOTA -l notice -s "FOTA_PMODE: Error in installation"
				# If we had a signature mismatch (403 error) run check_md5.sh
				echo "FOTA_PMODE: Starting Display app for LED blinking in background" | tee -a $FOTA_LOG_FILE
				$MIFI_UPI_DISP_APP
				grep "rc_string=E_RB_SOURCE_FILE_SIG_MISMATCH" \
					/opt/nvtl/data/fota/update_err_status.bin
				if [ $? -eq 0 ]; then
					echo "FOTA_PMODE: Update failed with 403 error - running check_md5.sh" | \
						tee -a $FOTA_LOG_FILE
					/opt/nvtl/bin/check_md5.sh | tee -a $FOTA_LOG_FILE
					find_403_update_failure_reason
					sleep 10
			rm -f $FOTA_STAGING_UPDATE_POST_INSTALL
			rm -f $INTERRUPTION_COUNT
			rm -f $CUSTOM_SCRIPT_COOKIE
			sync; sync;
			echo "FOTA_PMODE: Removed POST install cookie" | tee -a $FOTA_LOG_FILE
			# For chimay, omadm FOTA package required to reboot IPQ.
			if [ -f "$FOTA_STAGING_IPQ_REBOOT_REQUIRED" ] && [ -f "$FOTA_SESSION_LOCK_FILE" ];then
				agent=$(cat $FOTA_SESSION_LOCK_FILE)
				echo "FOTA_PMODE: Agent :: [$agent]" | tee -a $FOTA_LOG_FILE
				if [ "$agent" = "omadm" ];then
					count=0
					while true; do	
						time=$(date)
						/etc/init.d/mosquitto.sh start
						sleep 2
						/opt/nvtl/bin/settings.sh start
						sleep 2
						/opt/nvtl/bin/nvtl_msgbus.sh start
						sleep 2
						/opt/nvtl/bin/com_subsystem.sh start
						sleep 5
						status=$(/opt/nvtl/bin/com_subsystem_cli execute_shell_cmd reboot 1)
						valid=$(echo "$status" | grep "success")
						echo "[$time] :: [FOTA_PMODE]: Valid status :: [$valid]" | tee -a $FOTA_LOG_FILE
						if [ ! -z "$valid" ];then
							echo "[$time] :: [FOTA_PMODE]: Initiated the reboot command to IPQ" | tee -a $FOTA_LOG_FILE
							sleep 180
							break
						else
							echo "[$time] :: [FOTA_PMODE]: Reboot coomand failed to reboot the IPQ" | tee -a $FOTA_LOG_FILE
						fi
						if [ $count -eq 9 ];then
							echo "[$time] :: [FOTA_PMODE]: Timeout..unable to reboot the IPQ using communication system" | tee -a $FOTA_LOG_FILE
							break
						else
							count=$((count+1))
							sleep 5
						fi
					done
			handle_power_up_scenario			
			$NVTL_LOG -p 1 -m FOTA -l err -s "FOTA_PMODE: FATAL error"
			echo "FOTA_PMODE: FATAL: Error should not get here" | tee -a $FOTA_LOG_FILE
			#Go back to RL3
			echo "FOTA_PMODE: Going to RL 3" | tee -a $FOTA_LOG_FILE			
			telinit 3
 	echo "FOTA_PMODE: done" | tee -a $FOTA_LOG_FILE
case "$1" in
		do_start
	restart)
		$0 stop
		$0 start
		if [ "$FOTA_CUSTOM_INSTALL" == "$0" ]; then
			do_start
			echo "FOTA_PMODE: Usage fota upgrade { start | stop | restart}" >&2
			exit 1
