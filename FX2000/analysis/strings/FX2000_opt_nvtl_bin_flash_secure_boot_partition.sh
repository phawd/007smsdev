#!/bin/sh
# Shell script for updating secure boot images like abl.elf, aop.mbn, apdp.mbn, etc.
# set -x
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
SCRIPT=`basename $0`
#Cookies
if [ -e "/system/opt/nvtl/data/fota/update_log" ];then
	LOG_FILE="/system/opt/nvtl/data/fota/update_log"
	LOG_FILE="/opt/nvtl/data/fota/update_log"
exit_with_err()
	echo "$SCRIPT: exit_with_err \"$2\"" >> $LOG_FILE
	exit $1
print_log()
	echo "$SCRIPT: $1" >> $LOG_FILE
flash_parition()
	PARTITION=$1
	IMG_PATH=$2
	mtd_num=`cat /proc/mtd | grep -w $PARTITION | awk '{print $1}' | sed "s/[^0-9]//g"`
	if [ "$rc" != "0" ]; then
		exit_with_err 22 "Get mtd number for $PARTITION failed, rc=$rc"
	print_log "partition number for $PARTITION is [$mtd_num]"
	image_len=`ls -l $IMG_PATH | awk '{ print $5 }'`
	if [ "$image_len" == "0" ]; then
		exit_with_err 23 "$IMG_PATH image length 0"
	print_log "$IMG_PATH img length=[$image_len]"
	DEV_MTD="/dev/mtd${mtd_num}"
	#Erase the partition
	flash_erase $DEV_MTD 0 0
	if [ "$rc" != "0" ]; then
		exit_with_err 24 "Erasing $DEV_MTD partition failed, rc=$rc"
	print_log "$DEV_MTD flash erase successfull"
	sleep 2
	#Flash paritition with new image
	/opt/nvtl/bin/tests/mifi_mtd_test -p $PARTITION -w 0 -l $image_len -I $IMG_PATH
	if [ "$rc" != "0" ]; then
		exit_with_err 25 "Flashing $PARTITION partition is failed, rc=$rc"
	sleep 2
	print_log "$PARTITION partition flashed successfully"
	sync;sync;
flash_secure_boot_partitions()
	#flash abl partition
	flash_parition abl $abl_img
	#flash aop partition
	flash_parition aop $aop_img
	#flash apdp partition
	flash_parition apdp $apdp_img
	#flash multi_image partition
	flash_parition multi_image $multi_image_img
	#flash qhee partition
	flash_parition qhee $qhee_img
	#flash sbl partition
	flash_parition sbl $sbl_img
	#flash tz partition
	flash_parition tz $tz_img
	#flash tz_devcfg partition
	flash_parition tz_devcfg $tz_devcfg_img
	#flash uefi partition
	flash_parition uefi $uefi_img
	#flash xbl_config partition
	flash_parition xbl_config $xbl_config_img
	#flash sec partition
	flash_parition sec $sec_img
	#flash IPA_FW partition
	flash_parition ipa_fw $ipa_fw_img
scout_secure_boot_images()
	abl_img="$img_path/abl.elf"
	if [ ! -e "$abl_img" ]; then
		exit_with_err 10 "$abl_img is not found."
	aop_img="$img_path/aop.mbn"
	if [ ! -e "$aop_img" ]; then
		exit_with_err 11 "$_img is not found."
	apdp_img="$img_path/apdp.mbn"
	if [ ! -e "$apdp_img" ]; then
		exit_with_err 12 "$apdp_img is not found."
	multi_image_img="$img_path/multi_image.mbn"
	if [ ! -e "$multi_image_img" ]; then
		exit_with_err 13 "$multi_image_img is not found."
	qhee_img="$img_path/hyp.mbn"
	if [ ! -e "$qhee_img" ]; then
		exit_with_err 14 "$qhee_img is not found."
	sbl_img="$img_path/sbl1.mbn"
	if [ ! -e "$sbl_img" ]; then
		exit_with_err 15 "$sbl_img is not found."
	tz_img="$img_path/tz.mbn"
	if [ ! -e "$tz_img" ]; then
		exit_with_err 16 "$tz_img is not found."
	tz_devcfg_img="$img_path/devcfg.mbn"
	if [ ! -e "$tz_devcfg_img" ]; then
		exit_with_err 17 "$tz_devcfg_img is not found."
	uefi_img="$img_path/uefi.elf"
	if [ ! -e "$uefi_img" ]; then
		exit_with_err 18 "$uefi_img is not found."
	xbl_config_img="$img_path/xbl_cfg.elf"
	if [ ! -e "$xbl_config_img" ]; then
		exit_with_err 19 "$xbl_config_img is not found."
	sec_img="$img_path/sec.elf"
	if [ ! -e "$sec_img" ]; then
		exit_with_err 20 "$sec_img is not found."
	ipa_fw_img="$img_path/ipa_fws.elf"
	if [ ! -e "$ipa_fw_img" ]; then
		exit_with_err 21 "$ipa_fw_img is not found."
extract_secure_boot_images()
	print_log "Extracting $secure_boot_img_path into $img_path directory"
	if [ ! -e "$secure_boot_img_path" ]; then
		exit_with_err 2 "secure boot img [$secure_boot_img_path] is not exist."
	rm -rf $img_path
	mkdir -p $img_path
	tar -xvzf $secure_boot_img_path -C $img_path > /dev/null 2>&1
	if [ $rc -ne 0 ]; then
		exit_with_err 3 "'tar xvzff $secure_boot_img_path -C $upi_tmp' failed with $rc"
	chown -R root.root $img_path
	echo "usage: $SCRIPT <scout | apply> <secure_boot_image_tgz_file>"
	exit_with_err 1 "Not enough number of arguments"
get_cmd_line()
	if [ $1 -ne 2 ]; then
	mode=$2
	secure_boot_img_path=$3
	get_cmd_line $# $1 $2
	img_path=/tmp/secure_boot
	extract_secure_boot_images
	case $mode in
		scout_secure_boot_images
		scout_secure_boot_images
		flash_secure_boot_partitions
	#remove secure boot img dir
	rm -rf $img_path
