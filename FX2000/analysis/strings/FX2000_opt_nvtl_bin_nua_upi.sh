#!/bin/sh
# nua_upi.sh <scout | apply> <root_dir> <staging_dir>
exit_with_err()
	killall mifi_upi_disp
	nvtl_log -p 0 -m FOTA -l err -s "$pname: $2"
	echo "$pname: exit_with_err \"$2\"" >> /system/opt/nvtl/data/fota/update_log
	exit $1
update_percent()
	current_time=`cat /proc/uptime | awk '{print $1}'`
	total_time=`dc $current_time $start_time sub p`
	temp=`dc $total_time $max_update_time div 100 mul p`.
	percent=`echo $temp | awk -F '.' '{print $1}'`
	if [ $percent -gt 100 ]; then
		percent=100
	echo $percent > $update_progress_file
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: percent=$percent"
# The file /system/opt/nvtl/data/fota/update_err_status.bin contains the following:
#   "vrm_rc=%d rc_string=%s"
#     vrm_rc = return value of RB_vRM_Update()
#  rc_string = string for vrm_rc
# See //MiFiOS2/source/core/fota/components/update_agent_nua/vRM_Update_RetCodes.txt
update_err_status_file()
	case $1 in
	signature_err)
		result="vrm_rc=-2147483330 rc_string=E_RB_SOURCE_FILE_SIG_MISMATCH:File signature does not match signature"
	pkg_corrupted)
		result="vrm_rc=-2147483613 rc_string=E_RB_READ_ERROR:flash reading failure"
	success)
		result="vrm_rc=0 rc_string=S_RB_SUCCESS: Success"
	bspatch_failed)
		result="vrm_rc=-200 rc_string=bspatch_failed: FATAL"
		result="vrm_rc=-201 rc_string=miscellaneous: FATAL"
	echo $result > /system/opt/nvtl/data/fota/update_err_status.bin
# The file /system/opt/nvtl/data/fota/staging/result_failure contains the following:
#   "%d" of vrm_rc
# vrm_rc = return value of RB_vRM_Update()
# See //MiFiOS2/source/core/fota/components/update_agent_nua/vRM_Update_RetCodes.txt
update_result_failure_file()
	case $1 in
	signature_err)
		result="-2147483330"
	pkg_corrupted)
		result="-2147483613"
	success)
		result="0"
	bspatch_failed)
		result="-200"
		result="-201"
	echo $result > /system/opt/nvtl/data/fota/staging/result_failure
update_result()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: update_result: result=$1"
	update_err_status_file $1
	update_result_failure_file $1
	echo "usage: $pname <scout | apply> <root_dir> <staging_dir>"
get_cmd_line()
	if [ $1 -ne 3 ]; then
	upi_mode=$2
	root_dir=$3
	staging_dir=$4
get_state()
	if [ ! -f $staging_dir/nua_upi_state ]; then
		echo idle > $staging_dir/nua_upi_state
		sync; sync
	state=`cat $staging_dir/nua_upi_state`
set_state()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: set_state: state=$1"
	echo $1 > $staging_dir/nua_upi_state-tmp
	mv $staging_dir/nua_upi_state-tmp $staging_dir/nua_upi_state
	sync; sync
	get_state
verify_upi_package()
	for file in \
			$upi_tmp/boot/boot.bsdiff \
			$upi_tmp/boot/boot.new_info \
			$upi_tmp/boot/boot.old_info \
			$upi_tmp/modem/add_file_list \
			$upi_tmp/modem/add_file_list \
			$upi_tmp/modem/delete_file_list \
			$upi_tmp/modem/add_file_list \
			$upi_tmp/modem/diff_file_list \
			$upi_tmp/modem/diff_file_list_old_md5 \
			$upi_tmp/modem/diff_file_list_new_md5 \
			$upi_tmp/system/add_file_list \
			$upi_tmp/system/add_symlink_list \
			$upi_tmp/system/delete_file_list \
			$upi_tmp/system/delete_symlink_list \
			$upi_tmp/system/diff_file_list \
			$upi_tmp/system/diff_symlink_list \
			$upi_tmp/system/diff_file_list_old_md5 \
			$upi_tmp/system/diff_file_list_new_md5
		if [ ! -f $file ]; then
			update_result pkg_corrupted
			exit_with_err 10 "$pname: verify_upi_package: file $file does not exist"
	for dir in \
			$upi_tmp/modem/BSDIFF \
			$upi_tmp/system/ADDFILE \
			$upi_tmp/system/ADDSYM \
			$upi_tmp/system/BSDIFF
		if [ ! -d $dir ]; then
			update_result pkg_corrupted
			exit_with_err 11 "$pname: verify_upi_package: dir $dir does not exist"
verify_upi_package_px3()
	for file in \
			$upi_tmp/boot/boot.bsdiff \
			$upi_tmp/boot/boot.new_info \
			$upi_tmp/boot/boot.old_info \
			$upi_tmp/boot/resource.bsdiff \
			$upi_tmp/boot/resource.new_info \
			$upi_tmp/boot/resource.old_info \
			$upi_tmp/system/add_file_list \
			$upi_tmp/system/add_symlink_list \
			$upi_tmp/system/delete_file_list \
			$upi_tmp/system/delete_symlink_list \
			$upi_tmp/system/diff_file_list \
			$upi_tmp/system/diff_symlink_list \
			$upi_tmp/system/diff_file_list_old_md5 \
			$upi_tmp/system/diff_file_list_new_md5
		if [ ! -f $file ]; then
			update_result pkg_corrupted
			exit_with_err 10 "$pname: verify_upi_package: file $file does not exist"
	for dir in \
			$upi_tmp/system/ADDFILE \
			$upi_tmp/system/ADDSYM \
			$upi_tmp/system/BSDIFF
		if [ ! -d $dir ]; then
			update_result pkg_corrupted
			exit_with_err 11 "$pname: verify_upi_package: dir $dir does not exist"
extract_package()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: extracting upi_package into $upi_tmp directory"
	rm -rf $upi_tmp
	mkdir -p $upi_tmp
	tar xf $upi_package -C $upi_tmp > /dev/null 2>&1
	if [ $rc -ne 0 ]; then
		update_result pkg_corrupted
		exit_with_err 12 "'tar xf upi_package -C $upi_tmp' failed with $rc"
	rm -rf $upi_package
	chown -R root.root $upi_tmp
prepare()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: start preparing"
	# verify the contents of the upi_package
	if [ "$target" == "px3" ]; then
		verify_upi_package_px3
		verify_upi_package
read_boot_image_from_nand()
	rm -f $staging_dir/old_boot.img
	old_boot_len=`awk '{print $2}' $upi_tmp/boot/boot.old_info`
	/opt/nvtl/bin/tests/mifi_mtd_test -p boot -r 0 -l $old_boot_len -O $staging_dir/old_boot.img
	if [ $rc -ne 0 ]; then
		update_result pkg_corrupted
		exit_with_err 13 "/opt/nvtl/bin/tests/mifi_mtd_test (read) failed with $rc"
read_image_from_mmc()
	filename=$1
	mmcblk=$2
	length=$3
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: read_image_from_mmc: filename=$filename mmcblk=$mmcblk length=$length"
	rm -f $filename
	num_blks=`dc $length 512 / p | awk -F '.' '{print $1}'`
	num_blks=`dc $num_blks 1 + p`
	dd if=$mmcblk of=$filename bs=512 count=$num_blks &> /dev/null
	if [ $rc -ne 0 ]; then
		update_result pkg_corrupted
		exit_with_err 13 "dd (read) failed with $rc"
	truncate -s $length $filename
scout_boot()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: scout_boot: +++"
	old_boot_md5=`awk '{print $1}' $upi_tmp/boot/boot.old_info`
	new_boot_md5=`awk '{print $1}' $upi_tmp/boot/boot.new_info`
	new_boot_len=`awk '{print $2}' $upi_tmp/boot/boot.new_info`
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: reading boot image from NAND"
	read_boot_image_from_nand
	# verify the length and md5sum
	nand_boot_md5=`md5sum $staging_dir/old_boot.img | awk '{print $1}'`
	nand_boot_len=`ls -l $staging_dir/old_boot.img | awk '{print $5}'`
	if [ "$nand_boot_md5" != "$old_boot_md5" ]; then
		update_result signature_err
		exit_with_err 20 "nand_boot_md5=$nand_boot_md5 != old_boot_md5=$old_boot_md5"
	if [ "$nand_boot_len" != "$old_boot_len" ]; then
		update_result signature_err
		exit_with_err 21 "nand_boot_len=$nand_boot_len != old_boot_len=$old_boot_len"
scout_boot_px3()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: scout_boot: +++"
	old_boot_md5=`awk '{print $1}' $upi_tmp/boot/boot.old_info`
	old_boot_len=`awk '{print $2}' $upi_tmp/boot/boot.old_info`
	new_boot_md5=`awk '{print $1}' $upi_tmp/boot/boot.new_info`
	new_boot_len=`awk '{print $2}' $upi_tmp/boot/boot.new_info`
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: reading boot image from MMC"
	read_image_from_mmc $staging_dir/old_boot.img /dev/mmcblk0p6 $old_boot_len
	# verify the length and md5sum
	mmc_boot_md5=`md5sum $staging_dir/old_boot.img | awk '{print $1}'`
	mmc_boot_len=`ls -l $staging_dir/old_boot.img | awk '{print $5}'`
	if [ "$mmc_boot_md5" != "$old_boot_md5" ]; then
		update_result signature_err
		exit_with_err 20 "mmc_boot_md5=$mmc_boot_md5 != old_boot_md5=$old_boot_md5"
	if [ "$mmc_boot_len" != "$old_boot_len" ]; then
		update_result signature_err
		exit_with_err 21 "mmc_boot_len=$mmc_boot_len != old_boot_len=$old_boot_len"
	old_resource_md5=`awk '{print $1}' $upi_tmp/boot/resource.old_info`
	old_resource_len=`awk '{print $2}' $upi_tmp/boot/resource.old_info`
	new_resource_md5=`awk '{print $1}' $upi_tmp/boot/resource.new_info`
	new_resource_len=`awk '{print $2}' $upi_tmp/boot/resource.new_info`
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: reading resource image from MMC"
	read_image_from_mmc $staging_dir/old_resource.img /dev/mmcblk0p5 $old_resource_len
	# verify the length and md5sum
	nand_resource_md5=`md5sum $staging_dir/old_resource.img | awk '{print $1}'`
	nand_resource_len=`ls -l $staging_dir/old_resource.img | awk '{print $5}'`
	if [ "$nand_resource_md5" != "$old_resource_md5" ]; then
		update_result signature_err
		exit_with_err 20 "nand_resource_md5=$nand_resource_md5 != old_resource_md5=$old_resource_md5"
	if [ "$nand_resource_len" != "$old_resource_len" ]; then
		update_result signature_err
		exit_with_err 21 "nand_resource_len=$nand_resource_len != old_resource_len=$old_resource_len"
verify_diff_file()
	tgt_root=$1
	diff_file_list_with_md5=$2
	# get the modem and system partition available size
	system_size=$(df | grep "/system" | awk '{print $4}')
	system_size=$(($system_size*1024))
	while read line; do
		file=`echo $line | awk '{print $2}'`
		refmd5=`echo $line | awk '{print $1}'`
		md5=`md5sum $tgt_root/$file | awk '{print $1}'`
		file_size=`ls -l $tgt_root/$file | awk '{print $5}'`
		file_name=`basename $file`
		if [ $file_size -gt $system_size ]; then
			update_result signature_err
			exit_with_err 22 "There is no space on system partition[$system_size] to take backup for $file_name [$file_size]"
		if [ "$md5" != "$refmd5" ]; then
			update_result signature_err
			exit_with_err 22 "$file: md5=$md5 != refmd5=$refmd5"
		update_percent
	done < $diff_file_list_with_md5
verify_delete_file()
	tgt_root=$1
	delete_file_list=$2
	while read file; do
		if [ ! -e "$tgt_root/$file" ]; then
			update_result signature_err
			exit_with_err 23 "verify_delete_file: $file does not exist"
	done < $delete_file_list
verify_delete_symlink()
	tgt_root=$1
	delete_symlink_list=$2
	while read symlink; do
		if [ ! -d $tgt_root/$symlink ] && [ ! -h $tgt_root/$symlink ]; then
			update_result signature_err
			exit_with_err 25 "verify_delete_symlink: $symlink does not exist"
	done < $delete_symlink_list
verify_add_file()
	tgt_root=$1
	add_file_list=$2
	while read file; do
		if [ -e "$tgt_root/$file" ]; then
			update_result signature_err
			exit_with_err 26 "verify_add_file: $file exists"
	done < $add_file_list
verify_add_symlink()
	tgt_root=$1
	add_symlink_list=$2
	while read symlink; do
		if [ ! -d $tgt_root/$symlink ] && [ -h $tgt_root/$symlink ]; then
			update_result signature_err
			exit_with_err 27 "verify_add_symlink: $symlink exists"
	done < $add_symlink_list
# verify md5sum of files that are different
# verify existence of files and symlinks that will be removed
# verify existence of symlinks that are different
# verify non-existence of files and symlinks that will be added
scout_system()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: scout_system: +++"
	verify_diff_file $root_dir/system $upi_tmp/system/diff_file_list_old_md5
	verify_delete_file $root_dir/system $upi_tmp/system/delete_file_list
	verify_delete_symlink $root_dir/system $upi_tmp/system/delete_symlink_list
	# symlinks that are different are replaced so treat as delete for scout
	verify_delete_symlink $root_dir/system $upi_tmp/system/diff_symlink_list
	verify_add_file $root_dir/system $upi_tmp/system/add_file_list
	verify_add_symlink $root_dir/system $upi_tmp/system/add_symlink_list
# verify md5sum of files that are different
# verify existence of files that will be removed
# verify non-existence of files that will be added
scout_modem()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: scout_modem: +++"
	verify_diff_file $root_dir/firmware $upi_tmp/modem/diff_file_list_old_md5
	verify_delete_file $root_dir/firmware $upi_tmp/modem/delete_file_list
	verify_add_file $root_dir/firmware $upi_tmp/modem/add_file_list
do_scout()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: do_scout: state=$state"
	if [ "$state" == "idle" ]; then
		prepare
		set_state prepare_done
	update_percent
	if [ "$state" == "prepare_done" ]; then
		if [ "$target" == "px3" ]; then
			scout_boot_px3
			scout_boot
		set_state scout_boot_done
	update_percent
	if [ "$state" == "scout_boot_done" ]; then
		scout_system
		set_state scout_system_done
	update_percent
	if [ "$state" == "scout_system_done" ]; then
		if [ "$target" != "px3" ]; then
			scout_modem
		set_state scout_modem_done
	update_percent
bspatch_one_file()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: bspatch_one_file $1 $2 $3"
	oldfile=$1
	newfile=$2
	patchfile=$3
	bspatch $oldfile $newfile $patchfile
	if [ $rc -ne 0 ]; then
		update_result bspatch_failed
		exit_with_err 30 "'bspatch $oldfile $newfile $patchfile' failed with $rc"
patch_boot_file()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: patch_boot_file: +++"
	rm -f $state_dir/new_boot.img
	bspatch_one_file $staging_dir/old_boot.img $state_dir/new_boot.img $upi_tmp/boot/boot.bsdiff
	new_boot_len_info=`awk '{print $2}' $upi_tmp/boot/boot.new_info`
	new_boot_md5_info=`awk '{print $1}' $upi_tmp/boot/boot.new_info`
	new_boot_len=`ls -l $state_dir/new_boot.img | awk '{print $5}'`
	new_boot_md5=`md5sum $state_dir/new_boot.img | awk '{print $1}'`
	if [ "$new_boot_len_info" != "$new_boot_len" ]; then
		update_result boot_len_wrong
		exit_with_err 31 "new_boot_len_info=$new_boot_len_info != new_boot_len=$new_boot_len"
	if [ "$new_boot_md5_info" != "$new_boot_md5" ]; then
		update_result boot_md5_wrong
		exit_with_err 32 "new_boot_md5_info=$new_boot_md5_info != new_boot_md5=$new_boot_md5"
patch_boot_file_px3()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: patch_boot_file_px3: +++"
	patch_boot_file
	rm -f $staging_dir/new_resource.img
	bspatch_one_file $staging_dir/old_resource.img $staging_dir/new_resource.img $upi_tmp/boot/resource.bsdiff
	new_resource_len_info=`awk '{print $2}' $upi_tmp/boot/resource.new_info`
	new_resource_md5_info=`awk '{print $1}' $upi_tmp/boot/resource.new_info`
	new_resource_len=`ls -l $staging_dir/new_resource.img | awk '{print $5}'`
	new_resource_md5=`md5sum $staging_dir/new_resource.img | awk '{print $1}'`
	if [ "$new_resource_len_info" != "$new_resource_len" ]; then
		update_result boot_len_wrong
		exit_with_err 31 "new_resource_len_info=$new_resource_len_info != new_resource_len=$new_resource_len"
	if [ "$new_resource_md5_info" != "$new_resource_md5" ]; then
		update_result boot_md5_wrong
		exit_with_err 32 "new_resource_md5_info=$new_resource_md5_info != new_resource_md5=$new_resource_md5"
write_boot_file_to_nand()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: write_boot_file_to_nand: +++"
	/opt/nvtl/bin/tests/mifi_mtd_test -p boot -w 0 -l $new_boot_len -I $state_dir/new_boot.img
	if [ $rc -ne 0 ]; then
		exit_with_err 35 "/opt/nvtl/bin/tests/mifi_mtd_test (write) failed with $rc"
	/opt/nvtl/bin/tests/mifi_mtd_test -p boot -r 0 -l $new_boot_len -O /tmp/boot.img
	if [ $rc -ne 0 ]; then
		exit_with_err 36 "/opt/nvtl/bin/tests/mifi_mtd_test (2nd read) failed with $rc"
	cmp $state_dir/new_boot.img /tmp/boot.img
	if [ $rc -ne 0 ]; then
		exit_with_err 36 "'cmp $state_dir/new_boot.img /tmp/boot.img' failed with $rc"
write_image_to_mmc()
	filename=$1
	mmcblk=$2
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: write_image_to_mmc: filename=$filename mmcblk=$mmcblk"
	dd if=$filename of=$mmcblk bs=512 &> /dev/null
	if [ $rc -ne 0 ]; then
		update_result pkg_corrupted
		exit_with_err 35 "dd (write) failed with $rc"
write_boot_files_to_mmc()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: write_boot_files_to_mmc: +++"
	write_image_to_mmc $state_dir/new_boot.img /dev/mmcblk0p6
	read_image_from_mmc /tmp/boot.img /dev/mmcblk0p6 $new_boot_len
	cmp $state_dir/new_boot.img /tmp/boot.img
	if [ $rc -ne 0 ]; then
		exit_with_err 36 "'cmp $state_dir/new_boot.img /tmp/boot.img' failed with $rc"
	write_image_to_mmc $state_dir/new_resource.img /dev/mmcblk0p5
	read_image_from_mmc /tmp/resource.img /dev/mmcblk0p5 $new_resource_len
	cmp $state_dir/new_resource.img /tmp/resource.img
	if [ $rc -ne 0 ]; then
		exit_with_err 36 "'cmp $state_dir/new_resource.img /tmp/resourceboot.img' failed with $rc"
scout_secure_boot_images()
	if [ "$state" == "scout_modem_done" ]; then
		secure_boot_img=/tmp/secure_boot_img
		if [ "$target" != "px3" ] && [ -e "$secure_boot_img" ]; then
			if [ -e "$staging_dir/flash_secure_boot_partition" ];then
				chmod +x $staging_dir/flash_secure_boot_partition
				echo "Executing from staging dir [$staging_dir/flash_secure_boot_partition]" >> /system/opt/nvtl/data/fota/update_log
				$staging_dir/flash_secure_boot_partition scout $secure_boot_img
				/opt/nvtl/bin/flash_secure_boot_partition.sh scout $secure_boot_img
			rc=$?
			if [ $rc -ne 0 ]; then
				update_result pkg_corrupted
				exit_with_err 37 "'applying secure boot images failed' failed with $rc"
apply_secure_boot_images()
	if [ "$state" == "apply_modem_add_file_done" ]; then
		secure_boot_img=/tmp/secure_boot_img
		if [ "$target" != "px3" ] && [ -e "$secure_boot_img" ]; then
			if [ -e "$staging_dir/flash_secure_boot_partition" ];then
				echo "Executing from staging dir [$staging_dir/flash_secure_boot_partition]" >> /system/opt/nvtl/data/fota/update_log
				chmod +x $staging_dir/flash_secure_boot_partition
				$staging_dir/flash_secure_boot_partition apply $secure_boot_img
				/opt/nvtl/bin/flash_secure_boot_partition.sh apply $secure_boot_img
			rc=$?
			if [ $rc -ne 0 ]; then
				update_result pkg_corrupted
				exit_with_err 42 "'applying secure boot images failed' failed with $rc"
apply_boot()
	# Handle the case where the boot images are the same (small/large test delta files)
	cmp $upi_tmp/boot/boot.old_info $upi_tmp/boot/boot.new_info > /dev/null 2>&1
	if [ $? -eq 0 ]; then
		set_state apply_boot_done
	if [ "$state" == "scout_modem_done" ]; then
		if [ "$target" == "px3" ]; then
			patch_boot_file_px3
			patch_boot_file
		if [ "$target" == "px3" ]; then
			write_boot_files_to_mmc
			write_boot_file_to_nand
		set_state write_boot_file_to_nand_done
	update_percent
	rm -f /tmp/boot.img $state_dir/new_boot.img $staging_dir/old_boot.img
	if [ "$state" == "write_boot_file_to_nand_done" ]; then
		set_state apply_boot_done
	update_percent
increment_line_number()
	let line_number=line_number+1
	echo $line_number > $staging_dir/line_number_tmp
	mv $staging_dir/line_number_tmp $staging_dir/line_number
	sync; sync
zero_line_number()
	echo 0 > $staging_dir/line_number
	sync; sync
# update one file:
# - Check md5sum of tgt_dir/file:
#   - if != new (assuming it should be old due to mv used below):
#     - Copy the tgt_dir/<file> to state_dir/old/<file>
#     - Patch old file creating state_dir/new/<file>
# - Set mode bits on state_dir/new/<file> using state_dir/old/<file>
# - Move state_dir/new/<file> tgt_dir/<file>
# - Verify new md5sum
# - Remove state_dir/old/<file> and state_dir/new/<file>
update_one_file()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: update_one_file: $1 $2 $3 $4 $5"
	file=$1
	tgt_dir=$2
	bsdiff_dir=$3
	refmd5=$4
	ref_src_md5sum=$5
	# md5sum of $tgt_dir/$file should be either old or new
	# since we have access to the new one use it
	# this can occur if power is cut after the file is moved but
	# before the line number is incremented
	newmd5=`md5sum $tgt_dir/$file | awk '{print $1}'`
	if [ "$refmd5" != "$newmd5" ]; then
		filebase=`basename $file`
		if [ ! -d "$staging_dir/old" ]; then
			mkdir -p $staging_dir/old
		filebase_stat="${filebase}_stat"
		chmod_bits=`cat $staging_dir/old/$filebase_stat`
		if [ "$chmod_bits" == "" ]; then
			rm -rf $staging_dir/old/*
			cp -f $tgt_dir/$file $staging_dir/old/$filebase
			sync;sync
			chmod_bits=`stat -c "%a %n" $staging_dir/old/$filebase`
			echo -n "$chmod_bits" > $staging_dir/old/$filebase_stat
			sync;sync
			#looks like interruption occured
			backup_md5sum=`md5sum $staging_dir/old/$filebase | awk '{print $1}'`
			if [ "$ref_src_md5sum" != "$backup_md5sum" ]; then
				device_md5sum=`md5sum $tgt_dir/$file | awk '{print $1}'`
				if [ "$device_md5sum" = "$ref_src_md5sum" ]; then
					rm -rf $staging_dir/old/*
					cp -f $tgt_dir/$file $staging_dir/old/$filebase
					sync;sync
					chmod_bits=`stat -c "%a %n" $staging_dir/old/$filebase`
					echo -n "$chmod_bits" > $staging_dir/old/$filebase_stat
					sync;sync
				else
					exit_with_err 40 "$pname: update_one_file: file=$tgt_dir/$file: device_md5sum [$device_md5sum] != ref_src_md5sum [$ref_src_md5sum]"
		bspatch_one_file $staging_dir/old/$filebase $state_dir/new/$filebase $bsdiff_dir/$file
		chmod $chmod_bits $state_dir/new/$filebase
		mv -f $state_dir/new/$filebase $tgt_dir/$file
		sync; sync
	newmd5=`md5sum $tgt_dir/$file | awk '{print $1}'`
	if [ "$refmd5" != "$newmd5" ]; then
		exit_with_err 40 "$pname: update_one_file: file=$tgt_dir/$file: $refmd5 != $newmd5"
	rm -f $state_dir/new/* $staging_dir/old/*
apply_diff_file()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: apply_diff_file: $1 $2"
	tgt_root=$1
	upi_dir=$2
	diff_file_list_with_md5=$upi_dir/diff_file_list_new_md5
	diff_old_file_list_with_md5=$upi_dir/diff_file_list_old_md5
	line_read=0
	line_number=0
	# To recovery from power interruption read up to line number discarding the input
	if [ -f $staging_dir/line_number ]; then
		line_number=`cat $staging_dir/line_number`
	while read line; do
		file=`echo $line | awk '{print $2}'`
		md5=`echo $line | awk '{print $1}'`
		src_md5=`cat $diff_old_file_list_with_md5 | grep $file | awk '{print $1}'`
		if [ $line_read -lt $line_number ]; then
			nvtl_log -p 0 -m FOTA -l notice -s \
				"$pname: apply_diff_file: skipping line=$line_read file=$file"
			nvtl_log -p 0 -m FOTA -l notice -s "$pname: apply_diff_file: updating file=$file"
			update_one_file $file $tgt_root $upi_dir/BSDIFF $md5 $src_md5
			increment_line_number
			update_percent
		let line_read=line_read+1
	done < $diff_file_list_with_md5
apply_delete_file()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: apply_delete_file: $1 $2"
	tgt_root=$1
	delete_file_list=$2
	while read file; do
		# Use -r in case it's a directory
		rm -rf "$tgt_root/$file"
	done < $delete_file_list
apply_delete_symlink()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: apply_delete_symlink: $1 $2"
	tgt_root=$1
	delete_symlink_list=$2
	while read symlink; do
		# Use -r in case it's a directory
		rm -rf "$tgt_root/$symlink"
	done < $delete_symlink_list
apply_add_file()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: apply_add_file: $1 $2 $3"
	tgt_root=$1
	add_file_list=$2
	add_file_dir=$3
	while read file; do
		cp -af "$add_file_dir/$file" "$tgt_root/$file"
		update_percent
	done < $add_file_list
apply_add_symlink()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: apply_add_symlink: $1 $2 $3"
	tgt_root=$1
	add_symlink_list=$2
	add_symlink_dir=$3
	while read symlink; do
		# Only copy symlinks
		if [ -h $add_symlink_dir/$symlink ]; then
			mkdir -p `dirname $tgt_root/$symlink`
			# read contents of symlink then create a new one
			new_symlink=`ls -l $add_symlink_dir/$symlink | awk '{print $11}'`
			nvtl_log -p 0 -m FOTA -l notice -s \
				"$pname: apply_add_symlink: 'ln -s $new_symlink $tgt_root/$symlink'"
			ln -s $new_symlink $tgt_root/$symlink
			if [ $? -ne 0 ]; then
				exit_with_err 41 "$pname: apply_add_symlink: 'ln -s $new_symlink $tgt_root/$symlink' failed"
		update_percent
	done < $add_symlink_list
apply_system()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: apply_system: +++"
	if [ "$state" == "apply_boot_done" ]; then
		apply_diff_file $root_dir/system $upi_tmp/system
		set_state apply_system_diff_file_done
	if [ "$state" == "apply_system_diff_file_done" ]; then
		zero_line_number
		set_state apply_system_diff_file_zero_line_number
	if [ "$state" == "apply_system_diff_file_zero_line_number" ]; then
		apply_delete_file $root_dir/system $upi_tmp/system/delete_file_list
		set_state apply_system_delete_file_done
	if [ "$state" == "apply_system_delete_file_done" ]; then
		apply_delete_symlink $root_dir/system $upi_tmp/system/delete_symlink_list
		set_state apply_system_delete_symlink_done
	if [ "$state" == "apply_system_delete_symlink_done" ]; then
		apply_add_file $root_dir/system $upi_tmp/system/add_file_list $upi_tmp/system/ADDFILE
		set_state apply_system_add_file_done
	if [ "$state" == "apply_system_add_file_done" ]; then
		apply_add_symlink $root_dir/system $upi_tmp/system/add_symlink_list $upi_tmp/system/ADDSYM
		set_state apply_system_add_symlink_done
	if [ "$state" == "apply_system_add_symlink_done" ]; then
		# symlinks that are different are replaced so treat as delete / add
		apply_delete_symlink $root_dir/system $upi_tmp/system/diff_symlink_list
		apply_add_symlink $root_dir/system $upi_tmp/system/diff_symlink_list $upi_tmp/system/ADDSYM
		set_state apply_system_diff_symlink_done
# verify md5sum of files that are different
# verify existence of files that will be removed
# verify non-existence of files that will be added
apply_modem()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: apply_modem: +++"
	if [ "$state" == "apply_system_diff_symlink_done" ]; then
		apply_diff_file $root_dir/firmware $upi_tmp/modem/
		set_state apply_modem_diff_file_done
	if [ "$state" == "apply_modem_diff_file_done" ]; then
		zero_line_number
		set_state apply_modem_diff_file_zero_line_number
	if [ "$state" == "apply_modem_diff_file_zero_line_number" ]; then
		apply_delete_file $root_dir/firmware $upi_tmp/modem/delete_file_list
		set_state apply_modem_delete_file_done
	if [ "$state" == "apply_modem_delete_file_done" ]; then
		apply_add_file $root_dir/firmware $upi_tmp/modem/add_file_list $upi_tmp/modem/ADDFILE
		set_state apply_modem_add_file_done
do_apply()
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: do_apply: +++"
	scout_secure_boot_images
	apply_boot
	apply_system
	if [ "$target" != "px3" ]; then
		apply_modem
	apply_secure_boot_images
init_progress_display()
	start_time=`cat /proc/uptime | awk '{print $1}'`
	max_update_time=200
	echo 0 > $update_progress_file
	if [ -f $staging_dir/Installing-Update-Screen.png ]; then
		image_file=$staging_dir/Installing-Update-Screen 
		image_file=/opt/nvtl/display/fota/Installing-Update-10-min
	mifi_upi_disp $image_file 1 1 $update_progress_file > /dev/null 2>&1 &
	pname=nua_upi.sh
	get_cmd_line $# $1 $2 $3
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: upi_mode=$upi_mode root_dir=$root_dir staging_dir=$staging_dir"
	target=`cat /system/target`
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: target=$target"
	upi_package=/dev/upi_package
	state_dir=/dev/upi_state
	upi_tmp=/tmp/upi_tmp
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: upi_package=$upi_package upi_tmp=$upi_tmp state_dir=$state_dir"
	mkdir -p $state_dir $state_dir/old $state_dir/new
	# first extract the package.
	extract_package
	get_state
	nvtl_log -p 0 -m FOTA -l notice -s "$pname: state=$state"
	echo "$pname: state=$state" >> /system/opt/nvtl/data/fota/update_log
	echo "=========================================================================" >> /system/opt/nvtl/data/fota/update_log
	echo "df -h" >> /system/opt/nvtl/data/fota/update_log
	df -h >> /system/opt/nvtl/data/fota/update_log
	echo "=========================================================================" >> /system/opt/nvtl/data/fota/update_log
	echo "ls -lR /system/opt/nvtl/data/fota" >> /system/opt/nvtl/data/fota/update_log
	ls -lR /system/opt/nvtl/data/fota >> /system/opt/nvtl/data/fota/update_log
	echo "=========================================================================" >> /system/opt/nvtl/data/fota/update_log
	update_progress_file=$state_dir/progress
	init_progress_display
	case $upi_mode in
		set_state idle
		do_scout
		do_scout
		do_apply
		update_result success
	echo 100 > $update_progress_file
export PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
