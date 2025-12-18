#!/usr/bin/env sh
# INIT script for kernel crash log
# Currently support mdm9640 and sdx20
get_kernel_arch()
	mdm9640=0
	sdx20=0
	sdx55=0
	grep "CONFIG_ARCH_MDM9640_NVTL=y" /tmp/kernel_config &> /dev/null
	if [ $? -eq 0 ]; then
		mdm9640=1
	grep "CONFIG_ARCH_SDX20_NVTL=y" /tmp/kernel_config &> /dev/null
	if [ $? -eq 0 ]; then
		sdx20=1
	grep "CONFIG_ARCH_SDXPRAIRIE_NVTL=y" /tmp/kernel_config &> /dev/null
        if [ $? -eq 0 ]; then
                sdx55=1
        fi
	if [ $mdm9640 -eq 0 ] && [ $sdx20 -eq 0 ] && [ $sdx55 -eq 0 ]; then
		logger -p local1.crit -t kernel_crash_log.sh "Kernel architecture not supported"
		exit 30
parse_kernel_config()
	if [ $mdm9640 -eq 1 ]; then
		ramoops_line=$(dmesg | grep "cma: CMA: reserved"|grep "ramoops_mem")
		if [ $? -eq 0 ]; then
			size=`echo "$ramoops_line" |awk -F" " '{print $6}'`
			ramoops_size=$(expr $size \* 1024 \* 1024)
			ramoops_addr=`echo "$ramoops_line" |awk -F" " '{print $9}'`
			logger -p local1.crit -t kernel_crash_log.sh "RAMOOPS buffer not found - exiting"
			exit 11
	if [ $sdx20 -eq 1 ]; then
		ramoops_line1=$(dmesg | grep "ramoops_region@" | grep size)
		if [ $? -eq 0 ]; then
			ramoops_line=$(echo $ramoops_line1 | awk -F ':' '{print $3}')
			# ramoops_line should be this: 'base 0x9fb00000, size 1 MiB'
			size=$(echo $ramoops_line | awk '{print $4}')
			ramoops_size=$(expr $size \* 1024 \* 1024)
			ramoops_addr=$(echo $ramoops_line | awk '{print $2}' | awk -F ',' '{print $1}')
			logger -p local1.crit -t kernel_crash_log.sh "RAMOOPS buffer not found - exiting"
			exit 12
	if [ $sdx55 -eq 1 ]; then
		ramoops_line1=$(ls /sys/firmware/devicetree/base/reserved-memory | grep "ramoops_region")                
		if [ $? -eq 0 ]; then
			ramoops_addr=0x$(echo $ramoops_line1 | awk -F '@' '{print $2}')
			# Note size must be coorinated between this entry and the entry in
			#   /Firmware/SDX55/Main_LE10/SDX55_apps/apps_proc/ \
			#     kernel/msm-4.14/arch/arm/boot/dts/moretti(|firestorm|wavemaker|chimay|stormbreaker)/sdxprairie.dtsi
			ramoops_size=0x100000
			logger -p local1.crit -t kernel_crash_log.sh "RAMOOPS buffer not found - exiting"
			exit 12
	lbshift=`grep CONFIG_LOG_BUF_SHIFT /tmp/kernel_config | awk -F = '{print $2}'`
	dmesg_size=`dc 2 $lbshift exp p`
save_clear_logs()
	log_dir=/opt/nvtl/log/crash
	mkdir -p $log_dir
	if [ -f $log_dir/which ]; then
		which=`cat $log_dir/which`
		which=0
	rm -rf $log_dir/$which
	mkdir -p $log_dir/$which
	logger -p local1.crit -t kernel_crash_log.sh "ramoops_size=$ramoops_size ramoops_addr=$ramoops_addr dmesg_size=$dmesg_size directory=$log_dir/$which"
	kernel_crash_log $ramoops_size $ramoops_addr $dmesg_size $log_dir/$which
	if [ $rc -ne 0 ]; then
		if [ $rc -eq 10 ]; then
			logger -p local1.crit -t kernel_crash_log.sh "crash log not found"
			logger -p local1.crit -t kernel_crash_log.sh "failed"
		logger -p local1.crit -t kernel_crash_log.sh "crash log found"
		# Increment directory pointer
		let which=which+1
		if [ $which -gt 3 ]; then
			which=0
	echo $which > $log_dir/which
start_ramoops_module()
	# This helps with testing when the script is re-run.
	rmmod ramoops
	sleep 1
	ramoops_module=/lib/modules/`uname -r`/kernel/drivers/char/ramoops.ko
	if [ -f $ramoops_module ]; then
		insmod $ramoops_module mem_size=$ramoops_size mem_address=$ramoops_addr \
			record_size=$dmesg_size dump_oops=1
		if [ $? -ne 0 ]; then
			logger -p local1.crit -t kernel_crash_log.sh "Could not insmod $ramoops_module"
			exit 20
		logger -p local1.crit -t kernel_crash_log.sh "Could not find $ramoops_module"	
		exit 21
export PATH=$PATH:/opt/nvtl/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
# Uncompress the kernel configuration into a file
cat /proc/config.gz | gzip -d > /tmp/kernel_config
get_kernel_arch
parse_kernel_config
save_clear_logs
start_ramoops_module
