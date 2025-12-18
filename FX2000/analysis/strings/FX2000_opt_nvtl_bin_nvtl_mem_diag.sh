#!/bin/sh
##################################################################################################
#	Memory Diagnostics Program
##################################################################################################
# The purpose of the program is to keep track of the RAM free memory and do following
# * Collect and store memory diagnostics periodically for analysis ie) ps,top etc
# * Execute memory compaction cmds to free pages
# * Kill low priority process to free some memory to avoid OOM
# * Keep track of all tmpfs mount points size and remove/backup oversized files to free memory
# RAM free memory is splitted into 3 zones, which is user configurable
# * Safe Zone 
# * Moderate Zone
# * Critical Zone
# History:
# Date - Version - Description
# 6/17/2020 - 1.0 - Add version to sync between nvtl_mem_diag.sh and nvtl_log_analyzer tool
# 6/19/2020 - 1.1 - Get device model number and collect battery params only if supported
# 5/13/2021 - 1.2 - Get no of max & opened file descriptors. 
#                   Get session id after wait time to get actual date instead of default 1/1/1970
# 5/24/2021 - 1.3 - Get per process open fd count
##################################################################################################
export PATH=$PATH:/opt/nvtl/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
Version="1.3"
###########################
# LOG Configuration
###########################
log_dir=/opt/nvtl/log/mem_diag
log_file=$log_dir/mem_diag.log
MAX_LOG_FILE_SIZE_KB=1024
MAX_NO_OF_BACKUPS=10
##################################################################################################
# Configuration Parameters to Define  Memory Zone
##################################################################################################
# Free mem 15MB and ABOVE are considered as safe zone
SAFE_ZONE_LEAST_MEM=15
# Free mem 5MB and BELOW are considered as critical zone
CRITICAL_ZONE_START_MEM=5
# Free mem between 15MB and 5MB are considered as moderate zone (NO parameter needed)
# Zone specific polling interval in seconds ie) how frequent to check system's free memory
SAFE_ZONE_POLL_INTERVAL_SEC=60
MODERATE_ZONE_POLL_INTERVAL_SEC=30
CRITICAL_ZONE_POLL_INTERVAL_SEC=15
# Zone Interval in Minutes ie) how frequent to store mem/process diagnostics (ps,top,meminfo etc)
SAFE_ZONE_STORE_MEM_STATS_INTERVAL_MINS=3
MODERATE_ZONE_STORE_MEM_STATS_INTERVAL_MINS=2
CRITICAL_ZONE_STORE_MEM_STATS_INTERVAL_MINS=1
# Enabling debug mode will store diagnostics in polling interval of respective zone,
# otherwise it'll use above <zone>_STORE_MEM_STATS_INTERVAL_MINS
ENABLE_DEBUG_MODE=0
TOP_CPU_USAGE_THRESHOLD=5
##################################################################################################
    #TS=`date +%m/%d/%Y_%H:%M:%S`
    #echo "$TS: $1" >> $log_file
newline()
    #TS=`date +%m/%d/%Y_%H:%M:%S`
    #echo "------- $TS: $1 -------" 
get_process_openfd_count()
	DATE=`date +%m/%d/%Y_%H:%M:%S`
	# Get PID of running process
	ps | awk '{print $1}' |  awk '{if(NR>1)print}' > $log_dir/pid.tmp
	# Get per process open fd count by parsing /proc fs
	for pid in `cat $log_dir/pid.tmp`;do	
		if [ -f /proc/$pid/comm ]; then		
			echo "$pid,$(ls /proc/$pid/fd/ | wc -l),$(cat /proc/$pid/comm)" >> $log_dir/ofd_current_snapshort.txt
	if [ -f $log_dir/.ofd_prev_snapshot.txt ]; then
		diff -w $log_dir/.ofd_prev_snapshot.txt $log_dir/ofd_current_snapshort.txt  |  sed -n '/^+/ p' | awk '{if(NR>1)print}' | sed -r 's/\+//g' > $log_dir/ofd_delta_to_store.tmp
		# log first time
		cp $log_dir/ofd_current_snapshort.txt $log_dir/ofd_delta_to_store.tmp
		echo "TIME,PID,OPEN_FD,CMD" > $log_dir/openfd.csv
	size=`ls -l $log_dir/ofd_delta_to_store.tmp | awk '{print $5}'`
	if [ $size -ne 0 ]; then
		# Add time stamp after taking delta, otherwise all process will have delta due to timestamp
		awk 'BEGIN{OFS=","} {print "'"$DATE"'", $0}' $log_dir/ofd_delta_to_store.tmp >  $log_dir/ofd_delta_to_store_w_time.tmp
		cat $log_dir/ofd_delta_to_store_w_time.tmp >> $log_dir/openfd.csv
		#sync				
		mv $log_dir/ofd_current_snapshort.txt $log_dir/.ofd_prev_snapshot.txt 
	#Remove all temporary files
	rm $log_dir/*.tmp
get_iface_stats()
	store=0
	DATE=`date +%m/%d/%Y_%H:%M:%S`
	iface=$1	
	current="${iface}_current_snapshort.txt"
	previous="${iface}_prev_snapshort.txt"
	str1="collisions,multicast,rx_bytes,rx_compressed,rx_crc_errors,rx_dropped,rx_errors,rx_fifo_errors,rx_frame_errors"
	str2="rx_length_errors,rx_missed_errors,rx_nohandler,rx_over_errors,rx_packets,tx_aborted_errors,tx_bytes,tx_carrier_errors"
	str3="tx_compressed,tx_dropped,tx_errors,tx_fifo_errors,tx_heartbeat_errors,tx_packets,tx_window_errors"
	if [ -d /sys/class/net/$iface/statistics ];then				
		cat /sys/class/net/$iface/statistics/collisions >  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/multicast >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/rx_bytes >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/rx_compressed >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/rx_crc_errors >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/rx_dropped >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/rx_errors >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/rx_fifo_errors >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/rx_frame_errors >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/rx_length_errors >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/rx_missed_errors >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/rx_nohandler >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/rx_over_errors >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/rx_packets >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/tx_aborted_errors >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/tx_bytes >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/tx_carrier_errors >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/tx_compressed >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/tx_dropped >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/tx_errors >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/tx_fifo_errors >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/tx_heartbeat_errors >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/tx_packets >>  $log_dir/iface_unsorted.tmp
		cat /sys/class/net/$iface/statistics/tx_window_errors >>  $log_dir/iface_unsorted.tmp		
		echo "0" > $log_dir/iface_unsorted.tmp
	cp $log_dir/iface_unsorted.tmp $log_dir/.$current
	if [ -f $log_dir/.$previous ]; then
			cmp $log_dir/.$previous $log_dir/.$current > $log_dir/delta.tmp
			size=`ls -l $log_dir/delta.tmp | awk '{print $5}'`
			if [ $size -ne 0 ]; then
					store=1				
			store=1
			echo "TIME,$str1,$str2,$str3" > $log_dir/$iface.csv
	if [ $store = 1 ]; then
			awk 'BEGIN{RS="\n";ORS=","} {print}' $log_dir/.$current | sed 's/.$//' > $log_dir/current_to_store_sorted.tmp
			awk 'BEGIN{OFS=","} {print "'"$DATE"'", $0}' $log_dir/current_to_store_sorted.tmp > $log_dir/current_to_store_sorted_time.tmp
			cat $log_dir/current_to_store_sorted_time.tmp >> $log_dir/$iface.csv
			#sync
			mv $log_dir/.$current $log_dir/.$previous
	rm $log_dir/*.tmp
get_all_iface_stats_debug()
	get_iface_stats rmnet_data0
	get_iface_stats rndis0
	get_iface_stats wlan0
	get_iface_stats wlan1
get_data_stats_debug()
	store=0
	DATE=`date +%m/%d/%Y_%H:%M:%S`
	data_stats_tmp=$log_dir/data_stats.tmp
	data_tx_tmp=$log_dir/data_tx.tmp
	data_rx_tmp=$log_dir/data_rx.tmp
	if_tx="rmnet_data0_tx,rndis0_tx,wlan0_tx,wlan1_tx,br0_tx,br0_wlan0_tx,br0_wlan1_tx"
	if_rx="rmnet_data0_rx,rndis0_rx,wlan0_rx,wlan1_rx,br0_rx,br0_wlan0_rx,br0_wlan1_rx"
	netfilter="nf_count"
	ipv4_v6_str1="modem_ipv4_tx,modem_ipv6_tx,ipv4_rx,ipv6_rx,ipv4_lc_tx,ipv6_lc_tx,ipv4_lc_rx,ipv6_lc_rx,ipv4_pkt_tx,ipv6_pkt_tx"
	ipv4_v6_str2="ipv4_pkt_rx,ipv6_pkt_rx,ipv4_pkt_tx_err,ipv6_pkt_tx_err,ipv4_pkt_rx_err,ipv6_pkt_rx_err"
	ipv4_v6_str3="ipv4_pkt_tx_ofl,ipv6_pkt_tx_ofl,ipv4_pkt_rx_ofl,ipv6_pkt_rx_ofl"
	if [ -d /sys/class/net/rmnet_data0 ];then
		cat /sys/class/net/rmnet_data0/statistics/tx_bytes >  $data_tx_tmp
		cat /sys/class/net/rmnet_data0/statistics/rx_bytes >>  $data_rx_tmp
		echo "0" >  $data_tx_tmp
		echo "0" >> $data_rx_tmp
	if [ -d /sys/class/net/rndis0 ];then
		cat /sys/class/net/rndis0/statistics/tx_bytes >>  $data_tx_tmp
		cat /sys/class/net/rndis0/statistics/rx_bytes >>  $data_rx_tmp
		echo "0" >>  $data_tx_tmp
		echo "0" >>  $data_rx_tmp
	if [ -d /sys/class/net/wlan0 ];then
		cat /sys/class/net/wlan0/statistics/tx_bytes >>  $data_tx_tmp
		cat /sys/class/net/wlan0/statistics/rx_bytes >>  $data_rx_tmp
		echo "0" >>  $data_tx_tmp
		echo "0" >>  $data_rx_tmp
	if [ -d /sys/class/net/wlan1 ];then
		cat /sys/class/net/wlan1/statistics/tx_bytes >>  $data_tx_tmp
		cat /sys/class/net/wlan1/statistics/rx_bytes >>  $data_rx_tmp
		echo "0" >>  $data_tx_tmp
		echo "0" >>  $data_rx_tmp
	if [ -d /sys/class/net/bridge0/lower_wlan0 -a -d /sys/class/net/bridge0/lower_wlan1 ]; then
		cat /sys/class/net/bridge0/statistics/tx_bytes  >>  $data_tx_tmp
		cat /sys/class/net/bridge0/lower_wlan0/statistics/tx_bytes  >>  $data_tx_tmp
		cat /sys/class/net/bridge0/lower_wlan1/statistics/tx_bytes  >>  $data_tx_tmp
		cat /sys/class/net/bridge0/statistics/rx_bytes  >>  $data_rx_tmp
		cat /sys/class/net/bridge0/lower_wlan0/statistics/rx_bytes  >>  $data_rx_tmp
		cat /sys/class/net/bridge0/lower_wlan1/statistics/rx_bytes  >>  $data_rx_tmp
		echo "0" >>  $data_tx_tmp
		echo "0" >>  $data_tx_tmp
		echo "0" >>  $data_tx_tmp
		echo "0" >>  $data_rx_tmp
		echo "0" >>  $data_rx_tmp
		echo "0" >>  $data_rx_tmp
	cat $data_tx_tmp > $data_stats_tmp
	cat $data_rx_tmp >> $data_stats_tmp
	cat /proc/sys/net/netfilter/nf_conntrack_count >>  $data_stats_tmp
	nwcli qmi_idl get_pkt_stats > $log_dir/modem_data_usage.tmp
	awk '/bytes_tx_ok/ {print $0}' $log_dir/modem_data_usage.tmp | sed 's/^[^=]*=//g' >  $log_dir/modem_data_usage_unsorted.tmp
	awk '/bytes_rx_ok/ {print $0}' $log_dir/modem_data_usage.tmp | sed 's/^[^=]*=//g' >>  $log_dir/modem_data_usage_unsorted.tmp
	awk '/bytes_lc_tx_ok/ {print $0}' $log_dir/modem_data_usage.tmp | sed 's/^[^=]*=//g' >>  $log_dir/modem_data_usage_unsorted.tmp
	awk '/bytes_lc_rx_ok/ {print $0}' $log_dir/modem_data_usage.tmp | sed 's/^[^=]*=//g' >>  $log_dir/modem_data_usage_unsorted.tmp
	awk '/pkt_tx_ok/ {print $0}' $log_dir/modem_data_usage.tmp | sed 's/^[^=]*=//g' >>  $log_dir/modem_data_usage_unsorted.tmp
	awk '/pkt_rx_ok/ {print $0}' $log_dir/modem_data_usage.tmp | sed 's/^[^=]*=//g' >>  $log_dir/modem_data_usage_unsorted.tmp
	awk '/pkt_tx_err/ {print $0}' $log_dir/modem_data_usage.tmp | sed 's/^[^=]*=//g' >>  $log_dir/modem_data_usage_unsorted.tmp
	awk '/pkt_rx_err/ {print $0}' $log_dir/modem_data_usage.tmp | sed 's/^[^=]*=//g' >>  $log_dir/modem_data_usage_unsorted.tmp
	awk '/pkt_tx_ofl/ {print $0}' $log_dir/modem_data_usage.tmp | sed 's/^[^=]*=//g' >>  $log_dir/modem_data_usage_unsorted.tmp
	awk '/pkt_rx_ofl/ {print $0}' $log_dir/modem_data_usage.tmp | sed 's/^[^=]*=//g' >>  $log_dir/modem_data_usage_unsorted.tmp
	cat $log_dir/modem_data_usage_unsorted.tmp >> $data_stats_tmp
	cp $data_stats_tmp $log_dir/.data_debug_current_snapshort.txt
	if [ -f $log_dir/.data_debug_prev_snapshort.txt ]; then
			cmp $log_dir/.data_debug_prev_snapshort.txt $log_dir/.data_debug_current_snapshort.txt > $log_dir/delta.tmp
			size=`ls -l $log_dir/delta.tmp | awk '{print $5}'`
			if [ $size -ne 0 ]; then
					store=1					
			store=1
			echo "TIME,$if_tx,$if_rx,$netfilter,$ipv4_v6_str1,$ipv4_v6_str2,$ipv4_v6_str3" > $log_dir/data_stats_debug.csv
	if [ $store = 1 ]; then
			awk 'BEGIN{RS="\n";ORS=","} {print}' $log_dir/.data_debug_current_snapshort.txt | sed 's/.$//' > $log_dir/current_to_store_sorted.tmp
			awk 'BEGIN{OFS=","} {print "'"$DATE"'", $0}' $log_dir/current_to_store_sorted.tmp > $log_dir/current_to_store_sorted_time.tmp
			cat $log_dir/current_to_store_sorted_time.tmp >> $log_dir/data_stats_debug.csv
			#sync
			mv $log_dir/.data_debug_current_snapshort.txt $log_dir/.data_debug_prev_snapshort.txt
	rm $log_dir/*.tmp
get_meminfo()
	store=0
	DATE=`date +%m/%d/%Y_%H:%M:%S`
	str1="MemFree,MemAvailable,Cached,Active,Inactive,Active(anon)"
	str2="Inactive(anon),Active(file),Inactive(file),Unevictable,Dirty"
	str3="Writeback,AnonPages,Mapped,Shmem,Slab,SReclaimable,SUnreclaim"
	str4="KernelStack,PageTables,CommitLimit,Committed_AS,VmallocTotal"
	str5="VmallocUsed,VmallocChunk,CmaTotal,CmaFree"
	in_file=$log_dir/meminfo.tmp	
	out_file=$log_dir/meminfo_unsorted.tmp
	cat /proc/meminfo > $in_file
	awk '/MemFree:/ {print $2}' $in_file > $out_file
	awk '/MemAvailable:/ {print $2}' $in_file >> $out_file 
	awk '/^Cached:/ {print $2}' $in_file >> $out_file
	awk '/Active:/ {print $2}' $in_file >> $out_file
	awk '/Inactive:/ {print $2}' $in_file  >> $out_file
	awk '/Active\(anon\):/ {print $2}' $in_file >> $out_file
	awk '/Inactive\(anon\):/ {print $2}' $in_file >> $out_file
	awk '/Active\(file\):/ {print $2}' $in_file >> $out_file
	awk '/Inactive\(file\):/ {print $2}' $in_file >> $out_file
	awk '/Unevictable:/ {print $2}' $in_file >> $out_file
	awk '/Dirty:/ {print $2}' $in_file >> $out_file
	awk '/Writeback:/ {print $2}' $in_file >> $out_file
	awk '/AnonPages:/ {print $2}' $in_file >> $out_file
	awk '/Mapped:/ {print $2}' $in_file >> $out_file
	awk '/Shmem:/ {print $2}' $in_file >> $out_file
	awk '/Slab:/ {print $2}' $in_file >> $out_file
	awk '/SReclaimable:/ {print $2}' $in_file >> $out_file
	awk '/SUnreclaim:/ {print $2}' $in_file >> $out_file
	awk '/KernelStack:/ {print $2}' $in_file >> $out_file
	awk '/PageTables:/ {print $2}' $in_file >> $out_file
	awk '/CommitLimit:/ {print $2}' $in_file >> $out_file
	awk '/Committed_AS:/ {print $2}' $in_file >> $out_file
	awk '/VmallocTotal:/ {print $2}' $in_file >> $out_file
	awk '/VmallocUsed:/ {print $2}' $in_file >> $out_file
	awk '/VmallocChunk:/ {print $2}' $in_file >> $out_file
	awk '/CmaTotal:/ {print $2}' $in_file >> $out_file
	awk '/CmaFree:/ {print $2}' $in_file >> $out_file
	cp $out_file $log_dir/.meminfo_current_snapshot.txt
	if [ -f $log_dir/.meminfo_prev_snapshot.txt ]; then
			cmp $log_dir/.meminfo_prev_snapshot.txt $log_dir/.meminfo_current_snapshot.txt > $log_dir/delta.tmp
			size=`ls -l $log_dir/delta.tmp | awk '{print $5}'`
			if [ $size -ne 0 ]; then
					store=1
			store=1		
			awk '/MemTotal:/ {print "MemTotal=", $2}' $in_file > $log_dir/meminfo.csv
			echo "TIME,$str1,$str2,$str3,$str4,$str5" >> $log_dir/meminfo.csv
	if [ $store = 1 ]; then			
			awk 'BEGIN{RS="\n";ORS=","} {print}' $log_dir/.meminfo_current_snapshot.txt | sed 's/.$//' > $log_dir/current_to_store_sorted.tmp
			awk 'BEGIN{OFS=","} {print "'"$DATE"'", $0}' $log_dir/current_to_store_sorted.tmp > $log_dir/current_to_store_sorted_time.tmp
			cat $log_dir/current_to_store_sorted_time.tmp >> $log_dir/meminfo.csv
			#sync
			mv $log_dir/.meminfo_current_snapshot.txt $log_dir/.meminfo_prev_snapshot.txt
	rm $log_dir/*.tmp
get_data_stats()
	store=0
	DATE=`date +%m/%d/%Y_%H:%M:%S`
	data_stats_tmp=$log_dir/data_stats.tmp
	data_tx_tmp=$log_dir/data_tx.tmp
	data_rx_tmp=$log_dir/data_rx.tmp
	if_tx="rmnet_data0_tx,rndis0_tx,wlan0_tx,wlan1_tx,br0_tx,br0_wlan0_tx,br0_wlan1_tx,modem_ipv4_tx,modem_ipv6_tx"
	if_rx="rmnet_data0_rx,rndis0_rx,wlan0_rx,wlan1_rx,br0_rx,br0_wlan0_rx,br0_wlan1_rx,modem_ipv4_rx,modem_ipv6_rx"
	netfilter="nf_count"
	if [ -d /sys/class/net/rmnet_data0 ];then
		cat /sys/class/net/rmnet_data0/statistics/tx_bytes >  $data_tx_tmp
		cat /sys/class/net/rmnet_data0/statistics/rx_bytes >>  $data_rx_tmp
		echo "0" >  $data_tx_tmp
		echo "0" >> $data_rx_tmp
	if [ -d /sys/class/net/rndis0 ];then
		cat /sys/class/net/rndis0/statistics/tx_bytes >>  $data_tx_tmp
		cat /sys/class/net/rndis0/statistics/rx_bytes >>  $data_rx_tmp
		echo "0" >>  $data_tx_tmp
		echo "0" >>  $data_rx_tmp
	if [ -d /sys/class/net/wlan0 ];then
		cat /sys/class/net/wlan0/statistics/tx_bytes >>  $data_tx_tmp
		cat /sys/class/net/wlan0/statistics/rx_bytes >>  $data_rx_tmp
		echo "0" >>  $data_tx_tmp
		echo "0" >>  $data_rx_tmp
	if [ -d /sys/class/net/wlan1 ];then
		cat /sys/class/net/wlan1/statistics/tx_bytes >>  $data_tx_tmp
		cat /sys/class/net/wlan1/statistics/rx_bytes >>  $data_rx_tmp
		echo "0" >>  $data_tx_tmp
		echo "0" >>  $data_rx_tmp
	if [ -d /sys/class/net/bridge0/lower_wlan0 -a -d /sys/class/net/bridge0/lower_wlan1 ]; then
		cat /sys/class/net/bridge0/statistics/tx_bytes  >>  $data_tx_tmp
		cat /sys/class/net/bridge0/lower_wlan0/statistics/tx_bytes  >>  $data_tx_tmp
		cat /sys/class/net/bridge0/lower_wlan1/statistics/tx_bytes  >>  $data_tx_tmp
		cat /sys/class/net/bridge0/statistics/rx_bytes  >>  $data_rx_tmp
		cat /sys/class/net/bridge0/lower_wlan0/statistics/rx_bytes  >>  $data_rx_tmp
		cat /sys/class/net/bridge0/lower_wlan1/statistics/rx_bytes  >>  $data_rx_tmp
		echo "0" >>  $data_tx_tmp
		echo "0" >>  $data_tx_tmp
		echo "0" >>  $data_tx_tmp
		echo "0" >>  $data_rx_tmp
		echo "0" >>  $data_rx_tmp
		echo "0" >>  $data_rx_tmp
	nwcli qmi_idl get_pkt_stats > $log_dir/modem_data_usage.tmp
	awk '/bytes_tx_ok/ {print $0}' $log_dir/modem_data_usage.tmp | sed 's/^[^=]*=//g' >  $log_dir/modem_tx_data_usage_unsorted.tmp
	size=`ls -l $log_dir/modem_tx_data_usage_unsorted.tmp | awk '{print $5}'`
	if [ $size = 0 ]; then
		echo "0" >>  $data_tx_tmp
		echo "0" >>  $data_tx_tmp		
		cat $log_dir/modem_tx_data_usage_unsorted.tmp >>  $data_tx_tmp
	awk '/bytes_rx_ok/ {print $0}' $log_dir/modem_data_usage.tmp | sed 's/^[^=]*=//g' >  $log_dir/modem_rx_data_usage_unsorted.tmp
	size=`ls -l $log_dir/modem_rx_data_usage_unsorted.tmp | awk '{print $5}'`
	if [ $size = 0 ]; then
		echo "0" >>  $data_rx_tmp
		echo "0" >>  $data_rx_tmp
		cat $log_dir/modem_rx_data_usage_unsorted.tmp >>  $data_rx_tmp
	cat $data_tx_tmp > $data_stats_tmp
	cat $data_rx_tmp >> $data_stats_tmp
	cat /proc/sys/net/netfilter/nf_conntrack_count >>  $data_stats_tmp
	cp $data_stats_tmp $log_dir/.ifconfig_current_snapshort.txt
	if [ -f $log_dir/.ifconfig_prev_snapshort.txt ]; then
			cmp $log_dir/.ifconfig_prev_snapshort.txt $log_dir/.ifconfig_current_snapshort.txt > $log_dir/delta.tmp
			size=`ls -l $log_dir/delta.tmp | awk '{print $5}'`
			if [ $size -ne 0 ]; then
					store=1					
			store=1
			echo "TIME,$if_tx,$if_rx,$netfilter" > $log_dir/data_stats.csv
	if [ $store = 1 ]; then
			awk 'BEGIN{RS="\n";ORS=","} {print}' $log_dir/.ifconfig_current_snapshort.txt | sed 's/.$//' > $log_dir/current_to_store_sorted.tmp
			awk 'BEGIN{OFS=","} {print "'"$DATE"'", $0}' $log_dir/current_to_store_sorted.tmp > $log_dir/current_to_store_sorted_time.tmp
			cat $log_dir/current_to_store_sorted_time.tmp >> $log_dir/data_stats.csv
			#sync
			mv $log_dir/.ifconfig_current_snapshort.txt $log_dir/.ifconfig_prev_snapshort.txt
	rm $log_dir/*.tmp
get_device_temp()
	xo_device_temp=0
	thermal_type=""
	for i in `seq 1 100`; do		
		if [ -f /sys/class/thermal/thermal_zone$i/type ]; then
			thermal_type=`cat /sys/class/thermal/thermal_zone$i/type`		
			if [ $thermal_type == "xo-therm-usr" ]; then												
				nvtl_log -p 1 -m KEVENT -l notice -s "$SCRIPTNAME: xo_thermal_zone_index=$i"	
				if [ -f /sys/class/thermal/thermal_zone$i/temp ]; then
					xo_device_temp=`cat /sys/class/thermal/thermal_zone$i/temp`
					# variable is empty when reading disabled thermal zone, so assign 0
					if [ -z "$xo_device_temp" ]; then
						nvtl_log -p 1 -m KEVENT -l notice -s "$SCRIPTNAME: xo_device_temp is empty"
						xo_device_temp=0
					fi					
				fi							
				break
get_battery_modem_stats()
	store=0
	DATE=`date +%m/%d/%Y_%H:%M:%S`
	# QMI allows max 10 arrays
	str0="B0:pci,B0:band,B0:status,B0:bandwidth"
	str1="B1:pci,B1:band,B1:status,B1:bandwidth"
	str2="B2:pci,B2:band,B2:status,B2:bandwidth"
	str3="B3:pci,B3:band,B3:status,B3:bandwidth"
	str4="B4:pci,B4:band,B4:status,B4:bandwidth"
	str5="B5:pci,B5:band,B5:status,B5:bandwidth"
	str6="B6:pci,B6:band,B6:status,B6:bandwidth"
	str7="B7:pci,B7:band,B7:status,B7:bandwidth"
	str8="B8:pci,B8:band,B8:status,B8:bandwidth"
	str9="B9:pci,B9:band,B9:status,B9:bandwidth"
	Bat_str="Bat_Status,Bat_Current,Bat_Temp"
	Modem_str="Modem_Tech,SNR,RSRP,Bandwidth,$str0,$str1,$str2,$str3,$str4,$str5,$str6,$str7,$str8,$str9"
	if [ $Model = "M2100" -o $Model = "M2000" -o $Model = "M2000A" -o $Model = "M2000B" -o $Model = "M2000C" -o $Model = "M2000D" ]; then
		cat /sys/class/power_supply/battery/status  > $log_dir/battery.tmp
		cat /sys/class/power_supply/battery/current_now >> $log_dir/battery.tmp
		cat /sys/class/power_supply/battery/temp >> $log_dir/battery.tmp
		# get xo-therm-usr temperature
		get_device_temp
		echo $xo_device_temp >> $log_dir/battery.tmp
		get_device_temp
		echo $xo_device_temp > $log_dir/battery.tmp
	modem2_cli get_signal > $log_dir/modem_signal.tmp
	awk '/tech/ {print $1 $2}' $log_dir/modem_signal.tmp | sed 's/^[^:]*://g' | tr -d [] > $log_dir/modem_unsorted.tmp
	awk '/snr/ {print $1}' $log_dir/modem_signal.tmp | sed 's/^[^:]*://g' | tr -d [] >> $log_dir/modem_unsorted.tmp
	awk '/rsrp/ {print $1}' $log_dir/modem_signal.tmp | sed 's/^[^:]*://g' | tr -d [] >> $log_dir/modem_unsorted.tmp
	modem2_cli get_bandwidth > $log_dir/modem_band.tmp
	awk '/bandwidth :/ {print $2}'  $log_dir/modem_band.tmp | sed 's/^[^:]*://g' | tr -d [] >> $log_dir/modem_unsorted.tmp
	modem2_cli get_ca_band_list > $log_dir/modem_band_list.tmp
	awk '/ca_bands\[/ {print $3}' $log_dir/modem_band_list.tmp | sed 's/^[^:]*://g' | tr -d [] >> $log_dir/modem_unsorted.tmp
	cat $log_dir/battery.tmp > $log_dir/.bat_modem_current_snapshot.txt
	cat $log_dir/modem_unsorted.tmp >> $log_dir/.bat_modem_current_snapshot.txt
	if [ -f $log_dir/.bat_modem_prev_snapshot.txt ]; then
			cmp $log_dir/.bat_modem_prev_snapshot.txt $log_dir/.bat_modem_current_snapshot.txt > $log_dir/delta.tmp
			size=`ls -l $log_dir/delta.tmp | awk '{print $5}'`
			if [ $size -ne 0 ]; then
					store=1
			store=1	
			# Some products don't have Battery
			if [ $Model = "M2100" -o $Model = "M2000" -o $Model = "M2000A" -o $Model = "M2000B" -o $Model = "M2000C" -o $Model = "M2000D" ]; then
				echo "TIME,$Bat_str,Device_Temp,$Modem_str" > $log_dir/battery_modem_signal.csv
				echo "TIME,Device_Temp,$Modem_str" > $log_dir/battery_modem_signal.csv
	if [ $store = 1 ]; then
			awk 'BEGIN{RS="\n";ORS=","} {print}' $log_dir/.bat_modem_current_snapshot.txt | sed 's/.$//' > $log_dir/current_to_store_sorted.tmp
			awk 'BEGIN{OFS=","} {print "'"$DATE"'", $0}' $log_dir/current_to_store_sorted.tmp > $log_dir/current_to_store_sorted_time.tmp
			cat $log_dir/current_to_store_sorted_time.tmp >> $log_dir/battery_modem_signal.csv
			#sync
			mv $log_dir/.bat_modem_current_snapshot.txt $log_dir/.bat_modem_prev_snapshot.txt
	rm $log_dir/*.tmp
get_multi_top()
	DATE=`date +%m/%d/%Y_%H:%M:%S`
	top -b -n 4 -d 3 > $log_dir/top.txt
	# Ignore 1st instance, store only 2,3,4th instance into separate file
	awk -v start=2 -v finish=3 '/Mem:/{n++};n==finish{exit};n>=start' $log_dir/top.txt  > $log_dir/top_2.txt
	awk -v start=3 -v finish=4 '/Mem:/{n++};n==finish{exit};n>=start' $log_dir/top.txt  > $log_dir/top_3.txt
	awk -v start=4 '/Mem:/{n++};n>=start' $log_dir/top.txt  > $log_dir/top_4.txt
	for t in 2 3 4;do
		top_input_file=top_$t.txt	
		sed -n '/CPU:/ p' $log_dir/$top_input_file > $log_dir/sys_cpu_usage_unsorted.tmp
		awk 'BEGIN{OFS=","} {print $2,$4,$6,$8,$10,$12,$14}' $log_dir/sys_cpu_usage_unsorted.tmp | sed 's/%//g' > $log_dir/sys_cpu_usage.tmp
		SYS_CPU_USAGE=`cat $log_dir/sys_cpu_usage.tmp`
		sed -n '/PID/,$ p' $log_dir/$top_input_file | awk '{if(NR>1)print}' > $log_dir/ps_cpu_use_unsorted.tmp
		awk -v var1="$TOP_CPU_USAGE_THRESHOLD" '$8 > var1 {print $0}' $log_dir/ps_cpu_use_unsorted.tmp | awk 'BEGIN{OFS=","} {print $1, $8, $9 }' > $log_dir/top_current_snapshort.txt
		if [ -f $log_dir/.top_prev_snapshot.txt ]; then
			diff -w $log_dir/.top_prev_snapshot.txt $log_dir/top_current_snapshort.txt  | sed -n '/^+/ p' | awk '{if(NR>1)print}' | sed -r 's/\+//g' > $log_dir/delta_to_store.tmp		
			# log first time
			cp $log_dir/top_current_snapshort.txt $log_dir/delta_to_store.tmp
			echo "TIME,PID,%CPU,COMMAND,%CPU:USR,%CPU:SYS,%CPU:NIC,%CPU:IDLE,%CPU:IO,%CPU:IRQ,%CPU:SIRQ" > $log_dir/top.csv
		size=`ls -l $log_dir/delta_to_store.tmp | awk '{print $5}'`
		if [ $size -ne 0 ]; then
			awk 'BEGIN{OFS=","} {print "'"$DATE"'", $0}' $log_dir/delta_to_store.tmp >  $log_dir/delta_to_store_w_time.tmp
			awk -v var2="$SYS_CPU_USAGE" 'BEGIN{FS=",";OFS=","} {print $1, $2, $3, $4, var2}' $log_dir/delta_to_store_w_time.tmp > $log_dir/delta_to_store_w_time_cpu.tmp
			cat $log_dir/delta_to_store_w_time_cpu.tmp >> $log_dir/top.csv
			#sync
			if [ -f $log_dir/.top_prev_snapshot.txt ]; then
				mv $log_dir/.top_prev_snapshot.txt $log_dir/.top_prev_snapshot-old.txt 
			mv $log_dir/top_current_snapshort.txt $log_dir/.top_prev_snapshot.txt 
		#Remove all temporary files
		rm $log_dir/*.tmp
	mv $log_dir/top.txt $log_dir/.top.txt
	rm $log_dir/top_*.txt
mem_zone_switch_stats()
	zone=$1
	no_of_records=$2
	DATE=`date +%m/%d/%Y_%H:%M:%S`
	free_mem=`free -m | awk 'NR==2{print $4}';`
	if [ ! -f $log_dir/mem_zone_switch.csv ]; then
		echo "TIME,MEM_ZONE,FREE_MEM,NO OF RECORDS COLLECTED" > $log_dir/mem_zone_switch.csv
	echo "$DATE,$zone,$free_mem,$no_of_records" >> $log_dir/mem_zone_switch.csv
get_connected_device()
	dmdb_cli get_connected_device_list > $log_dir/device_connect_cmd.tmp
	awk '/count:/ {print $1}' $log_dir/device_connect_cmd.tmp | sed 's/^[^:]*://g' | tr -d [] > $log_dir/device_connect.tmp
	awk '/USB/ {print $1}' $log_dir/device_connect_cmd.tmp > $log_dir/usb.tmp
	size=`ls -l $log_dir/usb.tmp | awk '{print $5}'`
	if [ $size = 0 ]; then
		echo "0" >> $log_dir/device_connect.tmp
		echo "1" >> $log_dir/device_connect.tmp
	# Get no of opened file descriptors
	lsof | wc -l >>  $log_dir/device_connect.tmp
	# Get max no of file descriptors
	cat /proc/sys/fs/file-max >> $log_dir/device_connect.tmp
	awk 'BEGIN{RS="\n";ORS=","} {print}' $log_dir/device_connect.tmp | sed 's/.$//' > $log_dir/device_connect_sorted.tmp
get_process_stats()
	DATE=`date +%m/%d/%Y_%H:%M:%S`
	free_mem=`free -m | awk 'NR==2{print $4}';`
	ps -e -o pid,ppid,rss,comm | awk '{if(NR>1)print}' > $log_dir/ps.tmp
	#strip kernel started process as NO RSS value, PPID=0,2 
	awk '$2 == "2" || $2 == "0" { next } { print }' $log_dir/ps.tmp > $log_dir/ps_mifios.tmp
	#sort only pid,rss,cmd column
	awk 'BEGIN{OFS=","} {print $1,$3,$4}' $log_dir/ps_mifios.tmp > $log_dir/ps_sorted.tmp
	# store current ps detail for reference
	cp $log_dir/ps_sorted.tmp $log_dir/.ps.txt
	#get pid
	cat $log_dir/ps_mifios.tmp | awk '{print $1}' > $log_dir/pid.tmp
	#get oom values
	for pid in `cat $log_dir/pid.tmp`;do
		if [[ \( -f /proc/$pid/oom_score && -f /proc/$pid/oom_score_adj \) && -f /proc/$pid/oom_adj ]]; then		
			echo "$pid,$(cat /proc/$pid/oom_score),$(cat /proc/$pid/oom_score_adj),$(cat /proc/$pid/oom_adj)" >> $log_dir/oom_score.tmp
			echo "$pid,0,0,0" >> $log_dir/oom_score.tmp
	#merge process's rss and oom scores
	awk 'BEGIN{FS=",";OFS=","}NR==FNR{a[i++]=$0};{b[x++]=$0;};{k=x-i};END{for(j=0;j<i;) print a[j++],b[k++]}' $log_dir/ps_sorted.tmp $log_dir/oom_score.tmp > $log_dir/ps_oom_merged.tmp 
	#sort as pid, rss, oom_score, oom_score_adj, oom_adj, cmd column
	awk 'BEGIN{FS=",";OFS=","} {print $1,$2,$5,$6,$7,$3}' $log_dir/ps_oom_merged.tmp > $log_dir/ps_oom_merged_sorted.tmp
	cp $log_dir/ps_oom_merged_sorted.tmp $log_dir/current_snapshort.txt
	if [ -f $log_dir/.prev_snapshot.txt ]; then
		diff -w $log_dir/.prev_snapshot.txt $log_dir/current_snapshort.txt  |  sed -n '/^+/ p' | awk '{if(NR>1)print}' | sed -r 's/\+//g' > $log_dir/delta_to_store.tmp
		# log first time
		cp $log_dir/current_snapshort.txt $log_dir/delta_to_store.tmp
		echo "TIME,FREE_MEM,PID,RSS,OOM_SCORE,OOM_SCORE_ADJ,OOM_ADJ,CMD,CLIENT_COUNT,USB(RNDIS),OPEN_FILE,MAX_OPEN_FILE" > $log_dir/ps.csv
	size=`ls -l $log_dir/delta_to_store.tmp | awk '{print $5}'`
	if [ $size -ne 0 ]; then
		sed -i -e '/devuiappd/ s/m/000/g' $log_dir/delta_to_store.tmp				
		awk 'BEGIN{OFS=","} {print "'"$DATE"'", '$free_mem', $0}' $log_dir/delta_to_store.tmp >  $log_dir/delta_to_store_w_time_mem.tmp
		#add device count at end to ps.csv
		get_connected_device
		DEV_COUNT=`cat $log_dir/device_connect_sorted.tmp`
		awk -v var1="$DEV_COUNT" 'BEGIN{FS=",";OFS=","} {print $0, var1}' $log_dir/delta_to_store_w_time_mem.tmp > $log_dir/delta_to_store_w_time_mem_dev_count.tmp
		cat $log_dir/delta_to_store_w_time_mem_dev_count.tmp >> $log_dir/ps.csv
		#sync				
		mv $log_dir/current_snapshort.txt $log_dir/.prev_snapshot.txt 
	#Remove all temporary files
	rm $log_dir/*.tmp
get_tmpfs_stats()
	store=0
	DATE=`date +%m/%d/%Y_%H:%M:%S`
	du -k -d 0 /tmp | awk '{print $1}' > $log_dir/tmpfs.tmp
	du -k -d 0 /run | awk '{print $1}' >> $log_dir/tmpfs.tmp
	du -k -d 0 /var/log | awk '{print $1}' >> $log_dir/tmpfs.tmp
	du -k -d 0 /var/lock | awk '{print $1}' >> $log_dir/tmpfs.tmp
	du -k -d 0 /opt/nvtl/tmp | awk '{print $1}' >> $log_dir/tmpfs.tmp
	cp $log_dir/tmpfs.tmp $log_dir/.tmpfs_current_snapshort.txt
	if [ -f $log_dir/.tmpfs_prev_snapshort.txt ]; then
			cmp $log_dir/.tmpfs_prev_snapshort.txt $log_dir/.tmpfs_current_snapshort.txt > $log_dir/delta_to_store.tmp
			size=`ls -l $log_dir/delta_to_store.tmp | awk '{print $5}'`
			if [ $size -ne 0 ]; then
					store=1
			store=1
			echo "TIME,/tmp,/run,/var/log,/var/lock,/opt/nvtl/tmp" > $log_dir/tmpfs.csv
	if [ $store = 1 ]; then
			awk 'BEGIN{RS="\n";ORS=","} {print}' $log_dir/.tmpfs_current_snapshort.txt | sed 's/.$//' > $log_dir/delta_to_store_sorted.tmp
			awk 'BEGIN{OFS=","} {print "'"$DATE"'", $0}' $log_dir/delta_to_store_sorted.tmp > $log_dir/delta_to_store_sorted_time.tmp
			cat $log_dir/delta_to_store_sorted_time.tmp >> $log_dir/tmpfs.csv
			#sync
			mv $log_dir/.tmpfs_current_snapshort.txt $log_dir/.tmpfs_prev_snapshort.txt
	awk 'BEGIN {RS="\n";total=0;} {total=total+$1} END {print total;}' $log_dir/tmpfs.tmp > $log_dir/tmpfs_total_size.tmp
	tmpfs_size=`cat $log_dir/tmpfs_total_size.tmp`
	if [ $tmpfs_size -ge 4096 ]; then
		log "total tmpfs size(KB) is $tmpfs_size, collecting file list"
		echo "***** $DATE *******" > $log_dir/tmpfs_file_list.txt
		# TODO: this workaround, remove it once WebUi team fixed it properly
		if [ -f /tmp/tempdebuglogs_raw.tgz ]; then
			log "WARNING:/tmp/tempdebuglogs_raw.tgz exist, deleting it"
			rm -f /tmp/tempdebuglogs_raw.tgz
		if [ -f /opt/nvtl/tmp/*_log.tgz ]; then
			log "WARNING:/opt/nvtl/tmp/*_log.tgz exist, deleting it"
			rm -f /opt/nvtl/tmp/*_log.tgz
		if [ -f /var/log/debug-logs.tgz ]; then
			log "WARNING:/var/log/debug-logs.tgz exist, deleting it"
			rm -f /var/log/debug-logs.tgz
		echo "du -ah /tmp/*" >> $log_dir/tmpfs_file_list.txt
		du -ah /tmp/* >> $log_dir/tmpfs_file_list.txt
		echo "" >> $log_dir/tmpfs_file_list.txt
		echo "du -ah /var/log/*" >> $log_dir/tmpfs_file_list.txt
		du -ah /var/log/* >> $log_dir/tmpfs_file_list.txt
		echo "" >> $log_dir/tmpfs_file_list.txt
		echo "du -ah /opt/nvtl/tmp/*" >> $log_dir/tmpfs_file_list.txt
		du -ah /opt/nvtl/tmp/* >> $log_dir/tmpfs_file_list.txt
		echo "" >> $log_dir/tmpfs_file_list.txt		
	rm $log_dir/*.tmp
# Collect current process/memory status
common_task()
	log "common_task:Start"
	#get_process_stats
	#get_meminfo
	#get_tmpfs_stats
	#get_battery_modem_stats
	#get_data_stats
	#get_data_stats_debug
	#get_all_iface_stats_debug
	#get_multi_top
	#get_process_openfd_count
	# Check log limit and do backup
	#check_log_limit
	log "common_task:Done"
restart_killed_app()
	case "$1" in
			if [ -f /tmp/mem_diag_led_killed ]; then
				log "restarting led process"
				nvtl_log -p 1 -m KEVENT -l notice -s "$SCRIPTNAME:restarting led process"
				nvtl_led.sh start
				rm -f /tmp/mem_diag_led_killed
				#sync
		powersave)
			if [ -f /tmp/mem_diag_powersave_killed ]; then
				log "restarting powersave process"
				nvtl_log -p 1 -m KEVENT -l notice -s "$SCRIPTNAME:restarting powersave process"
				powersave.sh start
				rm -f /tmp/mem_diag_powersave_killed 
				#sync
		diag_read)
			if [ -f /tmp/mem_diag_diag_read_killed ]; then
				log "restarting diag_read process"
				nvtl_log -p 1 -m KEVENT -l notice -s "$SCRIPTNAME:restarting diag_read process"
				diag_read.sh start
				rm -f /tmp/mem_diag_diag_read_killed
				#sync
			if [ -f /tmp/mem_diag_gps_killed ]; then
				log "restarting gps process"
				nvtl_log -p 1 -m KEVENT -l notice -s "$SCRIPTNAME:restarting gps process"
				gps.sh start
				rm -f /tmp/mem_diag_gps_killed
				#sync
			if [ -f /tmp/mem_diag_vpn_killed ]; then
				log "restarting vpn process"
				nvtl_log -p 1 -m KEVENT -l notice -s "$SCRIPTNAME:restarting vpn process"
				vpn.sh start
				rm -f /tmp/mem_diag_vpn_killed 
				#sync	
		webserver)
			if [ -f /tmp/mem_diag_webserver_killed ]; then
				log "restarting webserver process"
				nvtl_log -p 1 -m KEVENT -l notice -s "$SCRIPTNAME:restarting webserver process"
				nvtl_webserver.sh start
				rm -f /tmp/mem_diag_webserver_killed 
				#sync	
			if [ -f /tmp/mem_diag_adbd_killed ]; then
				log "restarting adb process"
				nvtl_log -p 1 -m KEVENT -l notice -s "$SCRIPTNAME:restarting adb process"
				/sbin/adbd &					
				rm -f /tmp/mem_diag_adbd_killed 
				#sync	
			log "case: default: Error: Wrong value for case input"
# kill app to free memory
kill_app()
	#stop low priority process to free some memory(RAM)
	if [ ! -f /tmp/mem_diag_led_killed -o ! -f /tmp/mem_diag_powersave_killed ]; then
		echo "WARNING:Entered critical zone, killing led & powersave process"
		nvtl_log -p 1 -m KEVENT -l notice -s "$SCRIPTNAME: WARNING:Entered critical zone, killing led & powersave process"	
		nvtl_led.sh stop
		powersave.sh stop
		touch /tmp/mem_diag_led_killed
		touch /tmp/mem_diag_powersave_killed		
	elif [ ! -f /tmp/mem_diag_diag_read_killed ]; then
		#log "WARNING:Still in critical zone, killing diag_read process"
		nvtl_log -p 1 -m KEVENT -l notice -s "$SCRIPTNAME:WARNING:Still in critical zone, killing diag_read process"
		diag_read.sh stop		
		touch /tmp/mem_diag_diag_read_killed
		#sync	
	elif [ ! -f /tmp/mem_diag_gps_killed -o ! -f /tmp/mem_diag_vpn_killed ]; then
		#log "WARNING:Still in critical zone, killing gps & vpn process"
		nvtl_log -p 1 -m KEVENT -l notice -s "$SCRIPTNAME:WARNING:Still in critical zone, killing gps & vpn process"
		gps.sh stop
		vpn.sh stop
		touch /tmp/mem_diag_gps_killed
		touch /tmp/mem_diag_vpn_killed
	elif [ ! -f /tmp/mem_diag_webserver_killed ]; then
		#log "WARNING:Still in critical zone, killing webserver process"
		nvtl_log -p 1 -m KEVENT -l notice -s "$SCRIPTNAME:WARNING:Still in critical zone, killing webserver process"
		nvtl_webserver.sh stop 
		touch /tmp/mem_diag_webserver_killed 
	elif [ ! -f /tmp/mem_diag_adbd_killed ]; then
		#log "WARNING:Still in critical zone, killing adb process"
		nvtl_log -p 1 -m KEVENT -l notice -s "$SCRIPTNAME:WARNING:Still in critical zone, killing adb process"
		adb_pid=`pidof adbd`
		kill -9 $adb_pid
		touch /tmp/mem_diag_adbd_killed
		#sync	
		#log "WARNING:Still in critical zone, NO apps to kill, system may trigger OOM killer anytime"
		nvtl_log -p 1 -m KEVENT -l notice -s "$SCRIPTNAME:WARNING:Still in critical zone, NO apps to kill, system may trigger OOM killer anytime"
	if [ ! -f /tmp/mem_diag_app_restart_required ]; then
		log "/tmp/mem_diag_app_restart_required cookie created"
		touch /tmp/mem_diag_app_restart_required
# Safe zone specific task
safe_zone_task()
	# got some free mem, so restart app 
	if [ -f /tmp/mem_diag_app_restart_required ]; then
		mem=`free -m | awk 'NR==2{print $4}';`
		restart_killed_app adb
		if [ $mem -ge 18 ]; then
			restart_killed_app webserver
		if [ $mem -ge 21 -a $mem -le 24 ]; then
			restart_killed_app vpn
		elif [ $mem -ge 25 -a $mem -le 29 ]; then
			restart_killed_app vpn
			restart_killed_app gps
		elif [ $mem -ge 30 -a $mem -le 34 ]; then
			restart_killed_app vpn
			restart_killed_app gps
			restart_killed_app powersave			
		elif [ $mem -ge 35 ]; then
			restart_killed_app vpn
			restart_killed_app gps
			restart_killed_app powersave
			restart_killed_app led
			restart_killed_app diag_read
			# all killed process restarted, so remove cookie
			rm -f /tmp/mem_diag_app_restart_required
	# collect data for analysis
	#common_task	
# Moderate zone specific task
moderate_zone_task()
	mem=`free -m | awk 'NR==2{print $4}';`
	if [ $mem -ge 10 ]; then
		restart_killed_app adb
	# collect data for analysis
	#common_task
# Critical zone specific task
critical_zone_task()
	# stop low priority process to free memory
	kill_app
	# collect data for analysis
	#common_task	
mem_compaction()
	echo    5 > /proc/sys/vm/dirty_background_ratio
	echo   10 > /proc/sys/vm/dirty_ratio
	echo 1000 > /proc/sys/vm/dirty_expire_centisecs
	echo  200 > /proc/sys/vm/dirty_writeback_centisecs
	echo  200 > /proc/sys/vm/vfs_cache_pressure
    #To free pagecache, dentries and inodes
    #As this is a non-destructive operation, and dirty objects are not freeable,
    #the user should run "sync" first in order to make sure all cached objects are freed.
    #sync
    echo 3 > /proc/sys/vm/drop_caches
    #Perfroming the memory compaction, it may help in avoiding the OOM.
    echo 1 > /proc/sys/vm/compact_memory
    #nvtl_log -p 1 -m KEVENT -l notice -s "$SCRIPTNAME: drop_cache, compact_memory"	
get_product_model()
	Model=`sysintcli getHardwareInfo | awk '/info.model:/' | sed 's/^[^:]*://g' | tr -d []`
	echo "Model=$Model" > $log_dir/device_model
	log "Model=$Model"	
rotate_log_file()
	if [ ! -d $log_dir/backup ]; then		
		mkdir $log_dir/backup
		n=$MAX_NO_OF_BACKUPS		
		# Get file name without index in begining ie) 5-mem_diag_05102020_023321.tbz2 to mem_diag_05102020_023321.tbz2
		file_name_wo_index=`ls -l $log_dir/backup/${n}-* | awk '{print $9}'| sed 's/^[^-]*-//g'`
		# Delete log file with max no of backup index
		if [ -f $log_dir/backup/${n}-${file_name_wo_index} ]; then   			
			rm -f $log_dir/backup/${n}-${file_name_wo_index}
		# Rotate log files
		while [ $n -gt 1 ]
			i=$(( n-1 ))
			file_name_wo_index=`ls -l $log_dir/backup/${i}-* | awk '{print $9}'| sed 's/^[^-]*-//g'`
			if [ -f $log_dir/backup/${i}-${file_name_wo_index} ]; then            	        			
				mv $log_dir/backup/${i}-${file_name_wo_index} $log_dir/backup/${n}-${file_name_wo_index}
			fi			
	mv $log_dir/1-mem_diag*.tbz2 $log_dir/backup/
# Backup previous instance logs
backup_logs()
	if [ -d $log_dir ]; then
		log "$log_dir exist, take backup"
		session_id=`cat $log_dir/session_id`
		tar -cjf $log_dir/1-mem_diag_${session_id}.tbz2  --exclude='backup' $log_dir
		rotate_log_file
		rm -f $log_dir/*.txt $log_dir/*.log $log_dir/*.csv $log_dir/.*		
		mkdir -p $log_dir
check_log_limit()
	v1=$(du -k -d 0 $log_dir/ | awk '{print $1}')
	if [ -d $log_dir/backup ]; then
			v2=$(du -k -d 0 $log_dir/backup | awk '{print $1}')
	size=`expr $v1 - $v2`
	#log "$log_dir size(KB) (excluding backup)=$size"
	if [ $size -gt $MAX_LOG_FILE_SIZE_KB ]; then
			log "logs size exceeds limit,taking backup"
			backup_logs
# Makesure only one instance runs
ensure_one_instance()
	SCRIPTNAME=`basename $0`
	PIDFILE=/var/run/${SCRIPTNAME}.pid
	if [ -f ${PIDFILE} ]; then
# verify if the process is actually still running under this pid
		OLDPID=`cat ${PIDFILE}`
		RESULT=`ps | grep ${OLDPID} | grep ${SCRIPTNAME}`
		if [ -n "${RESULT}" ]; then
				#echo "Script already running! Exiting" | tee -a $LOGFILE
				echo "Script already running! Exiting"
				exit 255
# grab pid of this process and update the pid file with it
	PID=`ps | grep ${SCRIPTNAME} | head -n1 |  awk ' {print $1;} '`
	echo ${PID} > ${PIDFILE}
	echo ""
	echo "Usage:"
	echo "nvtl_mem_diag.sh <Mode> <Settings_Param> <Zone>"
	echo ""
	echo "Mode: daemon or CLI"
	echo ""
	echo "Settings_Param: "
	echo " max_log_file_size_kb, max_no_of_backups, safe_zone_least_mem, critical_zone_start_mem"
	echo " safe_zone_poll_interval_sec, moderate_zone_poll_interval_sec, critical_zone_poll_interval_sec"
	echo " safe_zone_store_mem_stats_interval_mins, moderate_zone_store_mem_stats_interval_mins"
	echo " critical_zone_store_mem_stats_interval_mins, enable_debug_mode, top_cpu_usage_threshold"
	echo ""
	echo "Zone: Safe or Moderate or Critical #Valid only for CLI mode"
	echo ""
	echo "eg:"
	echo "   nvtl_mem_diag.sh daemon 1024 10 15 5 60 30 15 3 2 1 0 5"
	echo "   nvtl_mem_diag.sh CLI    1024 10 15 5 60 30 15 3 2 1 0 5 Safe"
# program start executes here
# Variables
current_zone="NULL";
previous_zone="NULL";
poll_interval=30;
counter=0
exec_task=0
#default model Moretti
Model="M2100"
if [ "$#" = "13" -a "$1" = "daemon" ]; then
	echo "Entering daemon mode"
	MAX_LOG_FILE_SIZE_KB=$2
	MAX_NO_OF_BACKUPS=$3
	SAFE_ZONE_LEAST_MEM=$4
	CRITICAL_ZONE_START_MEM=$5
	SAFE_ZONE_POLL_INTERVAL_SEC=$6
	MODERATE_ZONE_POLL_INTERVAL_SEC=$7
	CRITICAL_ZONE_POLL_INTERVAL_SEC=$8
	SAFE_ZONE_STORE_MEM_STATS_INTERVAL_MINS=$9
	MODERATE_ZONE_STORE_MEM_STATS_INTERVAL_MINS=$10
	CRITICAL_ZONE_STORE_MEM_STATS_INTERVAL_MINS=$11
	ENABLE_DEBUG_MODE=$12
	TOP_CPU_USAGE_THRESHOLD=$13
elif [ "$#" = "14" -a "$1" = "CLI" ]; then
	if [ "$14" = "Safe" -o "$14" = "Moderate" -o "$14" = "Critical" ]; then
		echo "Entering CLI mode"
	if [ ! -e $log_dir ]; then
		echo "$log_dir Not exist! Creating"
		mkdir -p $log_dir
	case "$14" in
			echo "calling safe_zone_task()"
			safe_zone_task
		Moderate)
			echo "calling moderate_zone_task()"
			moderate_zone_task
		Critical) 
			echo "calling critical_zone_task()"
			critical_zone_task
			echo "case: default: Error: Wrong parameter"
	#mem_zone_switch_stats $14 0
	exit 0	
ensure_one_instance
#backup_logs
#echo "$Version" > $log_dir/version
# print current configuration
#log "nvtl_mem_diag.sh Started Successfully !"
nvtl_log -p 1 -m KEVENT -l notice -s "$SCRIPTNAME: Started Successfully !"
log "Version=$Version"
#echo "MAX_LOG_FILE_SIZE_KB=$MAX_LOG_FILE_SIZE_KB" > $log_dir/settings_params
#echo "MAX_NO_OF_BACKUPS=$MAX_NO_OF_BACKUPS" >> $log_dir/settings_params
#echo "SAFE_ZONE_LEAST_MEM=$SAFE_ZONE_LEAST_MEM" >> $log_dir/settings_params
#echo "CRITICAL_ZONE_START_MEM=$CRITICAL_ZONE_START_MEM" >> $log_dir/settings_params
#echo "SAFE_ZONE_POLL_INTERVAL_SEC=$SAFE_ZONE_POLL_INTERVAL_SEC" >> $log_dir/settings_params
#echo "MODERATE_ZONE_POLL_INTERVAL_SEC=$MODERATE_ZONE_POLL_INTERVAL_SEC" >> $log_dir/settings_params
#echo "CRITICAL_ZONE_POLL_INTERVAL_SEC=$CRITICAL_ZONE_POLL_INTERVAL_SEC" >> $log_dir/settings_params
#echo "SAFE_ZONE_STORE_MEM_STATS_INTERVAL_MINS=$SAFE_ZONE_STORE_MEM_STATS_INTERVAL_MINS" >> $log_dir/settings_params
#echo "MODERATE_ZONE_STORE_MEM_STATS_INTERVAL_MINS=$MODERATE_ZONE_STORE_MEM_STATS_INTERVAL_MINS" >> $log_dir/settings_params
#echo "CRITICAL_ZONE_STORE_MEM_STATS_INTERVAL_MINS=$CRITICAL_ZONE_STORE_MEM_STATS_INTERVAL_MINS" >> $log_dir/settings_params
#echo "ENABLE_DEBUG_MODE=$ENABLE_DEBUG_MODE" >> $log_dir/settings_params
#echo "TOP_CPU_USAGE_THRESHOLD=$TOP_CPU_USAGE_THRESHOLD" >> $log_dir/settings_params
if [ $ENABLE_DEBUG_MODE = 1 ]; then
# Store stats in polling interval
	safe_store_stats_interval_in_sec=$SAFE_ZONE_POLL_INTERVAL_SEC
	moderate_store_stats_interval_in_sec=$MODERATE_ZONE_POLL_INTERVAL_SEC
	critical_store_stats_interval_in_sec=$CRITICAL_ZONE_POLL_INTERVAL_SEC
# Polling interval defined in seconds but storing mem stats interval defined in Minutes
# convert minutes into seconds
	safe_store_stats_interval_in_sec=`expr $SAFE_ZONE_STORE_MEM_STATS_INTERVAL_MINS \* 60`
	moderate_store_stats_interval_in_sec=`expr $MODERATE_ZONE_STORE_MEM_STATS_INTERVAL_MINS \* 60`
	critical_store_stats_interval_in_sec=`expr $CRITICAL_ZONE_STORE_MEM_STATS_INTERVAL_MINS \* 60`
# Calculate no of polling iteration needed to execute respective zone task
safe_cnt=`expr $safe_store_stats_interval_in_sec / $SAFE_ZONE_POLL_INTERVAL_SEC`
moderate_cnt=`expr $moderate_store_stats_interval_in_sec / $MODERATE_ZONE_POLL_INTERVAL_SEC`
critical_cnt=`expr $critical_store_stats_interval_in_sec / $CRITICAL_ZONE_POLL_INTERVAL_SEC`
#echo "No of polling iteration need to execute safe zone task=$safe_cnt" >> $log_dir/settings_params
#echo "No of polling iteration need to execute moderate zone task=$moderate_cnt" >> $log_dir/settings_params
#echo "No of polling iteration need to execute critical zone task=$critical_cnt" >> $log_dir/settings_params
#cat /opt/nvtl/log/mem_diag/settings_params >> $log_file
# wait for all apps to launch before start logging data
sleep 30
# drop bootup caches otherwise free mem is very low 
mem_compaction
# get product model number
#get_product_model
# Save current timestamp as session id
#date +%m%d%Y_%H%M%S  > $log_dir/session_id
#session_id=`cat $log_dir/session_id`
log "session_id=$session_id"
# main infinite loop 
while true; do
# Get current free memory
	mem=`free -m | awk 'NR==2{print $4}';`
	#newline "" >>  $log_file
	log "free mem=$mem MB";
# Increase counter value everytime we get free memory 
	counter=$((counter+1))
# Find current memory zone 
	if [ "$mem" -ge $SAFE_ZONE_LEAST_MEM ]; then
		zone="Safe";
	elif [ "$mem" -lt $SAFE_ZONE_LEAST_MEM -a "$mem" -gt $CRITICAL_ZONE_START_MEM ]; then
		zone="Moderate";
	elif [ "$mem" -le $CRITICAL_ZONE_START_MEM ]; then
		zone="Critical";
		log "Error: mem value is not integer";
	current_zone="$zone"
	log "current_zone=$current_zone"
# Whenever current mem zone changed, set flag to immediately execute repective zone task
	if [ "$current_zone" != "$previous_zone" ]; then
		exec_task=1
		#mem_zone_switch_stats $current_zone $n
# When mem zone is not changed, check if polling iteration count reached expected interval 
# to execute respective zone task.If not keep polling
	elif [ "$current_zone" = "Safe" ]; then
		if [ $counter -ge $safe_cnt ]; then
			exec_task=1
	elif [ "$current_zone" = "Moderate" ]; then
		if [ $counter -ge $moderate_cnt ]; then
			exec_task=1
	elif [ "$current_zone" = "Critical" ]; then
		if [ $counter -ge $critical_cnt ]; then
			exec_task=1
			# stop low priority process to free memory ASAP, don't wait till critical_task called
			kill_app
# When flag is set, call respective zone task 
	if [ $exec_task = 1 ]; then
		case "$current_zone" in
			Safe)
				poll_interval=$SAFE_ZONE_POLL_INTERVAL_SEC;
				safe_zone_task
			Moderate)
				poll_interval=$MODERATE_ZONE_POLL_INTERVAL_SEC;
				moderate_zone_task
			Critical) 
				poll_interval=$CRITICAL_ZONE_POLL_INTERVAL_SEC;
				critical_zone_task
				log "case: default: Error: Wrong value for case input"
# Clear flags to indicate respective zone task is executed
		exec_task=0
		counter=0
		previous_zone="$current_zone";
# No of mem stats records stored
		n=$((n+1))
# Free some pages
	mem_compaction
	log "poll_interval=$poll_interval"
	sleep $poll_interval
