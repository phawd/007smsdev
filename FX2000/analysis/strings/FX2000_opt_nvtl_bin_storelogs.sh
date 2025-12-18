#!/bin/sh
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
PAGESIZE=4
TMPDIR=/opt/nvtl/tmp
LOGDIR=/opt/nvtl/tmp/log
archive_files()
    tar -cvzf ${LOGDIR}/$1 $2
get_ethernet_info()
	echo "get_ethernet_info"
	readstat=/opt/nvtl/ethernet/aquantis/Ethernet_readstat
	/opt/nvtl/ethernet/aquantis/tools/readstat > $readstat
	tar -cvzf ${LOGDIR}/ethernet_info.tgz /opt/nvtl/ethernet/aquantis/ --exclude "firmware" --exclude "tools" --exclude "Ethernet_update.sh"
get_settings_info()
	echo "get_settings_info"
	echo "============== Settings info ==================" > ${LOGDIR}/settings_info.txt
	settings_cli get_features >> ${LOGDIR}/settings_info.txt
	settings_cli get_branding_info >> ${LOGDIR}/settings_info.txt
get_var_log_files()
    echo "get_var_log_files"
    archive_files "varlogs.tgz" "/var/log"
get_modem_logs_files()
    if [ -d "/sdcard/diag_logs/logs" ] ; then
        echo "get_modem_files"
        archive_files "modem_log.tgz" "/sdcard/diag_logs/logs"
get_tmp_files()
    echo "get_tmp_files"
    # Get MD5sum files difference
    /opt/nvtl/bin/check_md5.sh > /tmp/linux_md5_check.txt
    archive_files "tmp.tgz" "/tmp"
get_sysconf_files()
    echo "get_sysconf_files"
    archive_files "sysconf.tgz" "/sysconf"
get_omadm_files()
    echo "get_omadm_files"
    archive_files "omadm.tgz" "/opt/nvtl/data/omadm"
get_tr069_files()
    if [ -d "/opt/nvtl/data/tr069" ] ; then
        echo "get_tr069_files"
        archive_files "tr069.tgz" "/opt/nvtl/data/tr069"
get_health_files()
    echo "get_mifi_health_files"
    archive_files "health.tgz" "/opt/nvtl/data/health"
get_nua_files()
    echo "get_nua_files"
    nua_data_dir="/opt/nvtl/data/nua"
    nua_log_pref="nua_log"
    nua_log_dir="/tmp/$nua_log_pref"
    rm -rf $nua_log_dir
    mkdir -p $nua_log_dir
    ls -la $nua_data_dir >$nua_log_dir/nua_dir_list
    if [ -f "$nua_data_dir/reg.xml" ]; then 
    	zip -P 123nua123 $nua_log_dir/reg.zip $nua_data_dir/reg.xml
    cp -f $nua_data_dir/dl_desc.secure $nua_log_dir
    tar cvzf ${LOGDIR}/nua.tgz -C $nua_log_dir . 
    rm -rf $nua_log_dir 
get_fota_files()
	echo "get_fota_files"
	/opt/nvtl/bin/fota_cli full_history > /opt/nvtl/data/fota/full_history.txt
	upgrade_file="/opt/nvtl/data/fota/upgrade.zip"
	if [ -f $upgrade_file ];then
		upgrade_file_info="/opt/nvtl/data/fota/upgrade_info"
		echo "Excluding the upgrade.zip file because it is large, even it does not require to include in log files"
		md5sum=$(md5sum $upgrade_file)
		echo "Md5sum = $md5sum" >$upgrade_file_info
		size=$(ls -l | grep -i "upgrade.zip" | awk '{print $5}')
		echo "Size = $size" >>$upgrade_file_info
		tar -cvzf ${LOGDIR}/fota.tgz --exclude='upgrade.zip' /opt/nvtl/data/fota
		archive_files "fota.tgz" "/opt/nvtl/data/fota"
	rm -rf /opt/nvtl/data/fota/full_history.txt
get_branding_info()
    echo "get_branding_info"
    cp /opt/nvtl/data/branding/startup/animation_3.png .
    cp /opt/nvtl/data/branding/startup/animation_14.png .
    cp /opt/nvtl/data/branding/startup/animation_23.png .
    tar -cvzf ${LOGDIR}/branding.tgz --exclude='startup' /opt/nvtl/data/branding animation_3.png animation_14.png animation_23.png
    rm -f branding_version animation_*
get_system_log_files()
    echo "get_system_log_files"
    archive_files "systemlog.tgz" "/opt/nvtl/log/*"
get_wdcp_files()
 if [ -d "/opt/nvtl/etc/wdcp" ] ; then
    echo "get_wdcp_files"
    archive_files "wdcp.tgz" "/opt/nvtl/etc/wdcp"
 if [ -d "/opt/nvtl/data/wdcp" ] ; then
    echo "get_wdcp_data_files"
    archive_files "wdcp_data.tgz" "/opt/nvtl/data/wdcp"
get_router2_files()
 if [ -d "/opt/nvtl/tmp/router2" ] ; then
    echo "get_router2_files"
    archive_files "router2.tgz" "/opt/nvtl/tmp/router2"
get_rsa_files()
 if [ -d "/opt/nvtl/data/rsa" ] ; then
    echo "get_rsa_files"
    archive_files "rsa.tgz" "/opt/nvtl/data/rsa"
get_routing_info()
    echo "get_routing_info"
    echo "iptables Filter: " > ${LOGDIR}/routing.txt
    sync && iptables -L -v -n >> ${LOGDIR}/routing.txt
    echo "iptables NAT: " >> ${LOGDIR}/routing.txt
    iptables -t nat -L -v -n >> ${LOGDIR}/routing.txt
    echo "/etc/resolv.conf: " >> ${LOGDIR}/routing.txt
    cat /etc/resolv.conf >> ${LOGDIR}/routing.txt
    echo "/etc/resolv.dnsmasq: " >> ${LOGDIR}/routing.txt
    cat /etc/resolv.dnsmasq >> ${LOGDIR}/routing.txt
    cat "/etc/resolv_data_usage.conf: " >> ${LOGDIR}/routing.txt
    cat /etc/resolv_data_usage.conf >> ${LOGDIR}/routing.txt
    cat "/etc/resolv_ota.conf: " >> ${LOGDIR}/routing.txt
    cat /etc/resolv_ota.conf >> ${LOGDIR}/routing.txt
    echo "/tmp/udhcpc.log: " >> ${LOGDIR}/routing.txt
    cat /tmp/udhcpc.log >> ${LOGDIR}/routing.txt
    echo "Bridge info: " >> ${LOGDIR}/routing.txt
    brctl show >> ${LOGDIR}/routing.txt    
    echo "ifconfig: " >> ${LOGDIR}/routing.txt
    ifconfig >> ${LOGDIR}/routing.txt
    echo "Route: " >> ${LOGDIR}/routing.txt
    route -n >> ${LOGDIR}/routing.txt
    echo "IPv6 Route: " >> ${LOGDIR}/routing.txt
    ip -6 route show  >> ${LOGDIR}/routing.txt
    echo "/tmp/router_log.txt: " >> ${LOGDIR}/routing.txt
    cat /tmp/routing_log.txt >> ${LOGDIR}/routing.txt
    if [ -f /tmp/dhcp.info ] ; then
        echo "IPPT info: " >> ${LOGDIR}/routing.txt
        echo "/tmp/dhcp.info: " >> ${LOGDIR}/routing.txt
        cat /tmp/dhcp.info >> ${LOGDIR}/routing.txt
    if [ -f /tmp/dhcp_previous.info ] ; then
        echo "PREVIOUS IPPT info: " >> ${LOGDIR}/routing.txt
        echo "/tmp/dhcp_previous.info: " >> ${LOGDIR}/routing.txt
        cat /tmp/dhcp_previous.info >> ${LOGDIR}/routing.txt
    # this dumps info into the /var/logs
    router2_cli log
get_system_info()
    echo "get_system_info"
    mkdir -p ${LOGDIR}/proc
    cp /opt/nvtl/etc/mifios-version $LOGDIR
    dmesg > ${LOGDIR}/dmesg.txt
    uptime > ${LOGDIR}/uptime.txt 
    runlevel > ${LOGDIR}/runlevel.txt    
    ps -e -o pid,ppid,user,vsz,rss,comm > ${LOGDIR}/ps.txt
    cat /proc/meminfo > ${LOGDIR}/proc/meminfo.txt
    free -m > ${LOGDIR}/free.txt
    du -h -c -d 1 / > ${LOGDIR}/du.txt
    df -h -a > ${LOGDIR}/df.txt
	lsmod > ${LOGDIR}/lsmod.txt
get_wifi_info()
	echo "get_wifi_info"
	echo "============== Wifi Profiles info ==================" > ${LOGDIR}/wifi_info.txt
	echo "============== Wifi Profile1 info =================" >> ${LOGDIR}/wifi_info.txt
	sync && wifi_cli get_ap_profile 1 >> ${LOGDIR}/wifi_info.txt
	echo "============== Wifi Profile2 info =================" >> ${LOGDIR}/wifi_info.txt
	wifi_cli get_ap_profile 2 >> ${LOGDIR}/wifi_info.txt
	echo "============== Wifi Profile3 info =================" >> ${LOGDIR}/wifi_info.txt
	wifi_cli get_ap_profile 3 >> ${LOGDIR}/wifi_info.txt
	echo "============== Wifi Profile4 info =================" >> ${LOGDIR}/wifi_info.txt
	wifi_cli get_ap_profile 4 >> ${LOGDIR}/wifi_info.txt
	echo "============== MAC Filtering Status =================" >> ${LOGDIR}/wifi_info.txt
	dmdb_cli get_mac_filter_enabled >> ${LOGDIR}/wifi_info.txt
	echo "============== Type of MAC Filtering=================" >> ${LOGDIR}/wifi_info.txt
	dmdb_cli get_mac_filter_type >> ${LOGDIR}/wifi_info.txt
get_gpio_info()
    echo "get_gpio_info"
    cat /sys/kernel/debug/gpio > ${LOGDIR}/gpio.txt
    echo "" >> ${LOGDIR}/gpio.txt
    for t in /sys/class/gpio/* ; do
        if [ -f $t/value ] ; then
            VAL=`cat $t/value`
            echo "$t = $VAL" >> ${LOGDIR}/gpio.txt
        fi
    done
get_connection_info()
    echo "get_connection_info"
    echo "======== Modem WWAN V4 Connection ===================" > ${LOGDIR}/connection_info.txt
    modem2_cli call_get_status 1 0 >> ${LOGDIR}/connection_info.txt
    echo "======== Modem WWAN V6 Connection ===================" >> ${LOGDIR}/connection_info.txt
    modem2_cli call_get_status 1 2 >> ${LOGDIR}/connection_info.txt
    echo "======== Modem State ===================" >> ${LOGDIR}/connection_info.txt
    modem2_cli get_state >> ${LOGDIR}/connection_info.txt
    echo "======== Modem Info ===================" >> ${LOGDIR}/connection_info.txt
    modem2_cli get_info >> ${LOGDIR}/connection_info.txt
    echo "======== Modem SIM Info ===================" >> ${LOGDIR}/connection_info.txt
    modem2_cli sim_get_status >> ${LOGDIR}/connection_info.txt
    modem2_cli sim_pin_get_status >> ${LOGDIR}/connection_info.txt
    echo "======== Modem Roaming Info ===================" >> ${LOGDIR}/connection_info.txt
    modem2_cli roam_get_enabled >> ${LOGDIR}/connection_info.txt
    modem2_cli get_service_info >> ${LOGDIR}/connection_info.txt
    modem2_cli validate_home >> ${LOGDIR}/connection_info.txt
    echo "======== Modem Signal ===================" >> ${LOGDIR}/connection_info.txt
    modem2_cli get_signal >> ${LOGDIR}/connection_info.txt
    echo "======== Modem Tech ===================" >> ${LOGDIR}/connection_info.txt
    modem2_cli active_tech_get >> ${LOGDIR}/connection_info.txt
    modem2_cli enabled_tech_get >> ${LOGDIR}/connection_info.txt
    modem2_cli prof_get_pri_tech 0 >> ${LOGDIR}/connection_info.txt
    modem2_cli prof_get_pri_tech 1 >> ${LOGDIR}/connection_info.txt
    modem2_cli prof_get_pri_tech 2 >> ${LOGDIR}/connection_info.txt
    modem2_cli prof_get_cust_tech 0 >> ${LOGDIR}/connection_info.txt
    modem2_cli prof_get_cust_tech 1 >> ${LOGDIR}/connection_info.txt
    modem2_cli prof_get_cust_tech 2 >> ${LOGDIR}/connection_info.txt
    echo "======== CCM Current Wan ===================" >> ${LOGDIR}/connection_info.txt
    ccm2_cli get_curr_wan >> ${LOGDIR}/connection_info.txt
    echo "======== CCM Current Wan Stats ===================" >> ${LOGDIR}/connection_info.txt
    ccm2_cli get_curr_wan_stats 1 >> ${LOGDIR}/connection_info.txt
    echo "======== CCM Connection State ===================" >> ${LOGDIR}/connection_info.txt
    ccm2_cli get_conn_state >> ${LOGDIR}/connection_info.txt
    echo "======== CCM Autoconnect State ===================" >> ${LOGDIR}/connection_info.txt
    ccm2_cli get_wwan_ac_state >> ${LOGDIR}/connection_info.txt
    echo "======== CCM cust apn State ===================" >> ${LOGDIR}/connection_info.txt
    ccm2_cli apps_call_state >> ${LOGDIR}/connection_info.txt
    ccm2_cli dm_call_state >> ${LOGDIR}/connection_info.txt
get_sms_files()
    echo "get_sms_files"
    archive_files "sms.tgz" "/opt/nvtl/data/sms"
get_dmdb_files()
    echo "get_dmdb_files"
    archive_files "dmdb.tgz" "/opt/nvtl/data/dmdb"
get_modem2_files()
    echo "get_modem2_files"
    archive_files "modem2.tgz" "/opt/nvtl/data/modem2"
###############################################################################
# Advanced log information
###############################################################################
get_battery_info()
    echo "get_battery_info"
    for t in /sys/class/power_supply/bq27500-0/* /sys/devices/virtual/batt_sim/batt_sim/control/* /sys/devices/platform/msm_ssbi.0/pm8018-core/pm8xxx-adc/*
        if [ -f $t ] && [ -r $t ]
        then
            echo "$t" >> ${LOGDIR}/batt.txt
            cat $t >> ${LOGDIR}/batt.txt
        fi
    done
get_regulator_info()
    echo "get_regulator_info"
    for t in /sys/class/regulator/*; do
        echo -n "reg=" >> ${LOGDIR}/regulator.txt
        cat $t/name >> ${LOGDIR}/regulator.txt
        if [ -f $t/min_microvolts ] ; then
            echo -n "min_uV=" >> ${LOGDIR}/regulator.txt
			cat $t/min_microvolts  >> ${LOGDIR}/regulator.txt
        fi
        if [ -f $t/microvolts ] ; then
            echo -n "uV=" >> ${LOGDIR}/regulator.txt
            cat $t/microvolts >> ${LOGDIR}/regulator.txt
        fi
        if [ -f $t/max_microvolts ] ; then
            echo -n "max_uV=" >> ${LOGDIR}/regulator.txt
            cat $t/max_microvolts >> ${LOGDIR}/regulator.txt
        fi
        for j in /sys/kernel/debug/regulator/`cat $t/name`/*; do
            tmp=`echo ${j##*/} | cut -d . -f 1`
            echo -e -n $tmp"\t:" >> ${LOGDIR}/regulator.txt
            cat $j >> ${LOGDIR}/regulator.txt
        done
    done
get_charger_registers()
    echo "get_charger_registers"
    dump_chg_drv >> ${LOGDIR}/charger.txt
get_advanded_power_info()
    echo "get_advanced_power_info"
    cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq >> ${LOGDIR}/scaling_cur_freq.txt
    get_battery_info
    get_regulator_info
    get_charger_registers
get_procfs_info()
    echo "get_procfs_info"
    mkdir -p ${LOGDIR}/proc
    cat /proc/cpuinfo >> $logdir/cpuinfo.txt
    cat /proc/partitions >> ${LOGDIR}/proc/partitions.txt
    cat /proc/iomem >> ${LOGDIR}/proc/iomem.txt
    cat /proc/interrupts >> ${LOGDIR}/proc/interrupts.txt
get_process_info()
    echo "get_process_info"
    list_threads.sh >> ${LOGDIR}/list_threads.txt
    top -n 2 >> ${LOGDIR}/top.txt
    echo m > /proc/sysrq-trigger
    grep Normal /var/log/messages | tail -1 >> ${LOGDIR}/process_memory.txt
    memused=0
    for file in /proc/*; do
        if [ -f "$file/statm" ] && [ -f $file/cmdline ]
        then
            process_cmdline=`cat "$file/cmdline"`
            if [ "$process_cmdline" != "" ]
            then
                process=`cat "$file/stat" | cut -d" " -f2`
                process_name=`echo $process | sed s/\(// | sed s/\)//`
                resident=`cat "$file/statm" | cut -d" " -f2`
                let  "resident = resident * $PAGESIZE"
                memused=$(($memused+$resident))
                echo -e -n "$resident\t" >> ${LOGDIR}/process_memory.txt
                echo "$process_name" >> ${LOGDIR}/process_memory.txt
            fi
        fi
    done
    echo -e "$memused\t:TOTAL RAM USAGE">>${LOGDIR}/process_memory.txt
    #sock stat info?
    for t in /proc/*; do
        if [ -f $t/cmdline ] ; then
            process_cmdline=`cat "$t/cmdline"`
            if [ "$process_cmdline" != "" ]
            then
                echo -e -n "proc\t:" >> ${LOGDIR}/sockstat.txt
                echo $process_cmdline >> ${LOGDIR}/sockstat.txt
                if [ -f $t/net/sockstat ] ; then
                    cat $t/net/sockstat >> ${LOGDIR}/sockstat.txt
                fi
           fi
        fi
        echo >> ${LOGDIR}/sockstat.txt
    done
get_msg_queue_info()
    echo "get_msg_queue_info"
    #queue info
    mkdir -p /dev/mqueue
	mount -t mqueue none /dev/mqueue
	for t in /dev/mqueue/*; do
		echo $t >>  ${LOGDIR}/queue.txt
		cat $t >> ${LOGDIR}/queue.txt
	mifi_psm_mb_evt -s >> ${LOGDIR}/queue.txt
	umount /dev/mqueue
get_msgbus_info()
    echo "get_msgbus_info"
	msgbusclilogfile=${LOGDIR}/msgbus.txt
	MSGBUSCLI="msgbus_cli MsgBusGet"
	echo "dsm.broadcast" >> $msgbusclilogfile
	$MSGBUSCLI dsm.broadcast >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.device_state" >> $msgbusclilogfile
	$MSGBUSCLI modem2.device_state >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.service" >> $msgbusclilogfile
	$MSGBUSCLI modem2.service >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.registration_status" >> $msgbusclilogfile
	$MSGBUSCLI modem2.registration_status >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.sig_str" >> $msgbusclilogfile
	$MSGBUSCLI modem2.sig_str >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.uim_state" >> $msgbusclilogfile
	$MSGBUSCLI modem2.uim_state >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.pin1_state" >> $msgbusclilogfile
	$MSGBUSCLI modem2.pin1_state >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.pin2_state" >> $msgbusclilogfile
	$MSGBUSCLI modem2.pin2_state >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.conn_stats" >> $msgbusclilogfile
	$MSGBUSCLI modem2.conn_stats >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.conn_dormancy" >> $msgbusclilogfile
	$MSGBUSCLI modem2.conn_dormancy >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.eri_info" >> $msgbusclilogfile
	$MSGBUSCLI modem2.eri_info >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.roam_state" >> $msgbusclilogfile
	$MSGBUSCLI modem2.roam_state >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.time_change" >> $msgbusclilogfile
	$MSGBUSCLI modem2.time_change >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.fota" >> $msgbusclilogfile
	$MSGBUSCLI modem2.fota >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.reject_cause" >> $msgbusclilogfile
	$MSGBUSCLI modem2.reject_cause >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.modem2.plmn_mode" >> $msgbusclilogfile
	$MSGBUSCLI modem2.modem2.plmn_mode >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.operator_change" >> $msgbusclilogfile
	$MSGBUSCLI modem2.operator_change >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.scan_result" >> $msgbusclilogfile
	$MSGBUSCLI modem2.scan_result >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.mns_status" >> $msgbusclilogfile
	$MSGBUSCLI modem2.mns_status >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.data_signal_change" >> $msgbusclilogfile
	$MSGBUSCLI modem2.data_signal_change >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.voice_signal_change" >> $msgbusclilogfile
	$MSGBUSCLI modem2.voice_signal_change >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.emergency_mode" >> $msgbusclilogfile
	$MSGBUSCLI modem2.emergency_mode >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.wifi_band_conflict" >> $msgbusclilogfile
	$MSGBUSCLI modem2.wifi_band_conflict >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.non_pri_sim" >> $msgbusclilogfile
	$MSGBUSCLI modem2.non_pri_sim >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.conn_state" >> $msgbusclilogfile
	$MSGBUSCLI modem2.conn_state >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.call_fail" >> $msgbusclilogfile
	$MSGBUSCLI modem2.call_fail >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.operating.mode" >> $msgbusclilogfile
	$MSGBUSCLI modem2.operating.mode >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.wap.push" >> $msgbusclilogfile
	$MSGBUSCLI modem2.wap.push >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.factory.reset" >> $msgbusclilogfile
	$MSGBUSCLI modem2.factory.reset >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.sim.activation" >> $msgbusclilogfile
	$MSGBUSCLI modem2.sim.activation >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.sim.pco_event" >> $msgbusclilogfile
	$MSGBUSCLI modem2.sim.pco_event >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.radio_mode" >> $msgbusclilogfile
	$MSGBUSCLI modem2.radio_mode >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.radio_global" >> $msgbusclilogfile
	$MSGBUSCLI modem2.radio_global >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.uicc.launch.browser" >> $msgbusclilogfile
	$MSGBUSCLI modem2.uicc.launch.browser >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.uicc.display_text" >> $msgbusclilogfile
	$MSGBUSCLI modem2.uicc.display_text >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.update_roam_cntl_required" >> $msgbusclilogfile
	$MSGBUSCLI modem2.update_roam_cntl_required >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "modem2.pip_tone" >> $msgbusclilogfile
	$MSGBUSCLI modem2.pip_tone >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "ccm2.wan_connection" >> $msgbusclilogfile
	$MSGBUSCLI ccm2.wan_connection >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "ccm2.wan_stats" >> $msgbusclilogfile
	$MSGBUSCLI ccm2.wan_stats >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "ccm2.apps_status" >> $msgbusclilogfile
	$MSGBUSCLI ccm2.apps_status >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "ccm2.device_management_status" >> $msgbusclilogfile
	$MSGBUSCLI ccm2.device_management_status >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "ccm2.usb_status" >> $msgbusclilogfile
	$MSGBUSCLI ccm2.usb_status >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "wifi.sta_connected" >> $msgbusclilogfile
	$MSGBUSCLI wifi.sta_connected >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "wifi.sta_disconnected" >> $msgbusclilogfile
	$MSGBUSCLI wifi.sta_disconnected >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "wifi.wps_sta_connected" >> $msgbusclilogfile
	$MSGBUSCLI wifi.wps_sta_connected >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "wifi.wps_sta.disconnected" >> $msgbusclilogfile
	$MSGBUSCLI wifi.wps_sta.disconnected >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "wifi.wlan0.sta_list_updated" >> $msgbusclilogfile
	$MSGBUSCLI wifi.wlan0.sta_list_updated >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "wifi.wlan1.sta_list_updated" >> $msgbusclilogfile
	$MSGBUSCLI wifi.wlan1.sta_list_updated >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "wifi.wlan0.if_up" >> $msgbusclilogfile
	$MSGBUSCLI wifi.wlan0.if_up >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "wifi.wlan0.if_down" >> $msgbusclilogfile
	$MSGBUSCLI wifi.wlan0.if_down >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "bckrst.backup_complete" >> $msgbusclilogfile
	$MSGBUSCLI bckrst.backup_complete >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "bckrst.restore_complete" >> $msgbusclilogfile
	$MSGBUSCLI bckrst.restore_complete >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "nvtl.ans.notifications" >> $msgbusclilogfile
	$MSGBUSCLI nvtl.ans.notifications >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "nvtl.dua.usage.info" >> $msgbusclilogfile
	$MSGBUSCLI nvtl.dua.usage.info >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "nvtl.dua.usage.level" >> $msgbusclilogfile
	$MSGBUSCLI nvtl.dua.usage.level >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "led.ready" >> $msgbusclilogfile
	$MSGBUSCLI led.ready >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "devui.ready" >> $msgbusclilogfile
	$MSGBUSCLI devui.ready >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "webui.ready" >> $msgbusclilogfile
	$MSGBUSCLI webui.ready >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "webui.softwareupdate.status" >> $msgbusclilogfile
	$MSGBUSCLI webui.softwareupdate.status >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "nvtl.wdcp.acl" >> $msgbusclilogfile
	$MSGBUSCLI nvtl.wdcp.acl >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "dmdb.connected.device.list" >> $msgbusclilogfile
	$MSGBUSCLI dmdb.connected.device.list >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "dmdb.blacklist.device" >> $msgbusclilogfile
	$MSGBUSCLI dmdb.blacklist.device >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "dmdb.dus.traffic_status" >> $msgbusclilogfile
	$MSGBUSCLI dmdb.dus.traffic_status >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "dmdb.dus.report.statistics" >> $msgbusclilogfile
	$MSGBUSCLI dmdb.dus.report.statistics >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "sms.list.unread" >> $msgbusclilogfile
	$MSGBUSCLI sms.list.unread >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "sms.list.changed" >> $msgbusclilogfile
	$MSGBUSCLI sms.list.changed >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "sms.msg.wdcp" >> $msgbusclilogfile
	$MSGBUSCLI sms.msg.wdcp >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "sms.voicemail.indication" >> $msgbusclilogfile
	$MSGBUSCLI sms.voicemail.indication >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "gps.engine.fix" >> $msgbusclilogfile
	$MSGBUSCLI gps.engine.fix >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "gps.engine.status" >> $msgbusclilogfile
	$MSGBUSCLI gps.engine.status >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "file_sharing.broadcast" >> $msgbusclilogfile
	$MSGBUSCLI file_sharing.broadcast >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "omadm.broadcast" >> $msgbusclilogfile
	$MSGBUSCLI omadm.broadcast >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "nvtl.voice.refresh" >> $msgbusclilogfile
	$MSGBUSCLI nvtl.voice.refresh >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "nvtl.voice.vcm_call_state" >> $msgbusclilogfile
	$MSGBUSCLI nvtl.voice.vcm_call_state >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "nvtl.voice.vcm_serv_state" >> $msgbusclilogfile
	$MSGBUSCLI nvtl.voice.vcm_serv_state >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "nvtl.voice.dtm_state" >> $msgbusclilogfile
	$MSGBUSCLI nvtl.voice.dtm_state >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "nvtl.voice.dnp_state" >> $msgbusclilogfile
	$MSGBUSCLI nvtl.voice.dnp_state >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "nvtl.voice.cmd_rx" >> $msgbusclilogfile
	$MSGBUSCLI nvtl.voice.cmd_rx >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "nvtl.voice.settings" >> $msgbusclilogfile
	$MSGBUSCLI nvtl.voice.settings >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "nvtl.voice.dtmf" >> $msgbusclilogfile
	$MSGBUSCLI nvtl.voice.dtmf >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "nvtl.voice.hook_status" >> $msgbusclilogfile
	$MSGBUSCLI nvtl.voice.hook_status >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "nvtl.ui.i18n" >> $msgbusclilogfile
	$MSGBUSCLI nvtl.ui.i18n >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "nvtl.ui.wifi.profile" >> $msgbusclilogfile
	$MSGBUSCLI nvtl.ui.wifi.profile >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "nvtl.ui.wifi.settings" >> $msgbusclilogfile
	$MSGBUSCLI nvtl.ui.wifi.settings >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "nvtl.ui.display_wifi_key_on_screen" >> $msgbusclilogfile
	$MSGBUSCLI nvtl.ui.display_wifi_key_on_screen >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "nvtl.ui.display_admin_key_on_screen" >> $msgbusclilogfile
	$MSGBUSCLI nvtl.ui.display_admin_key_on_screen >> $msgbusclilogfile
	echo "" >> $msgbusclilogfile
	echo "nvtl.ui.admin_key" >> $msgbusclilogfile
	$MSGBUSCLI nvtl.ui.admin_key >> $msgbusclilogfile
collect_advanced_data()
    echo "get_advanced_data"
    get_advanded_power_info    
    get_procfs_info
    get_process_info
    get_msg_queue_info
###############################################################################
# End Advanced log information
###############################################################################
create_pkg()
    echo "create_pkg param = $1"
    datestring=`date +%Y%m%d_%H%M%S`
    file="${datestring}_log.tgz"
    echo "tar -cvzf ${TMPDIR}/$file $LOGDIR"
    tar -cvzf ${TMPDIR}/$file $LOGDIR
    rm -rf ${LOGDIR}
    if [ "$1" != "" ] ; then
        echo "mv ${TMPDIR}/$file $1"
        mv ${TMPDIR}/$file $1
    sync
collect_data()
    echo "collect_data"
    rm -rf $LOGDIR
    mkdir -p $LOGDIR
	get_ethernet_info
    get_settings_info
    get_tmp_files
    get_sysconf_files
    get_sms_files
    get_dmdb_files
    get_modem2_files
    get_nua_files
    get_omadm_files
    get_tr069_files
    get_health_files
    get_fota_files
    get_branding_info
    get_system_log_files
    get_routing_info
    get_system_info
    get_gpio_info
    get_connection_info
    get_battery_info
    get_wdcp_files
    get_msgbus_info
    get_router2_files
    get_rsa_files
    get_wifi_info
    # get var logs last as error/logs from above process may be added to /var/logs
    get_var_log_files
    get_modem_logs_files
clear_existing_pkg()
    if [ "$1" != "" ] ; then
        rm $1
case $1 in
    adv)
        clear_existing_pkg $2
        collect_data
        collect_advanced_data
        create_pkg $2
    del)
        clear_existing_pkg $2
        clear_existing_pkg $1
        collect_data
        create_pkg $1
        ;;
echo "done"
