local_echo()
        echo ""
        echo ""
        echo "check_md5.sh: $1"
        echo ""
        echo ""
generate_tmp_file()
	rm -f /tmp/md5.list
    dir_list="bin etc home init lib linuxrc mnt opt root sbin system usr"
	for dir in $dir_list; do
		find $dir -type f -exec md5sum {} \; >> /tmp/md5.list
filter_and_sort()
	sort -d -f -k 2 /tmp/md5.list > /tmp/md5.list.sorted
	grep -v -e etc.avahi.avahi.daemon.conf \
		-e etc.avahi.services.smb.service \
		-e etc.dns_cache.txt \
		-e etc.group \
		-e etc.gshadow \
		-e etc.hosts \
		-e etc.adb_devid \
		-e etc.ipacm.pid \
                -e etc.lighttpd.mod_rewrite.conf \
                -e etc.lighttpd.mod_proxy.conf \
                -e etc.resolv.conf \
                -e etc.resolv.dnsmasq \
                -e etc.shadow \
                -e etc.passwd \
                -e etc.IPACM_cfg.xml \
		-e etc.AR6004_hostapd.conf \
		-e etc.mobileap_firewall.xml \
		-e etc.samba.smb.conf \
		-e etc.samba.smbpasswd \
                -e etc.resolv_ota.conf \
                -e etc.resolv_data_usage.conf \
                -e etc.data.ipa\/. \
        -e etc.misc.wifi.WCNSS_qcom_cfg.ini \
		-e lib.firmware.bcm.nvram.txt \
		-e lib.firmware.wlan.qca_cld.wlan_mac.bin \
		-e lib.modules.*.modules.dep.bb \
                -e opt.nvtl.data \
                -e opt.nvtl.tmp \
                -e opt.nvtl.etc.system.md5sum.ref \
		-e opt.nvtl.etc.webui.menu_layout.json.en_US \
                -e opt.nvtl.webui.public \
                -e opt.nvtl.log. \
                -e opt.nvtl.wifi_macid \
                -e root.*history \
                -e usr.private \
                -e usr.lib.ipkg \
                -e usr.share.locale \
                -e opt.nvtl.ethernet.aquantis.ethernet_update_log \
		/tmp/md5.list.sorted > /tmp/md5.list
generate_tmp_file
filter_and_sort
rm -f /tmp/md5.list.sorted
diff /opt/nvtl/etc/system/md5sum.ref /tmp/md5.list >/tmp/check_md5_diff_result
if [ $rc -ne 0 ]; then
	cat /tmp/check_md5_diff_result
	local_echo "FAILED"
	rm -f check_md5_diff_result
	local_echo "PASSED"
