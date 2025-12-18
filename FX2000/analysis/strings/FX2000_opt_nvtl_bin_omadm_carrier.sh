#!/bin/sh
export LD_LIBRARY_PATH=/opt/nvtl/lib:$LD_LIBRARY_PATH
agent="$1"
input="/opt/nvtl/data/branding/carrier"
check_carrier_and_copy()
	if [ -n "$agent" ]; then
		val="$agent"
		/opt/nvtl/bin/nvtl_log -p 1 -m OMADM -l notice -s "Agent is= '$val'"
		if [ -e "$input" ]; then
			val=$(sed -nr '1s/^([^ ]+).*/\1/p' "$input")
			/opt/nvtl/bin/nvtl_log -p 1 -m OMADM -l notice -s "Carrier is= '$val'"
			/opt/nvtl/bin/nvtl_log -p 1 -m OMADM -l err -s "Carrier not found, exiting..."
			exit 2
	if [ ! -d "/opt/nvtl/data/branding/bin" ]; then
		mkdir -p /opt/nvtl/data/branding/bin
	if [ ! -d "/opt/nvtl/data/branding/etc/omadm" ]; then
		mkdir -p /opt/nvtl/data/branding/etc/omadm
	/opt/nvtl/bin/nvtl_log -p 1 -m OMADM -l notice -s "Copying all files related to $val..."
	case $val in
		[bB][eE][lL][lL])
			if [ ! -e "/opt/nvtl/data/branding/bin/omadmd" ]; then
				ln -s /opt/nvtl/bin/omadmd_bell /opt/nvtl/data/branding/bin/omadmd
			if [ ! -e "/opt/nvtl/data/branding/bin/omadm_wap_proxyd" ]; then
				ln -s /opt/nvtl/bin/omadm_wap_proxyd_bell /opt/nvtl/data/branding/bin/omadm_wap_proxyd
			if [ ! -e "/opt/nvtl/data/branding/bin/omadm_cli" ]; then
				ln -s /opt/nvtl/bin/omadm_cli_bell /opt/nvtl/data/branding/bin/omadm_cli
			if [ ! -e "/opt/nvtl/data/branding/etc/omadm/tree.xml" ]; then		
				ln -s /opt/nvtl/etc/omadm/tree_bell.xml /opt/nvtl/data/branding/etc/omadm/tree.xml
			if [ ! -e "/opt/nvtl/data/branding/etc/omadm/config.xml" ]; then
				cp /opt/nvtl/etc/omadm/config_bell.xml /opt/nvtl/data/branding/etc/omadm/config.xml
			if [ ! -e "/opt/nvtl/data/branding/lib/libomadm_api.so" ]; then
				ln -s /opt/nvtl/lib/libomadm_bell_api.so /opt/nvtl/data/branding/lib/libomadm_api.so
			if [ ! -e "/opt/nvtl/data/branding/lib/settings/libomadm_api.so" ]; then
				ln -s /opt/nvtl/lib/libomadm_bell_api.so /opt/nvtl/data/branding/lib/settings/libomadm_api.so
			if [ ! -e "/opt/nvtl/data/branding/lib/factory_reset/libomadm_api.so" ]; then			
				ln -s /opt/nvtl/lib/libomadm_bell_api.so /opt/nvtl/data/branding/lib/factory_reset/libomadm_api.so
		[aA][tT][tT] | [aA][tT]"&"[tT] | [aA][tT][nN][tT])
			if [ ! -e "/opt/nvtl/data/branding/bin/omadmd" ]; then
				ln -s /opt/nvtl/bin/omadmd_att /opt/nvtl/data/branding/bin/omadmd
			if [ ! -e "/opt/nvtl/data/branding/bin/omadm_wap_proxyd" ]; then
				ln -s /opt/nvtl/bin/omadm_wap_proxyd_att /opt/nvtl/data/branding/bin/omadm_wap_proxyd
			if [ ! -e "/opt/nvtl/data/branding/bin/omadm_cli" ]; then
				ln -s /opt/nvtl/bin/omadm_cli_att /opt/nvtl/data/branding/bin/omadm_cli
			if [ ! -e "/opt/nvtl/data/branding/etc/omadm/tree.xml" ]; then
				ln -s /opt/nvtl/etc/omadm/tree_prod_att.xml /opt/nvtl/data/branding/etc/omadm/tree.xml
			if [ ! -e "/opt/nvtl/data/branding/etc/omadm/tree_iot.xml" ]; then
				ln -s /opt/nvtl/etc/omadm/tree_iot_att.xml /opt/nvtl/data/branding/etc/omadm/tree_iot.xml
			if [ ! -e "/opt/nvtl/data/branding/etc/omadm/tree_lab.xml" ]; then
				ln -s /opt/nvtl/etc/omadm/tree_lab_att.xml /opt/nvtl/data/branding/etc/omadm/tree_lab.xml
			if [ ! -e "/opt/nvtl/data/branding/etc/omadm/config.xml" ]; then
				cp /opt/nvtl/etc/omadm/config_att.xml /opt/nvtl/data/branding/etc/omadm/config.xml
			if [ ! -e "/opt/nvtl/data/branding/lib/libomadm_api.so" ]; then
				ln -s /opt/nvtl/lib/libomadm_att_api.so /opt/nvtl/data/branding/lib/libomadm_api.so
			if [ ! -e "/opt/nvtl/data/branding/lib/settings/libomadm_api.so" ]; then
				ln -s /opt/nvtl/lib/libomadm_att_api.so /opt/nvtl/data/branding/lib/settings/libomadm_api.so
			if [ ! -e "/opt/nvtl/data/branding/lib/factory_reset/libomadm_api.so" ]; then
				ln -s /opt/nvtl/lib/libomadm_att_api.so /opt/nvtl/data/branding/lib/factory_reset/libomadm_api.so
		[sS][pP][rR][iI][nN][tT])
			if [ ! -e "/opt/nvtl/data/branding/bin/omadmd" ]; then
				ln -s /opt/nvtl/bin/omadmd_sprint /opt/nvtl/data/branding/bin/omadmd
			if [ ! -e "/opt/nvtl/data/branding/bin/omadm_wap_proxyd" ]; then
				ln -s /opt/nvtl/bin/omadm_wap_proxyd_sprint /opt/nvtl/data/branding/bin/omadm_wap_proxyd
			if [ ! -e "/opt/nvtl/data/branding/bin/omadm_cli" ]; then
				ln -s /opt/nvtl/bin/omadm_cli_sprint /opt/nvtl/data/branding/bin/omadm_cli
			if [ ! -e "/opt/nvtl/data/branding/etc/omadm/tree.xml" ]; then
				ln -s /opt/nvtl/etc/omadm/tree_sprint.xml /opt/nvtl/data/branding/etc/omadm/tree.xml
			if [ ! -e "/opt/nvtl/data/branding/etc/omadm/config.xml" ]; then
				cp /opt/nvtl/etc/omadm/config_sprint.xml /opt/nvtl/data/branding/etc/omadm/config.xml
			if [ ! -e "/opt/nvtl/data/branding/lib/libomadm_api.so" ]; then
				ln -s /opt/nvtl/lib/libomadm_sprint_api.so /opt/nvtl/data/branding/lib/libomadm_api.so
			if [ ! -e "/opt/nvtl/data/branding/lib/settings/libomadm_api.so" ]; then
				ln -s /opt/nvtl/lib/libomadm_sprint_api.so /opt/nvtl/data/branding/lib/settings/libomadm_api.so
			if [ ! -e "/opt/nvtl/data/branding/lib/factory_reset/libomadm_api.so" ]; then
				ln -s /opt/nvtl/lib/libomadm_sprint_api.so /opt/nvtl/data/branding/lib/factory_reset/libomadm_api.so
		[vV][zZ][wW] | [vV][eE][rR][iI][zZ][oO][nN])
			if [ ! -e "/opt/nvtl/data/branding/bin/omadmd" ]; then
				ln -s /opt/nvtl/bin/omadmd_vzw /opt/nvtl/data/branding/bin/omadmd
			if [ ! -e "/opt/nvtl/data/branding/bin/omadm_wap_proxyd" ]; then
				ln -s /opt/nvtl/bin/omadm_wap_proxyd_vzw /opt/nvtl/data/branding/bin/omadm_wap_proxyd
			if [ ! -e "/opt/nvtl/data/branding/bin/omadm_cli" ]; then
				ln -s /opt/nvtl/bin/omadm_cli_vzw /opt/nvtl/data/branding/bin/omadm_cli
			if [ ! -e "/opt/nvtl/data/branding/etc/omadm/tree.xml" ]; then
				ln -s /opt/nvtl/etc/omadm/tree_vzw.xml /opt/nvtl/data/branding/etc/omadm/tree.xml
			if [ ! -e "/opt/nvtl/data/branding/etc/omadm/config.xml" ]; then
				cp /opt/nvtl/etc/omadm/config_vzw.xml /opt/nvtl/data/branding/etc/omadm/config.xml
			if [ ! -e "/opt/nvtl/data/branding/lib/libomadm_api.so" ]; then
				ln -s /opt/nvtl/lib/libomadm_vzw_api.so /opt/nvtl/data/branding/lib/libomadm_api.so
			if [ ! -e "/opt/nvtl/data/branding/lib/settings/libomadm_api.so" ]; then
				ln -s /opt/nvtl/lib/libomadm_vzw_api.so /opt/nvtl/data/branding/lib/settings/libomadm_api.so
			if [ ! -e "/opt/nvtl/data/branding/lib/factory_reset/libomadm_api.so" ]; then
				ln -s /opt/nvtl/lib/libomadm_vzw_api.so /opt/nvtl/data/branding/lib/factory_reset/libomadm_api.so
			/opt/nvtl/bin/nvtl_log -p 1 -m OMADM -l err -s "Invalid carrier name... '$val'"
			exit 2
	/opt/nvtl/bin/nvtl_log -p 1 -m OMADM -l notice -s "Done" 
##############
##############
check_carrier_and_copy
