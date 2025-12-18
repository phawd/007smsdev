#!/bin/sh
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
export KERNEL=`uname -r`
export RETRY_LIMIT=5
MODULE_BASE=/lib/modules/$KERNEL/extra
log () {
	nvtl_log -p 1 -m "WIFI" -l 1 -s "wifi_diag.sh:$1"
ssid=Test-Diag
channel=36
bandwidth=80
runlevel=$1
mac0=`nwnvitem -r -e NW_NV_MAC_ID_I`
#mac1=`nwnvitem -r -e NW_NV_MAC_ID_2_I`
len0=${#mac0} 
#len1=${#mac1}
#basic validation not accurate
#if [ "$len0" != 17 ]  ||   [ "$len1" != 17 ] ||  [ "$mac0" == "00:00:00:00:00:00" ] || [ "$mac1" == "00:00:00:00:00:00" ]; then
if [ "$len0" != 17 ]  ||  [ "$mac0" == "00:00:00:00:00:00" ]; then
log " mac0 is incorrect "
temp=${mac0:12}
append_mac_ssid=${temp/:/}
ssid=$ssid-$append_mac_ssid
default_ap() {
	echo "interface=wlan0" > /tmp/wlan0_hostapd.conf	
	echo "ssid=$ssid" >> /tmp/wlan0_hostapd.conf
	echo "hw_mode=a" >> /tmp/wlan0_hostapd.conf
	echo "channel=36" >> /tmp/wlan0_hostapd.conf
	echo "driver=nl80211" >> /tmp/wlan0_hostapd.conf
	echo "ieee80211n=1" >> /tmp/wlan0_hostapd.conf
	echo "ieee80211ac=1" >> /tmp/wlan0_hostapd.conf
	echo "ht_capab=[HT40+]" >> /tmp/wlan0_hostapd.conf
	echo "vht_oper_chwidth=1" >> /tmp/wlan0_hostapd.conf
	echo "vht_oper_centr_freq_seg0_idx=42" >> /tmp/wlan0_hostapd.conf
	/opt/nvtl/bin/hostapd -dddd -f /tmp/wlan0_hostapd.log -B /tmp/wlan0_hostapd.conf
	#	add wlan0 to bridge 		
	brctl addif br0 wlan0	
case $1 in
		log "online mode" >&2
    		killall -9 router2d
		/opt/nvtl/bin/wifi.sh stop 
		sleep 2
    		/opt/nvtl/bin/router2d
		sleep 1
		/opt/nvtl/bin/wifid
		log "Factory mode" >&2
    		killall -9 router2d
		killall hostapd
		/opt/nvtl/bin/wifi.sh stop 
#		sleep 1
#		ifconfig wlan0 down
#		sleep 1
#		unload wlan driver to start in FTM mode
		rmmod wlan.ko
	    	insmod $MODULE_BASE/wlan.ko 
		sleep 1
#		ifconfig wlan0 up
#		start ftm daemon
#		echo 5 > /sys/module/wlan/parameters/con_mode
#		/opt/nvtl/bin/ftmdaemon -dd
		log "WIFI UP FOR USE" >&2
    		/opt/nvtl/bin/router2d
		sleep 5
		default_ap
		log "test mode" >&2
    		killall -9 router2d
		killall hostapd
		/opt/nvtl/bin/wifi.sh stop 
		sleep 2
		sleep 1
		ifconfig wlan0 down
		sleep 1
		rmmod wlan.ko
		sleep 2
	    	insmod $MODULE_BASE/wlan.ko 
		sleep 2
		ifconfig wlan0 up
		log "WIFI UP FOR USE" >&2
    		/opt/nvtl/bin/router2d
		sleep 5
		default_ap
		log "Unknown wifi mode $1" >&2
		exit 1
