#!/bin/sh
start_cookie="/tmp/check_md5_start"
linux_end_cookie="/tmp/linux_check_md5_complete"
modem_end_cookie="/tmp/modem_check_md5_complete"
if [ $# -ne 1 ]; then
	echo "Usage:: ./check_md5 [Linux | Modem | Linux_Modem]"
rm $end_cookie 2>/dev/null
touch $start_cookie
if [ -f "$start_cookie" ]; then
	rm $linux_end_cookie 2>/dev/null
	rm $modem_end_cookie 2>/dev/null
	if [ "$type" = "Linux" ];then
		return=$(/opt/nvtl/bin/check_md5_sdx55.sh)
		status=$(echo $return | grep "check_md5.sh:" | awk 'BEGIN {FS=" ";} {print $2}')
		if [ "$status" = "PASSED" ];then
			echo $status >$linux_end_cookie
			mv /tmp/check_md5_diff_result $linux_end_cookie
		rm /tmp/check_md5_diff_result 2>/dev/null
	elif [ "$type" = "Modem" ];then
		return=$(/opt/nvtl/bin/modem_check_md5.sh)
		status=$(echo $return | grep "check_md5.sh:" | awk 'BEGIN {FS=" ";} {print $2}')
		if [ "$status" = "PASSED" ];then
			echo $status >$modem_end_cookie
			mv /tmp/modem_check_md5_diff_result $modem_end_cookie
		rm /tmp/modem_check_md5_diff_result 2>/dev/null
	elif [ "$type" = "Linux_Modem" ]; then
		return=$(/opt/nvtl/bin/check_md5_sdx55.sh)
		status=$(echo $return | grep "check_md5.sh:" | awk 'BEGIN {FS=" ";} {print $2}')
		if [ "$status" = "PASSED" ];then
			echo $status >$linux_end_cookie
			mv /tmp/check_md5_diff_result $linux_end_cookie
		return=$(/opt/nvtl/bin/modem_check_md5.sh)
		status=$(echo $return | grep "check_md5.sh:" | awk 'BEGIN {FS=" ";} {print $2}')
		if [ "$status" = "PASSED" ];then
			echo $status >$modem_end_cookie
			mv /tmp/modem_check_md5_diff_result $modem_end_cookie
		rm /tmp/check_md5_diff_result 2>/dev/null
		rm /tmp/modem_check_md5_diff_result 2>/dev/null
	rm $start_cookie 2>/dev/null
	echo "Failed to create start_cookie"
