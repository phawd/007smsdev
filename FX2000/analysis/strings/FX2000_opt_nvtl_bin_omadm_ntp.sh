#!/bin/sh
export PATH=$PATH:/opt/nvtl/bin:/system/bin
SCRIPT_NAME=$0
LOG_FILE="/opt/nvtl/tmp/debug_log"
LOG2_FILE="/opt/nvtl/tmp/omadm_ntp"
LAST_TIME_REQ="/opt/nvtl/tmp/time_req"
PRIMARY_SERVER="google.com"
SECONDARY_SERVER="verizon.com"
OPR_MODE=""
INPUT_SERVER_INFO=""
print_log()
	date_str="`date`"	
	echo "$SCRIPT_NAME [$date_str]: $1" >> $LOG_FILE		
	echo "$SCRIPT_NAME [$date_str]: $1" >> $LOG2_FILE		
is_number()
	string="$1"
	low="$2"
	high="$3"
	temp="`echo $string | grep -E ^\-?[0-9]+$ >/dev/null 2>&1`"
	ret="$?"
	if [ "$ret" != "0" ]; then
		return 1;
	if [ $string -lt $low ]; then 
		print_log "value=[$string] < [$low]"
		return 1
	if [ $string -gt $high ]; then
		print_log "value=[$string] > [$high]"
		return 1
	return 0
android_date_str=""
rec_uptime_sec=""
month_no=""
convert_month_to_number()
	month_no=""
	count=0
	for j in Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec
		count=`expr $count + 1`
		#echo "count=$count, i=$i, input=$1"
		if [ "$1" == "$j" ]; then
			if [ $count -lt 10 ]; then 
				month_no="0$count"
			#else if [ $count -lt 13 ]; then
				month_no="$count"
#02-month (%m)
#01-day (%d)
#01-hour(%H) 
#56-minute (%m)
#2019-year (%Y)
#25 - second (%S) 
get_and_convert_date()
	android_date_str=""
	rec_uptime_sec=""
	rm -rf $LAST_TIME_REQ
	if [ "$INPUT_SERVER_INFO" != "" ]; then
 		#curl_cmd="/system/bin/curl --interface $INPUT_INTF -I $INPUT_SERVER --resolve $INPUT_SERVER:80:$INPUT_IP 2>/dev/null >$LAST_TIME_REQ"
 		curl_cmd="`/system/bin/curl $INPUT_SERVER_INFO 2>/dev/null >$LAST_TIME_REQ`"
		curl_cmd2="$curl_cmd"
		curl_cmd="`/system/bin/curl -I $PRIMARY_SERVER 2>/dev/null >$LAST_TIME_REQ`"
		curl_cmd2="`/system/bin/curl -I $SECONDARY_SERVER 2>/dev/null >$LAST_TIME_REQ`"
	$curl_cmd
	ret="$?"
	if [ "$ret" != "0" ]; then
		cat $LAST_TIME_REQ >>$LOG2_FILE 
		print_log "Error in curl ret=$ret, try secondary server"
		$curl_cmd2
		ret="$?"
		if [ "$ret" != "0" ]; then
			cat $LAST_TIME_REQ >>$LOG2_FILE 
			print_log "Error in curl ret=$ret, give up"
			return 1
	cat $LAST_TIME_REQ >>$LOG2_FILE 
	rec_uptime_sec="`cat /proc/uptime | awk -F [.] '{print $1}'`"
	date_str="`cat $LAST_TIME_REQ | grep -i '^date:' | sed 's/^[Dd]ate: //g'`"
	if [ "$date_str" == "" ]; then
		print_log "Invalid date string!"
		return 1
	day="`echo $date_str | awk '{print $2}'`"
	is_number $day "1" "31"
	ret="$?"
	if [ "$ret" != "0" ]; then
		print_log "Wrong day=[$day]"
		return 1
	month_no=""
	month_str="`echo $date_str | awk '{print $3}'`"
	convert_month_to_number $month_str
	is_number $month_no "1" "12"
	ret="$?"
	if [ "$ret" != "0" ]; then
		print_log "Wrong month_no=[$month_no]"
		return 1
	year="`echo $date_str | awk '{print $4}'`"
	is_number $year "1" "2100"
	ret="$?"
	if [ "$ret" != "0" ]; then
		print_log "Wrong year=[$year]"
		return 1
	hour="`echo $date_str | awk '{print $5}' | awk -F [:] '{print $1}'`"
	is_number $hour "0" "23"
	ret="$?"
	if [ "$ret" != "0" ]; then
		print_log "Wrong hour=[$hour]"
		return 1
	min="`echo $date_str | awk '{print $5}' | awk -F [:] '{print $2}'`"
	is_number $min "0" "59"
	ret="$?"
	if [ "$ret" != "0" ]; then
		print_log "Wrong min=[$min]"
		return 1
	sec="`echo $date_str | awk '{print $5}' | awk -F [:] '{print $3}'`"
	is_number $sec "0" "59"
	ret="$?"
	if [ "$ret" != "0" ]; then
		print_log "Wrong sec=[$sec]"
		return 1
	android_date_str=$month_no$day$hour$min$year.$sec
	print_log "Curl Date=[$android_date_str]"
	return 0
is_system_upto_date()
	now_secs_since_epoch="`/system/bin/date +'%s'`"
	now_uptime_sec="`cat /proc/uptime | awk -F [.] '{print $1}'`"
	internet_secs_since_epoch="`/system/bin/date -d $1 +'%s'`" 
	let uptime_diff=$now_uptime_sec-$rec_uptime_sec
	print_log "uptime diff=$uptime_diff, now=[$now_uptime_sec], rec=[$rec_uptime_sec]"
	let new_time_from_internet=$internet_secs_since_epoch+$uptime_diff
	let diff_seconds=$new_time_from_internet-$now_secs_since_epoch
	print_log "system time diff=$diff_seconds, time_now=$now_secs_since_epoch, time_new=$new_time_from_internet"
	if [ $diff_seconds -gt "299" -o $diff_seconds -lt "-299" ]; then 
		print_log "Time diff > 5minutes, set system time.."
		return 1
	print_log "System time [OK]"
	echo -n $1 >/data/nvtl/log/prev_date
	sync;sync;
	return 0
set_system_date()
	OPR_MODE="monitor"
	is_system_upto_date $1
	ret="$?"
	if [ "$ret" == "0" ]; then
		print_log "No need to set system time"
		return 0
	OPR_MODE="active" 
	/system/bin/date $1 >>/dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
	 	print_log "date command failure, ret=$ret"
		return "1"
	echo -n $1 >/data/nvtl/log/prev_date
	print_log "Date updated successfully [$1]"
	sync;sync;
	OPR_MODE="monitor"
	return 0
start_date_check()
	get_and_convert_date
	ret="$?"
	if [ "$ret" != "0" ]; then 
		print_log "Cannot fetch date, ret=$ret"
		return "1"
	set_system_date $android_date_str
	ret="$?"
	if [ "$ret" != "0" ]; then 
		print_log "Date command failed, ret=$ret"
		return "1"
	return 0
process_active_mode()
	if [ "$INPUT_SERVER_INFO" == "" ]; then
		rmnet_data_ip="`ifconfig rmnet_data0 | awk '/inet / {split($2,var,":"); print var[2]}'`"
		echo "$rmnet_data_ip"  | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" >>/dev/null
		ret="$?"
		if [ "$ret" != "0" ]; then
			print_log "rmnet_data_ip not found, retry"
			return 1;
		print_log "Found rmnet_data0 ip=$rmnet_data_ip"
		print_log "Skip interface IP assignment"
	start_date_check 
	ret="$?"
	if [ "$ret" != "0" ]; then 
		print_log "start_date_check failed try again.."
		OPR_MODE="active"
		return 1;
		print_log "Success, go -->[MONITOR]"
		OPR_MODE="monitor"
		return 0;
process_monitor_mode()
	is_system_upto_date $android_date_str
	ret="$?"
	if [ "$ret" != "0" ]; then 
		print_log "time off detected go -->[ACTIVE]"
		OPR_MODE="active"
		touch /opt/nvtl/tmp/omadm_time_set
		return 1;
		OPR_MODE="monitor"
		rm -rf /opt/nvtl/tmp/omadm_time_set
		return 0;
while_timeout=60
print_log "Input arg count=[$#]"
if [ "$#" == "2" ]; then
	INPUT_SERVER_INFO="$1"
	while_timeout=$2
	print_log "Starting cmd=[$INPUT_SERVER_INFO], timeout=[$while_timeout]"
OPR_MODE="active"
touch /opt/nvtl/tmp/omadm_time_set
while [ $i -lt $while_timeout ]
	if [ "$OPR_MODE" == "active" ]; then
		process_active_mode
	if [ "$OPR_MODE" == "monitor" ]; then
		process_monitor_mode
	i=`expr $i + 1`	
	sleep 5
if [ "$OPR_MODE" == "active" ]; then
	if [ -f "/data/nvtl/log/prev_date" ]; then
		and_date_str="`cat /data/nvtl/log/prev_date`"
		print_log "Using previous date=$and_date_str"
		set_system_date "$and_date_str"
print_log "Exiting, OPR_MODE=$OPR_MODE"
