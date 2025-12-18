#!/usr/bin/env sh
# Copy the active RAM based log files /var/log/debug_log,messages to NAND periodically.
# Use variables in /opt/nvtl/data/system/config.xml to control the feature:
#       SaveVarLogFiles: boolean enable
#  SaveVarLogFilesTimer: number of seconds to wait between copies
# Don't overwrite the files from last time
save_files_from_last_time()
	# Get the current index
	index_file=/opt/nvtl/log/var_logs/timer/index
	if [ ! -f $index_file ]; then
		echo 0 > $index_file
	index=`cat $index_file`
	echo "$index_file=$index" >> $tmp_log_file
	# Save files using the current index
	if [ -e $saved_log_dir_timer/debug_log ]; then
		mv -f $saved_log_dir_timer/debug_log $saved_log_dir_timer/debug_log.$index
	if [ -e $saved_log_dir_timer/messages ]; then
		mv -f $saved_log_dir_timer/messages $saved_log_dir_timer/messages.$index
	# Inc index for next time
	let index=index+1
	if [ $index -ge $max_index ]; then
		index=0
	echo $index > $index_file
	sync; sync
script_name=`basename $0`
config_file=/opt/nvtl/data/system/config.xml
saved_log_dir_timer=/opt/nvtl/log/var_logs/timer
system_tmp_dir=/opt/nvtl/tmp/system
tmp_log_file=$system_tmp_dir/saved_var_log_files_timer.log
# Make sure the config.xml exists
if [ ! -e $config_file ]; then
	logger -p local1.crit -t $script_name "$config_file does not exist"
# If this feature is not enabled exit now
enable=$(awk -F '[<>]' '/<SaveVarLogFiles>/{print $3}' $config_file)
if [ $enable -ne 1 ]; then
	logger -p local1.crit -t $script_name "feature not enabled"
# Get sleep timer
sleep_timer=$(awk -F '[<>]' '/<SaveVarLogFilesTimer>/{print $3}' $config_file)
# Make sure it's a number
if ! [ "$sleep_timer" -eq "$sleep_timer" 2> /dev/null ]; then
	logger -p local1.crit -t $script_name "SaveVarLogFilesTimer=$sleep_timer is invalid"
# Make sure it's a reasonable value
if [ $sleep_timer -le 5 -o $sleep_timer -gt 60 ]; then
	sleep_timer=30
# Get max index
max_index=$(awk -F '[<>]' '/<MaxVarLogFiles>/{print $3}' $config_file)
logger -p local1.crit -t $script_name "started: sleep_timer=$sleep_timer max_index=$max_index"
# Create the saved log directory and system/tmp directory
mkdir -p $saved_log_dir_timer $system_tmp_dir
# The first time this runs there will be logs from the previous instance.
# Let's not overwrite these files.
save_files_from_last_time
while true; do
	sleep $sleep_timer
	if [ -e $saved_log_dir_timer/debug_log ]; then
		mv -f $saved_log_dir_timer/debug_log $saved_log_dir_timer/debug_log.tmp
	if [ -e $saved_log_dir_timer/messages ]; then
		mv -f $saved_log_dir_timer/messages $saved_log_dir_timer/messages.tmp
	cp -f /var/log/debug_log $saved_log_dir_timer/debug_log
	cp -f /var/log/messages $saved_log_dir_timer/messages
	sync; sync
