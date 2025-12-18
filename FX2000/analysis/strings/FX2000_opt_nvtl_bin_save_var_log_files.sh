#!/usr/bin/env sh
# Use inotifywait to detect newly created /var/log/ rotate .0 files.
# When found copy to the /opt/nvtl/log/var_logs/ directory.
# Use variables in /opt/nvtl/data/system/config.xml to control the feature:
#  SaveVarLogFiles: boolean enable
#   MaxVarLogFiles: maximum number of files (of each type)
# Called to get the current index
get_index()
	index_file=$1
	g_index=`cat $index_file`
	echo "get_index(): index_file=$index_file g_index=$g_index" >> $tmp_log_file
# Called to get the next index after copying the file
inc_index()
	index_file=$1
	g_index=`cat $index_file`
	let g_index=g_index+1
	if [ $g_index -ge $max_index ]; then
		g_index=0
	echo $g_index > $index_file
	echo "inc_index(): index_file=$index_file g_index=$g_index" >> $tmp_log_file
script_name=`basename $0`
config_file=/opt/nvtl/data/system/config.xml
saved_log_dir=/opt/nvtl/log/var_logs
messages_index=$saved_log_dir/messages_index
debug_log_index=$saved_log_dir/debug_log_index
system_tmp_dir=/opt/nvtl/tmp/system
tmp_log_file=$system_tmp_dir/saved_var_log_files.log
# Make sure the config file exists
if [ ! -e $config_file ]; then
	logger -p local1.crit -t $script_name "$config_file does not exist"
# If this feature is not enabled exit now
enable=$(awk -F '[<>]' '/<SaveVarLogFiles>/{print $3}' $config_file)
if [ $enable -ne 1 ]; then
	logger -p local1.crit -t $script_name "feature not enabled"
# Create the saved log directory and system/tmp directory
mkdir -p $saved_log_dir $system_tmp_dir
# Get max number of files (of each type)
max_index=$(awk -F '[<>]' '/<MaxVarLogFiles>/{print $3}' $config_file)
# Copy the config file to the persistent log directory so debuglogs picks it up
cp -f $config_file $saved_log_dir/copy_of_config.xml
# Determine if log files are being compressed or not
strings /sbin/syslogd | grep tgz &> /dev/null
if [ $? -eq 0 ]; then
	compressed=".tgz"
	inotify_event=close_write
	compressed=""
	inotify_event=moved_to
messages_fname=messages.0$compressed
debug_log_fname=debug_log.0$compressed
logger -p local1.crit -t $script_name "started: messages_fname=$messages_fname debug_log_fname=$debug_log_fname max_index=$max_index"
# initialize the saved log file indices
for index_file in $messages_index $debug_log_index; do
	if [ ! -f $index_file ]; then
		echo 0 > $index_file
	index=`cat $index_file`
	echo "$index_file=$index" >> $tmp_log_file
# For compressed log files use 'close_write'; for non-compressed use 'moved_to'
inotifywait -m -e $inotify_event /var/log/ | while read inotifywait_output
	echo $inotifywait_output >> $tmp_log_file
	for filename in messages debug_log; do
		log_file=$filename.0$compressed
		index_file=$saved_log_dir/$filename\_index
		echo "log_file=$log_file index_file=$index_file" >> $tmp_log_file
		echo $inotifywait_output | grep $log_file &> /dev/null
		if [ $? -eq 0 ]; then
			get_index $index_file
			# if the log file is not compressed zip it
			if [ "$compressed" == "" ]; then
				zip $saved_log_dir/$log_file.zip.$g_index /var/log/$log_file >> $tmp_log_file
				cp -f /var/log/$log_file $saved_log_dir/$log_file.$g_index
				echo "copied $log_file to $saved_log_dir/$log_file.$g_index" >> $tmp_log_file
			inc_index $index_file
