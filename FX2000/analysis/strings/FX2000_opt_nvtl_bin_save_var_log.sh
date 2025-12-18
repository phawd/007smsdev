# Script used to copy /var/log/{messages*,debug_log*} to /opt/nvtl/log/watchdog/.
save_logs()
	log_dir=/opt/nvtl/log/watchdog
	mkdir -p $log_dir
	if [ -f $log_dir/which ]; then
		which=`cat $log_dir/which`
		which=0
	rm -rf $log_dir/$which
	mkdir -p $log_dir/$which
	cp /var/log/messages* /var/log/debug_log* $log_dir/$which/.
	# Collect current process/memory status
	echo "PID   PPID  USER     VSZ  RSS  COMMAND" >  $log_dir/$which/ps.txt
	ps -e -o pid,ppid,user,vsz,rss,comm | sort -k 5nr  >> $log_dir/$which/ps.txt 
	top -b -n 1 -m > $log_dir/$which/top.txt
	free -m  > $log_dir/$which/free.txt
	cat /proc/meminfo > $log_dir/$which/meminfo.txt
	# Increment directory pointer
	let which=which+1
	if [ $which -gt 3 ]; then
		which=0
	echo $which > $log_dir/which
save_logs
