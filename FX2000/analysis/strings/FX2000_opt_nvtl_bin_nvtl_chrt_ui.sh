# nvtl_chrt_ui.sh <process_name>
# This script is used to change the priority of all the threads within the
# process whose name matches the <process_name> argument.
# This script is currently used to increase the priority of device UI's.
if [ $# -lt 1 ]; then
	echo "usage: nvtl_chrt_ui.sh <process_name>"
pids=`pidof $1`
if [ "$pids" == "" ]; then
	echo "nvtl_chrt_ui.sh: pidof $1 not found"
for pid in $pids; do
	task_pids=`ls /proc/$pid/task`
	for task in $task_pids; do
		/usr/bin/chrt -p -f 1 $task > /dev/null
