#!/bin/sh
local_echo()
        echo ""
        echo ""
        echo " modem_check_md5.sh: $1"
        echo ""
        echo ""
generate_tmp_file()
	rm -f /tmp/md5.list
    dir_list="image"
	for dir in $dir_list; do
		find $dir -type f -exec md5sum {} \; >> /tmp/md5.list
filter_and_sort()
	sort -d -f -k 2 /tmp/md5.list > /tmp/md5.list.sorted
	grep -v -e  image.md5sum* \
	/tmp/md5.list.sorted > /tmp/md5.list
cd /firmware
generate_tmp_file
filter_and_sort
rm -f /tmp/md5.list.sorted
diff /firmware/image/md5sum.txt /tmp/md5.list >/tmp/modem_check_md5_diff_result
if [ $rc -ne 0 ]; then
	cat /tmp/modem_check_md5_diff_result
	local_echo "FAILED"
	rm -f modem_check_md5_diff_result
	local_echo "PASSED"
