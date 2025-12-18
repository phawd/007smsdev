#!/usr/bin/env sh
# update_ipk.sh [<"start"> | <dir_with_ipks> | <ipk_file>]
# Use ipkg-cl to remove and install packages.
# If the argument is "start" (used at start-up) the use the default directory,
# else if the argument is a directory use this directory,
# else if the argument is a file just install that file.
install_one_ipk()
	ipk_file=$1
	if [ ! -f $ipk_file ]; then
		echo "$pname: ipk=$ipk_file does not exist"
		exit 2
	ipk_full_name=`basename $ipk_file .ipk`
	ipk_name=`echo $ipk_full_name | awk -F _ '{print $1}'`
	ipk_type=`echo $ipk_full_name | awk -F _ '{print $3}'`
	echo "ipk_full_name=$ipk_full_name"
	echo "ipk_name=$ipk_name"
	echo "ipk_type=$ipk_type"
	if [ "$ipk_type" == "" ]; then
		echo "$pname: $ipk is not a valid package name"
		exit 3
	elif [ "$ipk_type" == "arm" ]; then
		ipk_cfg_file=/etc/ipkg.conf
		ipk_cfg_file=/etc/ipkg-$ipk_type.conf
	echo "ipk_cfg_file=$ipk_cfg_file"
	if [ ! -f $ipk_cfg_file ]; then
		echo "$pname: ipkg config file $ipk_cfg_file does not exist"
		exit 4
	ipkg-cl info $ipk_name | grep Architecture >/dev/null 2>&1
	if [ $? -eq 0 ]; then
		echo "$pname: removing $ipk_name"
		ipkg-cl remove -force-depends $ipk_name
		if [ $? -ne 0 ]; then
			echo "$pname: ipkg-cl remove -force-depends $ipk_name failed"
	ipkg-cl install -f $ipk_cfg_file $ipk_file
	if [ $? -ne 0 ]; then
		echo "$pname: ipkg-cl install -f $ipk_cfg_file $ipk_file failed"
		exit 5
	ipkg-cl info $ipk_name
install_dir_of_ipks()
	for file in `ls $1/*.ipk 2> /dev/null`; do
		install_one_ipk $file
pname=update_ipk.sh
default_dir=/opt/nvtl/data/ipkg
if [ $# -ne 1 ]; then
	echo "usage: $pname [start | <dir_with_ipks> | <ipk_file>]"
if [ "$1" == "start" ]; then
	install_dir_of_ipks $default_dir
	# Remove all of the ipks in the default dir
	rm -f $default_dir/*.ipk
elif [ -d $1 ]; then
	install_dir_of_ipks $1
	install_one_ipk $1
