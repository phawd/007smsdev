#!/usr/bin/env sh
# Extract compressed tar log files and cat into one complete file.
# fix_log_files.sh <logfile>
extract_one_file()
	if [ -f $1.tgz ]; then
		tar xvOf $1.tgz > $1
extract_all_files()
	if [ -f $1.2.tgz ]; then
		extract_one_file $1.2
	if [ -f $1.1.tgz ]; then
		extract_one_file $1.1
	if [ -f $1.0.tgz ]; then
		extract_one_file $1.0
cat_files()
	if [ -f $1.2 ]; then
		cat $1.2 $1.1 $1.0 $1 > $1_all
		rm -f $1.2 $1.1 $1.0
	elif [ -f $1.1 ]; then
		cat $1.1 $1.0 $1 > $1_all
		rm -f $1.1 $1.0
	elif [ -f $1.0 ]; then
		cat $1.0 $1 > $1_all
		rm -f $1.0
		cp $1 $1_all
if [ $# -ne 1 ]; then
	echo "usage: fix_log_files.sh <logfile>"
logfile=$1
extract_all_files $logfile
cat_files $logfile
