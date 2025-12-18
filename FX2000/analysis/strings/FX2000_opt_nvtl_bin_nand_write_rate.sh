#!/bin/sh
# Script for calculating the NAND write rate on the system
do_one_partition()
	uptime=`cat /proc/uptime | awk '{ print $1 }'`
	fskb=`df -k | grep $1 | awk '{ print $2 }'`
	mounted_on=`df -k | grep $1 | awk '{ print $6 }'`
	ubi_name=`cat /sys/class/ubi/$1_0/name`
	total_bytes=`cat /sys/class/ubi/$1/bytes_written`
	b_rate_sec=`dc $total_bytes $uptime div p`
	mb_rate_hour=`dc $b_rate_sec 60 60 mul mul 1024 1024 mul div p`
	mb_rate_day=`dc $mb_rate_hour 24 mul p`
	fsmb=`dc $fskb 1024 div p`
	# Decrease the lifetime NAND capacity by a factor of 10.
	tbw=`dc 10000 $fsmb mul p`
	cls=`dc $tbw $mb_rate_day div p`
	if [ $debug -gt 0 ]; then
		echo "       uptime : $uptime "
		echo "  total_bytes : $total_bytes"
		echo "   b_rate_sec : $b_rate_sec "
		echo " mb_rate_hour : $mb_rate_hour "
		echo "  mb_rate_day : $mb_rate_day"
	echo ""
	echo "                  UBI Name : $ubi_name"
	echo "                Mounted On : $mounted_on"
	echo "   Static NAND FS capacity : $fsmb MB"
	echo " Lifetime NAND FS capacity : $tbw MB"
	echo "           NAND Write Rate : $mb_rate_day MB / day"
	echo "      Calculated Life Span : $cls days"
	echo ""
if [ $# -gt 0 ]; then
	debug=1
	debug=0
do_one_partition ubi0
# do_one_partition ubi1
