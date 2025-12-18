#!/bin/sh
# Echo previous and current NVTL application runlevel strings.
# This is the runlevel mapping:
#   0 halt
#   1 LPM (low power mode)
#   2 FTM (factory test mode)
#   3 Online (normal mode)
#   4 LTM (lab test mode)
#   5 FOTA (programming mode)
#   6 reboot
get_run_string ()
	case $1 in
		rl_string="halt"
		rl_string="LPM"
		rl_string="FTM"
		rl_string="Online"
		rl_string="LTM"
		rl_string="FOTA"
		rl_string="reboot"
		rl_string="DSM"
		rl_string="invalid"
prev=`runlevel | awk '{print $1}'`
curr=`runlevel | awk '{print $2}'`
get_run_string $prev
prev_string=$rl_string
get_run_string $curr
curr_string=$rl_string
echo "prev=$prev_string curr=$curr_string"
