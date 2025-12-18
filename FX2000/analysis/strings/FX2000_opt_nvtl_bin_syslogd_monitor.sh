#!/bin/sh
# This script should be started and backgrounded.  It will loop forever
# checking whether the logger command blocks, implying that the rsyslogd
# daemon has hung.  If so, it will restart rsyslogd.
prog=`basename $0`
while true ; do
        logger &
        pid=$!
        sleep 20
	pidof_logger=`pidof logger`
        if [ "$pidof_logger" != "" ] ; then
                killall -9 syslogd
                killall -9 klogd
                sleep 3
                /etc/init.d/syslogd start
                logger -p syslog.crit -t $prog "rsyslogd was blocking; restarted"
        fi
        sleep 40
