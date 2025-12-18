#!/bin/sh
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib:/opt/nvtl/data/branding/lib
memusage_ensure_one_instance()
	SCRIPTNAME=`basename $0`
	PIDFILE=/var/run/${SCRIPTNAME}.pid
	if [ -f ${PIDFILE} ]; then
#verify if the process is actually still running under this pid
	   	OLDPID=`cat ${PIDFILE}`
	   	RESULT=`ps | grep ${OLDPID} | grep ${SCRIPTNAME}`  
	   	if [ -n "${RESULT}" ]; then
		 	echo "Script already running! Exiting" | tee -a $LOGFILE
		 	exit 255
#grab pid of this process and update the pid file with it
	PID=`ps | grep ${SCRIPTNAME} | head -n1 |  awk ' {print $1;} '`
	echo ${PID} > ${PIDFILE}
remove_pidfile()
	if [ -f ${PIDFILE} ]; then
 		echo "removing PIDFILE:${PIDFILE}" | tee -a $LOGFILE
		rm ${PIDFILE}
pidof_assign() 
	lighttpdpid=`pidof lighttpd`
	ccmpid=`pidof ccm`
	sysserpid=`pidof sysser.fcgi`
	restapipid=`pidof restapi.fcgi`
	anspid=`pidof ans`
	cdopid=`pidof nsphttpd`
	battpid=`pidof mifi_alska_batt`
	crondpid=`pidof crond`
	debugdpid=`pidof mifi_debugd`
	psmpid=`pidof mifi_psm`
	gettypid=`pidof getty`
	diagreadpid=`pidof diag_read`
	radishpid=`pidof radish`
	routerdpid=`pidof nvtl_routerd`
	klogdpid=`pidof klogd`
	msgbusdpid=`pidof msgbusd`
	syslogpid=`pidof syslogd`
	qmuxpid=`pidof qmuxd`
	nbnsdpid=`pidof nbnsd`
	powersavepid=`pidof mifi_powersave`
	dhcpdpid=`pidof dhcpd`
	hostapdpid=`pidof hostapd`
	dnsdpid=`pidof nvtl_dnsd`
	if [ "$dnsdpid" == "" ] ; then
		dnsdpid=`pidof dnsmasq`
	emwinpid=`pidof emwin_dui`
	mupid=`pidof nvtl_memusage.sh`
	slpid=`pidof store_logs.sh`
calculate_ram_files_usage()
	totalsize=0
#	echo "totalsize=$totalsize"
	dirname=/proc
	dirsize=`du -cs $dirname | grep total | awk '{print $1}'`
	totalsize=$(($totalsize+$dirsize))
#	echo "totalsize=$totalsize"
	dirname=/tmp
	dirsize=`du -cs $dirname | grep total | awk '{print $1}'`
	totalsize=$(($totalsize+$dirsize))
#	echo "totalsize=$totalsize"
	dirname=/var/log
	dirsize=`du -cs $dirname | grep total | awk '{print $1}'`
	totalsize=$(($totalsize+$dirsize))
#	echo "totalsize=$totalsize"
	dirname=/var/run
	dirsize=`du -cs $dirname | grep total | awk '{print $1}'`
	totalsize=$(($totalsize+$dirsize))
#	echo "totalsize=$totalsize"
	dirname=/var/lock
	dirsize=`du -cs $dirname | grep total | awk '{print $1}'`
	totalsize=$(($totalsize+$dirsize))
#	echo "totalsize=$totalsize"
	dirname=/sys/kernel/debug
	dirsize=`du -cs $dirname | grep total | awk '{print $1}'`
	totalsize=$(($totalsize+$dirsize))
#	echo "totalsize=$totalsize"
	dirname=/dev
	dirsize=`du -cs $dirname | grep total | awk '{print $1}'`
	totalsize=$(($totalsize+$dirsize))
#	echo "totalsize=$totalsize"
private_dirty_per_process()
    memused=0
    allentries=`cat /proc/$1/smaps | grep Private_Dirty | cut -d':' -f2 | awk '{print $1}'`
    for i in $allentries; do
	    memused=$(($memused+$i))
    done
print_private_dirty()
    runtime="__empty__"
	echo -n `printf "%s" $runtime` >> $LOGFILE
	memfree=0
	echo -n -e "\t"`printf "%05d" $memfree` >> $LOGFILE
	if [ "$lighttpdpid" == "" ] ; then
		echo -n -e "\tDEAD " >> $LOGFILE
        private_dirty_per_process $lighttpdpid
		echo -n -e "\t"`printf "%05d" $memused` >> $LOGFILE
	if [ "$ccmpid" == "" ] ; then
		echo -n -e "\tDEAD " >> $LOGFILE
        private_dirty_per_process $ccmpid
		echo -n -e "\t"`printf "%05d" $memused` >> $LOGFILE
	if [ "$sysserpid" == "" ] ; then
		echo -n -e "\tDEAD " >> $LOGFILE
        private_dirty_per_process $sysserpid
		echo -n -e "\t"`printf "%05d" $memused` >> $LOGFILE
	if [ "$restapipid" == "" ] ; then
		echo -n -e "\tDEAD " >> $LOGFILE
        private_dirty_per_process $restapipid
		echo -n -e "\t"`printf "%05d" $memused` >> $LOGFILE
	if [ "$anspid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
        private_dirty_per_process $anspid
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$cdopid" == "" ] ; then
		echo -n -e "\tDEAD " >> $LOGFILE
        private_dirty_per_process $cdopid
		echo -n -e "\t"`printf "%05d" $memused` >> $LOGFILE
	if [ "$battpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
        private_dirty_per_process $battpid
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$psmpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
        private_dirty_per_process $psmpid
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$diagreadpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
        private_dirty_per_process $diagreadpid
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$radishpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
        private_dirty_per_process $radishpid
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$routerdpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
        private_dirty_per_process $routerdpid
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$klogdpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
        private_dirty_per_process $klogdpid
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$msgbusdpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
        private_dirty_per_process $msgbusdpid
 		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$qmuxpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
        private_dirty_per_process $qmuxpid
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$powersavepid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
        private_dirty_per_process $powersavepid
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$dhcpdpid" == "" ] ; then
		echo -n -e "\tDEAD " >> $LOGFILE
        private_dirty_per_process $dhcpdpid
		echo -n -e "\t"`printf "%05d" $memused` >> $LOGFILE
	if [ "$hostapdpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
        private_dirty_per_process $hostapdpid
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$dnsdpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
        private_dirty_per_process $dnsdpid
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$emwinpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
	    echo -n -e "\t" >> $LOGFILE
        for j in $emwinpid; do
            private_dirty_per_process $j
		    echo -n `printf "%04d " $memused` >> $LOGFILE
        done
	if [ "$crondpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
        private_dirty_per_process $crondpid
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$nbnsdpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
        private_dirty_per_process $nbnsdpid
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$syslogpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
        private_dirty_per_process $syslogpid
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$gettypid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
        private_dirty_per_process $gettypid
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$debugdpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
        private_dirty_per_process $debugdpid
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	echo -n -e "\t"`printf "%05d" 0` >> $LOGFILE
# forcing carriage return
	echo >> $LOGFILE
LOGFILE=/var/log/memusage.log
LOGFILE=/opt/nvtl/log/memusage.log
echo "LOGFILE:$LOGFILE" | tee -a $LOGFILE
memusage_ensure_one_instance
SLEEPDUR=60
if [ "$1" != "" ] ; then
# overriding sleep interval with commandline param
	SLEEPDUR=$1
#if [ $SLEEPDUR -eq 0 ] ; then	# enable mem frag logging to /var/log/messages
	echo 1 > /proc/sys/kernel/sysrq
#	echo m > /proc/sysrq-trigger
#	grep Normal /var/log/messages |  tail -1 >> $LOGFILE
echo "SLEEPDUR:$SLEEPDUR" | tee -a $LOGFILE 
echo >> $LOGFILE
echo "Mem Usage Log: " >> $LOGFILE
echo -e "Time/Misc\tFree \tLight\tCCM  \tFastC\tREST\tANS \tcdo  \tbatt\tpsm \tdiag\trdsh\trotr\tklg \tmsgb\tqmux\tpwrs\tdhcpd\thsap\tdnsd \temwin     \tcrnd\tnbns\tsysl\tgty \tdbg \tramfs" >> $LOGFILE
echo -e "---------\t-----\t-----\t-----\t-----\t-----\t----\t-----\t----\t----\t----\t----\t----\t----\t----\t----\t----\t-----\t----\t-----\t----------\t----\t----\t----\t----\t----\t-----" >> $LOGFILE
CURR_ITER_COUNT=0
while [ 1 ] ; do
	pidof_assign
    runtime=`uptime | cut -d ' ' -f 2`
	echo -n `printf "%9.9s" $runtime` >> $LOGFILE
	memfree=`cat /proc/meminfo | grep MemFree | awk 'BEGIN {} { print $2}'`
	echo -n -e "\t"`printf "%05d" $memfree` >> $LOGFILE
	if [ "$lighttpdpid" == "" ] ; then
		echo -n -e "\tDEAD " >> $LOGFILE
    	memused=`pmap -x $lighttpdpid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%05d" $memused` >> $LOGFILE
	if [ "$ccmpid" == "" ] ; then
		echo -n -e "\tDEAD " >> $LOGFILE
    	memused=`pmap -x $ccmpid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%05d" $memused` >> $LOGFILE
	if [ "$sysserpid" == "" ] ; then
		echo -n -e "\tDEAD " >> $LOGFILE
    	memused=`pmap -x $sysserpid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%05d" $memused` >> $LOGFILE
	if [ "$restapipid" == "" ] ; then
		echo -n -e "\tDEAD " >> $LOGFILE
    	memused=`pmap -x $restapipid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%05d" $memused` >> $LOGFILE
	if [ "$anspid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
    	memused=`pmap -x $anspid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$cdopid" == "" ] ; then
		echo -n -e "\tDEAD " >> $LOGFILE
    	memused=`pmap -x $cdopid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%05d" $memused` >> $LOGFILE
	if [ "$battpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
    	memused=`pmap -x $battpid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$psmpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
    	memused=`pmap -x $psmpid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$diagreadpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
    	memused=`pmap -x $diagreadpid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$radishpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
    	memused=`pmap -x $radishpid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$routerdpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
    	memused=`pmap -x $routerdpid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$klogdpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
    	memused=`pmap -x $klogdpid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$msgbusdpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
    	memused=`pmap -x $msgbusdpid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$qmuxpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
    	memused=`pmap -x $qmuxpid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$powersavepid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
    	memused=`pmap -x $powersavepid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$dhcpdpid" == "" ] ; then
		echo -n -e "\tDEAD " >> $LOGFILE
    	memused=`pmap -x $dhcpdpid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%05d" $memused` >> $LOGFILE
	if [ "$hostapdpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
    	memused=`pmap -x $hostapdpid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$dnsdpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
    	memused=`pmap -x $dnsdpid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$emwinpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
    	memused=`pmap -x $emwinpid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%4d" $memused` >> $LOGFILE
	if [ "$crondpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
    	memused=`pmap -x $crondpid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$nbnsdpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
    	memused=`pmap -x $nbnsdpid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$syslogpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
    	memused=`pmap -x $syslogpid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$gettypid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
    	memused=`pmap -x $gettypid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	if [ "$debugdpid" == "" ] ; then
		echo -n -e "\tDEAD" >> $LOGFILE
    	memused=`pmap -x $debugdpid | grep total | awk 'BEGIN {}{ print $4}'`
		echo -n -e "\t"`printf "%04d" $memused` >> $LOGFILE
	calculate_ram_files_usage
	echo -n -e "\t"`printf "%05d" $totalsize` >> $LOGFILE
# forcing carriage return
	echo >> $LOGFILE
    print_private_dirty
	echo "                         [4K]   [8K]   [16]   [32]   [64]   128K   256K   512K   [1M]   [2M]   [4M]" >> $LOGFILE
	cat /proc/buddyinfo | tail -1 >> $LOGFILE
	if [ $(( CURR_ITER_COUNT % 10 )) -eq 0 ] ; then
		echo "------------------" >> $LOGFILE
		echo "/proc/meminfo ....." >> $LOGFILE
		echo "------------------" >> $LOGFILE
		cat /proc/meminfo  >> $LOGFILE
		echo "------------------" >> $LOGFILE
        echo -e "Time/Misc\tFree \tLight\tCCM  \tFastC\tREST\tANS \tcdo  \tbatt\tpsm \tdiag\trdsh\trotr\tklg \tmsgb\tqmux\tpwrs\tdhcpd\thsap\tdnsd \temwin     \tcrnd\tnbns\tsysl\tgty \tdbg \tramfs" >> $LOGFILE
        echo -e "---------\t-----\t-----\t-----\t-----\t----\t----\t-----\t----\t----\t----\t----\t----\t----\t----\t----\t----\t-----\t----\t-----\t----------\t----\t----\t----\t----\t----\t-----" >> $LOGFILE
	if [ $SLEEPDUR -eq 0 ] ; then
		remove_pidfile
		exit 0
	sleep $SLEEPDUR
# increment success iteration count
	CURR_ITER_COUNT=$(($CURR_ITER_COUNT+1))
remove_pidfile
