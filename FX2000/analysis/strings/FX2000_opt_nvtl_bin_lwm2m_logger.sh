#! /bin/sh
export PATH=/opt/nvtl/data/branding/bin:$PATH:/usr/sbin:/opt/nvtl/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib:/opt/nvtl/data/branding/lib
LOG_FILE="/var/log/lwm2m_log"
MAX_LOG_FILE_SIZE_KB=1024 ## 1 mb = 1024 kb
SLEEP_TIME_IN_SEC=300
NUM_OF_FILES=9
if sysintcli getLWM2MCarrierEnabled | grep "enabled:\[0\]" > /dev/null 2>&1 ; then
    nvtl_log -p 0 -m LWM2M -l debug -s "LWM2M is disabled in features...exiting"
    exit 0
while true
    if [ -f $LOG_FILE ]; then
        log_size=0
        log_size=`du -k $LOG_FILE | awk '{print $1}'`;
        if [ $log_size -gt $MAX_LOG_FILE_SIZE_KB ]; then
            COUNTER=$NUM_OF_FILES
            # Rotate the files
            while [ $COUNTER -ge 0 ]
            do
                log_file=${LOG_FILE}.${COUNTER}.tgz
                if [ -f $log_file ]; then
                    if [ $COUNTER -eq $NUM_OF_FILES ]; then
                        rm -f ${log_file}
                    else
                        mv ${log_file} ${next_file}
                    fi
                fi
                next_file=$log_file
                let COUNTER=COUNTER-1
            done
            tar -cvzf ${LOG_FILE}.0.tgz ${LOG_FILE}
            >${LOG_FILE}
            sync
            sync
        fi
    sleep $SLEEP_TIME_IN_SEC
