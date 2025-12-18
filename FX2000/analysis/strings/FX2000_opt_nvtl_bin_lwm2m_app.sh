#!/bin/sh
export PATH=/opt/nvtl/data/branding/bin:$PATH:/usr/sbin:/opt/nvtl/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib:/opt/nvtl/data/branding/lib
LWM2M_APP=lwm2md
LWM2M_PATH="/opt/nvtl/bin"
BOOTSTRAP="/opt/nvtl/data/lwm2m/use_bootstrap"
IOT="/opt/nvtl/data/lwm2m/use_iot"
LWM2M_APP_USE_DM="/opt/nvtl/data/lwm2m/use_ota_call"
while true
    PID=`pidof $LWM2M_APP`
    if [ -z "$PID" ]
    then
        #
        # formulate the command
        # /opt/nvtl/bin/lwm2md --server-uri coaps://InteropLwM2M.dm.iot.att.com:5684 --endpoint-name urn:imei:9900130900111546 --security-mode psk --identity 39393030313330393030313131353436 --key 998f967e8d2785f53c3c44d57cdb5879
        #
        imei=$(lwm2m_model_cli get_dev_info | grep imei | sed -e 's/[^0-9]//g')
        identity=$(echo -n ${imei} | hexdump -v -e '/1 "%02x"')
        testserver_url=$(lwm2m_model_cli get_cfg| grep "sdm testserver_url" | awk -F '[' '{print $2}' | sed -e 's/]//g')
        testserver_port=$(lwm2m_model_cli get_cfg| grep "sdm testserver_port" | awk -F '[' '{print $2}' | sed -e 's/]//g')
        server_url=$(lwm2m_model_cli get_cfg| grep "sdm server_url" | awk -F '[' '{print $2}' | sed -e 's/]//g')
        server_port=$(lwm2m_model_cli get_cfg| grep "sdm server_port" | awk -F '[' '{print $2}' | sed -e 's/]//g')
        bootstrap_testserver_url=$(lwm2m_model_cli get_cfg| grep "sdm bootstrap testserver_url" | awk -F '[' '{print $2}' | sed -e 's/]//g')
        bootstrap_testserver_port=$(lwm2m_model_cli get_cfg| grep "sdm bootstrap testserver_port" | awk -F '[' '{print $2}' | sed -e 's/]//g')
        bootstrap_server_url=$(lwm2m_model_cli get_cfg| grep "sdm bootstrap server_url" | awk -F '[' '{print $2}' | sed -e 's/]//g')
        bootstrap_server_port=$(lwm2m_model_cli get_cfg| grep "sdm bootstrap server_port" | awk -F '[' '{print $2}' | sed -e 's/]//g')
        lifetime=$(lwm2m_model_cli get_lifetime | grep "lifetime=" | awk -F '[' '{print $2}' | sed -e 's/]//g')
        secret_key=$(lwm2m_model_cli get_dev_info | grep psk | awk -F '[' '{print $2}' | sed -e 's/].//g')
        while [ -z "$secret_key" ]
        do
            sleep 5
            secret_key=$(lwm2m_model_cli get_dev_info | grep psk | awk -F '[' '{print $2}' | sed -e 's/].//g')
        done
        if [ -e $BOOTSTRAP ]; then
                echo "BS ON"
            if [ -e $IOT ]; then
                echo " connecting to IOT-BS "
                url="${bootstrap_testserver_url}:${bootstrap_testserver_port} --bootstrap"
            else 
                echo " connecting to Server-BS "
                url="${bootstrap_server_url}:${bootstrap_server_port} --bootstrap"
            fi
        elif [ -e $IOT ]; then
            echo " connecting to IOT Server "
            url="${testserver_url}:${testserver_port}"
        else
            echo "Connecting to Production Server "
            url="${server_url}:${server_port}"
        fi
        nvtl_log -p 0 -m LWM2M -l debug -s "[lwm2m_app_start] Starting $LWM2M_APP"
        nvtl_log -p 0 -m LWM2M -l debug -s "${LWM2M_PATH}/${LWM2M_APP} --server-uri $url --endpoint-name urn:imei:${imei} --security-mode psk --identity ${identity} --key ${secret_key}"
        start-stop-daemon -S -x ${LWM2M_PATH}/${LWM2M_APP} -- --server-uri $url --endpoint-name urn:imei:${imei} --security-mode psk --identity ${identity} --key ${secret_key} -l ${lifetime} --binding UQS --disable-stdin >> /var/log/lwm2m_log 2>&1
        sleep 60
        nvtl_log -p 0 -m LWM2M -l debug -s "[lwm2m_app_start] $LWM2M_APP killed"
    else
        echo "$LWM2M_APP is already running"
        nvtl_log -p 0 -m LWM2M -l debug -s "$LWM2M_APP is already running"
    break;
