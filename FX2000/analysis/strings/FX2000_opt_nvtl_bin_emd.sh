#!/bin/sh
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
export KERNEL=`uname -r`
MODULE_BASE=/lib/modules/$KERNEL/extra
# init.d script for the emd listed
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
case $1 in
		echo -n "Starting $EMD: "
		/opt/nvtl/bin/nwnvitem -r -e NW_NV_ASYNC_DATA_ORIG_STR_I  >  /opt/nvtl/data/eth/qcom/emac_config.ini
		if [ `lsmod | grep -i emac_dwc_eqos | wc -l` == 0 ]; then
			insmod $MODULE_BASE/emac_dwc_eqos.ko > /dev/null 2>&1
		start-stop-daemon -S -b -a /opt/nvtl/bin/$EMD
#		/etc/initscripts/emac_dwc_eqos_start_stop_le stop
#		echo "Moretti Unload EMAC"
		echo "done"
		echo -n "Stopping $EMD: "
		start-stop-daemon -K -x /opt/nvtl/bin/$EMD
		sleep 1
		echo "done"
	restart)
		$0 stop
		$0 start
		echo "Usage: $EMD { start | stop | restart}" >&2
		exit 1
