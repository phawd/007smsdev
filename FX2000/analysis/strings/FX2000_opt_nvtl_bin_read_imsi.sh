#! /bin/sh
IMSI_FILE="/opt/nvtl/data/branding/imsi"
# Read IMSI
imsi=$(/opt/nvtl/bin/atcmd "AT+CIMI" | awk 'NR==2 {res = $0} END {if ($0 == "OK") {print res}}')
# echo "$(date) : IMSI-[$imsi] " 2>&1 >> /opt/nvtl/data/branding/log
# Check if IMSI read is valid or not
if [[ "$imsi" != "$(printf $imsi | grep -E ^[0-9]+$)" ]] || [[ "${#imsi}" != "15" ]]; then
	# echo "$(date) : IMSI validations failed " 2>&1 >> /opt/nvtl/data/branding/log
printf $imsi > ${IMSI_FILE}
