#! /bin/sh
CARRIER_COOKIE="/opt/nvtl/data/branding/carrier"
BRANDING_TAR="/opt/nvtl/data/branding/branding.tgz"
BRANDING_TMO_TAR="/opt/nvtl/data/branding/branding_tmo.tgz"
BRANDING_SPRINT_TAR="/opt/nvtl/data/branding/branding_sprint.tgz"
HFA_RUN="/opt/nvtl/data/omadm/hfa_run"
HFA_FLAG="/opt/nvtl/data/omadm/hfa_flag"
HFA_STAGE="/opt/nvtl/data/omadm/hfa_stage"
HFA_DISABLED="/opt/nvtl/data/omadm/hfa_disabled"
IMSI_FILE="/opt/nvtl/data/branding/imsi"
existing_imsi=""
curr_imsi=""
function log() {
	echo "$(date) : $1 " 2>&1 >> /opt/nvtl/data/branding/log
if [ -e "$BRANDING_TMO_TAR" ] && [ -e "$BRANDING_SPRINT_TAR" ]; then
	log "Determine the branding to apply...Sprint or TMO."
if [ -f "$IMSI_FILE" ]; then
	existing_imsi=$(cat ${IMSI_FILE})
# clear IMSI entry
rm -f $IMSI_FILE
# read IMSI from device using AT-CMD
# There is a chance that reading AT-CMD might get stuck for a long time.
# Lets do 10 retries with an interval of 2 sec
COUNTER=0 
while [ $COUNTER -lt 10 ]
	/opt/nvtl/bin/read_imsi.sh &
	sleep 2
	if [ ! -f "$IMSI_FILE" ]; then
		let COUNTER=COUNTER+1
if [ ! -f "$IMSI_FILE" ]; then
	log "Could not read IMSI"
	if [ ! -f "$CARRIER_COOKIE" ]; then
		log "Carrier not present, apply TMO branding"
		if [ -e "$BRANDING_TAR" ]; then
			rm -rf $BRANDING_TAR
		cp -f $BRANDING_TMO_TAR $BRANDING_TAR
		curr_carrier=$(cat ${CARRIER_COOKIE})
		if [[ "$curr_carrier" == "sprint" ]] || [[ "$curr_carrier" == "tmo" ]]; then
			log "Keeping old configurations as it is and exiting ..."
			exit 2
			log "Carrier is neither tmo nor sprint, apply TMO branding"
			if [ -e "$BRANDING_TAR" ]; then
				rm -rf $BRANDING_TAR
			cp -f $BRANDING_TMO_TAR $BRANDING_TAR
	curr_imsi=$(cat ${IMSI_FILE})
	log "previous_imsi:[${existing_imsi}], current_imsi:[${curr_imsi}]"
	if [[ "$existing_imsi" != "$curr_imsi" ]]; then
		if [ -e "$BRANDING_TAR" ]; then
			rm -rf $BRANDING_TAR
		if [ -e "$HFA_RUN" ]; then
			rm -rf $HFA_RUN
		if [ -e "$HFA_FLAG" ]; then
			rm -rf $HFA_FLAG
		if [ -e "$HFA_STAGE" ]; then
			rm -rf $HFA_STAGE
		if [ -e "$HFA_DISABLED" ]; then
			rm -rf $HFA_DISABLED
		imsi_id=$(printf ${curr_imsi}| cut -c 1-6)
		if [[ "$imsi_id" == "312530" ]] || [[ "$imsi_id" == "310120" ]]; then
			log "Apply SPRINT branding ... "
			cp -f $BRANDING_SPRINT_TAR $BRANDING_TAR
			log "Apply TMO branding"
			cp -f $BRANDING_TMO_TAR $BRANDING_TAR
		log "Same IMSI, nothing to do."
