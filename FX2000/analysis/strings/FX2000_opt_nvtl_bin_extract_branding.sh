#! /bin/sh
CARRIER_COOKIE="/opt/nvtl/data/branding/carrier"
CARRIER_INIT_COOKIE="/opt/nvtl/data/branding/carrier_init_done"
BRANDING_IPK="/opt/nvtl/data/branding/branding.ipk"
BRANDING_TAR="/opt/nvtl/data/branding/branding.tgz"
IMSI_FILE="/opt/nvtl/data/branding/imsi"
HFA_RUN="/opt/nvtl/data/omadm/hfa_run"
HFA_FLAG="/opt/nvtl/data/omadm/hfa_flag"
HFA_STAGE="/opt/nvtl/data/omadm/hfa_stage"
HFA_DISABLED="/opt/nvtl/data/omadm/hfa_disabled"
is_extraction_success=0
branding_tmo=""
function log() {
	echo "$(date) : $1 " 2>&1 >> /opt/nvtl/data/branding/log
if [ -e "$BRANDING_TAR" ]; then
	branding_tmo=$(tar tvf ${BRANDING_TAR} | grep branding_tmo.tgz | awk '{print $6}')
if [[ "$branding_tmo" == "branding_tmo.tgz" ]]; then
	log "Multiple branding pkgs found"
	curr_dir=$(pwd)
	cd /opt/nvtl/data/branding
	tar xvf ${BRANDING_TAR}
	if [ -e "$IMSI_FILE" ]; then
		rm -f $IMSI_FILE
	if [ -e "$HFA_RUN" ]; then
		rm -rf $HFA_RUN
	if [ -e "$HFA_FLAG" ]; then
		rm -rf $HFA_FLAG
	if [ -e "$HFA_STAGE" ]; then
		rm -rf $HFA_STAGE
	if [ -e "$HFA_DISABLED" ]; then
		rm -rf $HFA_DISABLED
	cd $curr_dir
/opt/nvtl/bin/choose_carrier_branding.sh
if [ -e "$BRANDING_IPK" ] || [ -e "$BRANDING_TAR" ]; then
	log "extract_branding - begin"
if [ -e "$BRANDING_IPK" ]; then
	log "branding.ipk found"
	log "current branding-version:[$(/usr/bin/ipkg-cl info branding | grep Version | awk '{print $2}')]"
	/usr/bin/ipkg-cl remove branding
	log "previously installed branding pkg removed."
	/usr/bin/ipkg-cl install $BRANDING_IPK
	if [ $? -eq 0 ]; then
		is_extraction_success=1
		log "branding.ipk extracted successfully"
		log "new branding-version:[$(/usr/bin/ipkg-cl info branding | grep Version | awk '{print $2}')]"
		#rm -rf $BRANDING_IPK
if [ -e "$BRANDING_TAR" ]; then
	log "branding.tgz found"
	if [ -e "/opt/nvtl/data/branding/version" ]; then
		log "current branding-version:[$(cat /opt/nvtl/data/branding/version)]"
	tar -xvf $BRANDING_TAR -C /
	if [ $? -eq 0 ]; then
		is_extraction_success=1
		log "branding.tgz extracted successfully"
		log "new branding-version:[$(cat /opt/nvtl/data/branding/version)')]"
		#rm -rf $BRANDING_TAR
if [ "$is_extraction_success" -eq 1 ]; then
	# branding.xml
	if [ -f "/sysconf/branding_new.xml" ]; then
		mv /sysconf/branding_new.xml /sysconf/branding.xml
		log "branding.xml copied successfully"
	if [ -d "/usr/share/locale_new" ]; then
		rm -rf /usr/share/locale
		mv /usr/share/locale_new /usr/share/locale
		log "branding_i18n copied successfully"
	# webui
	if [ -d "/opt/nvtl/webui/public_new" ]; then
		cp -r /opt/nvtl/webui/public/cgi /opt/nvtl/webui/public_new/
		rm -rf /opt/nvtl/webui/public
		mv /opt/nvtl/webui/public_new /opt/nvtl/webui/public
		log "branding_webui_apps_themes copied successfully"
	# configurations
	if [ -d "/opt/nvtl/data/branding/etc_new" ]; then
		rm -rf /opt/nvtl/data/branding/etc
		mv /opt/nvtl/data/branding/etc_new /opt/nvtl/data/branding/etc
		log "branding_configs copied successfully"
	# deviceui images
	if [ -d "/opt/nvtl/data/branding/deviceui_new" ]; then
		rm -rf /opt/nvtl/data/branding/deviceui
		mv /opt/nvtl/data/branding/deviceui_new /opt/nvtl/data/branding/deviceui
		log "branding_devui_images copied successfully"
	# lpm images
	if [ -d "/opt/nvtl/data/branding/lpm_new" ]; then
		rm -rf /opt/nvtl/data/branding/lpm
		mv /opt/nvtl/data/branding/lpm_new /opt/nvtl/data/branding/lpm
		log "branding_lpm_images copied successfully"
	# startup
	if [ -d "/opt/nvtl/data/branding/startup_new" ]; then
		rm -rf /opt/nvtl/data/branding/startup
		mv /opt/nvtl/data/branding/startup_new /opt/nvtl/data/branding/startup
		log "branding_startup copied successfully"
	if [ -d "/opt/nvtl/data/branding/wdcp_new" ]; then
		rm -rf /opt/nvtl/data/branding/wdcp
		mv /opt/nvtl/data/branding/wdcp_new /opt/nvtl/data/branding/wdcp
		log "branding_wdcp copied successfully"
	rm -f /opt/nvtl/data/branding/bin/*
	rm -rf /opt/nvtl/data/branding/lib
	mkdir -p /opt/nvtl/data/branding/lib/settings
	mkdir -p /opt/nvtl/data/branding/lib/factory_reset
	rm -rf $CARRIER_INIT_COOKIE
	rm -rf $CARRIER_COOKIE
	log "deleted carrier_init_cookie"
if [ -e "$BRANDING_IPK" ] || [ -e "$BRANDING_TAR" ]; then
	log "extract_branding - end"
