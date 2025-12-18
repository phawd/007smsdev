#!/bin/sh
agent="$1"
input="/opt/nvtl/data/branding/carrier"
SRC_ETC=/opt/nvtl/etc
SRC_LIB=/opt/nvtl/lib
SRC_BIN=/opt/nvtl/bin
BRANDING_DIR=/opt/nvtl/data/branding
BRANDING_BIN_DIR=$BRANDING_DIR/bin
BRANDING_LIB_DIR=$BRANDING_DIR/lib
BRANDING_DUA_ETC_DIR=$BRANDING_DIR/etc/dua
check_carrier_and_copy()
	if [ -n "$agent" ]; then
		val=$agent
		nvtl_log -p 0 -m DUA -l debug -s "carrier for dua is='$val'"
		if [ -e "$input" ]; then
			val=$(sed -nr '1s/^([^ ]+).*/\1/p' "$input")
			nvtl_log -p 0 -m DUA -l debug -s "Carrier is='$val'"
			nvtl_log -p 1 -m DUA -l err -s "Carrier not found, exiting..."
			exit 2
	if [ ! -d "$BRANDING_BIN_DIR" ]; then
                mkdir -p $BRANDING_BIN_DIR
        fi
	if [ ! -d "$BRANDING_DUA_ETC_DIR" ]; then
		mkdir -p $BRANDING_DUA_ETC_DIR
	nvtl_log -p 0 -m DUA -l notice -s "Copying all files related to $val..."
	case $val in
		[bB][eE][lL][lL])	
			if [ ! -e "$BRANDING_DUA_ETC_DIR/config.xml" ]; then
				cp $SRC_ETC/dua/config_insg.xml $BRANDING_DUA_ETC_DIR/config.xml
			if [ ! -e "$BRANDING_LIB_DIR/libdua_api.so" ]; then
				ln -s $SRC_LIB/libdua_insg_api.so $BRANDING_LIB_DIR/libdua_api.so
			if [ ! -e "$BRANDING_LIB_DIR/settings/libdua_api.so" ]; then
				ln -s $SRC_LIB/libdua_insg_api.so $BRANDING_LIB_DIR/settings/libdua_api.so
			if [ ! -e "$BRANDING_BIN_DIR/duad" ]; then
				ln -s $SRC_BIN/duad_insg $BRANDING_BIN_DIR/duad
			if [ ! -e "$BRANDING_BIN_DIR/dua_cli" ]; then
				ln -s $SRC_BIN/dua_insg_cli $BRANDING_BIN_DIR/dua_cli
		[aA][tT][tT] | [aA][tT]"&"[tT] | [aA][tT][nN][tT])
			if [ ! -e "$BRANDING_DUA_ETC_DIR/config.xml" ]; then
				cp $SRC_ETC/dua/config_insg.xml $BRANDING_DUA_ETC_DIR/config.xml
			if [ ! -e "$BRANDING_LIB_DIR/libdua_api.so" ]; then
				ln -s $SRC_LIB/libdua_insg_api.so $BRANDING_LIB_DIR/libdua_api.so
			if [ ! -e "$BRANDING_LIB_DIR/settings/libdua_api.so" ]; then
				ln -s $SRC_LIB/libdua_insg_api.so $BRANDING_LIB_DIR/settings/libdua_api.so
			if [ ! -e "$BRANDING_BIN_DIR/duad" ]; then
				ln -s $SRC_BIN/duad_insg $BRANDING_BIN_DIR/duad
			if [ ! -e "$BRANDING_BIN_DIR/dua_cli" ]; then
				ln -s $SRC_BIN/dua_insg_cli $BRANDING_BIN_DIR/dua_cli
		[sS][pP][rR][iI][nN][tT])
			if [ ! -e "$BRANDING_DUA_ETC_DIR/config.xml" ]; then
				cp $SRC_ETC/dua/config_insg.xml $BRANDING_DUA_ETC_DIR/config.xml
			if [ ! -e "$BRANDING_LIB_DIR/libdua_api.so" ]; then
				ln -s $SRC_LIB/libdua_insg_api.so $BRANDING_LIB_DIR/libdua_api.so
			if [ ! -e "$BRANDING_LIB_DIR/settings/libdua_api.so" ]; then
				ln -s $SRC_LIB/libdua_insg_api.so $BRANDING_LIB_DIR/settings/libdua_api.so
			if [ ! -e "$BRANDING_BIN_DIR/duad" ]; then
				ln -s $SRC_BIN/duad_insg $BRANDING_BIN_DIR/duad
			if [ ! -e "$BRANDING_BIN_DIR/dua_cli" ]; then
				ln -s $SRC_BIN/dua_insg_cli $BRANDING_BIN_DIR/dua_cli
		[iI][nN][sS][gG])
			if [ ! -e "$BRANDING_DUA_ETC_DIR/config.xml" ]; then
				cp $SRC_ETC/dua/config_insg.xml $BRANDING_DUA_ETC_DIR/config.xml
			if [ ! -e "$BRANDING_LIB_DIR/libdua_api.so" ]; then
				ln -s $SRC_LIB/libdua_insg_api.so $BRANDING_LIB_DIR/libdua_api.so
			if [ ! -e "$BRANDING_LIB_DIR/settings/libdua_api.so" ]; then
				ln -s $SRC_LIB/libdua_insg_api.so $BRANDING_LIB_DIR/settings/libdua_api.so
			if [ ! -e "$BRANDING_BIN_DIR/duad" ]; then
				ln -s $SRC_BIN/duad_insg $BRANDING_BIN_DIR/duad
			if [ ! -e "$BRANDING_BIN_DIR/dua_cli" ]; then
				ln -s $SRC_BIN/dua_insg_cli $BRANDING_BIN_DIR/dua_cli
		[vV][zZ][wW] | [vV][eE][rR][iI][zZ][oO][nN])
			if [ ! -e "$BRANDING_DUA_ETC_DIR/config.xml" ]; then
				cp $SRC_ETC/dua/config_vzw.xml $BRANDING_DUA_ETC_DIR/config.xml
			if [ ! -e "$BRANDING_LIB_DIR/libdua_api.so" ]; then
				ln -s $SRC_LIB/libdua_vzw_api.so $BRANDING_LIB_DIR/libdua_api.so
			if [ ! -e "$BRANDING_LIB_DIR/settings/libdua_api.so" ]; then
				ln -s $SRC_LIB/libdua_vzw_api.so $BRANDING_LIB_DIR/settings/libdua_api.so
			if [ ! -e "$BRANDING_BIN_DIR/duad" ]; then
				ln -s $SRC_BIN/duad_vzw $BRANDING_BIN_DIR/duad
			if [ ! -e "$BRANDING_BIN_DIR/dua_cli" ]; then
				ln -s $SRC_BIN/dua_vzw_cli $BRANDING_BIN_DIR/dua_cli
			nvtl_log -p 1 -m DUA -l err -s "Invalid carrier name... '$val'"
			exit 2
	nvtl_log -p 0 -m DUA -l notice -s "Done" 
##############
##############
check_carrier_and_copy
