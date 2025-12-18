#!/bin/sh
export SHELL=/bin/sh PATH=$PATH:/opt/nvtl/bin LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
# SYSTEM  FILES
HOMEDIR=/opt/nvtl/data/fota
STAGING=$HOMEDIR/staging
BINDIR=/opt/nvtl/bin/tests
LOGFILE=update_log
LOG=$HOMEDIR/$LOGFILE
#Device files
SYSCONF_DIR=/sysconf
if [ "$#" -eq 1 ]; then
	SYSCONF_DIR=$1
elif [ "$#" -eq 2 ]; then
	SYSCONF_DIR=$1
	STAGING=$2
DEF_SETTINGS_XML=$SYSCONF_DIR/settings_def.xml
SETTINGS_XML=$SYSCONF_DIR/settings.xml
FEATURES_XML=$SYSCONF_DIR/features.xml
#New config file from PRI
FOTA_PKG_SETTINGS_DEF_XML=$STAGING/settings_def.xml
 #Old config file from PRI
FOTA_PKG_OLD_SETTINGS_DEF_XML=$STAGING/orig_settings_def.xml
#features.xml from New PRI
FOTA_PKG_FEATURES_XML=$STAGING/features.xml
#xpath_cross_merge.xml if present handle cross merge of some xpath
FOTA_PKG_XPATH_CROSS_MERGE_XML=$STAGING/xpath_cross_merge.xml
FOTA_CFG_XML_UPDATER=$BINDIR/fota_cfg_xml_updater
FOTA_CFG_XML_UPDATER_FROM_PKG=$STAGING/fota_cfg_xml_updater
WORKING_COPY="$STAGING/working_copy.xml"
OLD_USER_COPY="$STAGING/old_user_copy.xml"
sync_to_disk()
	echo "FOTA_LINUX_PRI: Sync to Disk"  >>$LOG
critical_merge_error()
	tam_def_config=$2
	device_def_config=$3
	device_user_config=$4
	echo "FOTA_LINUX_PRI: Error: $msg" >>$LOG
	echo "FOTA_LINUX_PRI: Copying Tam default config($tam_def_config) to device default config($device_def_config)" >>$LOG
	cp -f $tam_def_config $device_def_config
	#rm -f $device_user_config
	cp -f $tam_def_config $device_user_config
	sync_to_disk 
user_config_merge_error()
	msg=$1	
	device_def_config=$2
	device_user_config=$3
	echo "FOTA_LINUX_PRI: Error: $msg" >>$LOG
	echo "FOTA_LINUX_PRI: Copying Device default config($device_def_config) to User config($device_user_config)" >>$LOG
	cp -f $device_def_config  $device_user_config
	sync_to_disk	 
# Return values: No-error/Success - 0; Failure - 1; Critical - 2
fota_update_linux_config_files()
	tam_new_def_config=$1	 		
	tam_old_def_config=$2	
	device_def_config=$3
	device_user_config=$4
	type=$5
	xpath_cross_merge=$6
	ret_result=0
	#Check TAM new and old Def files, if not present then nothing to do
	if [ ! -f "$tam_new_def_config" ] || [ ! -f "$tam_old_def_config" ]; then
		echo "FOTA_LINUX_PRI: No need to update $type default & user files" >>$LOG
		if [ -f "$tam_new_def_config" ]; then 
			if [ ! -f "$device_def_config" ]; then
				#First remove the extra files in sysconf dir
				rm -f $device_def_config.*
				rm -f $device_user_config.*
				critical_merge_error "$device_def_config not found!" $tam_new_def_config $device_def_config $device_user_config
				return 2		 
			#Validate files to make sure they are ok 
			echo "FOTA_LINUX_PRI: ########Validating--- ($device_def_config)"  >>$LOG
			$FOTA_CFG_XML_UPDATER  -o $device_def_config >>$LOG 2>&1
			ret=$?
			if [ "$ret" -ne "0" ]; then
				#First remove the extra files in sysconf dir
				rm -f $device_def_config.*
				rm -f $device_user_config.*
				critical_merge_error "Validation of $device_def_config file failed!" $tam_new_def_config $device_def_config $device_user_config			 
				return 2
			echo "FOTA_LINUX_PRI: *******Validation successful--- ($device_def_config)"  >>$LOG
			if [ -f $device_user_config ]; then 
				#Do a Pre-Validation to detect if the device user config file is valid 
				echo "FOTA_LINUX_PRI: ########Validating--- ($device_user_config)"  >>$LOG
				$FOTA_CFG_XML_UPDATER  -o $device_user_config >>$LOG 2>&1
				ret=$?
				if [ "$ret" -ne "0" ]; then
					rm -f $device_user_config.*
					user_config_merge_error "Present user with default settings!" $device_def_config $device_user_config			 
					return 1
				echo "FOTA_LINUX_PRI: *******Validation successful--- ($device_user_config)"  >>$LOG
		return 0		
	echo " " >>$LOG
	echo "FOTA_LINUX_PRI: ---------Updating both $type files--------" >>$LOG
	#First remove the extra files in sysconf dir
	rm -f $device_def_config.*
	rm -f $device_user_config.*
	if [ ! -f "$device_def_config" ]; then
		critical_merge_error "$device_def_config not found!" $tam_new_def_config $device_def_config $device_user_config
		return 2		 
	#Backup device_def_config and work on the backup copy	
 	cp -f $device_def_config  $WORKING_COPY
	#Do a Pre-Validation to detect if the device def file is valid 
	echo "FOTA_LINUX_PRI: ########Pre-Validating--- ($device_def_config)"  >>$LOG
	$FOTA_CFG_XML_UPDATER  -o $WORKING_COPY >>$LOG 2>&1
	if [ "$ret" -ne "0" ]; then
		critical_merge_error "Validation of $device_def_config file failed!" $tam_new_def_config $device_def_config $device_user_config			 
		return 2
	echo "FOTA_LINUX_PRI: #######Starting to update:$device_def_config"  >>$LOG
	$FOTA_CFG_XML_UPDATER  -s $tam_old_def_config -n $tam_new_def_config -d $WORKING_COPY  >>$LOG 2>&1
	if [ "$ret"  -ne "0" ]; then
		echo "FOTA_LINUX_PRI: Error: XML update failed for default settings ($device_def_config), ret=$ret"  >>$LOG
		critical_merge_error "Merge completely Failed!" $tam_new_def_config $device_def_config $device_user_config
		return 2;		
	cp -f $WORKING_COPY  $device_def_config 
	echo "FOTA_LINUX_PRI: ******Default settings successfully updated ($device_def_config)"  >>$LOG
	sync_to_disk; 
	#Now, Validate the Updated config file 
	echo "FOTA_LINUX_PRI: ########Validating--- ($device_def_config)"  >>$LOG
	$FOTA_CFG_XML_UPDATER  -o $device_def_config >>$LOG 2>&1
	if [ "$ret" -ne "0" ]; then
		critical_merge_error "Validation of $device_def_config file failed!" $tam_new_def_config $device_def_config $device_user_config			 
		return 2
	echo "FOTA_LINUX_PRI: *******Validation successful--- ($device_def_config)"  >>$LOG
	#Do a Pre-Validation to detect if the device user settings file is valid
	if [ -f  "$device_user_config" ]; then
		echo "FOTA_LINUX_PRI: ########Pre-Validating--- ($device_user_config)"  >>$LOG
		$FOTA_CFG_XML_UPDATER  -o $device_user_config >>$LOG 2>&1
		ret=$?
		if [ "$ret" -ne "0" ]; then
			user_config_merge_error "Present user with default settings!" $device_def_config $device_user_config			 
			return 1
		echo "FOTA_LINUX_PRI: *******Pre-Validation successful--- ($device_user_config)"  >>$LOG
		echo "FOTA_LINUX_PRI: $device_user_config file is not present and Default settings applied"  >>$LOG
	if [ -f "$xpath_cross_merge" ]; then
		#Backup default config and then work on that
		rm -f $OLD_USER_COPY		
		cp -f $device_user_config  $OLD_USER_COPY				
	#Now deal with User config
	if [ -f "$device_user_config" ]; then 
		echo " ">>$LOG
		echo "FOTA_LINUX_PRI: #######Starting to update:$device_user_config"  >>$LOG
		#Backup default config and then work on that
		rm -f $WORKING_COPY		
		cp -f $device_user_config  $WORKING_COPY
		$FOTA_CFG_XML_UPDATER  -s $tam_old_def_config -n $tam_new_def_config -d $WORKING_COPY >>$LOG 2>&1
		ret=$?
		if [ "$ret" -eq "0" ]; then
			cp -f $WORKING_COPY  $device_user_config
			sync_to_disk;
			echo "FOTA_LINUX_PRI: ******User settings successfully updated ($device_user_config)"  >>$LOG
			if [ -f "$xpath_cross_merge" ]; then
				rm -f $WORKING_COPY
				echo "FOTA_LINUX_PRI: ******Starting Cross-merge of XPATH"  >>$LOG				
				$FOTA_CFG_XML_UPDATER -c -s $OLD_USER_COPY -n $device_user_config -d $WORKING_COPY -t $xpath_cross_merge >>$LOG 2>&1
				ret=$?
				if [ "$ret" -eq "0" ]; then
					cp -f $WORKING_COPY  $device_user_config
					echo "FOTA_LINUX_PRI: ******Cross-merge successful"  >>$LOG
				else
					echo "FOTA_LINUX_PRI: ******Error: cross-merge failed, continue"  >>$LOG
			fi			
			#Now, validate the merged user settings file 
			echo "FOTA_LINUX_PRI: ########Validating--- ($device_user_config)"  >>$LOG
			$FOTA_CFG_XML_UPDATER  -o $device_user_config >>$LOG 2>&1
			ret=$?
			if [ "$ret" -eq "0" ]; then
				sync_to_disk;
				echo "FOTA_LINUX_PRI: *******Validation successful--- ($device_user_config)"  >>$LOG
				return $ret_result;	
			fi			
			echo "FOTA_LINUX_PRI: Error: Validation of $device_user_config file failed" >>$LOG			
		else						
			echo "FOTA_LINUX_PRI: Error: Merge of user settings file failed($device_user_config), ret=$ret"  >>$LOG									 			
		user_config_merge_error "Present user with default settings!" $device_def_config $device_user_config		
		return 1;
	return $ret_result;	
#Linux PRI error codes, this script should return
# For SYS -- 1, 2
# For UI -- 3, 6
#Start....
RET_VAL=0
if [ -f $FOTA_PKG_FEATURES_XML ] ; then
	rm -rf $FEATURES_XML*
	cp -f $FOTA_PKG_FEATURES_XML $FEATURES_XML
	echo "FOTA_LINUX_PRI: Replaced features.xml file" >> $LOG
	sync_to_disk;
#Incase, if we want to use XML updater from the DLPKG
if [ -f "$FOTA_CFG_XML_UPDATER_FROM_PKG" ]; then
	echo "FOTA_LINUX_PRI: Found $FOTA_CFG_XML_UPDATER_FROM_PKG, using it..." >> $LOG
	FOTA_CFG_XML_UPDATER=$FOTA_CFG_XML_UPDATER_FROM_PKG
	chmod 777 $FOTA_CFG_XML_UPDATER
if [ -f "$FOTA_CFG_XML_UPDATER" ]; then
	fota_update_linux_config_files $FOTA_PKG_SETTINGS_DEF_XML $FOTA_PKG_OLD_SETTINGS_DEF_XML $DEF_SETTINGS_XML $SETTINGS_XML "Setting" $FOTA_PKG_XPATH_CROSS_MERGE_XML
	if [ "$ret"  -ne "0" ]; then
		echo "FOTA_LINUX_PRI: Error: Failed to update setting files:$ret" >> $LOG
		RET_VAL=$ret
	sync_to_disk;	
echo "FOTA_LINUX_PRI: $0 -- RET_VAL=$RET_VAL"  >>$LOG
exit $RET_VAL
