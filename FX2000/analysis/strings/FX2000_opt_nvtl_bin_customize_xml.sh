#! /bin/sh
###########################################################################
# Script to merge an xml customization file into PRI'd configuration and user settings
###########################################################################
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
SYS_DEF_CFG_FILE=/sysconf/sys_def_config.xml
SYS_DEF_CUST_FILE=/sysconf/sys_def_cust.xml
SYS_DEF_CUST_TEMPLATE=/sysconf/sys_def_cust.tmpl
SYS_CFG_FILE=/sysconf/sys_config.xml
UI_DEF_CFG_FILE=/sysconf/ui_def_config.xml
UI_DEF_CUST_FILE=/sysconf/ui_def_cust.xml
UI_DEF_CUST_TEMPLATE=/sysconf/ui_def_cust.tmpl
UI_CFG_FILE=/sysconf/ui_config.xml
XML_MERGE=/opt/nvtl/bin/xmlmergecust
XML_VALIDATE=/opt/nvtl/bin/xmlvalidate
LOG_FILE=/tmp/xmlcust.log
FILE_CHANGED=0
EXIT_CODE=0
RESTORE_EXIT_CODE=112
logf() {
	# check for existence of log file if not then create and set mode to 666
	# to allow any process to read or write to log file  
	if [ ! -f $LOG_FILE ]; then
		touch $LOG_FILE
        	chmod 666 $LOG_FILE
        	logf "Create $LOG_FILE"
    	fi 
	# append log entry to log file    
	dt=$(date +"%Y-%m-%d %T")
	echo $dt $1 >> $LOG_FILE
################################################################
##  Check to see if the input file either has no md5 hash
##  or if the hash file is out of date indicating a change of the xml
################################################################
check_file_changed(){
    FNAME=$1
    FMD5="${FNAME}.sav.md5"
    TEMP_FILE_MD5=/tmp/tmp.md5
    if [ -f $FNAME ]
    then
        if [ -f $FMD5 ]
        then
            calculate_checksum $FNAME $TEMP_FILE_MD5
            if cmp -s $FMD5 $TEMP_FILE_MD5; then
                logf "$FNAME: File has valid checksum" 
    	    else
                logf "$FNAME: file has changed!"
                FILE_CHANGED=2
            fi
        else
            logf "$FNAME: File has no checksum"  
            #calculate_checksum $FNAME $FMD5
            FILE_CHANGED=1
        fi
################################################################
##  Use the xmlmergecust utility to merge the customization xml tags
##  onto the destination xml
################################################################
merge_xml_files(){
   SRC_FILE=$1
   DEST_FILE=$2
   TMPL_FILE=$3
   IS_VALID=0
   logf "Merging file $SRC_FILE into $DEST_FILE"
   #create a temporary working copy so that we can validate the result afterwards
   cp ${DEST_FILE} ${DEST_FILE}.tmp
   #do the merge
   if [ -f $TMPL_FILE ]; then
       $XML_MERGE $SRC_FILE "${DEST_FILE}.tmp" $TMPL_FILE
       $XML_MERGE $SRC_FILE "${DEST_FILE}.tmp"
   #validate the resultant tmp file can be parsed by xml parser
   logf "Validating newly merged XML file ${DEST_FILE}.tmp"
   IS_VALID=`$XML_VALIDATE "${DEST_FILE}.tmp"`
   if [ $IS_VALID -eq 1 ]
        logf "XML Validation of ${DEST_FILE}.tmp succeeded"
        mv "${DEST_FILE}.tmp" ${DEST_FILE}
   	calculate_checksum $SRC_FILE "${SRC_FILE}.sav.md5"
   	calculate_checksum $DEST_FILE "${DEST_FILE}.sav.md5"
        log "XML validation failed for ${DEST_FILE}.tmp"
        rm "${DEST_FILE}.tmp"
################################################################
##  Create a file containing the md5 hash of the input file
################################################################
calculate_checksum() {
    logf "$1: Called calculate_checksum"
    md5sum $1 | awk '{ print $1 }' > $2
################################################################
##  during bootup make sure the ui_config.xml or sys_config.xml
##  exist. if not, copy them from their PRI defaults
################################################################
ensure_user_cfg_file_exists(){
    CFG_FILE=$1
    USR_FILE=$2
    if [ ! -f $USR_FILE ]
    then
        if [ -f $CFG_FILE ]
        then
	    logf "User copy of $USR_FILE does not exist, creating"
            cp $CFG_FILE $USR_FILE
            logf "Creating md5 checksum of new copy of $USR_FILE"
            calculate_checksum $USR_FILE "${USR_FILE}.sav.md5"
        fi
####################################################################
##  Check the customization xml and the master PRI xml for changes
##  if they have changed, then apply the customization to the files
####################################################################
apply_customization(){
    CUST_FILE=$1
    CFG_FILE=$2
    USR_FILE=$3
    TMPL_FILE=$4
    FILE_CHANGED=0
    ensure_user_cfg_file_exists $CFG_FILE $USR_FILE
    if [ -f $CUST_FILE ]
    then
        logf "$CUST_FILE Customization file found, checking for modifications.."
        check_file_changed $CUST_FILE
        if [ $FILE_CHANGED -ne 2 ]                                         
        then                                                                    
            check_file_changed $CFG_FILE
            calculate_checksum $CFG_FILE "${CFG_FILE}.sav.md5"                                    
        fi                                                                      
    else
        logf "$CUST_FILE not found"
    if [ $FILE_CHANGED -eq 1 ]
    then
       logf "Customization or config files changed, applying customization"
       #update only the current user file, don't touch the PRI default
       merge_xml_files $CUST_FILE $USR_FILE $TMPL_FILE
       calculate_checksum $CUST_FILE "${CUST_FILE}.sav.md5"
    elif [ $FILE_CHANGED -eq 2 ]
    then
    	EXIT_CODE=$RESTORE_EXIT_CODE
    else
       logf "no need to apply customization"
apply_customization $SYS_DEF_CUST_FILE $SYS_DEF_CFG_FILE $SYS_CFG_FILE $SYS_DEF_CUST_TEMPLATE
apply_customization $UI_DEF_CUST_FILE $UI_DEF_CFG_FILE $UI_CFG_FILE $UI_DEF_CUST_TEMPLATE
exit $EXIT_CODE
