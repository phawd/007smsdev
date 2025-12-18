#! /bin/sh
###########################################################################
# Script to backup and verify sys_config.xml
###########################################################################
XML_SAV_MD5=sav.md5
XML_CUR_MD5=cur.md5
BCK_FILE=bck
BCK_SAV_MD5=bck.sav.md5
BCK_CUR_MD5=bck.cur.md5
LOG_FILE=/tmp/xml.log
TOOL_CHANGED_FILE=/sysconf/tool_changed_xml
RUN_OP=0
###########################################################################
# Function to log message to file  
###########################################################################
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
###########################################################################
# Function to check run level.  Only do xml backup and validation operations  
# in run level 3 and 4.  
###########################################################################
check_run_level() {
#   logf "check run level"
    RUN_OP=0
    RUNLEVEL=`runlevel | awk '{ print $2 }'` 
    case $RUNLEVEL in
         "3")
         RUN_OP=1
         ;;
         "4")
         RUN_OP=1
         ;;
         *)
         RUN_OP=0
         ;;
    esac 
#   logf "runlevel $RUNLEVEL $RUN_OP" 
###########################################################################
# Function to backup xml file and checksum file
###########################################################################
backup_xml() {
    logf "$1: Called backup_xml" 
    cp -af $1 $1.$BCK_FILE
    cp -af $1.$XML_SAV_MD5 $1.$BCK_SAV_MD5
###########################################################################
# Function to restore backup xml file and checksum file
# This is used when original xml file failed checksum test
###########################################################################
restore_backup_xml() {
    logf "$1: Called restore_backup_xml"
    cp -af $1.$BCK_FILE $1
    cp -af $1.$BCK_SAV_MD5 $1.$XML_SAV_MD5
###########################################################################
# Function calculate checksum file
###########################################################################
calculate_checksum() {
    logf "$1: Called calculate_checksum"
    md5sum $1 | awk '{ print $1 }' > $1.$XML_SAV_MD5
###########################################################################
# Function to restore default config file 
###########################################################################
restore_default_xml() {
    logf "$1: Called restore_default_xml"
    cp -af $2 $1	
    calculate_checksum $1
###########################################################################
# Function to check for existence of special file indicating that xml file 
# has been changed externally.  In this case, ignore checksum and generate
# new checksum and backup. Remove special file once done. 
########################################################################### 
check_tool_changed_xml() {
    if [ -f $TOOL_CHANGED_FILE ]; then
        logf "xml files changed by external tool."
        logf "regenerate new checksum and backup for both active and default xml"
        calculate_checksum $1
        backup_xml $1    
        calculate_checksum $2
        rm -f $TOOL_CHANGED_FILE
    fi    
###########################################################################
###########################################################################
# Function to validate default xml checksum and if checksum fails then
# clear up md5 checksum and backup for both current and default xml files.  
# This is to handle case where the default xml ile was modified via configPro 
# or FOTA. 
########################################################################### 
check_default_xml() {
    if [ ! -f $2.$XML_SAV_MD5 ]; then
        logf "$2: No checksum file found. Generate checksum and create backup."
        calculate_checksum $2
    fi    
        
    md5sum $2 | awk '{ print $1 }' > $2.$XML_CUR_MD5
    if cmp -s $2.$XML_CUR_MD5 $2.$XML_SAV_MD5; then
        logf "$2: Default file has valid checksum" 
    else
        logf "$2: Default file failed checksum test" 
        logf "regenerate new checksum and backup for both active and default xml"
        calculate_checksum $1
        backup_xml $1    
        calculate_checksum $2
###########################################################################
# Function to validate xml checksum and restore backup or
# default xml file.
########################################################################### 
validate_xml() {
    logf "Called validate_xml $1 $2" 
# check for run level before validating. 
# can not do validation when file system is not available
# Only run level 3 or 4 will be able to validate xml.
    check_run_level
    if [ $RUN_OP -eq 0 ]; then
        return 0
    check_tool_changed_xml $1 $2
           
    check_default_xml $1 $2
    if [ ! -f $1 ]; then
        logf "$1: File not found. Create new config file using default $2."
        restore_default_xml $1 $2 
        backup_xml $1    
    fi        
    if [ ! -f $1.$XML_SAV_MD5 ]; then
        logf "$1: No checksum file found. Generate checksum and create backup."
        calculate_checksum $1
        backup_xml $1
    fi    
        
    md5sum $1 | awk '{ print $1 }' > $1.$XML_CUR_MD5
    if cmp -s $1.$XML_CUR_MD5 $1.$XML_SAV_MD5; then
        logf "$1: File has valid checksum" 
    else
        logf "$1: File failed checksum test" 
        md5sum $1.$BCK_FILE | awk '{ print $1 }' > $1.$BCK_CUR_MD5 
        if cmp -s $1.$BCK_CUR_MD5 $1.$BCK_SAV_MD5; then 
            logf "$1: Restore Backup" 
            restore_backup_xml $1
        else
            logf "$1: Backup XML failed chechsum test.  Restore from default."
            restore_default_xml $1 $2
            backup_xml $1    
        fi 
###########################################################################
# Execute user command
# of the format: <command> <filename> <default_filename>
# where <filename> will have full path name such as "/sysconf/sys_config.xml"
# or "/sysconf/ui_config.xml" and <default_filename> is "/sysconf/sys_def_config.xml"
# or "/sysconf/ui_def_config.xml"
###########################################################################
$1 $2 $3
# End of script
