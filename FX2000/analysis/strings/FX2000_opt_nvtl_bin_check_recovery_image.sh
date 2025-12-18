# check_recovery_image.sh
# Using the file /opt/nvtl/etc/system/recovery_image.ref this script reads the recovery image
# from NAND, gets the md5sum of the image, and compares it against the reference.
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/nvtl/lib
pname=check_recovery_image.sh
# Get the reference values
if [ ! -f /opt/nvtl/etc/system/recovery_image.ref ]; then
	echo "$pname: reference file /opt/nvtl/etc/system/recovery_image.ref is missing"
	# Create the failed indicator file
	touch /tmp/recovery_image_success
recovery_len=`grep recovery_len /opt/nvtl/etc/system/recovery_image.ref  | awk -F = '{ print $2 }'`
recovery_md5=`grep recovery_md5 /opt/nvtl/etc/system/recovery_image.ref  | awk -F = '{ print $2 }'`
# Read the image
rm -f /tmp/recovery.img
echo "$pname: reading recovery image from NAND"
/opt/nvtl/bin/tests/mifi_mtd_test -p recovery -r 0 -l $recovery_len -O /tmp/recovery.img
if [ $? -ne 0 ]; then
	echo "$pname: mifi_mtd_test -p recovery -r 0 -l $recovery_len -O /tmp/recovery.img failed"
	# Create the failed indicator file
	touch /tmp/recovery_image_fail
	rm -f /tmp/recovery.img
# Calculate the md5sum and compare it to the reference
echo "$pname: calculating md5sum"
md5=`md5sum /tmp/recovery.img | awk '{ print $1 }'`
if [ "$md5" != "$recovery_md5" ]; then
	echo "$pname: md5 reference $recovery_md5 does not match calculated value $md5"
	# Create the failed indicator file
	touch /tmp/recovery_image_fail
	rm -f /tmp/recovery.img
# Remove the failed indicator file and create the success indicator file
touch /tmp/recovery_image_success
rm -f /tmp/recovery.img
echo "$pname: success"
