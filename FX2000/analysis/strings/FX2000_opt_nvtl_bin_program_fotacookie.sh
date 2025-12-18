# Clear / set the FOTA cookie by writing to the appropriate /dev/mmcblk0pN partition.
# NOTE: Currently this works only for the Rockchip RK3128, model: rockchip,px3se-sdk
#       (grep Machine: /var/log/messages | grep -i rockchip; echo $?)
# program_fotacookie.sh <clr | set>
script=program_fotacookie.sh
case $1 in
	echo "Clearing FOTA cookie"
	logger -p syslog.info -t $script: "Clearing FOTA cookie"
	dd of=/dev/mmcblk0p2 if=/opt/nvtl/etc/mifi_update_agent/clr_fotacookie.data bs=512 count=1 &> /dev/null
	echo "Setting FOTA cookie"
	logger -p syslog.info -t $script: "Setting FOTA cookie"
	dd of=/dev/mmcblk0p2 if=/opt/nvtl/etc/mifi_update_agent/set_fotacookie.data bs=512 count=1 &> /dev/null
	echo "Usage $0 < clr | set >"
