#!/bin/sh
export LD_LIBRARY_PATH=/opt/nvtl/lib:$LD_LIBRARY_PATH
FEATURES_XML="/sysconf/features.xml"
NVTL_LOG="/opt/nvtl/bin/nvtl_log"

enable_eth()
{
    sed -i 's/<Ethernet>0/<Ethernet>1/' $FEATURES_XML
}

enable_usb_teth()
{
    sed -i 's/<USBTethering>0/<USBTethering>1/' $FEATURES_XML
}

disable_eth()
{
    sed -i 's/<Ethernet>1/<Ethernet>0/' $FEATURES_XML
}

disable_usb_teth()
{
    sed -i 's/<USBTethering>1/<USBTethering>0/' $FEATURES_XML
}

if [ $# -eq 0 ]; then
    disable_eth
    disable_usb_teth
    $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "USB_TETHRING and ETHERNET are Disabled."
    exit 1
elif [ $# -eq 1 ]; then
    if [ "$1" == "eth0" ]; then
      $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "USB_TETHRING-disabled, ETHERNET-Enabled."
      enable_eth
      disable_usb_teth
    elif [ "$1" == "eth.usb" ]; then
      enable_usb_teth
      disable_eth
      $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "USB_TETHRING-disabled, ETHERNET-Enabled."
    else
      $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "Invalid argument value provided."
      exit 0
    fi
elif [ $# -eq 2 ]; then
    if ([ "$1" == "eth0" ] && [ "$2" == "eth.usb" ]) || ([ "$2" == "eth0" ] && [ "$1" == "eth.usb" ]); then
      enable_usb_teth
      enable_eth
      $NVTL_LOG -p1 -m "LONGSHIP" -l notice -s "USB_TETHRING and ETHERNET are Enabled."
      exit 1
    else
      $NVTL_LOG -p1 -m "LONGSHIP" -l err -s "Bad arguments provided."
      exit 0
    fi
fi
