#!/usr/bin/env sh
#
# The Qualcomm prebuilt packages have post install scripts that use /usr/sbin/update-rc.d.
# We don't want these post install scripts to do anything so we just return 0 with this script.

exit 0
