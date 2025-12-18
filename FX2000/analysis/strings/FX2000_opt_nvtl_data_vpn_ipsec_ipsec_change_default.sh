#Script to Change IPSec Default Behavior.
#Usage- sh <script-name>
#!/bin/sh
CHARON_CONFIG="/etc/strongswan.d/charon.conf"
sed -i 's/# retransmit_base/retransmit_base/' $CHARON_CONFIG
sed -i 's/# retransmit_jitter/retransmit_jitter/' $CHARON_CONFIG
sed -i 's/# retransmit_limit = 0/retransmit_limit = 120/' $CHARON_CONFIG
sed -i 's/# retransmit_timeout/retransmit_timeout/' $CHARON_CONFIG
sed -i 's/# retransmit_tries/retransmit_tries/' $CHARON_CONFIG
sed -i 's/# make_before_break = no/make_before_break = yes/' $CHARON_CONFIG
ipsec reload &
