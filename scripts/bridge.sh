#!/bin/bash

# disable hR's links with s1 and s3
ifconfig hR-eth0 0.0.0.0 down
ifconfig hR-eth1 0.0.0.0 down

# set up a network bridge (invisible link through h3)
brctl addbr hR-br0
brctl addif hR-br0 hR-eth0
brctl addif hR-br0 hR-eth1

# allow lldp forwarding over the bridge
echo 16384 > /sys/class/net/hR-br0/bridge/group_fwd_mask

# re-connect to switches using invisible link
ifconfig hR-eth0 up
ifconfig hR-eth1 up
ifconfig hR-br0 up
