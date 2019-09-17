#!/bin/bash

# disable h3's links with s1 and s3
ifconfig h3-eth0 0.0.0.0 down
ifconfig h3-eth1 0.0.0.0 down

# set up a network bridge (invisible link through h3)
brctl addbr h3-br0
brctl addif h3-br0 h3-eth0
brctl addif h3-br0 h3-eth1

# allow lldp forwarding over the bridge
echo 16384 > /sys/class/net/h3-br0/bridge/group_fwd_mask

# re-connect to switches using invisible link
ifconfig h3-eth0 up
ifconfig h3-eth1 up
ifconfig h3-br0 up
