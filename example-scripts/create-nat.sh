#!/bin/bash

# Note: This requires this instance to have Source/Dest check disabled.
# aws ec2 modify-instance-attribute --instance-id=<instID> --no-source-dest-check

echo "==> Setting up two-armed NAT"
echo Mode is $1, In Int is $2, Out Int is $3, ENI is $4

iptables -F
iptables -t nat -F
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i $2 -o eth0 -j ACCEPT

echo 1 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/$2/rp_filter
