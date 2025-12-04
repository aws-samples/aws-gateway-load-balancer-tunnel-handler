#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. This material is AWS Content under the AWS Enterprise Agreement 
# or AWS Customer Agreement (as applicable) and is provided under the AWS Intellectual Property License.

# Note: This requires this instance to have Source/Dest check disabled.
# aws ec2 modify-instance-attribute --instance-id=<instID> --no-source-dest-check

echo Mode is $1, In Int is $2, Out Int is $3, ENI is $4

# Get our output interface (eth0, ens5, etc)
OUTINT=`ip route show default | cut -f 5 -d ' '`

if [ "$1" = "CREATE" ]; then
  echo "==> Setting up two-armed NAT"

  iptables -t nat -A POSTROUTING -o $OUTINT -j MASQUERADE
  iptables -A FORWARD -i $2 -o $OUTINT -j ACCEPT
  ip6tables -t nat -A POSTROUTING -o $OUTINT -j MASQUERADE
  ip6tables -A FORWARD -i $2 -o $OUTINT -j ACCEPT

  echo 1 > /proc/sys/net/ipv4/ip_forward
  echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
  echo 0 > /proc/sys/net/ipv4/conf/$2/rp_filter
  echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
else
  echo "==> Destroying up two-armed NAT"

  iptables -t nat -D POSTROUTING -o $OUTINT -j MASQUERADE
  iptables -D FORWARD -i $2 -o $OUTINT -j ACCEPT
  ip6tables -t nat -D POSTROUTING -o $OUTINT -j MASQUERADE
  ip6tables -D FORWARD -i $2 -o $OUTINT -j ACCEPT
fi
