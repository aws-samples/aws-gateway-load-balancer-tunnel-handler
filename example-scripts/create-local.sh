#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. This material is AWS Content under the AWS Enterprise Agreement 
# or AWS Customer Agreement (as applicable) and is provided under the AWS Intellectual Property License.

# This version of the create script makes it so locally-hosted services can answer and reply backc through GWLB
# correctly.

# This requires the following packages to be installed:
# yum install iproute iptables

echo Mode is $1, In Int is $2, Out Int is $3, ENI is $4

if [ "$1" = "CREATE" ]; then
  echo "==> Setting up local server support"

  # Make sure conntrack mod is installed
  modprobe ip_conntrack

  # Set up the route table
  ip route flush table 100
  ip -6 route flush table 100
  ip route add 0.0.0.0/0 dev $3 table 100
  ip -6 route add ::/0 dev $3 table 100

  # Set up route rules and tables to ensure traffic goes back out the interface we got it from for traffic seen from gwi
  # Traffic outbound - set a mark on ingress and save it on egress to CONNMARK for restoring on inbound
  iptables -t mangle -F PREROUTING
  iptables -t mangle -F POSTROUTING
  ip6tables -t mangle -F PREROUTING
  ip6tables -t mangle -F POSTROUTING

  # Set locally-sourced traffic to use gwo if appropriate
  iptables -t mangle -A OUTPUT -j CONNMARK --restore-mark

  # Set marks on traffic coming in from GWI, and ensure they're saved
  iptables -t mangle -A PREROUTING -i $2 -j MARK --set-mark 100
  iptables -t mangle -A PREROUTING -i $2 -j CONNMARK --save-mark
  ip6tables -t mangle -A PREROUTING -i $2 -j MARK --set-mark 100
  ip6tables -t mangle -A PREROUTING -i $2 -j CONNMARK --save-mark

  # And now anything marked 100 goes to our table 100
  ip rule add fwmark 100 table 100
  ip -6 rule add fwmark 100 table 100

  echo 1 > /proc/sys/net/ipv4/ip_forward
  echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
  echo 0 > /proc/sys/net/ipv4/conf/$2/rp_filter
  echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
else
  echo "==> Destroying local server support"

  # Delete our rules we created
  ip rule del table $4
  ip rule del table $4
  ip -6 rule del table $4
  ip -6 rule del table $4

fi
