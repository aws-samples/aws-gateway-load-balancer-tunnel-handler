#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Note: This requires this instance to have Source/Dest check disabled, as for any NAT instance (https://docs.aws.amazon.com/vpc/latest/userguide/work-with-nat-instances.html).
# aws ec2 modify-instance-attribute --instance-id=<instID> --no-source-dest-check

echo Mode is $1, In Int is $2, Out Int is $3, ENI is $4

# Get our output interface (eth0, ens5, etc)
OUTINT=`ip route show default | cut -f 5 -d ' '`

# Replies from the internet are un-NATed to the application's address, which isn't reachable from this VPC:
# they have to go back out this endpoint's gwo- interface, so gwlbtun returns them through GWLB. Connections
# that arrive on gwi- get a connection mark, and replies carrying it are routed by a table that points at gwo-.
# The gwo- interface index, unique while the interface exists, numbers both (the DESTROY hook runs before the
# interfaces are removed).
MARK=$((1000 + $(cat /sys/class/net/$3/ifindex)))

if [ "$1" = "CREATE" ]; then
  echo "==> Setting up two-armed NAT"

  iptables -t nat -A POSTROUTING -o $OUTINT -j MASQUERADE
  iptables -A FORWARD -i $2 -o $OUTINT -j ACCEPT
  ip6tables -t nat -A POSTROUTING -o $OUTINT -j MASQUERADE
  ip6tables -A FORWARD -i $2 -o $OUTINT -j ACCEPT

  for T in iptables ip6tables; do
    $T -t mangle -A PREROUTING -i $2 -j CONNMARK --set-mark $MARK
    $T -t mangle -A PREROUTING -i $OUTINT -j CONNMARK --restore-mark
    $T -A FORWARD -i $OUTINT -o $3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  done
  for V in -4 -6; do
    ip $V route replace default dev $3 table $MARK
    ip $V rule add fwmark $MARK table $MARK
  done

  echo 1 > /proc/sys/net/ipv4/ip_forward
  echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
  echo 0 > /proc/sys/net/ipv4/conf/$2/rp_filter
  # Nothing on a GWLB tunnel answers IPv6 router solicitations, and the kernel's retries would count as
  # tunnel activity (keeping -t from ever timing the tunnel out). IPv6 traffic through the tunnel is unaffected.
  echo 0 > /proc/sys/net/ipv6/conf/$2/router_solicitations
  echo 0 > /proc/sys/net/ipv6/conf/$3/router_solicitations
  echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
else
  echo "==> Removing two-armed NAT"

  iptables -t nat -D POSTROUTING -o $OUTINT -j MASQUERADE
  iptables -D FORWARD -i $2 -o $OUTINT -j ACCEPT
  ip6tables -t nat -D POSTROUTING -o $OUTINT -j MASQUERADE
  ip6tables -D FORWARD -i $2 -o $OUTINT -j ACCEPT

  for T in iptables ip6tables; do
    $T -t mangle -D PREROUTING -i $2 -j CONNMARK --set-mark $MARK
    $T -t mangle -D PREROUTING -i $OUTINT -j CONNMARK --restore-mark
    $T -D FORWARD -i $OUTINT -o $3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  done
  for V in -4 -6; do
    ip $V rule del fwmark $MARK table $MARK
    ip $V route flush table $MARK
  done
fi
