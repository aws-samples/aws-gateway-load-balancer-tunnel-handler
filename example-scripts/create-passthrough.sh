#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

echo "==> Setting up simple passthrough"
echo Mode is $1, In Int is $2, Out Int is $3, ENI is $4

tc qdisc add dev $2 ingress
tc filter add dev $2 parent ffff: protocol all prio 2 u32 match u32 0 0 flowid 1:1 action mirred egress redirect dev $3

if [ "$1" = "CREATE" ]; then
  # Nothing on a GWLB tunnel answers IPv6 router solicitations, and the kernel's retries would count as
  # tunnel activity (keeping -t from ever timing the tunnel out). IPv6 traffic through the tunnel is unaffected.
  sysctl -q net.ipv6.conf.$2.router_solicitations=0 net.ipv6.conf.$3.router_solicitations=0
fi
