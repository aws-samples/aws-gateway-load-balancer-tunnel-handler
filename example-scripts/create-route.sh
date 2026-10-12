#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

echo "==> Setting up to simply route incoming packets back out"
echo Mode is $1, In Int is $2, Out Int is $3, ENI is $4

sysctl net.ipv4.ip_forward=1
sysctl net.ipv4.conf.$2.rp_filter=0
sysctl net.ipv6.conf.all.forwarding=1
if [ "$1" = "CREATE" ]; then
  # Nothing on a GWLB tunnel answers IPv6 router solicitations, and the kernel's retries would count as
  # tunnel activity (keeping -t from ever timing the tunnel out). IPv6 traffic through the tunnel is unaffected.
  sysctl net.ipv6.conf.$2.router_solicitations=0 net.ipv6.conf.$3.router_solicitations=0
fi
