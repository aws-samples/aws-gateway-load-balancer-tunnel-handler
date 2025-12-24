#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

echo "==> Setting up simple passthrough"
echo Mode is $1, In Int is $2, Out Int is $3, ENI is $4

tc qdisc add dev $2 ingress
tc filter add dev $2 parent ffff: protocol all prio 2 u32 match u32 0 0 flowid 1:1 action mirred egress mirror dev $3
