#!/bin/bash

echo "==> Setting up to simply route incoming packets back out"
echo Mode is $1, In Int is $2, Out Int is $3, ENI is $4

echo 1 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/$2/rp_filter
