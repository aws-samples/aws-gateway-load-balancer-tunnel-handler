#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. This material is AWS Content under the AWS Enterprise Agreement 
# or AWS Customer Agreement (as applicable) and is provided under the AWS Intellectual Property License.

# This version of the create-nat script deals with multiple endpoints that may have overlapping IP CIDR ranges.

# Note: This requires this instance to have Source/Dest check disabled.
# aws ec2 modify-instance-attribute --instance-id=<instID> --no-source-dest-check

echo Mode is $1, In Int is $2, Out Int is $3, ENI is $4

if [ "$1" = "CREATE" ]; then
  echo "==> Setting up two-armed NAT"

  # Make sure conntrack mod is installed
  modprobe ip_conntrack

  # Ensure there is a route table named for this ENI
  grep $4 /etc/iproute2/rt_tables > /dev/null
  if [ $? -ne 0 ]; then
    LASTTAB=`grep -v "#" /etc/iproute2/rt_tables | cut -f 1 | tail -n 1`
    NEWTAB=$((LASTTAB+1))
    echo -e "$NEWTAB\t$4" >> /etc/iproute2/rt_tables
  fi

  # Since in stock Linux, our new tables will start with an ID of 1 and go up, we will re-use that number as
  # the eth0 alias for numbering
  TABLENUM=`grep $4 /etc/iproute2/rt_tables | cut -f 1`

  # Flush the existing route table
  ip route flush table $4
  # Set output routes. Get the VPC assigned IPv4 and IPv6 blocks for the VPC this ENI ends at
  VPCID=`aws ec2 describe-vpc-endpoints --filters Name=vpc-endpoint-id,Values=vpce-$4 --region us-west-2 | jq -r .VpcEndpoints[].VpcId`
  IPV4=`aws ec2 describe-vpcs --filters Name=vpc-id,Values=$VPCID --region us-west-2 | jq -r .Vpcs[].CidrBlockAssociationSet[].CidrBlock`
  IPV6=`aws ec2 describe-vpcs --filters Name=vpc-id,Values=$VPCID --region us-west-2 | jq -r .Vpcs[].Ipv6CidrBlockAssociationSet[].Ipv6CidrBlock`
  echo "- Routing far-side VPC blocks of $IPV4 and $IPV6 via $3 on table $4"
  ip route add $IPV4 dev $3 table $4
  ip -6 route add $IPV6 dev $3 table $4

  # Add default routes
  ip route add 0.0.0.0/0 via 10.10.0.1 table $4

  # Get the ::1 address of eth0
  OURV6=`ifconfig eth0 | grep "prefixlen 128" | cut -f 10 -d ' '`
  DRV6=`python3 -c "import ipaddress as ipa; a=ipa.ip_interface('$OURV6/64'); print(a.network.network_address + 1);"`
  ip -6 route add ::/0 via $DRV6 table $4

  # Add interfaces to that route table for outbound
  ip rule add iif $2 table $4
  ip -6 rule add iif $2 table $4

  # Set up IPTables to do the NAT. We do a mark on ingress to make it easy to match on egress.
  # We save and restore the mark using CONNTRACK to do our connection tracking

  # Traffic outbound - set a mark on ingress and save it on egress to CONNMARK for restoring on inbound
  iptables -t mangle -A PREROUTING -i $2 -j MARK --set-mark $TABLENUM
  iptables -t mangle -A POSTROUTING -j CONNMARK --save-mark
  iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
  ip6tables -t mangle -A PREROUTING -i $2 -j MARK --set-mark $TABLENUM
  ip6tables -t mangle -A POSTROUTING -j CONNMARK --save-mark
  ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

  # Traffic inbound - restore the mark from CONNMARK
  iptables -t mangle -A PREROUTING -i eth0 -j CONNMARK --restore-mark
  ip6tables -t mangle -A PREROUTING -i eth0 -j CONNMARK --restore-mark
  # Use that mark to go to the correct routing table
  ip rule add fwmark $TABLENUM table $4
  ip -6 rule add fwmark $TABLENUM table $4

  echo 1 > /proc/sys/net/ipv4/ip_forward
  echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
  echo 0 > /proc/sys/net/ipv4/conf/$2/rp_filter
  echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
else
  echo "==> Destroying up two-armed NAT"

  # Delete our rules we created
  ip rule del table $4
  ip rule del table $4
  ip -6 rule del table $4
  ip -6 rule del table $4

fi
