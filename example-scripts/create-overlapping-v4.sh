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

  # Get what interface are we routing traffic out to (eth0, enX0, etc)
  OUTINT=`ip route show default | cut -f 5 -d ' '`

  # Have we set our global rules yet? If not, set them up.
  iptables -t mangle -L INPUT -n  | grep -q "CONNMARK save"
  if [ $? -eq 1 ]; then
    # Need to set global rules.
    echo "- First tunnel detected. Setting global networking configuration."
    # Save connmark on egress
    iptables -t mangle -A POSTROUTING -j CONNMARK --save-mark
    # Enable NAT to our outbound interface
    iptables -t nat -A POSTROUTING -o $OUTINT -j MASQUERADE
    # Ensure traffic go to us locally (INPUT) and coming from us locally (OUTPUT) are marked and restored.
    iptables -t mangle -A INPUT -j CONNMARK --save-mark
    iptables -t mangle -A OUTPUT -j CONNMARK --restore-mark
    # Traffic inbound from NATting- restore the mark from CONNMARK
    iptables -t mangle -A PREROUTING -i $OUTINT -j CONNMARK --restore-mark
    # Enable forwarding.
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
  fi

  # Ensure there is a route table named for this ENI
  grep $4 /etc/iproute2/rt_tables > /dev/null
  if [ $? -ne 0 ]; then
    LASTTAB=`grep -v "#" /etc/iproute2/rt_tables | cut -f 1 | tail -n 1`
    NEWTAB=$((LASTTAB+1))
    echo -e "$NEWTAB\t$4" >> /etc/iproute2/rt_tables
  fi
  TABLENUM=`grep $4 /etc/iproute2/rt_tables | cut -f 1`

  # Flush the existing route table
  ip route flush table $4
  # Set output routes. Get the VPC assigned IPv4 and IPv6 blocks for the VPC this ENI ends at
  VPCID=`aws ec2 describe-vpc-endpoints --filters Name=vpc-endpoint-id,Values=vpce-$4 | jq -r .VpcEndpoints[].VpcId`
  IPV4=`aws ec2 describe-vpcs --filters Name=vpc-id,Values=$VPCID | jq -r .Vpcs[].CidrBlockAssociationSet[].CidrBlock`
  echo "- Routing far-side VPC blocks of $IPV4 via $3 on table $4"
  ip route add $IPV4 dev $3 table $4

  echo "- Routing all other traffic received from $2 to be NATed out $OUTINT"
  # Add default routes to send traffic out for NAT'ing
  ip route add 0.0.0.0/0 dev $OUTINT table $4

  # Add interfaces to that route table for outbound
  ip rule add iif $2 table $4

  # Traffic outbound - set a mark on ingress and save it on egress to CONNMARK for restoring on inbound
  iptables -t mangle -A PREROUTING -i $2 -j MARK --set-mark $TABLENUM
  # Use those marks to go to the correct routing table
  ip rule add fwmark $TABLENUM table $4
  # Ignore reverse path filter for this interface
  echo 0 > /proc/sys/net/ipv4/conf/$2/rp_filter

else
  echo "==> Destroying up two-armed NAT"

  # Delete our rules we created
  ip rule del fwmark $TABLENUM table $4
  ip rule del table $4
  ip rule del table $4

  # Delete table entries create
  iptables -t mangle -D PREROUTING -i $2 -j MARK --set-mark $TABLENUM
fi
