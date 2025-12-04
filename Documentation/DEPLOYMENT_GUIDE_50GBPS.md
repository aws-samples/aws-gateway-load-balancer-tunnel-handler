# Deployment Guide for 50 Gbps Throughput

## Quick Start

This guide provides step-by-step instructions for deploying the optimized GWLB tunnel handler for 50+ Gbps throughput in NO_RETURN_TRAFFIC mode.

## Prerequisites

- AWS EC2 instances with Enhanced Networking (ENA)
- Linux kernel 3.11+ (for SO_BUSY_POLL support)
- Root or CAP_NET_ADMIN capability
- Compiled binary with performance optimizations

## Instance Selection

### Recommended: c6gn.16xlarge
- **vCPUs**: 64
- **Network**: 100 Gbps
- **Cost**: ~$2.30/hour
- **Throughput**: 30-35 Gbps per instance

### Alternative: c7gn.16xlarge
- **vCPUs**: 64
- **Network**: 200 Gbps (with ENA Express)
- **Cost**: ~$2.90/hour
- **Throughput**: 35-45 Gbps per instance

## System Configuration

### 1. Kernel Parameters

Create `/etc/sysctl.d/99-gwlb-tuning.conf`:

```bash
# Network buffer sizes (256MB max)
net.core.rmem_max = 268435456
net.core.rmem_default = 134217728
net.core.wmem_max = 268435456
net.core.wmem_default = 134217728

# Increase backlog for high packet rates
net.core.netdev_max_backlog = 500000
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 8000

# TCP buffer sizes
net.ipv4.tcp_rmem = 4096 87380 268435456
net.ipv4.tcp_wmem = 4096 65536 268435456

# Enable TCP timestamps for better performance
net.ipv4.tcp_timestamps = 1

# Increase connection tracking table size
net.netfilter.nf_conntrack_max = 2000000
```

Apply settings:
```bash
sudo sysctl -p /etc/sysctl.d/99-gwlb-tuning.conf
```

### 2. NIC Configuration

```bash
# Increase ring buffer sizes
sudo ethtool -G eth0 rx 8192 tx 8192

# Disable interrupt coalescing for lower latency
sudo ethtool -C eth0 rx-usecs 0 rx-frames 1

# Enable multi-queue (if not already enabled)
sudo ethtool -L eth0 combined 32

# Verify settings
sudo ethtool -g eth0
sudo ethtool -c eth0
sudo ethtool -l eth0
```

### 3. CPU Isolation (Optional - for ultra-low latency)

Add to `/etc/default/grub`:
```bash
GRUB_CMDLINE_LINUX="isolcpus=0-47 nohz_full=0-47 rcu_nocbs=0-47"
```

Update grub and reboot:
```bash
sudo update-grub
sudo reboot
```

### 4. IRQ Affinity

Pin NIC interrupts to specific cores:

```bash
#!/bin/bash
# Pin eth0 interrupts to cores 0-31

DEVICE="eth0"
CORES="0-31"

# Get IRQ numbers for the device
IRQS=$(grep $DEVICE /proc/interrupts | awk '{print $1}' | sed 's/://')

# Set affinity for each IRQ
for IRQ in $IRQS; do
    echo $CORES > /proc/irq/$IRQ/smp_affinity_list
done
```

## Application Configuration

### Thread Configuration

For 64 vCPU instance (c6gn.16xlarge):

```bash
# 48 UDP receiver threads on cores 0-47
# 16 TUN writer threads on cores 48-63
./gwlbtun \
  --udpaffinity 0-47 \
  --tunaffinity 48-63 \
  -c /opt/gwlb/hooks/create.sh \
  -r /opt/gwlb/hooks/destroy.sh \
  -p 8080 \
  -j
```

### Hook Scripts

Create `/opt/gwlb/hooks/create.sh`:
```bash
#!/bin/bash
ACTION=$1
INGRESS=$2
EGRESS=$3
ENI_ID=$4

if [ "$ACTION" = "CREATE" ]; then
    # Disable reverse path filtering
    echo 0 > /proc/sys/net/ipv4/conf/$INGRESS/rp_filter
    
    # Increase interface queue length
    ip link set $INGRESS txqueuelen 10000
    
    # Bring interface up
    ip link set $INGRESS up
    
    # Log creation
    logger "GWLB: Created interface $INGRESS for ENI $ENI_ID"
fi
```

Create `/opt/gwlb/hooks/destroy.sh`:
```bash
#!/bin/bash
ACTION=$1
INGRESS=$2
EGRESS=$3
ENI_ID=$4

if [ "$ACTION" = "DESTROY" ]; then
    logger "GWLB: Destroyed interface $INGRESS for ENI $ENI_ID"
fi
```

Make scripts executable:
```bash
chmod +x /opt/gwlb/hooks/*.sh
```

## Systemd Service

Create `/etc/systemd/system/gwlbtun.service`:

```ini
[Unit]
Description=AWS Gateway Load Balancer Tunnel Handler
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/gwlb
ExecStart=/opt/gwlb/gwlbtun \
  --udpaffinity 0-47 \
  --tunaffinity 48-63 \
  -c /opt/gwlb/hooks/create.sh \
  -r /opt/gwlb/hooks/destroy.sh \
  -p 8080 \
  -j
Restart=always
RestartSec=5
LimitNOFILE=1048576
LimitNPROC=1048576

# Capabilities needed
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable gwlbtun
sudo systemctl start gwlbtun
```

## Monitoring

### Health Check

```bash
# Check application health
curl http://localhost:8080/

# Get detailed statistics (JSON)
curl http://localhost:8080/ | jq .
```

### System Metrics

```bash
# Monitor packet processing
watch -n1 'netstat -su | grep -A5 "Udp:"'

# Check for packet drops
watch -n1 'ethtool -S eth0 | grep -i drop'

# Monitor CPU usage per thread
top -H -p $(pgrep gwlbtun)

# Check socket buffer usage
ss -m sport = :6081
```

### CloudWatch Metrics

Key metrics to monitor:
- `NetworkPacketsIn` - Should be ~1.5-2M pps per instance at 50 Gbps
- `CPUUtilization` - Target <70%, alert >85%
- `NetworkIn` - Should match expected throughput
- Custom metric: Packet drops (from health endpoint)

## Troubleshooting

### Issue: High Packet Loss

**Check socket buffers:**
```bash
# Verify buffer size
ss -m sport = :6081 | grep -i rcv

# Check for overruns
netstat -su | grep "packet receive errors"
```

**Solution:**
```bash
# Increase buffer size
sudo sysctl -w net.core.rmem_max=536870912  # 512MB
```

### Issue: High CPU Usage

**Check thread distribution:**
```bash
# See which cores are busy
mpstat -P ALL 1

# Check if threads are on correct cores
ps -eLo pid,tid,psr,comm | grep gwlbtun
```

**Solution:**
- Verify CPU isolation is working
- Check IRQ affinity settings
- Increase number of UDP threads

### Issue: High Latency

**Check busy polling:**
```bash
# Verify SO_BUSY_POLL is enabled
sysctl net.core.busy_poll
sysctl net.core.busy_read
```

**Solution:**
```bash
# Enable busy polling globally
sudo sysctl -w net.core.busy_poll=50
sudo sysctl -w net.core.busy_read=50
```

### Issue: Interface Creation Failures

**Check capabilities:**
```bash
# Verify CAP_NET_ADMIN
getcap /opt/gwlb/gwlbtun

# Or run with sudo
sudo /opt/gwlb/gwlbtun ...
```

**Check logs:**
```bash
journalctl -u gwlbtun -f
dmesg | tail -50
```

## Performance Validation

### Test 1: Baseline Throughput

```bash
# Generate UDP traffic to port 6081
iperf3 -c <instance-ip> -u -b 50G -l 1400 -p 6081 -P 32 -t 60

# Monitor on instance
watch -n1 'curl -s http://localhost:8080/ | jq .UDPPacketReceiver'
```

Expected results:
- Packet rate: 1.5-2M pps per instance
- CPU usage: 50-70%
- Packet loss: <0.1%

### Test 2: Burst Handling

```bash
# Burst to 60 Gbps for 5 minutes
iperf3 -c <instance-ip> -u -b 60G -l 1400 -p 6081 -P 32 -t 300

# Check for drops
netstat -su | grep "packet receive errors"
```

Expected results:
- No packet drops during burst
- CPU usage: 70-85%
- Recovery time: <1 second

### Test 3: Multiple ENI Endpoints

```bash
# Simulate traffic from 100 different ENI endpoints
# (requires custom test tool)

# Monitor ENI handler count
curl -s http://localhost:8080/ | jq '.enis | length'
```

Expected results:
- All ENIs created successfully
- No memory leaks
- Consistent performance across ENIs

## Deployment Checklist

- [ ] Instance type selected (c6gn.16xlarge or better)
- [ ] Kernel parameters configured
- [ ] NIC settings optimized
- [ ] CPU isolation configured (optional)
- [ ] IRQ affinity set
- [ ] Application compiled with optimizations
- [ ] Hook scripts created and tested
- [ ] Systemd service configured
- [ ] Health check endpoint accessible
- [ ] Monitoring configured
- [ ] Performance tests passed
- [ ] Documentation reviewed

## Scaling

### Horizontal Scaling

For 50 Gbps with redundancy:

**Option 1: 2 instances (minimal)**
- Each handles 25 Gbps normally
- Can burst to 35 Gbps if one fails
- Cost: ~$3,350/month

**Option 2: 3 instances (recommended)**
- Each handles 16-17 Gbps normally
- Can lose 1 instance without degradation
- Cost: ~$5,000/month

**Option 3: 4 instances (high availability)**
- Each handles 12-13 Gbps normally
- Can lose 2 instances without degradation
- Cost: ~$6,700/month

### Auto Scaling Configuration

```yaml
AutoScalingGroup:
  MinSize: 2
  MaxSize: 6
  DesiredCapacity: 3
  TargetTrackingScaling:
    - MetricName: NetworkPacketsIn
      TargetValue: 1500000  # packets/sec
    - MetricName: CPUUtilization
      TargetValue: 65
```

## Support

For issues or questions:
1. Check logs: `journalctl -u gwlbtun -f`
2. Review health endpoint: `curl http://localhost:8080/`
3. Check system metrics: `netstat -su`, `ethtool -S eth0`
4. Review this guide's troubleshooting section

## References

- [PERFORMANCE_OPTIMIZATIONS.md](./PERFORMANCE_OPTIMIZATIONS.md) - Technical details
- [AWS Enhanced Networking](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enhanced-networking.html)
- [Linux Network Tuning](https://www.kernel.org/doc/Documentation/networking/scaling.txt)
