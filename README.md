# aws-gateway-load-balancer-tunnel-handler
This software supports using the Gateway Load Balancer AWS service. It is designed to be ran on a GWLB target, takes in the Geneve encapsulated data and creates Linux tun (layer 3) interfaces per endpoint. This allows standard Linux tools (iptables, etc.) to work with GWLB.

See the 'example-scripts' folder for some of the options that can be used as create scripts for this software.

## Prebuilt binaries
Every push to `main` and every tagged release publishes prebuilt Linux binaries for `x86_64` and `aarch64` (Graviton), built on Amazon Linux 2023. They dynamically link AL2023's glibc, so they run on AL2023 and other distributions with a compatible (equal or newer) glibc; on older systems, build from source instead (see below).

Newest stable build (tracks `main`):
```
# x86_64 (Intel/AMD)
curl -LO https://github.com/aws-samples/aws-gateway-load-balancer-tunnel-handler/releases/download/latest/gwlbtun-linux-x86_64
# aarch64 (Graviton/ARM)
curl -LO https://github.com/aws-samples/aws-gateway-load-balancer-tunnel-handler/releases/download/latest/gwlbtun-linux-aarch64
chmod +x gwlbtun-linux-*
```

A specific version, frozen for pinning (e.g. v3.2):
```
curl -LO https://github.com/aws-samples/aws-gateway-load-balancer-tunnel-handler/releases/download/v3.2/gwlbtun-linux-x86_64
```

All releases, with changelogs, are on the [Releases page](https://github.com/aws-samples/aws-gateway-load-balancer-tunnel-handler/releases). You can confirm the version of a downloaded binary with `./gwlbtun-linux-x86_64 -h` (the first line reports e.g. `v3.2`).

## To Compile
On an Amazon Linux 2 or AL2023 host, copy this code down, and install dependencies:

```
sudo yum groupinstall "Development Tools"
sudo yum install cmake3
```

In the directory with the source code, do ```cmake3 .; make``` to build. This code works with both Intel and Graviton-based architectures.

**This version has integrated Boost libraries from 1.92 - no additional Boost download is required (as opposed to previous versions).**

## Usage

gwlbtun can be launched in several different ways - native CLI or in a container. 

### Native CLI

For Linux, the application requires CAP_NET_ADMIN capability to create the tunnel interfaces along with the example helper scripts.
```
AWS Gateway Load Balancer Tunnel Handler v4.0
Usage: ./gwlbtun [options]
Example: ./gwlbtun

  -h         Print this help
  -c FILE    Command to execute when a new tunnel has been built. See below for arguments passed.
  -r FILE    Command to execute when a tunnel times out and is about to be destroyed. See below for arguments passed.
  -t TIME    Minimum time in seconds between last packet seen and to consider the tunnel timed out. Set to 0 (the default) to never time out tunnels.
             Note the actual time between last packet and the destroy call may be longer than this time.
  -i TIME    Idle timeout for the TCP flow cache. Set this to match what GWLB is configured for. Defaults to 350 seconds. UDP and Other flow caches use a fixed 120 second idle timeout.
  -p PORT    Listen to TCP port PORT and provide a health status report on it.
  -j         For health check detailed statistics, output as JSON instead of text.  
  -s         Only return simple health check status (only the HTTP response code), instead of detailed statistics.
  -d         Enable debugging output. Short version of --logging all=debug.
  -e OBJFILE Load the eBPF program from OBJFILE to accelerate known-flow packet processing in-kernel (tc clsact ingress + egress).
  -I IFNAME  Attach the eBPF ingress program to IFNAME instead of auto-detecting the default-route NIC. Use when GWLB traffic arrives on a dedicated ENI separate from the management interface. (--ebpf-interface)

Threading options:
  --udpthreads NUM         Generate NUM threads for the UDP receiver.
  --udpaffinity AFFIN      Generate threads for the UDP receiver, pinned to the cores listed. Takes precedence over udptreads.
  --tunthreads NUM         Generate NUM threads for each tunnel processor.
  --tunaffinity AFFIN      Generate threads for each tunnel processor, pinned to the cores listed. Takes precedence over tunthreads.

Performance options:
  --rcvbuf SIZE            Socket receive buffer size in megabytes. Default is 128MB.
                           For 50+ Gbps throughput, use 128-256MB. Requires net.core.rmem_max sysctl >= SIZE*1024*1024.
  --busypoll USEC          Busy-poll the NIC up to USEC microseconds per receive (lower latency, higher CPU).
                           Default 0 (disabled). Try 50 for latency-sensitive high packet rates.
  --reserve RESV           Pre-size the flow caches to avoid rehash stalls under high flow counts.
                           RESV is six comma-separated entry counts in order v4TCP,v4UDP,v4Other,v6TCP,v6UDP,v6Other
                           (0 = don't pre-size that cache). Default 16384,16384,1024,1024,1024,1024.
                           Prefix with 'vpce-<id>:' to override a specific GWLB endpoint; repeat for several.
                           e.g. --reserve 5000000,50000,50000,20,20,20 --reserve vpce-0abc...:2000000,2000000,1024,1024,1024,1024

AFFIN arguments take a comma separated list of cores or range of cores, e.g. 1-2,4,7-8.
It is recommended to have the same number of UDP threads as tunnel processor threads, in one-arm operation.
If unspecified, the thread argument(s) will assume <N> as a default, based on the number of cores present.

Logging options:
  --logging CONFIG         Set the logging configuration, as described below.
---------------------------------------------------------------------------------------------------------
Hook scripts arguments:
These arguments are provided when gwlbtun calls the hook scripts (the -c <FILE> and/or -r <FILE> command options).
On gwlbtun startup, it will automatically create gwi-<X> and gwo-<X> interfaces upon seeing the first packet from a specific GWLBE, and the hook scripts are invoked when interfaces are created or destroyed. You should at least disable rpf_filter for the gwi-<X> tunnel interface with the hook scripts.
The hook scripts will be called with the following arguments:
1: The string 'CREATE' or 'DESTROY', depending on which operation is occurring.
2: The interface name of the ingress interface (gwi-<X>).
3: The interface name of the egress interface (gwo-<X>).  Packets can be sent out via in the ingress
   as well, but having two different interfaces makes routing and iptables easier.
4: The GWLBE ENI ID in base 16 (e.g. '2b8ee1d4db0c51c4') associated with this tunnel.

The <X> in the interface name is replaced with the base 60 encoded ENI ID (to fit inside the 15 character
device name limit).
---------------------------------------------------------------------------------------------------------
The logging configuration can be set by passing a string to the --logging option. That string is a series of <section>=<level>, comma separated and case insensitive.
The available sections are: core udp geneve tunnel healthcheck os ebpf all 
The logging levels available for each are: critical important info debug debugdetail 
The default level for all sections is 'important'.
```

### Docker
The Dockerfile builds a container image for the GWLB tunnel handler:

```dockerfile
FROM amazonlinux:2023.6.20250203.1

RUN yum update; yum install -y iproute-tc iptables tcpdump iputils procps

COPY example-scripts/* .
COPY gwlbtun .

ENTRYPOINT ["./gwlbtun"] 
CMD ["-c", "./create-route.sh", "-p", "8060"]
````
#### Key Components:

  - Build Stage :
    - Uses golang:1.20-alpine as builder image
    - Compiles the application with CGO disabled
    - Builds for Linux platform
  - Final Stage :
    - Based on Alpine 3.18
    - Installs required packages (iproute2, bash, iptables)
    - Copies binary and scripts from builder
    - Sets up entrypoint and default command

### DaemonSet Configuration (gwlbtun-ds.yaml)
The DaemonSet ensures that the tunnel handler runs on each node in the Kubernetes cluster.

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: gwlbtun-node
spec:
  selector:
    matchLabels:
      app: gwlbtun-node
  template:
    metadata:
      labels:
        app: gwlbtun-node
        component: network
    spec:
      containers:
      - image: "[docker image]"
        imagePullPolicy: IfNotPresent
        name: gwlbtun
        command:
        - ./gwlbtun
        - -c
        - ./create-route.sh
        - -p
        - "8060"
        resources:
          requests:
            cpu: 10m
            memory: 300Mi
        securityContext:
          privileged: true
          capabilities:
            add: ["NET_ADMIN"]
      hostNetwork: true
      hostPID: true
      nodeSelector:
        kubernetes.io/os: linux
      restartPolicy: Always
```
#### Key Components:
  - DaemonSet Name : gwlbtun-node
  - Container Configuration :
    -  Port: 8060
    - Resource requests: 10m CPU, 300Mi memory
    - Runs with privileged access and NET_ADMIN capabilities
    - Uses host network and PID namespace
  - Node Selection : Runs only on Linux nodes
  - Restart Policy : Always restarts on failure

### Prerequisites
- Kubernetes cluster with Linux nodes
- kubectl configured with cluster access
- Docker registry access

### Deployment Steps
1. Build and push the Docker image:

```bash
# Build the Docker image
docker build -t your-registry/gwlbtun:tag .

# Push to your registry
docker push your-registry/gwlbtun:tag
```
2. Update the image reference in gwlbtun-ds.yaml:

```yaml
image: "your-registry/gwlbtun:tag"
```

3. Apply the DaemonSet:

```bash
kubectl apply -f gwlbtun-ds.yaml
```

Verification
Check if the DaemonSet pods are running:

```bash
kubectl get pods -l app=gwlbtun-node
```

Monitoring
Monitor the tunnel handler logs:

```bash
kubectl logs -l app=gwlbtun-node
```
Configuration Parameters
- -c: Path to the route creation script

- -p: Port number for the tunnel handler (default: 8060)

Security Considerations
The DaemonSet runs with privileged access

NET_ADMIN capability is required for network operations

Consider implementing network policies for additional security.

## Source code layout
main.cpp contains the start of the code, but primarily interfaces with GeneveHandler, defined in GeneveHandler.cpp. 
That class launches the multithreaded UDP receiver, and then creates GeneveHandlerENI class instances per GWLB ENI detected.
The GeneveHandlerENI class instantiates the TunInterfaces as needed, and generally manages the entire packet handling flow for that ENI. 
GenevePacket and PacketHeader handle parsing and validating GENEVE packets and IP packets respectively, and are called by GeneveHandler as needed.
Logger handles processing logging messages from all threads, ensuring they get output correctly to terminal, and filtering against the logging configuration provided.

## Multithreading
gwlbtun supports multithreading, and doing so is recommended on multicore systems. You can specify either the number or threads, or a specific affinity for CPU cores, for both the UDP receiver and the tunnel handler threads. You should test to see which set of options work best for your workload, especially if you have additional processes doing processing on the device. By default, gwlbtun will create one UDP receive thread and one tunnel processing thread per core. 

gwlbtun labels its threads with its name (gwlbtun), and either Uxxx for the UDP threads option which is simply an index, or UAxxx for the UDP affinity option, with the number being the core that thread is set for. The tunnel threads are labeled the same, except with a T instead of a U.

## Tested performance numbers
Since it's initial release, gwlbtun has had many improvements to its packet processing. More are planned for the upcoming 4.0 branch (which includes eBPF acceleration). Comparing some prior versions (2022.11 pre-Boost, 3.0, and now 3.2):

| Frame size | 2022.11 (pre-Boost) | v3.0 | v3.2 | pre-Boost &rarr; v3.2 |
|------------|--------------------:|-----:|-----:|:---------------------:|
| 64 B   |  99k pps | 173k pps | 291k pps | 2.9&times; |
| 128 B  |  98k pps | 174k pps | 303k pps | 3.1&times; |
| 256 B  |  97k pps | 189k pps | 309k pps | 3.2&times; |
| 512 B  | 108k pps | 183k pps | 308k pps | 2.9&times; |
| 1024 B | 110k pps | 193k pps | 300k pps | 2.7&times; |
| 1280 B | 109k pps | 198k pps | 297k pps | 2.7&times; |
| 1518 B | 112k pps | 196k pps | 294k pps | 2.6&times; |

The move to the concurrent hash map (v3.0) delivered roughly a 1.8&times; increase in sustained forwarding rate over the original design, and the subsequent tuning through v3.2 added another ~1.6&times;, compounding to about 2.9&times; over the 2022.11 baseline. The gains are largest for small frames, where per-packet cache overhead dominates.

**Test setup:** gwlbtun ran on a single **c6in.xlarge** behind a Gateway Load Balancer, with a TRex load generator (c6in.4xlarge) driving UDP traffic through the GWLB endpoint and back in a loopback topology. Each trial offered a fixed packet rate for 15 seconds across roughly 59,000 concurrent flows (randomized source port). The figure reported is the *delivered* forwarding ceiling - the highest sustained packets-per-second gwlbtun actually returned - taken as the maximum across an offered-load sweep of 0.5-8 Mpps. These are a relative comparison on identical hardware and topology; absolute numbers will vary with instance type, flow count, frame size, and configuration.

## Kernel sysctls
Because most usages of gwlbtun have it sitting in the middle of a communications path (bump in the wire), none of the traffic is directly destined for it. Thus, in most cases, you should disable the reverse path filter (rp_filter) on associated GWI interfaces, in order for the kernel to allow the traffic through. The hook scripts are a good place to do this (the input interface is passed as $2) and the examples in example-scripts show different ways. One option:
```
sysctl net.ipv4.conf.$2.rp_filter=0
```

Additionally, if you're doing NAT or other forwarding operations, you need to enable IP forwarding for IPv4 and IPv6 as appropriate:
```
sysctl net.ipv4.ip_forward=1
sysctl net.ipv6.conf.all.forwarding=1
```

## Kernel XPS (Transmit Packet Steering)
If you are using gwlbtun in a two-arm mode configuration (usually NAT'ing through it), the default Linux kernel XPS configuration has a poor interaction with the tun driver by default. While gwlbtun does use multiple TUN handlers to improve performance, Linux will put nearly all of the NAT'ed traffic on a single transmit queue, reducing performance.
To correct this, add commands similar to the following to your instance (or as part of the init script from gwlbtun):
```
echo 1 > /sys/class/net/ens5/queues/tx-0/xps_cpus  # CPU 0
echo 2 > /sys/class/net/ens5/queues/tx-1/xps_cpus  # CPU 1
echo 4 > /sys/class/net/ens5/queues/tx-2/xps_cpus  # CPU 2
echo 8 > /sys/class/net/ens5/queues/tx-3/xps_cpus  # CPU 3
```
Keep repeating for each CPU. This can help with getting pps_allowance_exceeded counts at lower traffic levels that don't make sense - it's pps_allowance_exceeded on a single queue. You can verify if this problem is occurring, and if it is fixed,  via ```ethtool -S ens5 | grep queue_.*_tx_cnt```:
```
Before XPS (bad scenario):
    queue_0_tx_cnt:  12,751,829 pkts  (100.0%)
    queue_1_tx_cnt:          52 pkts  (0.0%)
    queue_2_tx_cnt:           8 pkts  (0.0%)
    queue_3_tx_cnt:          47 pkts  (0.0%)

After XPS:
    queue_0_tx_cnt:  4,805,760 pkts  (27.4%)
    queue_1_tx_cnt:  4,093,697 pkts  (23.3%)
    queue_2_tx_cnt:  4,321,438 pkts  (24.6%)
    queue_3_tx_cnt:  4,320,083 pkts  (24.6%)
```

## Advanced usages

### eBPF/XDP acceleration (v4.0, in development)

gwlbtun 4.0 adds an optional in-kernel fast path for established flows, built as a companion eBPF object (`gwlbtun-ebpf.o`) that gwlbtun loads and attaches at runtime. It is strictly an accelerator: anything the fast path does not recognize or cannot handle falls through to the normal userspace processing, so behavior is unchanged when eBPF is disabled or when a packet misses.

**Building it.** If `clang` and `libbpf` (`libbpf-devel`) are present, CMake auto-detects them, compiles `gwlbtun-ebpf.o`, and builds gwlbtun with eBPF support (you will see `-- eBPF support enabled` in the CMake output). Without them, gwlbtun builds exactly as before and processes everything in userspace. On Amazon Linux 2023:
```
sudo dnf install -y clang libbpf-devel
cmake3 . && make
```

**Running it.** Pass the object with `-e <path>/gwlbtun-ebpf.o`. gwlbtun needs `CAP_BPF` and `CAP_NET_ADMIN` (run as root, or grant those capabilities) to load the program and attach the tc hooks. By default it attaches the ingress program to the default-route NIC; use `-I <ifname>` (`--ebpf-interface`) when GWLB traffic arrives on a dedicated ENI separate from the management interface.
```
sudo ./gwlbtun -c ./create-passthrough.sh -p 8060 -e ./gwlbtun-ebpf.o -I ens5
```

**What it does.** On the GWLB-facing interface, a tc-clsact **ingress** program parses GENEVE and, for a flow present in its BPF map, decapsulates and redirects the inner packet straight to the matching `gwi` interface — skipping the userspace UDP-socket/TUN round-trip. A tc **egress** program on `gwo` re-encapsulates return traffic (using a cached return L2 header) and sends it back to GWLB in-kernel. gwlbtun's userspace stays the control plane: it learns new flows on their first packet, populates the maps, and ages idle flows out using the in-kernel liveness timestamps. Known-flow counters and loader status are surfaced in the health check output (the `ebpf` section).

**Status.** The ingress and egress fast paths and the control-plane map population are implemented and are being validated on live GWLB traffic; the eBPF datapath is opt-in and should be treated as in-development for 4.0. Two dispositions (`DISP_FORWARD` and `DISP_DROP`) are reserved in the datapath for a future conntrack-driven offload but are not yet implemented — such flows simply take the normal path today.

### No return mode
If you are only interested in the ability to receive traffic to an L3 tunnel interface, and will never send traffic back to GWLB, you can #define NO_RETURN_TRAFFIC in utils.h. This removes the gwo interfaces and all cookie flow tracking, which saves on time used to synchronize that flow tracking table. Note that this puts your appliance in a two-arm mode with GWLB, and also may result in asymmetric traffic routing, which may have performance implications elsewhere. 

### Handling overlapping CIDRs
See the example-scripts/create-nat-overlapping.sh script for an example of handling overlapping CIDRs in different GWLB endpoints in two-arm mode. This script leverages conntrack and marking to accomplish this.

### Supporting very high packet rates
If your deployment is supporting high packet rates (greater than 1M pps typically), you may need to tweak some kernel settings to handle microbursts in traffic well. In testing in extremely high PPS scenarios (a fleet of iperf-based senders, all going through one c6in.32xlarge instance), you may want to consider settings akin to this (if memory allows):
```
sysctl -w net.core.rmem_max=50000000
sysctl -w net.core.rmem_default=50000000
```

You can see if this problem is occurring by monitoring for UDP receive buffer errors (RcvbufErrors) with commands similar to:
```
# cat /proc/net/snmp | grep Udp: 
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
Udp: 2985556669902 428 0 666162 0 0 0 0 0
```

If RcvbufErrors is incrementing steadily, you should increase the rmem values as described above.

### Health Check output
If you do not provide the -s flag, the health check port produces human-readable statistics about the traffic gwlbtun is processing. If you add in the -j flag, this output is formatted as JSON for consumption by outside monitoring processes.

## Security
See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License
This tool is licensed under the MIT-0 License. See the LICENSE file.

### json.hpp
The class is licensed under the MIT License:

Copyright © 2013-2022 Niels Lohmann

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### Boost libraries

Boost Software License - Version 1.0 - August 17th, 2003

Permission is hereby granted, free of charge, to any person or organization
obtaining a copy of the software and accompanying documentation covered by
this license (the "Software") to use, reproduce, display, distribute,
execute, and transmit the Software, and to prepare derivative works of the
Software, and to permit third-parties to whom the Software is furnished to
do so, all subject to the following:

The copyright notices in the Software and this entire statement, including
the above license grant, this restriction and the following disclaimer,
must be included in all copies of the Software, in whole or in part, and
all derivative works of the Software, unless such copies or derivative
works are solely in the form of machine-executable object code generated by
a source language processor.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
