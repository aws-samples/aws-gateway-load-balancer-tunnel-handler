# aws-gateway-load-balancer-tunnel-handler
This software supports using the Gateway Load Balancer AWS service. It is designed to be ran on a GWLB target, takes in the Geneve encapsulated data and creates Linux tun (layer 3) interfaces per endpoint. This allows standard Linux tools (iptables, etc.) to work with GWLB.

See the 'example-scripts' folder for some of the options that can be used as create scripts for this software.

## Quickstart
gwlbtun is designed so that most deployments only need the hook scripts that set up and tear down each endpoint's tunnel interfaces, plus a health check port for the GWLB target group:

```
sudo ./gwlbtun -c example-scripts/create-route.sh -r example-scripts/create-route.sh -p 80
```

For each GWLB endpoint (GWLBe) that sends it traffic, gwlbtun creates a pair of Linux tun interfaces when that endpoint's first packet arrives, named after the endpoint's ID:

- `gwi-<X>` (in): gwlbtun removes the GENEVE encapsulation and writes the original packets here, so to Linux they look like ordinary packets arriving on that interface. Match on it in iptables, tc or routing rules to handle one endpoint's traffic.
- `gwo-<X>` (out): whatever Linux sends out of this interface, gwlbtun encapsulates again and returns to GWLB through the same endpoint. Only packets belonging to flows GWLB sent are returned; an appliance can't start new flows through GWLB.

The `-c` hook runs once a pair exists and is where you connect the two interfaces; there are several example scripts in the [example-scripts](example-scripts) directory to see different techniques. The `-r` hook runs when an endpoint's pair is removed: when gwlbtun stops (or restarts), and, if you set `-t`, when the endpoint goes idle (off by default). The hook arguments are under [Usage](#usage).

It picks well-performing defaults on its own (for example, one UDP receiver thread per network receive queue), so most users won't need any of the threading or performance options described under [Usage](#usage). They're there if you need them: [README-Large-Instances.md](README-Large-Instances.md) covers instances with many vCPUs, and every option can also be set from a configuration file (see [Configuration file](#configuration-file)). [example-scripts/gwlbtun.service](example-scripts/gwlbtun.service) is a systemd unit that runs gwlbtun from a configuration file, with install steps in its header.

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

A specific version, frozen for pinning (e.g. v3.3):
```
curl -LO https://github.com/aws-samples/aws-gateway-load-balancer-tunnel-handler/releases/download/v3.3/gwlbtun-linux-x86_64
```

All releases, with changelogs, are on the [Releases page](https://github.com/aws-samples/aws-gateway-load-balancer-tunnel-handler/releases). You can confirm the version of a downloaded binary with `./gwlbtun-linux-x86_64 -h` (the first line reports e.g. `v3.3`).

## To Compile
On an Amazon Linux 2023 host, copy this code down, and install the build tools:

```
sudo dnf install -y gcc gcc-c++ cmake make git
```

In the directory with the source code, do ```cmake . && make``` to build. This code works with both Intel and Graviton-based architectures.

**This version has integrated Boost libraries from 1.92 - no additional Boost download is required (as opposed to previous versions).**

## Usage

gwlbtun can be launched in several different ways - native CLI or in a container. 

### Native CLI

For Linux, the application requires CAP_NET_ADMIN capability to create the tunnel interfaces along with the example helper scripts.

```
AWS Gateway Load Balancer Tunnel Handler v3.3
Usage: ./gwlbtun [options]
Example: ./gwlbtun

  -h         Print this help
  -f FILE    Read options from the YAML configuration file FILE (--config). Keys are the long option names,
             e.g. 'udpthreads: 8' or 'interface: [ens5, ens6]'; flags take true or false. Options given on the
             command line override the file (for -I and --reserve, they replace the file's list).
  --show-config  Print the effective configuration as a YAML configuration file, and exit.
  -c FILE    Command to execute when a new tunnel has been built. See below for arguments passed. (--cmdnew)
  -r FILE    Command to execute when a tunnel times out and is about to be destroyed. See below for arguments passed. (--cmddel)
  -t TIME    Minimum time in seconds between last packet seen and to consider the tunnel timed out. Set to 0 (the default) to never time out tunnels.
             Note the actual time between last packet and the destroy call may be longer than this time. (--timeout)
  -i TIME    Idle timeout for the TCP flow cache. Set this to match what GWLB is configured for. Defaults to 350 seconds. UDP and Other flow caches use a fixed 120 second idle timeout. (--idle)
  -p [ADDR:|IFNAME:]PORT  Listen to TCP port PORT and provide a health status report on it. By default it
             listens on every address; prefix an address (10.0.1.5:80, [fd00::5]:80) or an interface name
             (ens6:80) to listen only there. (--port)
  -I IFNAME  Receive GENEVE traffic only on interface IFNAME. Repeat, or give a comma-separated list, for
             several interfaces; each gets its own set of UDP receiver threads. Default: all interfaces.
             Several gwlbtun processes can run in one network namespace if each uses -I with
             different interfaces; a process without -I must be the only one. (--interface)
  -j         For health check detailed statistics, output as JSON instead of text. (--json)
  -s         Only return simple health check status (only the HTTP response code), instead of detailed statistics. (--simple)
  -d         Enable debugging output. Short version of --logging all=debug. (--debug)

Threading options:
  --udpthreads NUM         Generate NUM threads for the UDP receiver.
  --udpaffinity AFFIN      Generate threads for the UDP receiver, pinned to the cores listed. Takes precedence over udpthreads.
  --udpaffinity nearest    The default: one UDP thread per receive queue, each pinned to the closest CPU that services
                           no queue (its queue CPU's hyperthread sibling, else a CPU sharing its L3 cache, else its
                           NUMA node). Threads with no such CPU, as when every CPU services a queue, are unpinned.
  --tunthreads NUM         Generate NUM threads for each tunnel processor.
  --tunaffinity AFFIN      Generate threads for each tunnel processor, pinned to the cores listed. Takes precedence over tunthreads.

Performance options:
  --rcvbuf SIZE            Socket receive buffer size in megabytes (1 to 2047). Default is 128MB.
                           For 50+ Gbps throughput, use 128-256MB. Requires net.core.rmem_max sysctl >= SIZE*1024*1024.
  --busypoll USEC          Busy-poll the NIC up to USEC microseconds per receive (lower latency, higher CPU).
                           Default 0 (disabled). Try 50 for latency-sensitive high packet rates.
  --sndbuf SIZE            Send buffer in megabytes for each raw socket returning traffic to GWLB (one per tunnel
                           thread). Default 16MB.
  --reserve RESV           Pre-size the flow caches to avoid rehash stalls under high flow counts.
                           RESV is six comma-separated entry counts in order v4TCP,v4UDP,v4Other,v6TCP,v6UDP,v6Other
                           (0 = don't pre-size that cache; at most 100000000 each). Default 16384,16384,1024,1024,1024,1024.
                           Prefix with 'vpce-<id>:' to override a specific GWLB endpoint; repeat for several.
                           e.g. --reserve 5000000,50000,50000,20,20,20 --reserve vpce-0abc...:2000000,2000000,1024,1024,1024,1024

AFFIN arguments take a comma separated list of cores or range of cores, e.g. 1-2,4,7-8.
By default (--udpaffinity nearest) gwlbtun starts one UDP thread per receive queue of each interface it receives
on, pinned near its queue (or one unpinned thread per core, <N>, if it can't find the queues). Whenever an interface
has exactly one UDP thread per receive queue, gwlbtun asks the kernel (Linux 6.2+) to hand each queue's packets to
its own thread: thread i gets queue i's packets.
--tunthreads defaults to one per core, less any needed to leave room for the gwi- writers: Linux allows 256 queues
per tun interface, shared by the tunnel threads and the writers (at least one per receive queue). At most 255.

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
4: The ID of the GWLB endpoint associated with this tunnel, as 17 hex digits without the 'vpce-' prefix
   (e.g. '0123456789abcdef0' for endpoint vpce-0123456789abcdef0).

The <X> in the interface name is replaced with the GWLB endpoint ID encoded in base 60 (to fit inside the
15 character device name limit). With -I, <X> is instead a hash of the endpoint ID and the -I interface
list, so processes serving the same endpoint on different interfaces get different devices.
---------------------------------------------------------------------------------------------------------
The logging configuration can be set by passing a string to the --logging option. That string is a series of <section>=<level>, comma separated and case insensitive.
The available sections are: core udp geneve tunnel healthcheck os all 
The logging levels available for each are: critical important info debug debugdetail 
The default level for all sections is 'info'.
```

### Configuration file
Every option can also come from a YAML file given with `-f FILE`. The keys are the long option names (each short option's long name is in parentheses in the help above); options that can be repeated take a list, and flags take `true` or `false`:

```yaml
# /etc/gwlbtun.yaml
cmdnew: /opt/gwlbtun/create-route.sh
port: "ens6:80"
interface: [ens6]
json: true
timeout: 300
reserve:
  - 500000,50000,1024,1024,1024,1024
```

Options given on the command line override the file, so `gwlbtun -f /etc/gwlbtun.yaml -d` adds debug logging. For the options that can be given more than once (`-I`, `--reserve`), a command-line occurrence replaces the file's list rather than adding to it, and `--udpthreads`/`--udpaffinity` (and `--tunthreads`/`--tunaffinity`) count as one setting. `--show-config` prints the effective configuration in the same format and exits, which is a quick way to check what a file and command line add up to, or to write a first configuration file.

[example-configurations](example-configurations) has commented files for a small appliance ([c6in.xlarge](example-configurations/c6in.xlarge.yaml), where the defaults are right) and a large one ([c8in.96xlarge](example-configurations/c8in.96xlarge.yaml), with the tested thread layout).

### Large instances
On instances with many vCPUs (roughly 32 and up), the default thread counts start far more threads than the network interface can feed, and throughput drops. [README-Large-Instances.md](README-Large-Instances.md) explains how to lay out threads and interrupts; on a c8in.96xlarge lossless forwarding went from about 2.5M packets per second with gwlbtun 3.2's defaults to about 8M with v3.3 and that layout.

### Limiting gwlbtun to specific interfaces
By default gwlbtun accepts GENEVE (UDP 6081) on every interface and serves its health check on every address. On an appliance with a separate management interface, restrict both:

```
./gwlbtun -I ens6 -p ens6:80 -c ./create-route.sh
```

`-I` can be repeated (or given a comma-separated list) to serve several interfaces from one process. Each listed interface gets its own receiver threads: by default one per receive queue of that interface, or `--udpthreads` threads each if that's given (so the total is that count times the number of interfaces).

Replies to GWLB always leave by the interface the endpoint's traffic arrived on, from the address it arrived at, whether or not `-I` is used. This matters when an instance has more than one ENI registered as a GWLB target: without it, the kernel would route replies by destination alone and could send them out of the wrong ENI, where EC2's source/destination check drops them.

One process can serve all interfaces, or several processes can each serve their own interfaces with `-I` (for example one per ENI, as separate failure domains). gwlbtun refuses to start if that would mean two processes receiving on the same interface, or a process without `-I` alongside any other. If two processes try to create the same tunnel device, the second one logs `Unable to create TUN device ... (IFF_TUN_EXCL): a device with that name already exists - is this the only gwlbtun trying to use it?`, drops that endpoint's packets, and retries every 5 seconds.

### Docker
The Dockerfile builds a container image for the GWLB tunnel handler:

```dockerfile
FROM amazonlinux:2023.6.20250203.1

RUN yum update; yum install -y iproute-tc iptables tcpdump iputils procps

COPY example-scripts/* .
COPY gwlbtun .

ENTRYPOINT ["./gwlbtun"] 
CMD ["-c", "./create-route.sh", "-p", "80"]
```
#### Key Components:

  - Single-stage image based on Amazon Linux 2023.
  - Installs the tools the example hook scripts and troubleshooting use: `iproute-tc`, `iptables`, `tcpdump`, `iputils` and `procps`.
  - Copies the example hook scripts and a **prebuilt** `gwlbtun` binary from the build context. The image does not compile gwlbtun: build it first (`cmake . && make`), or download a release binary (see Prebuilt binaries above) and name it `gwlbtun`.
  - The default command runs `create-route.sh` as the create hook and serves the health check on port 80 (`-p 80`). `-p` is the health check port, not a data port; GWLB traffic always arrives on UDP 6081.

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
    - Health check port: 8060 (`-p 8060`, overriding the image's default of 80)
    - Resource requests: 10m CPU, 300Mi memory
    - Runs with privileged access and NET_ADMIN capabilities
    - Uses host network and PID namespace
  - Node Selection : Runs only on Linux nodes
  - Restart Policy : Always restarts on failure

Because the pod uses the host network, only one gwlbtun can run per node: a second instance in the same network namespace exits at startup. During a rolling update, a replacement pod that starts before the old one has stopped restarts until the old pod is gone.

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
gwlbtun supports multithreading, and doing so is recommended on multicore systems. You can specify either the number of threads, or a specific affinity for CPU cores, for both the UDP receiver and the tunnel handler threads. You should test to see which set of options work best for your workload, especially if you have additional processes doing processing on the device. By default, gwlbtun creates one UDP receive thread per receive queue of each interface, pinned near that queue's CPU (`--udpaffinity nearest`; unpinned when every CPU services a queue, as on most sizes up to about 8 vCPUs; see [ENA queues](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ena-queues.html)), and one tunnel processing thread per core, up to 255 per tunnel interface. `--show-config` prints the layout it will use. For instances with many vCPUs, see [README-Large-Instances.md](README-Large-Instances.md).

gwlbtun labels its threads with its name (gwlbtun), and either Uxxx for an unpinned UDP thread, where the number is simply an index, or UAxxx for a pinned one, with the number being the core that thread is pinned to. The tunnel threads are labeled the same, except with a T instead of a U.

## Tested performance numbers
Since it's initial release, gwlbtun has had many improvements to its packet processing. More are planned for the upcoming 4.0 branch (which includes eBPF acceleration). Comparing some prior versions (2022.11 pre-Boost, 3.0, 3.2, and now 3.3):

| Frame size | 2022.11 (pre-Boost) | v3.0 | v3.2 | v3.3 |
|------------|--------------------:|-----:|-----:|-----:|
| 64 B   | 99k pps | 173k pps | 328k pps | 452k pps |
| 128 B  | 98k pps | 174k pps | 330k pps | 444k pps |
| 256 B  | 97k pps | 189k pps | 329k pps | 436k pps |
| 512 B  | 108k pps | 183k pps | 324k pps | 409k pps |
| 1024 B | 110k pps | 193k pps | 308k pps | 378k pps |
| 1280 B | 109k pps | 198k pps | 301k pps | 365k pps |
| 1518 B | 112k pps | 196k pps | 307k pps | 371k pps |

The move to the concurrent hash map (v3.0) delivered roughly a 1.8&times; increase in sustained forwarding rate over the original design, and the subsequent tuning through v3.2 added another ~1.7&times;, compounding to about 3&times; over the 2022.11 baseline. v3.3 adds another 1.2-1.4&times; on this small instance; its larger gains are on instances with many vCPUs (see [README-Large-Instances.md](README-Large-Instances.md)). The gains are largest for small frames, where per-packet overhead dominates. The v3.2 and v3.3 columns were measured together, alternating between the two versions (three runs each, median shown); the older columns come from earlier sessions, so ratios against them are approximate (v3.2 measured 291-309k pps in an earlier session).

**Test setup:** gwlbtun ran on a single **c6in.xlarge** behind a Gateway Load Balancer, with a TRex load generator (c6in.4xlarge) driving UDP traffic through the GWLB endpoint and back in a loopback topology. Each trial offered a fixed packet rate for 15 seconds across roughly 59,000 concurrent flows (randomized source port). The figure reported is the *delivered* forwarding ceiling - the highest sustained packets-per-second gwlbtun actually returned - taken as the maximum across an offered-load sweep of 0.5-8 Mpps. These are a relative comparison on identical hardware and topology. Your figures will vary with your specific workload (traffic sources, flow count and mix, packet sizes, and what the appliance does with each packet). We encourage you to test against your exact workload to gauge the performance you'll get.

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

The kernel sends IPv6 router solicitations on every new interface, retrying indefinitely on many distributions (`router_solicitations=-1`). Nothing on a GWLB tunnel answers them, and gwlbtun counts the retries as tunnel activity, which can keep `-t` from ever timing out an idle tunnel. Turning them off on the tunnel interfaces leaves IPv6 traffic through the tunnels unaffected; the example scripts do this on CREATE:
```
sysctl net.ipv6.conf.$2.router_solicitations=0 net.ipv6.conf.$3.router_solicitations=0
```

## Kernel XPS (Transmit Packet Steering)
In two-arm configurations (usually NAT'ing through gwlbtun), the kernel forwards the decapsulated traffic out of a network interface, and without an XPS map (as we found on Amazon Linux 2023 with ENA; the ENA driver doesn't set one up, verified in ENA source) it picks the transmit queue from the tun queue gwlbtun wrote the packet on. Before 3.3 gwlbtun wrote through one tun queue, so almost all forwarded traffic left on one transmit queue unless XPS was set up. gwlbtun 3.3 writes through at least one tun queue per receive queue, each with its own queue index, so forwarded traffic spreads over the transmit queues with no XPS setup. Traffic that gwlbtun sends back to GWLB itself (one-arm mode) isn't affected either way.

Some unusual configurations can still benefit from XPS: a `--tunthreads` value that leaves room for fewer writers than gwlbtun wants (it logs this at startup), forwarding out of an interface with more transmit queues than the interfaces gwlbtun receives on, or an instance where gwlbtun can't find the receive queues. [Forwarded traffic and transmit queues (XPS)](Documentation/Tun-Devices-and-Kernel-Limits.md#forwarded-traffic-and-transmit-queues-xps) explains how this works, how to check the transmit queue distribution, and how to set up XPS.

## Research notes
The [Documentation](Documentation/README.md) folder holds what we've learned developing and testing gwlbtun: CPU and thread layout, tun device and kernel limits, the return path to GWLB, GWLB behaviour seen from the appliance, and how to performance-test it.

## Advanced usages

### No return mode
If you are only interested in the ability to receive traffic to an L3 tunnel interface, and will never send traffic back to GWLB, you can build with `cmake -DCMAKE_CXX_FLAGS=-DNO_RETURN_TRAFFIC .` (or uncomment `#define NO_RETURN_TRAFFIC` in utils.h). This removes the gwo interfaces and all flow tracking. Replies then take another path, so routing is asymmetric. See [Documentation/NO_RETURN_TRAFFIC.md](Documentation/NO_RETURN_TRAFFIC.md). 

### Handling overlapping CIDRs
See the example-scripts/create-nat-overlapping.sh script for an example of handling overlapping CIDRs in different GWLB endpoints in two-arm mode. This script leverages conntrack and marking to accomplish this.

### Supporting very high packet rates
gwlbtun gives each UDP receiver socket a large receive buffer (`--rcvbuf`, 128 MB by default) so that microbursts don't overflow it. The kernel caps socket buffers at `net.core.rmem_max`, which is far smaller by default (about 208 KB), and gwlbtun logs a warning at startup when the cap is lower than what it asks for. Raise it (and persist it in `/etc/sysctl.d/`):
```
sysctl -w net.core.rmem_max=268435456
sysctl -w net.core.rmem_default=134217728
```

You can see if receive buffers are overflowing by monitoring for UDP receive buffer errors (RcvbufErrors) with commands similar to:
```
# cat /proc/net/snmp | grep Udp: 
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
Udp: 2985556669902 428 0 666162 0 0 0 0 0
```

If RcvbufErrors is incrementing steadily, check `rmem_max` first, then consider a larger `--rcvbuf`. On instances with many vCPUs, packet loss at high rates more often comes from the CPUs that service the network queues falling behind; [README-Large-Instances.md](README-Large-Instances.md) covers how to spot and fix that.

### Health Check output
If you do not provide the -s flag, the health check port produces human-readable statistics about the traffic gwlbtun is processing. If you add in the -j flag, this output is formatted as JSON for consumption by outside monitoring processes.

## Security
The health check listener has no authentication and answers anyone who can reach it. On production appliances, bind it to the interface or address GWLB checks (`-p IFNAME:PORT` or `-p ADDR:PORT`) and allow the health port only from the GWLB's subnets in the security group. Hook commands (`-c`/`-r`, which can also be set in a configuration file) run as gwlbtun's user, usually root, so keep configuration files and hook scripts owned by root and not writable by anyone else.

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License
This tool is licensed under the MIT-0 License. See the LICENSE file.

### libyaml
libyaml (used to read configuration files) is licensed under the MIT License, Copyright (c) 2017-2020 Ingy döt Net and Copyright (c) 2006-2016 Kirill Simonov. The full license text is in [third_party/libyaml/License](third_party/libyaml/License).

### json.hpp
nlohmann/json (used for the JSON health check output) is licensed under the MIT License, Copyright (c) 2013-2023 Niels Lohmann. The full license text is in [third_party/json/LICENSE.MIT](third_party/json/LICENSE.MIT).

### Boost libraries
The vendored Boost headers are licensed under the Boost Software License, Version 1.0. The full license text is in [third_party/boost/LICENSE_1_0.txt](third_party/boost/LICENSE_1_0.txt).
