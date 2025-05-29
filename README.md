# aws-gateway-load-balancer-tunnel-handler
This software supports using the Gateway Load Balancer AWS service. It is designed to be ran on a GWLB target, takes in the Geneve encapsulated data and creates Linux tun (layer 3) interfaces per endpoint. This allows standard Linux tools (iptables, etc.) to work with GWLB.

See the 'example-scripts' folder for some of the options that can be used as create scripts for this software.

## To Compile
On an Amazon Linux 2 or AL2023 host, copy this code down, and install dependencies:

```
sudo yum groupinstall "Development Tools"
sudo yum install cmake3
```

In the directory with the source code, do ```cmake3 .; make``` to build. This code works with both Intel and Graviton-based architectures.

**This version requires the Boost libraries, version 1.83.0 or greater.** This tends to be a newer version than available on distributions (for example, at time of writing, 1.75 is available in AL2023). You may need to go to https://www.boost.org/, download, and install a newer version than what's available in the repositories  

## Usage
For Linux, the application requires CAP_NET_ADMIN capability to create the tunnel interfaces along with the example helper scripts.
```
Tunnel Handler for AWS Gateway Load Balancer
Usage: ./gwlbtun [options]
Example: ./gwlbtun

  -h         Print this help
  -c FILE    Command to execute when a new tunnel has been built. See below for arguments passed.
  -r FILE    Command to execute when a tunnel times out and is about to be destroyed. See below for arguments passed.
  -t TIME    Minimum time in seconds between last packet seen and to consider the tunnel timed out. Set to 0 (the default) to never time out tunnels.
             Note the actual time between last packet and the destroy call may be longer than this time.
  -p PORT    Listen to TCP port PORT and provide a health status report on it.
  -j         For health check detailed statistics, output as JSON instead of text.  
  -s         Only return simple health check status (only the HTTP response code), instead of detailed statistics.
  -d         Enable debugging output. Short version of --logging all=debug.

Threading options:
  --udpthreads NUM         Generate NUM threads for the UDP receiver.
  --udpaffinity AFFIN      Generate threads for the UDP receiver, pinned to the cores listed. Takes precedence over udptreads.
  --tunthreads NUM         Generate NUM threads for each tunnel processor.
  --tunaffinity AFFIN      Generate threads for each tunnel processor, pinned to the cores listed. Takes precedence over tunthreads.

AFFIN arguments take a comma separated list of cores or range of cores, e.g. 1-2,4,7-8.
It is recommended to have the same number of UDP threads as tunnel processor threads, in one-arm operation.
If unspecified, --udpthreads <N> and --tunthreads <N> will be assumed as a default, based on the number of cores present.

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
The available sections are: core udp geneve tunnel healthcheck all 
The logging levels available for each are: critical important info debug debugdetail 
The default level for all secions is 'important'.
```

## Configuration Files

### Dockerfile
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

## Deployment
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

Consider implementing network policies for additional security


## Source code layout
main.cpp contains the start of the code, but primarily interfaces with GeneveHandler, defined in GeneveHandler.cpp. 
That class launches the multithreaded UDP receiver, and then creates GeneveHandlerENI class instances per GWLB ENI detected.
The GeneveHandlerENI class instantiates the TunInterfaces as needed, and generally manages the entire packet handling flow for that ENI. 
GenevePacket and PacketHeader handle parsing and validating GENEVE packets and IP packets respectively, and are called by GeneveHandler as needed.
Logger handles processing logging messages from all threads, ensuring they get output correctly to terminal, and filtering against the logging configuration provided.

## Multithreading
gwlbtun supports multithreading, and doing so is recommended on multicore systems. You can specify either the number or threads, or a specific affinity for CPU cores, for both the UDP receiver and the tunnel handler threads. You should test to see which set of options work best for your workload, especially if you have additional processes doing processing on the device. By default, gwlbtun will create one UDP receive thread and one tunnel processing thread per core. 

gwlbtun labels its threads with its name (gwlbtun), and either Uxxx for the UDP threads option which is simply an index, or UAxxx for the UDP affinity option, with the number being the core that thread is set for. The tunnel threads are labeled the same, except with a T instead of a U.

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

## Advanced usages

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
