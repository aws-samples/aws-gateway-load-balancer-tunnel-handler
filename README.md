# aws-gateway-load-balancer-tunnel-handler
This software supports using the Gateway Load Balancer AWS service. It is designed to be ran on a GWLB target, takes in the Geneve encapsulated data and creates Linux tun (layer 3) interfaces per endpoint. This allows standard Linux tools (iptables, etc.) to work with GWLB.

See the 'example-scripts' folder for some of the options that can be used as create scripts for this software.

## To Compile
On an Amazon Linux 2 host, copy this code down, and install dependencies:

```
sudo yum groupinstall "Development Tools"
sudo yum install cmake3
```

In the directory with the source code, do ```cmake3 .; make``` to build. This code works with both Intel and Graviton-based architectures.


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
  -s         Only return simple health check status (only the HTTP response code), instead of detailed statistics.
  -d         Enable debugging output.
  -x         Enable dumping the hex payload of packets being processed.

Threading options:
  --udpthreads NUM         Generate NUM threads for the UDP receiver.
  --udpaffinity AFFIN      Generate threads for the UDP receiver, pinned to the cores listed. Takes precedence over udptreads.
  --tunthreads NUM         Generate NUM threads for each tunnel processor.
  --tunaffinity AFFIN      Generate threads for each tunnel processor, pinned to the cores listed. Takes precedence over tunthreads.

AFFIN arguments take a comma separated list of cores or range of cores, e.g. 1-2,4,7-8.
It is recommended to have the same number of UDP threads as tunnel processor threads, in one-arm operation.

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
```

## Source code layout
main.cpp contains the start of the code, but primarily interfaces with GeneveHandler, defined in GeneveHandler.cpp. 
That class instantiates UDPPacketReceiver and TunInterface as needed, and generally manages the entire packet handling flow. 
GenevePacket and PacketHeader handle parsing and validating GENEVE packets and IP packets respectively, and are called by GeneveHandler as needed.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
