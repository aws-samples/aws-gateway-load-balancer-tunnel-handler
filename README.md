# aws-gateway-load-balancer-tunnel-handler
This software supports using the Gateway Load Balancer AWS service. It is designed to be ran on a GWLB target, takes in the Geneve encapsulated data and creates Linux tun (layer 3) interfaces per endpoint. This allows standard Linux tools (iptables, etc.) to work with GWLB.

See the 'example-scripts' folder for some of the options that can be used as create scripts for this software.

## To Compile
On an Amazon Linux 2 host, copy this code down, and install dependencies:

```
sudo yum groupinstall "Development Tools"
sudo yum install cmake3
```

In the directory with the source code, do ```cmake3 .; make``` to build.


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

---------------------------------------------------------------------------------------------------------
Tunnel command arguments:
The commands will be called with the following arguments:
1: The string 'CREATE' or 'DESTROY', depending on which operation is occurring.
2: The interface name of the ingress interface (gwi-<X>).
3: The interface name of the egress interface (gwo-<X>).  Packets can be sent out via in the ingress
   as well, but having two different interfaces makes routing and iptables easier.
4: The GWLBE ENI ID in base 16 (e.g. '2b8ee1d4db0c51c4') associated with this tunnel.

The <X> in the interface name is replaced with the base 60 encoded ENI ID (to fit inside the 15 character
device name limit).
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
