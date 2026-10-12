# The return path to GWLB

Applies to: gwlbtun 3.3 (standard builds; [NO_RETURN_TRAFFIC](NO_RETURN_TRAFFIC.md) builds have no
return path). Last checked: October 2026.

**Summary.** For every packet a tunnel thread reads from `gwo-<X>`, gwlbtun looks up the inner flow in
its flow cache to find the GENEVE header and outer addresses GWLB used for that flow, re-encapsulates
the packet and sends it to GWLB on a raw socket. gwlbtun drops packets of flows GWLB never sent it,
because it has no flow cookie to send them with: GWLB forwards a returned packet only if its inner
5-tuple and flow cookie match a flow GWLB sent, and silently drops it otherwise ([Integrate your custom
logic or appliance with AWS Gateway Load Balancer](https://aws.amazon.com/blogs/networking-and-content-delivery/integrate-your-custom-logic-or-appliance-with-aws-gateway-load-balancer/), step 6).
An appliance can't start new flows through GWLB.

## Flow cache

- Key: the inner 5-tuple (`PacketHeaderV4`/`V6`). Value: `GwlbData`, the GENEVE header bytes (options
  included, sent back unchanged), the outer source and destination address and port, and the interface
  the packet arrived on.
- Insert or refresh on the way in (`GeneveHandlerENI::udpReceiverCallback`), look up on the way out
  (`tunReceiverCallback`). One set of caches per GWLB endpoint, split by inner protocol into TCP, UDP
  and Other, each for IPv4 and IPv6, with separate idle timeouts: TCP `-i` (default 350 s, GWLB's
  default TCP idle timeout), UDP and Other 120 s.
- Expiry runs on the reaper thread every ~60 s (`GeneveHandler::sweep()`), never on the packet or health
  path. `--reserve` pre-sizes the tables so high flow counts don't stall on rehashing.
- (Measured) The appliance's cache size followed GWLB's `ActiveFlowCount` CloudWatch metric exactly,
  so the cache holds what GWLB forwards. Under packet-rate overload it grows only as fast as gwlbtun
  can insert (about 850–890k entries on a c6in.xlarge at ~2M pps offered).
- Set the TCP idle timeout (`-i`) to match the GWLB listener's
  [TCP idle timeout](https://docs.aws.amazon.com/elasticloadbalancing/latest/gateway/update-idle-timeout.html)
  if you change it (above 350 seconds, the same page says the appliance ENI's connection tracking timeout,
  `TcpEstablishedTimeout`, must be at least as long). A cache entry that expires before GWLB's flow does makes
  return packets for that flow drop until the next packet from GWLB refreshes it.

## Building the packet

`sendUdpSG()` in `utils.cpp` builds the outer IPv4 and UDP headers and sends them, the stored GENEVE
header and the inner packet as one scatter-gather `sendmsg()` on a `SOCK_RAW`/`IPPROTO_RAW` socket.

- **Addresses.** From the address GWLB sent to, back to the GWLB address it came from: source
  `dstAddr:srcPort`, destination `srcAddr:6081` (swap the IP addresses, keep the ports:
  [integration blog](https://aws.amazon.com/blogs/networking-and-content-delivery/integrate-your-custom-logic-or-appliance-with-aws-gateway-load-balancer/), step 4).
- **Outer UDP checksum is 0** ("no checksum", valid for IPv4). (Kernel behaviour.) For an
  `IPPROTO_RAW` socket the kernel fills in the IP header checksum but treats everything after the IP
  header as opaque, and no checksum offload is set up, so an unset field would go out as whatever was on
  the stack. That was a bug before 3.2.
- **TTL is 2, on purpose.** In our tests that is enough for a return packet to reach GWLB, and the low
  TTL limits how far a misrouted one can travel. Don't raise it.
- **Don't Fragment is set, and the IP ID is 0.** (3.3; kernel source and measured.) With DF set the
  packet is an atomic datagram (RFC 6864), and Linux leaves a zero ID alone. Without DF, Linux gives each
  raw `IP_HDRINCL` packet with a zero ID one from a counter keyed by source, destination and protocol, so
  every tunnel thread sending to the same GWLB address shares it; that cost 3–13% of a c8in.96xlarge's
  CPU at 12–14M pps. The packets were never fragmented anyway: the kernel rejects raw sends larger than
  the interface MTU (`EMSGSIZE`).
- **Out of the interface it came in on.** (Fixed in 3.3.) The packet carries an `IP_PKTINFO` control
  message with the ingress interface index and the source address. Without it the kernel routes by
  destination alone, so on an instance with two ENIs registered as targets, replies for traffic sent to
  the second ENI left by the first one with the second one's source address, and were dropped
  (observed, with source/destination checking on). (Measured on a two-ENI c6i.large: 0 of 20 replies for the secondary ENI before,
  20 of 20 after.) Setting the source also lets per-ENI source policy routing match.
- **Route caching for raw sends.** (Measured on a c8in.96xlarge.) Linux caches the route of an
  `IP_HDRINCL` raw send only when its next hop is a gateway: `raw_sendmsg` sets `FLOWI_FLAG_KNOWN_NH`,
  and `__mkroute_output` skips the per-CPU route cache for a directly connected next hop. When the GWLB
  is in the appliance's subnet, every return packet allocates and frees a route entry. A host route to
  the GWLB address via the subnet's router fixes it (see README-Large-Instances.md, step 4).

## Sockets and send buffers

- **One raw socket per tunnel thread.** (3.3.) Each tunnel thread opens its own socket at thread start
  (`ThreadRawSendSocket`) and the per-packet send only reads a `thread_local` fd. With one socket shared by
  an endpoint's threads, the socket's send-buffer accounting was a cache line written by every sending
  core; on a c8in.96xlarge switching to per-thread sockets raised the lossless rate from 2.0M to 3.5M pps
  (64 bytes). The endpoint's shared socket remains as a fallback if a thread can't open its own.
- **Send buffer.** (Measured.) With the default send buffer the tunnel threads spent most of their time
  waiting for buffer space (45% of CPU on the c8in at 2M pps). gwlbtun sets 16 MB per socket
  (`--sndbuf`, `SO_SNDBUFFORCE`, so `net.core.wmem_max` doesn't limit it; the kernel doubles the value for
  its own overhead). Whether per-thread sockets still need that much hasn't been measured.

## Debugging return traffic that never arrives

1. Capture the outer packets only: `tcpdump -ni <if> udp and dst port 6081 and host <GWLB IP>`.
   - Nothing leaving: the packet never got to gwlbtun's send (no flow-cache entry, wrong `gwo-`
     routing in the hook, or the tunnel read side), or it left by another interface (check every ENI).
   - Packets leaving but the flow still failing: look at the GWLB side (target health, the endpoint's
     route tables). The GENEVE header is sent back exactly as received.
2. gwlbtun's debug log (`--logging tunnel=debug`) reports return packets for flows "not seen coming in
   from GWLB".
3. On multi-ENI targets, check which ENI each reply leaves by (`tcpdump` on each).
