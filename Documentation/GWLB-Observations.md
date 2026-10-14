# GWLB and EC2 networking, as seen from the appliance

Applies to: gwlbtun 3.2 and 3.3. Last checked: October 2026, us-west-2.

**Summary.** What we observed about Gateway Load Balancer and EC2 networking while testing gwlbtun,
separated into what AWS documents and what we only observed. Observations describe our tests, not
guaranteed behaviour; check the linked documentation for current limits.

## Documented behaviour gwlbtun depends on

- **GENEVE on UDP 6081** ([target groups](https://docs.aws.amazon.com/elasticloadbalancing/latest/gateway/target-groups.html)),
  with GWLB-specific options that include the GWLB endpoint ID and a flow cookie
  ([integration blog](https://aws.amazon.com/blogs/networking-and-content-delivery/integrate-your-custom-logic-or-appliance-with-aws-gateway-load-balancer/)). gwlbtun stores each
  flow's GENEVE header and sends it back unchanged with the return packets.
- **MTU**: GWLB [supports packets up to 8500 bytes](https://docs.aws.amazon.com/elasticloadbalancing/latest/gateway/gateway-load-balancers.html),
  adds 68 bytes of encapsulation, doesn't fragment and doesn't send ICMP "fragmentation needed".
- **Idle timeouts**: TCP flows 350 seconds by default,
  [configurable from 60 to 6000](https://docs.aws.amazon.com/elasticloadbalancing/latest/gateway/update-idle-timeout.html).
  gwlbtun's TCP flow-cache timeout (`-i`, default 350) should match it. Per the same page, above 350 seconds
  the appliance ENI's connection tracking timeout (`TcpEstablishedTimeout`) must be at least as long. Non-TCP flows time out after 120 seconds,
  which [can't be changed](https://docs.aws.amazon.com/elasticloadbalancing/latest/gateway/gateway-load-balancers.html#idle-timeout).
- **Inline inspection**: GWLB sends the appliance flows that pass through an endpoint, and the appliance
  returns them ([integration blog](https://aws.amazon.com/blogs/networking-and-content-delivery/integrate-your-custom-logic-or-appliance-with-aws-gateway-load-balancer/), steps 2–7; asymmetric flows in the
  [GWLB documentation](https://docs.aws.amazon.com/elasticloadbalancing/latest/gateway/gateway-load-balancers.html)). gwlbtun only returns packets of flows it has seen from GWLB, and drops anything else
  (for example packets the appliance originates).

## Observed

**Throughput was lower on a new or idle load balancer.** In our tests, the first codebase measured
against a newly created or idle GWLB got markedly lower numbers (v3.2 at 64 bytes: about 122k pps, vs
307k pps after sustained traffic). It took around 10 minutes of sustained traffic to reach the full rate,
and rates were lower again after several idle minutes. New flows also reached the appliance more slowly
in the first minutes of such a run: about 27k new flows per second. These are our measurements, not GWLB
limits; GWLB scales automatically with traffic, and [LCU reservation](https://docs.aws.amazon.com/elasticloadbalancing/latest/gateway/capacity-unit-reservation.html) is the documented way to
start with a minimum capacity (we didn't test it). Every performance run should start with a warm-up
(see [Performance-Testing.md](Performance-Testing.md)).

**The flow count tracked GWLB's `ActiveFlowCount` metric, not the offered cardinality.** In our tests
gwlbtun's flow-cache size matched the `ActiveFlowCount` CloudWatch metric (namespace `AWS/GatewayELB`)
to the digit. With traffic that cycled a small set of source addresses, both quickly settled at a steady
working set well below the number of flows offered; with monotonically new source addresses they kept
growing, up to about 4.8M concurrent flows in our runs. If gwlbtun's cache size plateaus, compare it
with `ActiveFlowCount` before suspecting gwlbtun.

**The connection-tracking allowance stayed at zero, whatever the inner-flow count.** (Observed.) The
appliance's interface sees only the outer GENEVE packets between the GWLB and the appliance on port 6081,
not the inner flows, and in our tests `conntrack_allowance_exceeded` stayed at 0 however many inner flows
passed. Whether EC2 tracks those packets at all depends on the appliance's security group rules
([untracked connections](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-connection-tracking.html#untracked-connections)). The allowance that limited the appliance was packets per
second: `pps_allowance_exceeded` reached hundreds of millions in overload on a c6in.xlarge. Inner-flow
counts load gwlbtun's own flow cache instead. In our tests a traffic generator sending many distinct
flows from its own interface did hit its own connection-tracking allowance; security group rules that
leave the flows [untracked](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-connection-tracking.html#untracked-connections) avoid that.

**EC2 network allowance counters are the first thing to check.** `ethtool -S <if> | grep allowance`
shows packets queued or dropped because the instance exceeded its bandwidth, PPS, connection-tracking or
link-local allowance ([documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring-network-performance-ena.html)).
Non-zero values mean the instance reached one of those network allowances, not a gwlbtun limit. On the c8in.96xlarge tuned layout
they stayed at zero; the limits there were inside the appliance.

**Health checks arrive steadily.** GWLB health-checks every target continuously, so the health port
always has recent connections (and TIME_WAIT entries after a restart). gwlbtun 3.3 sets `SO_REUSEADDR`
on the health listener, so a restart doesn't fail with "Address already in use", and serves each health
client on its own short-lived thread, so a client that holds its connection can't delay GWLB's checks.

**A known flow can come back with a new flow cookie.** gwlbtun logs "GWLB data changed for an
established flow" when a packet from GWLB for a 5-tuple already in its flow cache carries a different
GENEVE header or outer addresses, and updates the cache entry. The message shows the inner flow and the
old and new values (from 3.3; earlier versions logged only that a change happened). For example, from a
test that sent the same inner flow twice with different cookies:

```
IPv4 UDP Flow Cache for GWLBe vpce-0f17e000000000a01: GWLB data changed for an established flow
(PacketHeaderV4: SrcIP: 10.9.8.7, DstIP: 192.0.2.1  Prot UDP, src pt 40000, dst pt 53): was Outer:
127.0.0.1:45000 -> 127.0.0.1:6081 ifindex 1 GWLBe endpoint: vpce-0f17e000000000a01 Attachment ID: 0x0
Flow Cookie: 0x11111111; now Outer: 127.0.0.1:45000 -> 127.0.0.1:6081 ifindex 1 GWLBe endpoint:
vpce-0f17e000000000a01 Attachment ID: 0x0 Flow Cookie: 0x22222222. Occurrences in this cache: 1
(logging the first and every 4096th). Usually benign; investigate if frequent (for example a gwlbtun/GWLB
idle-timeout mismatch).
```

(One line in the log; wrapped here.) We saw it once, in
a burst of tens of thousands within a fraction of a second on a c6in.xlarge appliance: one second after
a TRex run resumed the same set of UDP flows after exactly 120 seconds idle. GWLB's idle timeout for
non-TCP flows is 120 seconds ([GWLB documentation](https://docs.aws.amazon.com/elasticloadbalancing/latest/gateway/gateway-load-balancers.html#idle-timeout)), and GWLB
generates a flow cookie when it creates a flow entry ([Integrate your custom logic or appliance with AWS
Gateway Load Balancer](https://aws.amazon.com/blogs/networking-and-content-delivery/integrate-your-custom-logic-or-appliance-with-aws-gateway-load-balancer/)),
while gwlbtun's UDP cache entries had not been swept yet. Inferred cause: the flows had expired at GWLB
and come back as new flows with new cookies. That is harmless, since gwlbtun stores the new header.
Frequent occurrences outside such idle boundaries would point to an idle-timeout mismatch, for example a
TCP listener timeout different from gwlbtun's `-i`.

## Multiple ENIs and multiple processes

- An instance can have several ENIs registered as targets (for example IP targets, one per ENI). Before
  3.3, replies for traffic that arrived on a secondary ENI left by the primary one, with the secondary
  ENI's address, and were dropped (observed, with source/destination checking on). See [Return-Path.md](Return-Path.md).
- gwlbtun binds the GENEVE port with `SO_REUSEPORT`, so two processes receiving on the same interfaces
  would silently split the traffic. 3.3 refuses to start a second process unless each uses `-I` with
  different interfaces (an abstract Unix socket per interface, per network namespace).
