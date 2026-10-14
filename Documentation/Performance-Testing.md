# Performance testing gwlbtun

Applies to: gwlbtun 3.2 and 3.3. Last checked: October 2026.

**Summary.** How we measured gwlbtun, and the mistakes that made early numbers wrong. The short
version: use a DPDK generator, warm the GWLB up, compute rates from measured time, and read loss and
latency only below the knee.

Running these tests yourself costs money and generates high traffic volumes; read
[Testing in AWS](../tests/README.md#testing-in-aws) first, including the AWS testing policies it links
(the [Amazon EC2 Testing Policy](https://aws.amazon.com/ec2/testing/) covers network stress tests). These are stress tests of our
own appliance, in our own account and one Region.

## Test setup

- **Ring.** A TRex generator (c6in.4xlarge, DPDK on two ENIs) sends UDP from a sender subnet through a
  GWLB endpoint; GWLB delivers it to the gwlbtun appliance (c6in.xlarge for the README table), which
  passes it back through GWLB to the generator's receiver subnet. The appliance runs the passthrough
  hook (`tc` mirred from `gwi-` to `gwo-`).
- **Traffic.** About 59,000 concurrent flows (random UDP source port), fixed frame size per step, one
  offered rate per step, plus a separate 1,000 pps stream for latency.
- **Why DPDK.** Our kernel-socket generator (udpgen) topped out around 1.1M
  pps per sender, below the appliance's limit, so profiles taken with them show moderate load, and
  version differences fall inside run-to-run noise (±13–28%). TRex shows the real ceiling.
- **Functional test setups** (iperf3/udpgen through a GWLB, one per architecture) are useful as functional and
  regression checks, but identical runs varied by about 20%, so they can't resolve differences under
  about 10%.

## How the README table is made

The 7 frame sizes (64–1518 bytes) × offered rates of 0.5, 1, 2, 4 and 8M pps, 15 s per step. The
reported figure is the highest delivered rate over the sweep (received packets ÷ step time). Versions
are compared on the same appliance and generator, alternating between versions, with a warm-up first.
The figure is a forwarding ceiling under overload, not a lossless rate. For "how much can it carry
without loss", look at the lowest-loss steps or run a finer sweep below the knee.

## Pitfalls we hit

**New or idle load balancer.** In our tests, the first codebase measured on a newly created or idle GWLB
scored up to 60% lower. Warm up with ~10 minutes of sustained traffic before the first measurement, and a
couple of minutes after each appliance rebuild. See [GWLB-Observations.md](GWLB-Observations.md).

**Steps that ran longer than configured.** When the generator's transmit queues back up, TRex still
sends a step's full packet count, just more slowly (a "10M pps for 20 s" step took 47.7 s). Dividing
received packets by the configured duration then overstates the rate. Record each step's start and stop
time and divide by that.

**Offered rates the generator can't send.** At the 4M and 8M pps steps `pps_allowance_exceeded` rose on
both the generator and the appliance, and 1518 bytes at 8M pps (about 97 Gbps) is more than the
c6in.4xlarge's up-to-50 Gbps network bandwidth. EC2 [queues and then drops](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring-network-performance-ena.html) traffic above an
allowance, so "offered" isn't real, and every codebase shows a dip at 2–4M and a rise at 8M.
Check `ethtool -S` allowance counters on both ends; a c6in.4xlarge generator showed no allowance drops at
up to 3M pps.

**Generator limits on big appliances.** In our setup one c6in.32xlarge TRex box sustained about 10M pps
combined transmit and receive, so it can only push about 5M pps through an appliance and back. A c8in.96xlarge
forwarded all of it. Finding a big appliance's ceiling needs several generators or port pairs.

**Latency above the knee is queueing.** Below the knee (about 300k pps for v3.2 on a c6in.xlarge) RTT
through gwlbtun was 0.6–0.9 ms with tens of microseconds of jitter. Above it, latency rose to seconds as
queues filled. Only report latency from steps below the knee.

**Loss floor.** End-to-end loss in a 30 s step was 0.001–0.014% even far below capacity, from packets
in flight when a step stops and from loss outside the appliance. A pass/fail threshold below that floor
is random. Separate loss inside the appliance (interface rx vs tx) from end-to-end loss.

**Crashes hide behind loss numbers.** Loss is computed from generator counters, so a gwlbtun that
crashed and restarted mid-run just looks like more loss. Check the process ID, `dmesg` for segfaults
and core dumps alongside every perf run.

**Bursty traffic and idle teardown.** Tests of `-t` idle teardown with bursty traffic often see no
teardown at all in a few minutes, because the 60 s sweep rarely lands in an idle gap. Use one burst and
wait past the timeout plus a sweep.

## Profiling

`perf record -a -g` for 10 s under overload, on the appliance, was enough to find each large-instance
bottleneck (see [Tun-Devices-and-Kernel-Limits.md](Tun-Devices-and-Kernel-Limits.md) and
[CPUs-and-UDP-Affinity.md](CPUs-and-UDP-Affinity.md)). At moderate load gwlbtun's own user-space code
was only 5–8% of CPU; most went to kernel receive processing and the per-packet copy between kernel and
user space, which batching (`recvmmsg`, scatter-gather `sendmsg`) doesn't remove.

## History of the measured ceiling (c6in.xlarge, UDP)

| Version | Delivered ceiling | Main change |
|---|---|---|
| 2022.11 | ~100–110k pps | original design |
| 3.0 | ~175–200k pps | concurrent hash map flow cache |
| 3.1 | ~275–305k pps | scatter-gather send |
| 3.2 | ~290–310k pps | `recvmmsg` batch receive (no change in ceiling on this instance) |
| 3.3 | see the README table | large-instance changes |
