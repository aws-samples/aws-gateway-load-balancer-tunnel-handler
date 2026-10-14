# CPUs and UDP affinity

Applies to: gwlbtun 3.3. Last checked: October 2026, on c6in.xlarge, c6gn.xlarge and c8in.96xlarge
(AL2023, kernels 6.1 and 6.18).

**Summary.** The network interface, not the vCPU count, decides how many CPUs receive packets. Each
receive queue is serviced by one CPU, and gwlbtun's threads have to share the instance with that
receive processing. On instances with more vCPUs than queues, one UDP thread per vCPU (gwlbtun's
default before 3.3) starts far more threads than the queues can feed, and they get in each other's way.
gwlbtun now starts one UDP thread per receive queue by default, pins each on a free CPU next to its
queue's CPU where there is one, and ties each thread to its queue.

## How a GENEVE packet reaches a gwlbtun thread

1. The ENA network interface puts the packet on one of its receive queues, chosen by a hash of the
   packet's addresses and ports (RSS). In our tests GWLB's outer UDP source port varied per flow, so
   flows spread across queues (observed).
2. The CPU that services that queue's interrupt runs the kernel's receive processing (NAPI softirq)
   for it, up to the UDP socket lookup.
3. gwlbtun has one UDP socket per receiver thread, all bound to port 6081 with `SO_REUSEPORT`. The
   kernel picks one socket of the group for each packet, normally by a hash of the 4-tuple.
4. The receiver thread reads a batch with `recvmmsg()`, decapsulates, and writes the inner packet to
   the endpoint's `gwi-` interface. See [Tun-Devices-and-Kernel-Limits.md](Tun-Devices-and-Kernel-Limits.md).

## Findings

**Queue counts are capped well below the vCPU count on big instances.** (Measured.) A c8in.96xlarge
(384 vCPUs) had 32 queues per interface; a c6in.xlarge (4 vCPUs) had 4. The per-ENI and per-instance
limits for each instance type are in the [ENA queues documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ena-queues.html),
and on supported types the count can be configured per ENI, so gwlbtun looks it up per interface
(`/proc/interrupts` entries named `<ifname>-Tx-Rx-<n>`).

**Too many threads cost throughput.** (Measured, c8in.96xlarge, one GWLB endpoint, TRex, ~59k flows.)

| UDP / tunnel threads | Pinned | 64 B lossless | Behaviour in overload |
|---|---|---|---|
| 384 / 255 (one per vCPU) | no | ~2.5M pps | collapses to ~1.6M pps, 1–4 s latency |
| 128 / 128 | no | ~4M pps | ~2.2M pps, tens of ms |
| 128 / 128, IRQs pinned, threads away from queue CPUs | yes | ≥ 5.05M pps (generator limit) | 0.7 ms |
| 320 / 255 (every non-queue CPU) | yes | nearly as bad as the defaults | |
| 32 / 128, one UDP thread per queue on the queue CPU's hyperthread sibling, tied to the queue | yes | ≥ 5.05M pps | |

A later run compared the per-queue layouts directly (64 B, delivered at 8M pps offered, 2 reps; tunnel
threads pinned to 128 CPUs away from the queues except in the first two rows):

| UDP layout | IRQs | Delivered | Loss |
|---|---|---|---|
| one per queue, unpinned; 255 unpinned tunnel threads | irqbalance | 2.5M pps | 66% |
| one per queue, unpinned; 255 unpinned tunnel threads | pinned | 1.7M pps | 78% |
| one per queue, unpinned | pinned | 3.7M pps | 42% |
| one per queue, `nearest` | pinned | 5.0M pps (generator limit) | 0.1% |
| one per queue, hand-pinned on the siblings | pinned | 5.0M pps (generator limit) | 0.1% |

So the placement matters as much as the count, and `nearest` matched the hand-pinned layout up to what
one generator could send.

With four generators (up to ~20M pps offered; 64 B and 1024 B behaved alike), the layouts separated:

| UDP / tunnel threads | IRQs | Lossless to | Overloaded |
|---|---|---|---|
| 32 `nearest` (default) / 255 unpinned (default) | irqbalance | ~3M pps | 2–3.4M pps, seconds of latency |
| 32 `nearest` / 255 pinned off the queue CPUs and siblings | pinned | ~2–4M pps | ~4M pps |
| 32 `nearest` / 128 pinned | pinned | ~6M pps | collapses to 3.5–4.3M pps; queue CPUs ~95% busy |
| 128 pinned off the queue CPUs / 128 pinned | pinned | ~8M pps | holds ~8.2–8.9M pps; UDP CPUs ~97% busy |

At the 128/128 peak the appliance's NIC delivered ~8.9M pps and gwlbtun forwarded it all (no socket or
softnet drops; `ethtool -S` allowance counters at zero). The rest didn't reach the kernel: from ~9M pps
offered the NIC's `rx_packets` fell short of what was sent, with no instance counter accounting for the
difference, and from ~10M offered the NIC also dropped receive-ring overruns (`rx_overruns`, ~0.8M pps at
10M offered) with the queue CPUs only 55–65% busy at one-second resolution. Why the rings overrun with CPU
to spare is still open. A 4096-entry ring (set before pinning the interrupts: `ethtool -G` frees and
re-requests the queue interrupts, verified in [ENA source](https://github.com/amzn/amzn-drivers/tree/master/kernel/linux/ena), and in our tests that reset their
affinity) made 8M pps lossless but didn't raise the ~8.7–8.9M peak; 8192 was no better. (The
[amzn-drivers](https://github.com/amzn/amzn-drivers/tree/master/kernel/linux/ena) ENA driver, like AL2023's, reports `rx_overruns` as `rx_errors` and
`rx_over_errors` too; verified in ENA source and measured.) With one thread per queue the
thread shares its physical core with the queue's softirq, so both saturate together and throughput
collapses instead of levelling off. The tunnel thread count matters too: 255 was worse than 128 even
pinned away from the queues. (Measured, one run each; the 128/128 numbers repeated across two runs.)

All rows include the 3.3 code changes. For 1024-byte packets the 32-thread layout was lossless only to
about 4M pps; 128 UDP threads reached at least 4.79M pps.

**The queue CPUs must keep up, or the NIC drops packets you can't see.** (Measured.) When gwlbtun's
threads competed for the queue CPUs, the NIC dropped packets because the guest didn't refill receive
buffers in time: at default thread counts 2–4.9M pps, with 128+128 unpinned threads 1.2–3.2M pps, with
the pinned layout 0–1k pps. gwlbtun's counters don't show these drops. The ENA driver counts them as
`rx_overruns` in `ethtool -S` (no free descriptor in the receive ring; see the
[ENA best practices](https://github.com/amzn/amzn-drivers/blob/master/kernel/linux/ena/ENA_Linux_Best_Practices.rst)), and the amzn-drivers driver, like AL2023's, also as `rx_errors` /
`rx_over_errors` in `ip -s -s link` (verified in ENA source). Other signs are a gap between what the sender sent and the
interface's `rx_packets`, with idle CPUs elsewhere, and per-CPU drops or "time squeeze" in
`/proc/net/softnet_stat`.

**irqbalance undoes interrupt pinning.** (Observed.) It moves queue interrupts at runtime. The
[ENA best practices](https://github.com/amzn/amzn-drivers/blob/master/kernel/linux/ena/ENA_Linux_Best_Practices.rst) recommend keeping irqbalance running and excluding CPUs from it
(`IRQBALANCE_BANNED_CPUS`) rather than disabling it. Pinned layouts need it to leave the queue
interrupts alone, either stopped (what we tested) or with those interrupts excluded (irqbalance's
`--banirq`; untested), and the affinity set at boot, because gwlbtun reads interrupt affinity only
once, at startup.

**The receive ring size helped a little, once interrupts were pinned after setting it.** (Measured.) In an
early run, raising the ring to 8192 (the
largest `ethtool -g` reported on the c8in.96xlarge; ENA allows up to 16K depending on the instance type,
per the [ENA best practices](https://github.com/amzn/amzn-drivers/blob/master/kernel/linux/ena/ENA_Linux_Best_Practices.rst)) dropped the lossless rate to about 1M pps; we didn't confirm the
cause (that run may have lost its interrupt pinning to the ring change). In later runs with the interrupts pinned after the change, 4096 made 8M pps lossless and 8192
was no better than 4096 (above). The ENA best practices suggest a larger ring for bursty load; measure
before changing it.

**Tying sockets to queues needs Linux 6.2 or later.** (Documented in the kernel source.) With
`SO_INCOMING_CPU` set on the sockets of a reuseport group, `reuseport_select_sock_by_hash()`
(`net/core/sock_reuseport.c`, since the 6.2 fix "soreuseport: Fix socket selection for SO_INCOMING_CPU")
picks the socket whose incoming CPU is the CPU processing the packet, starting its scan at the hash
position, and falls back to the hashed socket. Older kernels accept the option and ignore it for
selection. On AL2023, kernels 6.12 and 6.18 have it and 6.1 doesn't; the `kernel-default` AMI parameter
[tracks the latest kernel](https://aws.amazon.com/blogs/compute/amazon-linux-default-ssm-parameter-will-now-track-the-latest-kernel/) from August 2026.

The scan is linear over the group, per packet. With one socket per queue that's cheap and each match is
unique. With several sockets per queue the first match after the hash position wins, so the extra
sockets get uneven traffic, and with hundreds of sockets the scan itself costs. gwlbtun therefore only
ties sockets when an interface has exactly one UDP thread per queue (the default, or `--udpthreads`/
`--udpaffinity` with that many entries), giving thread *i* queue *i*'s CPU. See
`resolveUdpPlan()` and `detectRxQueueCpus()` in `GwlbtunConfig.cpp`.

**Unpinned threads may still land on their queue's CPU.** (Inferred.) A receiver thread is woken by
the queue CPU's softirq, and the scheduler tends to wake it on or next to that CPU. Under heavy load the
thread and the receive processing then compete for one CPU. On instances with hyperthreads, pinning
thread *i* to the sibling of queue *i*'s CPU avoids that while keeping the caches shared. Whether the
unpinned layout is good enough on large instances was measured (table above): it isn't, which is why
`nearest` became the default.

## Cache sharing between CPUs

Placing a receiver near its queue's CPU only helps through shared caches. What "near" means depends on
the processor (topology is in `/sys/devices/system/cpu/cpu<N>/cache/index<L>/shared_cpu_list`, and
`lscpu -e`):

| Processor family (examples) | SMT | Shared with a neighbour |
|---|---|---|
| Intel Xeon (c6in, c7i, c8in) | 2 threads per core | L1/L2 with the hyperthread sibling; L3 across the socket, or per sub-NUMA cluster when the instance exposes several NUMA nodes per socket |
| AMD EPYC 3rd gen (c6a) | 2 threads per core | L1/L2 with the sibling; L3 per core complex (CCX) |
| AMD EPYC 4th gen (c7a, m7a) | off: [each vCPU is a physical core](https://aws.amazon.com/ec2/instance-types/m7a/) | L3 per core complex (CCX) |
| Graviton (c6gn, c7gn, c8gn) | none | private L1/L2 per core; last-level cache shared by all cores of a socket ([Graviton guide](https://github.com/aws/aws-graviton-getting-started); the largest Graviton4 sizes have two sockets) |

So on Intel the useful neighbour is the hyperthread sibling (then the same NUMA node), on 4th-gen AMD
it's another core in the same core complex, and on Graviton there's no closer neighbour than "same NUMA
node". This is an inference from the topology; we have only measured the Intel case.

## What gwlbtun does

- Default UDP threads (`--udpaffinity nearest`): one per receive queue of each interface it receives on
  (`-I`, or the default-route interface), each tied to its queue and pinned to the closest CPU that
  services no queue, ranked by the cache table above: a CPU sharing a level-1/2 cache (the hyperthread
  sibling), then one sharing any cache (L3), then the same NUMA node. With no free CPU, as on instances
  where every vCPU services a queue (most sizes up to about 8 vCPUs; see [ENA queues](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ena-queues.html)), the
  thread stays unpinned. One unpinned
  thread per vCPU where no queues are found. It logs the queue-to-CPU mapping it chose, and
  `--show-config` shows the resolved layout. (`resolveUdpPlan()` in `GwlbtunConfig.cpp`.)
- `--udpthreads N` / `--udpaffinity LIST` override the count (and pinning); the tie applies whenever the
  count equals the interface's queue count.
- Tunnel threads still default to one per vCPU, at most 255 and leaving room for the gwi- writers (224 on a c8in.96xlarge; see the tun limits note).
- The large-instance guide ([README-Large-Instances.md](../README-Large-Instances.md)) has the tested
  layouts and the interrupt pinning procedure.

## Open questions

- Tunnel threads still default to one per vCPU (224 on a c8in.96xlarge), unpinned; on a c8in.96xlarge 128 pinned
  away from the queue CPUs did much better (tables above).
- One thread per queue caps a c8in.96xlarge at ~6M pps; more UDP threads than queues (128) reached ~8M.
  A default that adds threads per queue on hosts with many spare CPUs hasn't been designed or tested.
- Large Graviton (c8gn) and AMD instances haven't been tested.
- Why the c8in.96xlarge's 32 receive rings overrun at ~8.9M pps with the queue CPUs ~60% busy. With
  3,000 flows instead of ~131,000, and 64 queues per ENI (set while the instance is stopped) with their
  interrupts on the interface's NUMA node and its hyperthread siblings, the peak rose to about 13M pps;
  128 queues did worse (see README-Large-Instances.md).
