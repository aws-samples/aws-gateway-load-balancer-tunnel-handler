# Running gwlbtun on large instances

> Applies to gwlbtun v3.3 and later (see
> [What changed in gwlbtun for large instances](#what-changed-in-gwlbtun-for-large-instances)).
> The measurements come from one c8in.96xlarge appliance behind one Gateway Load Balancer endpoint.
> Your figures will vary with your specific workload (traffic sources, flow count and mix, packet sizes, and what the appliance does with each packet). We encourage you to test against your exact workload to gauge the performance you'll get.

gwlbtun's defaults suit small and medium instances: one UDP receiver thread per receive queue of the
network interface, pinned next to the queue's CPU where there's a free one (where every vCPU services a
queue, as on most sizes up to about 8 vCPUs, the threads stay unpinned; larger sizes usually have fewer
queues than vCPUs, see [ENA queues](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ena-queues.html)), and one tunnel thread per vCPU (at most 255) on each
tunnel interface. On large instances (roughly 32 vCPUs and up, and especially the
96xlarge and 48xlarge sizes) the tunnel thread default creates far more threads than the network
interface can feed, and on the c8in.96xlarge the 32 UDP threads ran out of capacity well before the
instance did. The threads then compete with the kernel's network receive processing for CPU time. The result is lower
throughput than the instance can give, and latency in the seconds once the appliance is overloaded.

This guide explains why, and how to tune a large instance with gwlbtun's command-line options and a few
operating-system settings.

## Results at a glance

c8in.96xlarge (384 vCPUs, 32 network queues by default), one GWLB endpoint, UDP traffic from four TRex generators
at once (one can't load this instance; see [Testing notes](#testing-notes)), 30 seconds per offered
rate. "Lossless" means loss of 0.2% or less end to end, the floor of the test setup. Every v3.3 run used
`gwlbtun -c create-passthrough.sh -p 80 -t 300 -j` followed by the arguments in the second column;
interrupt pinning and the receive ring size are operating-system settings (step 2 below), not gwlbtun
arguments.

| Configuration (gwlbtun v3.3) | Additional gwlbtun arguments | 64-byte packets | 1024-byte packets | Latency |
|---|---|---|---|---|
| Defaults (32 UDP threads pinned near their queues, 224 unpinned tunnel threads per interface), irqbalance running | (none) | lossless to ~3M pps; ~4.3–4.5M pps once overloaded | lossless to ~3M pps; ~3.9–4.2M pps once overloaded | ~0.7 ms at 2M pps; 0.6–1.8 s once overloaded |
| Defaults for UDP, 128 tunnel threads pinned, interrupts pinned | `--tunaffinity 96-159,288-351` | lossless to at least 8M pps (the highest rate offered) | lossless to ~7M pps; ~4.5M pps once overloaded | ~0.7 ms below that |
| Tuned as described below (128 UDP + 128 tunnel threads pinned, interrupts pinned, 4096-entry receive ring) | `--udpaffinity 32-95,224-287 --tunaffinity 96-159,288-351` | lossless to ~8M pps; ~8.6–8.8M pps from 9M offered | lossless to ~8M pps (~65 Gbps); ~8.7–8.8M pps from 9M offered | ~0.8 ms below that |
| For comparison, gwlbtun 3.2 defaults (one thread per vCPU: 384 UDP + 255 tunnel threads, unpinned) | (none) | lossless to ~2.5M pps; collapses to ~1.6M pps | lossless to ~3M pps | 1–4 s once overloaded |

The rows above used traffic with about 131,000 concurrent flows. With 3,000 flows (750 per generator) the same
tuned layout peaked at about 11.6–12M pps instead of 8.8M, and with **64 network queues** (step 2) it went
further:

| Configuration (gwlbtun v3.3, 3,000 flows) | Additional gwlbtun arguments | 64-byte packets | 1024-byte packets | Latency |
|---|---|---|---|---|
| Tuned, 32 queues | `--udpaffinity 32-95,224-287 --tunaffinity 96-159,288-351` | 0.02% loss at 10M pps; peak ~11.6M pps at 12M offered | | ~0.7 ms at 10M pps |
| Tuned, 32 queues, 192 tunnel threads | `--udpaffinity 32-95,224-287 --tunaffinity 96-191,288-383` | ~12M pps, held from 14M to 16M offered | | ~1 ms at 12M pps |
| **Tuned, 64 queues** (interrupts on the interface's NUMA node, CPUs 0-31 and their siblings 192-223) | `--udpaffinity 32-95,224-287 --tunaffinity 96-159,288-351` | 0.4% loss at 12M pps; peak ~13.0M pps at 14M offered, ~12.3–12.8M above that | ~12.8M pps at 14M offered | 1–1.5 ms at 12M pps |

How far a given appliance goes depends on the traffic as much as on gwlbtun. In both cases gwlbtun forwarded
everything the interface delivered to the kernel at the peak; the rest either never reached the interface
or was lost after gwlbtun sent it, where no instance counter shows it (see below and
[Testing notes](#testing-notes)).

At the tuned configuration's peak the appliance's network interface delivered about 8.8–8.9M pps to the
kernel and gwlbtun forwarded all of it (no socket or softnet drops, and the `ethtool -S` allowance
counters stayed at zero). The rest of the offered load didn't reach the kernel, for two reasons. From
about 9M pps offered, the interface's `rx_packets` fell short of what the generators sent, and no instance
counter accounted for the difference. From about 10M pps offered, the interface also dropped packets as
receive-ring overruns (`rx_overruns`, reported as `rx_errors`; about 0.8M pps at 10M offered): its 32 receive queues, about 280k pps
each, weren't refilled fast enough, although the queue CPUs averaged only 55–65% busy at one-second
resolution. The UDP threads were about 97% busy, so they were close to their limit as well. gwlbtun
before these changes (v3.3 code without them, default threads) was lossless only to about 1M pps on the
same instance. On small instances they showed no regression: on c6in.xlarge and c6gn.xlarge appliances,
throughput was the same or better than before, within run-to-run variation.

## Why the defaults hurt on large instances

Three things limit gwlbtun on a large instance. Each one moves the limit somewhere else when you fix it,
so you need to address all three.

1. **The network interface has far fewer queues than the instance has vCPUs.** A c8in.96xlarge has 384
   vCPUs but each network interface has 32 receive queues by default (up to 128 if set when the
   instance is stopped; see step 2). Each queue is serviced by one CPU,
   which runs the kernel's receive processing (softirq) for that queue. If gwlbtun's threads also run on
   those CPUs, the queues aren't emptied fast enough and the interface drops packets before the kernel
   sees them. gwlbtun's counters don't show these drops. The ENA driver counts them as `rx_overruns`
   (`ethtool -S`; see the [ENA best practices](https://github.com/amzn/amzn-drivers/blob/master/kernel/linux/ena/ENA_Linux_Best_Practices.rst)), and the [amzn-drivers](https://github.com/amzn/amzn-drivers/tree/master/kernel/linux/ena) ENA driver,
   like AL2023's, also reports them as `rx_errors` (`ip -s link`) and `rx_over_errors`
   (`ip -s -s link`) (verified in ENA source). Other ENA driver builds may report them differently.
2. **Too many threads cause contention.** With the defaults, gwlbtun starts about 480 threads on a
   c8in.96xlarge (32 UDP threads and 224 per tunnel interface; 3.2 started about 900). Every packet passes through a few kernel objects shared per GWLB endpoint (the tunnel
   interfaces and their sockets). Hundreds of threads touching the same objects spend most of their CPU
   time waiting on each other: in our profiles, 60–80% of CPU went to lock contention.
3. **Changing the receive ring undoes interrupt pinning.** With the ENA driver, `ethtool -G` closes and
   reopens the interface, freeing and re-requesting its queue interrupts (verified in [ENA source](https://github.com/amzn/amzn-drivers/tree/master/kernel/linux/ena),
   `ena_update_queue_params()`), and in our tests any interrupt affinity set before it was lost. With interrupts pinned
   after the change, a larger ring helped a little: at 4096 entries the tuned layout was lossless at 8M
   pps (0.01% loss, against 1.8–2.7% with 1024 or 2048) and lost about 1% at 9M (3% at 1024), but the
   peak stayed at about 8.7–8.9M pps. 8192 entries were no better than 4096.

More queues helped once the rest was tuned: 64 queues, with their interrupts on the interface's NUMA node
(its 32 cores and their hyperthread siblings), raised the peak from about 11.6M to 13.0M pps (3,000 flows).
128 queues, or 64 spread over two NUMA nodes (CPUs 0-63), did worse than that (about 11–11.8M pps).

## Tuning procedure

The idea: give the network interface's queue CPUs to the kernel, run a moderate number of gwlbtun
threads pinned to other CPUs, and stop the system from moving things around.

### 1. Look at the instance's layout

```bash
IF=$(ip -o route show default | awk '{print $5; exit}')   # the interface carrying GENEVE (e.g. ens5, enp71s0)
ethtool -l $IF                                            # "Combined" = number of queues
cat /sys/class/net/$IF/device/numa_node                   # NUMA node the interface is attached to
lscpu | grep -E 'NUMA node[0-9]'                          # CPUs in each NUMA node
grep "$IF-Tx-Rx" /proc/interrupts | cut -d: -f1            # one interrupt per queue
```

On a c8in.96xlarge this shows 32 queues on NUMA node 0, whose CPUs are 0-31 (and their hyperthread
siblings 192-223).

**Optionally, give the interface more queues.** On instance types with flexible ENA queues (the
c8in.96xlarge allows up to 128 per interface), the count is set per network interface while the instance is
stopped ([ENA queues](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ena-queues.html)). 64 was the
best of 32, 64 and 128 in our tests:

```bash
aws ec2 stop-instances --instance-ids i-...          # then wait until it's stopped
aws ec2 modify-network-interface-attribute --network-interface-id eni-... \
    --attachment AttachmentId=eni-attach-...,EnaQueueCount=64
aws ec2 start-instances --instance-ids i-...
```

### 2. Pin each queue's interrupt to its own CPU, and keep irqbalance off them

Set the receive ring size first, because changing it re-creates the queues' interrupts and loses their
pinning (step 3 of the list above). 4096 entries made the tuned layout lossless at 8M pps; the default (1024) also works, with a
little loss near the limit:

```bash
ethtool -G $IF rx 4096
```

irqbalance moves interrupts between CPUs at runtime, which breaks any pinning you do. The
[ENA best practices](https://github.com/amzn/amzn-drivers/blob/master/kernel/linux/ena/ENA_Linux_Best_Practices.rst) recommend keeping irqbalance running, and excluding CPUs from it with
`IRQBALANCE_BANNED_CPUS`, rather than disabling it. For one-to-one queue pinning, which gwlbtun reads only
at startup, irqbalance must leave the queue interrupts alone: either stop it, as we did in these tests, or
exclude those interrupts from it (irqbalance's `--banirq` option, in `IRQBALANCE_ARGS` in
`/etc/sysconfig/irqbalance`; we didn't test this). Then pin queue *q*'s interrupt to a CPU on the
interface's NUMA node:

```bash
systemctl stop irqbalance && systemctl disable irqbalance    # what we tested; see above for the alternative
grep -E "$IF-Tx-Rx-[0-9]+" /proc/interrupts | while read line; do
    irq=$(echo "$line" | cut -d: -f1 | tr -d ' ')
    q=$(echo "$line" | grep -oE 'Tx-Rx-[0-9]+' | cut -d- -f3)
    echo $q > /proc/irq/$irq/smp_affinity_list      # queue q -> CPU q (CPUs 0-31 on a c8in.96xlarge)
done
```

With 64 queues, put queues 32-63 on the same NUMA node's hyperthread siblings (on a c8in.96xlarge, queue
*q* on CPU *q* for q < 32 and CPU *q* + 160 above that, so CPUs 0-31 and 192-223). Spreading them over a second
NUMA node (CPUs 0-63) was slower.

Use CPUs that belong to the interface's NUMA node. Leave those CPUs (and their hyperthread siblings) out
of the gwlbtun thread lists in the next step. Interrupt affinity isn't persistent; apply it at boot, for
example from a systemd unit that runs before gwlbtun.

### 3. Choose thread counts and pin them

Start with **four UDP threads per network queue and the same number of tunnel threads**, each pinned to
its own CPU away from the queue CPUs. On a c8in.96xlarge (32 queues) that is 128 + 128:

```bash
gwlbtun -c /path/to/create-script.sh -p 80 \
    --udpaffinity 32-95,224-287 \
    --tunaffinity 96-159,288-351
```

Here UDP receivers use NUMA nodes 1-2 and tunnel threads nodes 3-4; node 0 is left to the network
interface. The same layout as a configuration file is in
[example-configurations/c8in.96xlarge.yaml](example-configurations/c8in.96xlarge.yaml). Guidelines:

- Keep the UDP and tunnel thread lists separate from each other and from the queue CPUs.
- Linux allows at most 256 queues per tun interface. gwlbtun uses one queue per tunnel thread plus its
  writer queues (one per eight UDP threads, and at least one per network receive queue), so keep
  `tunnel threads + max(UDP threads / 8, receive queues) <= 256`; gwlbtun reduces the writer count if you
  exceed it.
- More threads isn't automatically better: unpinned default thread counts were the worst configuration
  we tested, and pinning *all* remaining CPUs (320 UDP + 255 tunnel threads) was nearly as bad.
- If you can't pin, at least reduce the counts (`--udpthreads 128 --tunthreads 128`). In our tests that
  was lossless to about 4M pps, but above that it fell to about 2.2M pps (with tens of milliseconds of
  latency rather than seconds). The pinned layout above was lossless to about 8M pps.
- Fewer tunnel threads helped: 255 tunnel threads, even pinned away from the queue CPUs, were lossless
  only to about 2–4M pps where 128 reached 6–7M (both with the default UDP threads).
- Keep the UDP threads at four per 32 queues or so: halving them to 64 (with 192 tunnel threads)
  collapsed to 3–7M pps, with either 32 or 64 queues.
- 192 tunnel threads (`--tunaffinity 96-191,288-383`) instead of 128 helped with 32 queues (about 12M
  against 11.6M pps) and made no difference with 64. Transmit packet steering (XPS) maps and the
  `pfifo_fast` queueing discipline instead of `fq_codel` made no measurable difference.

### 4. Route to the GWLB through the subnet's router

If the GWLB is in the same subnet as the appliance (common), add a host route to each GWLB IP address
through the subnet's router (the VPC router at the subnet's `.1` address), on every interface that
receives GENEVE:

```bash
ip route replace <GWLB IP>/32 via <subnet router, e.g. 10.100.21.1> dev $IF src <the interface's address>
# and, for a second interface with its own policy route table (amazon-ec2-net-utils creates one per ENI):
ip route replace <GWLB IP>/32 via <subnet router> dev $IF2 src <IF2's address> table <that table>
```

gwlbtun sends its return packets on raw sockets that write their own IP header (`IP_HDRINCL`). For those,
Linux caches the route only when its next hop is a gateway (`FLOWI_FLAG_KNOWN_NH` in `net/ipv4/raw.c` and
`net/ipv4/route.c`), so to a directly connected GWLB every return packet allocates and frees a route entry.
With one interface the route made no difference to throughput, but it removed the tunnel threads' lock
contention and kept latency at ~0.75 ms when overloaded (3 ms without). With two interfaces it was the
difference between ~7M and ~13M pps. Make the route persistent (for example from the hook script, or a
systemd unit) and keep it in step with the GWLB's addresses (its network interfaces in your VPC).

### 5. Kernel settings

```bash
sysctl -w net.core.rmem_max=268435456        # lets gwlbtun set its 128 MB UDP receive buffers (--rcvbuf)
sysctl -w net.core.rmem_default=134217728
```

Persist these in `/etc/sysctl.d/`. The ring size (step 2) and interrupt affinity aren't persistent
either; apply them at boot, before gwlbtun starts.

### Alternative: keep the default UDP threads, pin only the tunnel threads (Linux 6.2 or later)

By default gwlbtun starts one UDP thread per receive queue, pins each on the queue CPU's hyperthread
sibling (`--udpaffinity nearest`; it reads the queue CPUs from the interrupt affinity you set in step 2,
when gwlbtun starts), and ties thread *i*'s socket to the CPU servicing queue *i*. Kernels from 6.2 then
deliver each queue's packets to its own thread instead of spreading them by flow hash (the
`SO_INCOMING_CPU` socket option; older kernels ignore it). gwlbtun logs the queue-to-CPU mapping and
`one per receive queue of <interface>` when this is in effect. With only the tunnel threads pinned:

```bash
gwlbtun ... --tunaffinity 96-159,288-351
```

On the c8in.96xlarge this was lossless to about 6–7M pps for both packet sizes (64-byte packets reached
8M in one run), with a quarter of the UDP threads. Overloaded, it collapsed to 3.5–4.5M pps, with the queue CPUs fully busy (each UDP thread shares
a physical core with its queue's receive processing); the 128-thread layout holds its peak instead. Use the 128-thread layout for the highest rates. The queue tie needs Linux 6.2 or
later: on AL2023 that's kernel 6.12 or 6.18, not 6.1 (the AL2023 `kernel-default` AMI parameter
[tracks the latest kernel](https://aws.amazon.com/blogs/compute/amazon-linux-default-ssm-parameter-will-now-track-the-latest-kernel/) from August 2026; older or pinned AMIs may still run 6.1). Because
gwlbtun reads the interrupt affinity only at startup, keep irqbalance away from the queue interrupts
(step 2).

### 6. Verify

- gwlbtun's health page (`-p 80 -j`) shows per-thread packet counts. They should be spread across the
  UDP threads, and the tunnel interfaces should show no drops.
- `ethtool -S $IF | grep allowance` should stay at zero; non-zero values mean you've reached an EC2
  network allowance for the instance, not a gwlbtun limit.
- Watch `rx_overruns` in `ethtool -S $IF` (also `rx_errors` in `ip -s link` with AL2023's ENA driver):
  receive-ring overruns, packets the interface dropped because the queue CPUs didn't refill its rings in
  time ([ENA best practices](https://github.com/amzn/amzn-drivers/blob/master/kernel/linux/ena/ENA_Linux_Best_Practices.rst)).
- Compare the packets your upstream sends with `rx_packets` on `$IF`. A gap there that `rx_overruns`
  doesn't account for never reached the interface, as far as the instance can tell; with idle CPUs
  elsewhere, a gap that `rx_overruns` does account for usually means the queue CPUs are overloaded
  (step 2).
- `/proc/net/softnet_stat` (second column = drops, third = time squeeze) shows whether receive
  processing is keeping up per CPU.
- Measure latency under load. A tuned appliance stays under a millisecond up to its capacity; seconds of
  latency mean packets are queuing somewhere.

## What changed in gwlbtun for large instances

These changes remove the contention points we found while profiling the c8in.96xlarge. They need no
configuration.

- **The tunnel write queue no longer takes a global lock per packet.** gwlbtun writes decapsulated
  packets into the `gwi-` interface through dedicated writer queues that are detached from the
  interface's flow steering, so each write skips the kernel's per-interface flow-table update. Writers
  are shared by groups of eight UDP threads, with at least one per receive queue, and each keeps its own
  queue index, so forwarded traffic is spread over the transmit queues.
- **Each tunnel thread sends to GWLB on its own socket,** with a 16 MB send buffer (`--sndbuf` changes
  it; gwlbtun sets it with `SO_SNDBUFFORCE`, so `net.core.wmem_max` doesn't need raising), instead of
  every thread sharing one socket per endpoint. Before this, a full shared send buffer made tunnel
  threads wait, and its accounting was a cache line written by every sending core.
- **Per-packet counters are per thread,** and the per-packet reference to an endpoint is taken once per
  receive batch instead of once per packet. Both were cache lines written by every core for every packet.
- **Unpinned threads no longer inherit a pin.** An endpoint's tunnel threads are created on the UDP
  thread that saw its first packet, and used to inherit that thread's CPU pin, so with pinned UDP threads
  and unpinned tunnel threads every tunnel thread ran on one CPU.
- **Tunnel threads wait with epoll.** Each tunnel thread waits on its own epoll set holding its tun queue
  and the interface's stop event. With `poll()`, every wait added the thread to and removed it from the
  stop event's wait queue, which all of an interface's threads share; at 14M pps that queue's lock took
  about a fifth of the instance's CPU.
- **Return packets have Don't Fragment set** in their outer IPv4 header. Linux then leaves their IP ID at 0
  (RFC 6864 atomic datagrams) instead of drawing every packet's ID from one counter shared by all threads
  sending to the same GWLB address, which took 3–13% of CPU at 12–14M pps. These packets were never
  fragmented: the kernel rejects raw sends larger than the interface MTU instead.
- **Shutdown and endpoint teardown are faster:** destroying a tunnel interface wakes all of its threads
  at once instead of each one noticing a stop flag on a timer. Shutting down with 20 endpoints went from
  44 s to about 2 s (nearly all of it the kernel removing the interfaces), so systemd's default stop
  timeout no longer kills gwlbtun before its DESTROY hooks run on hosts with many endpoints.

## Testing notes

- One TRex generator can't load a large appliance. Ours topped out at about 5M pps whether it was a
  c6in.16xlarge (15 cores) or a c6in.32xlarge (31 cores), with one port pair. The results above use four
  generators sending at the same time, with their flow statistics added together.
- When a generator can't keep up, TRex still sends the full packet count for each step, just more slowly.
  Compute rates from measured time, not from the configured duration, or results look better than they are.
- Warm the GWLB up with sustained traffic for several minutes before measuring: in our tests, a new or
  idle load balancer gave lower numbers for the first several minutes. GWLB scales automatically with
  traffic, and [LCU reservation](https://docs.aws.amazon.com/elasticloadbalancing/latest/gateway/capacity-unit-reservation.html) is the documented way to start with a minimum capacity instead;
  we didn't test it.
- A second network interface on the c8in.96xlarge's second network card, as a second GWLB target
  (an IP target group with both addresses, 64 queues each, interrupts on each card's NUMA node, and the
  route above), didn't raise the peak: gwlbtun received and forwarded 15.1M pps across the two interfaces
  (about 7.5M each, with no drops) at 20M pps offered, against 14.5M with one, and delivered about 13M
  either way. The appliance had headroom left; no instance counter showed where the rest went. Without
the route, two interfaces
  collapsed to about 7M pps.
- The number of flows changed the results a lot. With about 131,000 flows, the instance's interface
  received at most about 8.9M pps, with no instance counter showing the rest; with 3,000 flows, the same
  instance received up to 14.6M pps. With 64 queues and 3,000 flows at 18M pps offered, the interface
  received 14.6M pps and gwlbtun sent all 14.6M back, but the generators got 12.2M: the instance counted
  no loss of its own, on the way in or out. Test with traffic that resembles yours.
