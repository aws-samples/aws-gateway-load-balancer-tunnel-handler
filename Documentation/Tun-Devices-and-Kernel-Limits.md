# Tun devices and kernel limits

Applies to: gwlbtun 3.3. Last checked: October 2026 (AL2023 kernels 6.1 and 6.18; kernel source
`drivers/net/tun.c` for v5.10, v6.1 and master).

**Summary.** Each GWLB endpoint gets two Linux tun interfaces: `gwi-<X>`, where gwlbtun writes the
decapsulated packets it receives from GWLB, and `gwo-<X>`, which gwlbtun reads to send traffic back.
Both are multi-queue devices (`IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE`) with an 8500-byte MTU. Most of
gwlbtun's large-instance limits came from how the kernel implements these devices.

## Device layout

- **Queues.** Each open file descriptor attached to a multi-queue tun device is one queue. gwlbtun opens
  one queue per tunnel thread on each device (the readers), plus writer queues on `gwi-`.
- **Names.** `gwi-`/`gwo-` plus the endpoint ID in base 60, to fit the kernel's 15-character limit
  (`IFNAMSIZ` 16 including the terminator). With `-I`, the suffix is a 64-bit FNV-1a hash of the
  endpoint ID and the interface list instead, so separate gwlbtun processes serving the same endpoint on
  different interfaces get different devices. Hooks receive the endpoint ID as an argument, so the name
  doesn't need to be reversible. See `devname_make()` in `GeneveHandler.cpp`.
- **MTU.** 8500 bytes, the largest packet [GWLB supports](https://docs.aws.amazon.com/elasticloadbalancing/latest/gateway/gateway-load-balancers.html).
  GWLB's encapsulation adds 68 bytes, so per that page the appliance's own interface needs an MTU of at
  least 8,568 bytes (an interface at EC2's [9001-byte jumbo frame MTU](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/network_mtu.html), which all current generation instance types support, covers it).

## Findings

**At most 256 queues per device.** (Kernel source: `MAX_TAP_QUEUES` 256; attaching one more fails with
`E2BIG`.) Before 3.3 gwlbtun started one tunnel thread per vCPU, so interface creation failed on hosts
with more than 255 vCPUs. Tunnel threads are now capped at 255 per device (`TUN_MAX_THREADS` in
`utils.h`), and the number of `gwi-` writer queues is reduced if readers plus writers would exceed 256.

**Writes into a multi-queue device take a per-device spinlock for unknown flows.** (Kernel source and
measured.) `tun_get_user()` updates the device's flow table on every write when the device has more than
one queue, no steering program, and the writing queue isn't detached. The table holds 4096 flows
(`MAX_TAP_FLOWS`); a flow that isn't in it is added under `tun->lock`. With ~59k flows nearly every write
missed the table. On a c8in.96xlarge with 384 UDP threads writing into one `gwi-`, 74% of CPU went to
`native_queued_spin_lock_slowpath` under `tun_flow_update`.

**Detached queues skip the flow table, and writes through them are still delivered.** (Kernel source
and measured.) `TUNSETQUEUE` with `IFF_DETACH_QUEUE` takes a queue out of the device's receive set, so
nothing is ever queued *to* it, but a `write()` on it still injects the packet into the stack, without the
flow-table update. gwlbtun's `gwi-` writers are detached queues (`TunSocket::detachQueue()`). On the
c8in this alone doubled the lossless rate (1M to 2M pps at 64 bytes).

**One writer fd for many threads is the next bottleneck.** (Measured.) With the lock gone, the shared
writer fd's accounting (a cache line written by every core) took about 23% of CPU. gwlbtun now gives
each group of 8 UDP threads its own writer (`GWI_WRITER_SHARE`), which measured the same as one writer
per thread while using an eighth of the queues. This only helped after the endpoint reference counting
was also fixed (per-batch references, per-thread counters): done earlier, it moved the contention onto
the endpoint's shared reference count and made things worse.

**The operator's tc rules run in the writer's context.** (Kernel behaviour, observed in profiles.) A
`write()` into `gwi-` runs the device's ingress processing, including a `tc ... mirred` redirect to
`gwo-` like the one in `example-scripts/create-passthrough.sh`, on the UDP receiver thread that wrote the
packet. Expensive per-packet rules there cost UDP-thread CPU.

**`IFF_TUN_EXCL` makes creation exclusive.** (Kernel source.) Without it, opening an existing name just
adds a queue to that device, so a second gwlbtun (or anything else) using the same name would silently
share the device and take some of its packets. The fd that creates each device sets `IFF_TUN_EXCL`, and
the kernel then fails with `EBUSY` if the name exists. gwlbtun logs "Unable to create TUN device ...
(IFF_TUN_EXCL): a device with that name already exists - is this the only gwlbtun trying to use it?",
drops that endpoint's packets and retries after 5 seconds. The other queues attach without the flag.

**`select()` corrupted memory past fd 1024.** (Measured, fixed in 3.3.) In 3.2 each endpoint opened two
fds per tunnel thread, so many-core hosts with several endpoints passed `FD_SETSIZE` (1024), where `FD_SET()`
writes beyond its array. The tunnel readers use epoll now. v3.2 segfaulted with `--tunthreads 70`
and 10 endpoints.

**`poll()` on a shared stop event serialized the readers.** (Measured, fixed in 3.3.) Waiting on the tun
queue and the interface's stop eventfd with `poll()` adds the thread to each fd's wait queue and removes it
again on every call. The stop eventfd is shared by all of an interface's readers, so with 128 of them its
wait-queue spinlock took about a fifth of a c8in.96xlarge's CPU at 14M pps. Each reader now has its own
epoll set, registered on both fds once when the thread starts.

**An endpoint needs about six fds per tunnel thread.** (3.3.) Per tunnel thread on each of `gwi-` and
`gwo-`: the tun queue, the thread's raw send socket and its epoll set; plus the `gwi-` writer queues, the
two stop eventfds and the endpoint's shared raw socket (`GeneveHandlerENI::fdsPerEndpoint()`). With 128
tunnel threads that is about 770 fds per endpoint. gwlbtun raises its open-file soft limit to the hard limit at startup and
logs roughly how many endpoints fit; past that, new endpoints fail to open their devices.

**The kernel sends IPv6 router solicitations on every new tun device.** (Observed on AL2023, where
`net.ipv6.conf.default.router_solicitations` is -1, retry forever.) gwlbtun reads them from `gwo-`, finds
no flow for them and drops them, but the read still counts as activity for `-t` idle teardown, so an
idle endpoint could stay up indefinitely. Nothing on a GWLB tunnel answers them. The example hooks set
`router_solicitations=0` on both devices at CREATE; setting it after the device is up stops the
retries. IPv6 must stay enabled because the tunnels carry IPv6 traffic.

## Forwarded traffic and transmit queues (XPS)

In two-arm configurations (usually NAT'ing through gwlbtun) the kernel forwards the packets gwlbtun writes
into `gwi-` out of a network interface. (Traffic gwlbtun sends back to GWLB itself, in one-arm mode, goes
through its raw sockets and isn't affected.)

**The kernel picks the transmit queue from the tun queue that wrote the packet.** (Kernel source and
measured.) A write into a multi-queue tun device records the writing queue's index on the packet, as if
it were the receive queue. When the packet is forwarded out an interface that has no XPS map (as we found
on Amazon Linux 2023 with ENA; the ENA driver doesn't set one up, verified in ENA source), the kernel reuses that index to pick the transmit queue (modulo the
interface's queue count). Up to 3.2 gwlbtun wrote through a single queue, so almost all forwarded
traffic left on one transmit queue, and that queue (and the CPU handling it) became the bottleneck.

**gwlbtun 3.3 spreads forwarded traffic over the transmit queues by itself.** Each endpoint opens at
least one `gwi-` writer per receive queue (and one per 8 UDP threads, if that's more), each with a
distinct queue index, and UDP thread *t* writes through writer *t* mod the writer count
(`GeneveHandlerENI::makeWriters()`). With as many writers as the egress interface has transmit queues,
every transmit queue gets traffic without XPS. Measured on a c6i.xlarge (4 queues), two-arm forwarding,
XPS cleared, 40,000 packets per run, 2 runs each:

| Build | Default threads | `--udpthreads 8` |
|---|---|---|
| Before the writer change (one writer) | 99.9% on queue 0 (one run happened to spread 32/11/24/34%) | 99.9% on queue 0 |
| 3.3 | 25/25/25/25% | 26/25/28/21% |

**When XPS still helps.** gwlbtun's writers can't cover every transmit queue when:

- `--tunthreads` leaves room on the 256-queue `gwi-` device for fewer writers than gwlbtun wants.
  gwlbtun logs this at startup ("... uses at most N transmit queue(s) unless XPS is set up. Use fewer
  tunnel threads to avoid this."); using fewer tunnel threads is the simpler fix.
- Traffic is forwarded out of an interface with more transmit queues than the interfaces gwlbtun
  receives on (gwlbtun sizes the writers from the receive queues it finds).
- gwlbtun can't find the interface's receive queues (it then falls back to one unpinned UDP thread per
  core, and one writer per 8 of them).

In those cases give every CPU an XPS mapping, for example CPU *c* to transmit queue *c* mod (number of
queues). Each queue's `xps_cpus` file takes a **hexadecimal** bitmask of CPUs: CPU 0 is `1`, CPU 1 is
`2`, CPU 2 is `4`, CPU 3 is `8`, CPU 4 is `10`, CPU 5 is `20`, and so on (so CPU 4 is `10`, not `16`).
Above 32 CPUs the mask is written as comma-separated groups of 8 hex digits, one per 32 CPUs, highest
first. Mapping only as many CPUs as there are queues isn't enough on instances with more vCPUs than
queues: traffic sent from an unmapped CPU falls back to the queue-index behaviour above. This fragment
maps every CPU (run it as root, at boot, before gwlbtun starts):

```bash
IF=ens5
NQ=$(ls -d /sys/class/net/$IF/queues/tx-* | wc -l)    # transmit queues on the interface
NCPU=$(nproc --all)
for ((q = 0; q < NQ; q++)); do
    mask=""
    for ((w = (NCPU + 31) / 32 - 1; w >= 0; w--)); do  # one 8-hex-digit group per 32 CPUs, highest first
        word=0
        for ((c = w * 32; c < (w + 1) * 32 && c < NCPU; c++)); do
            (( c % NQ == q )) && (( word |= 1 << (c - w * 32) ))
        done
        mask+=$(printf '%s%08x' "${mask:+,}" $word)
    done
    echo $mask > /sys/class/net/$IF/queues/tx-$q/xps_cpus   # CPU c sends on queue c % NQ
done
```

This changes how the interface queues all of its outgoing traffic, not just gwlbtun's, which is why
gwlbtun and its example hooks don't do it for you.

**Checking the distribution.** `ethtool -S ens5 | grep 'queue_.*_tx_cnt'` shows packets per transmit
queue. A lopsided distribution looks like this (from a two-arm test before the change):

```
queue_0_tx_cnt:  12,751,829 pkts  (100.0%)
queue_1_tx_cnt:          52 pkts  (0.0%)
queue_2_tx_cnt:           8 pkts  (0.0%)
queue_3_tx_cnt:          47 pkts  (0.0%)
```

and a healthy one like this:

```
queue_0_tx_cnt:  4,805,760 pkts  (27.4%)
queue_1_tx_cnt:  4,093,697 pkts  (23.3%)
queue_2_tx_cnt:  4,321,438 pkts  (24.6%)
queue_3_tx_cnt:  4,320,083 pkts  (24.6%)
```

A lopsided distribution usually shows up as one CPU saturated (in `top`, or `mpstat -P ALL`) and packet
loss well below the instance's limits. It isn't an EC2 allowance: `pps_allowance_exceeded` and the other
`ethtool -S` allowance counters count packets over
[the instance's maximums](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring-network-performance-ena.html),
not per queue, so they can stay at zero while a single queue is overloaded.

## Teardown order

Tunnel reader threads look up the endpoint's flow caches on every packet, so they must stop before the
caches are freed. Two crashes came from getting this wrong (both fixed in 3.2/3.3):

- `GeneveHandlerENI`'s destructor freed the flow caches (member destruction order) while its tun
  threads were still running. The flow caches (and the gwi- writers and shared send socket) are now
  declared before the tunnel interfaces, so member destruction stops and joins the threads first; the
  order-critical members are commented in the class.
- Endpoint creation through `concurrent_flat_map::try_emplace_or_cvisit()` can construct a losing
  candidate handler when two UDP threads see a new endpoint at once; its threads started in the
  constructor and outlived it. Now one UDP thread reserves the endpoint (under the lifecycle mutex),
  builds the handler with no lock held, and publishes it; others drop that endpoint's packets meanwhile.

Each tun interface's reader threads wait on a stop eventfd along with their queue, and destroying the
interface signals it, so all of its threads wake at once. Exit with 20 endpoints went from 44 s (3.2) to
about 2 s, nearly all of it the kernel removing the 40 devices.

## Open questions

- Whether a different writer share than 8 helps on hosts with very many UDP threads.
