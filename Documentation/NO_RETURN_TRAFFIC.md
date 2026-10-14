# NO_RETURN_TRAFFIC builds

Applies to: gwlbtun 3.2 and 3.3. Last checked: October 2026.

**Summary.** A compile-time variant for appliances that only receive traffic from GWLB and never send
any back through it. It drops everything gwlbtun needs for the return path, so each packet costs less.

## Building

```bash
cmake -DCMAKE_CXX_FLAGS=-DNO_RETURN_TRAFFIC . && make
```

(`utils.h` also has a commented-out `#define NO_RETURN_TRAFFIC`.) `gwlbtun -h` then ends with "This
version of GWLBTun has been compiled with NO_RETURN_TRAFFIC defined."

## What changes

- **No `gwo-` interface and no tunnel threads.** Each endpoint gets only `gwi-<X>`, which gwlbtun
  writes into. Hook scripts still get four arguments, with `none` as the egress interface (argument 3).
- **No flow cache.** Nothing is recorded per flow on the way in, so there's no insert per packet, no
  expiry sweep work and no flow-cache memory. `--tunthreads`, `--tunaffinity` and `--sndbuf` don't
  exist in this build, and `-i` has no effect.
- **Health output** has no `tunnelOut` section and no flow-cache statistics.
- Everything on the receive side is the same as the standard build: UDP threads, `-I`, `-p`, `-t`
  idle teardown, the single-instance guard.

## When to use it

GWLB delivers traffic to the appliance and expects it back; traffic the appliance doesn't return
doesn't continue through GWLB. This build fits deployments where the appliance is the end of the path
for that traffic, for example collection and analysis, or an appliance that forwards what it receives
by its own routing instead of back to GWLB. Any replies then take a different path, so routing is
asymmetric; GWLB [supports asymmetric flows](https://docs.aws.amazon.com/elasticloadbalancing/latest/gateway/gateway-load-balancers.html) but doesn't recommend them, so plan for it.

If you're not sure, use the standard build: it does everything this one does.

## Measured difference

Not measured reliably yet. The TRex ring needs return traffic, and our receive-only test setups have
had build issues, so we have no trustworthy standard vs receive-only comparison. Expect less CPU per
packet, since each packet is handled once instead of twice and there's no flow-cache insert.
