# gwlbtun research notes

These documents record what we learned while developing and testing gwlbtun (mainly the 3.2 and 3.3
releases): how the Linux kernel, EC2 networking and Gateway Load Balancer (GWLB) behave underneath
gwlbtun, what we measured, and why gwlbtun is built the way it is.

They are not a description of the code. The source and its comments are the reference for what
gwlbtun does; these notes explain the environment it runs in and point to the code that deals with
each finding. Usage and options are in the top-level [README](../README.md), and per-release changes
in [HISTORY.md](../HISTORY.md).

| Document | Read it when |
|---|---|
| [CPUs-and-UDP-Affinity.md](CPUs-and-UDP-Affinity.md) | choosing thread counts and CPU pinning, or tuning a large instance |
| [Tun-Devices-and-Kernel-Limits.md](Tun-Devices-and-Kernel-Limits.md) | changing how gwlbtun creates, reads or writes its `gwi-`/`gwo-` interfaces, or checking which transmit queues forwarded (two-arm) traffic uses |
| [Return-Path.md](Return-Path.md) | changing how traffic is sent back to GWLB, or debugging return traffic that never arrives |
| [GWLB-Observations.md](GWLB-Observations.md) | interpreting flow counts, idle timeouts, warm-up effects or EC2 network allowances |
| [Performance-Testing.md](Performance-Testing.md) | measuring gwlbtun, or reading the numbers in the README |
| [NO_RETURN_TRAFFIC.md](NO_RETURN_TRAFFIC.md) | building or deploying the receive-only variant |
| [README-Large-Instances.md](../README-Large-Instances.md) | (user guide) tuning gwlbtun on instances with many vCPUs |

## Conventions

- Each document starts with the versions it applies to and when it was last checked.
- Statements are marked as **measured** (with the setup and numbers), **documented** (with a link to
  the AWS, ENA driver or kernel documentation or source), or **inferred** (our reasoning, which may be
  wrong). Statements about AWS behaviour without a link are our observations, not AWS guarantees.
- Kernel behaviour is described for the kernels we tested (AL2023's 6.1 and 6.18), with the kernel
  source file where we checked it. Other kernels may differ.
- When code changes make a note wrong, fix the note in the same change, or delete it.
