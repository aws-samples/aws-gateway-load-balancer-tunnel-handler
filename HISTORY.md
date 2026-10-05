## eBPF/XDP acceleration (v4.0, in development):
- Initial in-kernel XDP ingress fast path. An XDP program on the GWLB-facing interface parses GENEVE and, for flows present in a BPF map, decapsulates and redirects the inner packet directly to the `gwi` interface, bypassing the userspace UDP-socket/TUN round-trip; unknown flows fall through to userspace. Build with libbpf + clang and pass `-e <gwlbtun-ebpf.o>`. Control-plane population of the flow map and the return (`gwo`) path are still in progress.

## v3.2:
- Corrected terminology: the GENEVE Option Class 0x0108 type-1 field is the GWLB **endpoint** (VPC endpoint, `vpce-`) identifier, not the ENI of that endpoint. Logs and health output now label it "GWLB endpoint" and show the `vpce-` prefix. **Health JSON change:** the per-ENI object's `eniStr` key is renamed to `gwlbEndpointId` (value now `vpce-`-prefixed) - update any tooling that parses the health JSON.
- Vendored a header-only subset of Boost (1.92) and nlohmann/json into `third_party/`, so the build no longer needs a separate Boost download or install - `cmake3 . && make` is self-contained on a stock Amazon Linux host (#24, #25, thanks @lyoung-confluent).
- recvmmsg() batch receive on the UDP ingress path, configurable SO_RCVBUF, and reduced shutdown latency for higher throughput (#21, thanks @nikvouk-aws).
- Flow cache split into separate TCP/UDP/Other tables, with a configurable TCP idle timeout via `-i TIME` to match the GWLB flow timeout (UDP and Other use a fixed 120-second idle timeout).
- New `--busypoll USEC` option to busy-poll the NIC on the UDP ingress path for lower latency under high packet rates (default off).
- High-scale flow-cache optimizations: a coarse (1-second) idle timer refreshed in place, flow-cache expiry on a dedicated reaper thread off the health path, optional `--reserve` pre-sizing of the per-table caches, and cache-line isolation of the hot per-ENI counters. Measured on the test rig (256 B, single appliance): no-drop throughput on par with the prior split-cache build (~300k pps) with the tightest latency tail of the builds compared (worst case ~1.7 ms under overload vs ~2.9-5.0 ms before), and ~0% loss at/under the no-drop ceiling. Also fixes a latent shutdown-ordering use-after-free (tunnel threads outliving the flow caches they read), which `--reserve` turned from benign into a reliable crash.
- Raised the GWI/GWO tunnel MTU to carry 8500-byte payloads (8500 + 68 B GENEVE + 28 B UDP headers), matching GWLB's maximum.
- IPv4/IPv6 dual-stack health-check listener (works on RHEL 10+, where the previous socket setup failed).
- Container image and Kubernetes DaemonSet manifest (#13, thanks @ahmetayd).
- Reliability and portability hardening: fixed data races flagged by ThreadSanitizer, replaced unaligned reads of on-the-wire fields with well-defined accesses, now compute and report real health status (#34), route SIGTERM cleanly through the shutdown handler, and build with `-Wshadow` in the always-on warning set.
- Fixes: malformed health-check JSON (#26), uninitialized health socket busy-loop (#29), uninitialized outer UDP checksum (#28), Geneve per-option bounds check (#31), socket/write return-value handling (#32), fd cleanup on ENI teardown (#36), compiler warnings (#33), and build hygiene (#24, #25) - thanks @lyoung-confluent.

## Public Development v3.1:
- Performance improvements to /dev/net/tun handling, packet manipulation, and memory usage. The improvements help more on higher CPU core counts - at 4 cores, the improvements result in approximately 4.3% improvement as measured by packets per second, but at 32 cores it's 37.2% more.
- Clean up /dev/net/tun fd handling to reduce file descriptor count
- Improved flow cookie tracker hashing algorithm to reduce collisions in high cps, low entropy scenarios.
- Several bug fixes (rare crash on startup, rare FD leaks on error paths)

## 2024.09.01 Release (v3.0):
- Support GWLB variable timeouts for the flow cache.

## 2024.08.07 Release (v2.5):
- Add in JSON health check output support.
- Fix a bug that occasionally caused a crash on startup if the logger thread didn't quite initialize quick enough
- Fix a second related bug that occasionally caused a crash on shutdown if the logger thread didn't terminate in the right order.

## 2023.10.03 Release (v2.4):
- Replace flow caches with version based on Boost's concurrent_flat_map, improving performance and reducing CPU usage due to time spent waiting for locks.
- Standardized logging into its own class and thread, with improved configuration options
- General code cleanup - broke out per ENI handling to its own class (GeneveHandlerENI) which simplified code a fair bit.

## 2023.06.07 Release:
- Add NO_RETURN_TRAFFIC define by request - this strips out some of the internal tracking and removes the ability to send packets back to GWLB, but increases performance on incoming packet handling.

## 2022.11.17 Release:
- **Update to support IPv6 payloads from GWLB**
- Updated CMakeLists file to cleanly separate Debug and Release build options
- Rearrange initializers to cleanup some harmless ```-Wreorder``` warnings, and reorder a couple fields to optimize memory access
- Update packet hashing algorithm to be in one place (utils.h, defined inline), along with adding stats as to how the hash algorithm is performing to the status webpage when the debug flag is on. Thusfar in testing, the simple add-all-fields algorithm does well with avoiding collisions and is fast.
- Updated help on script parameters, as suggested by liujunhui74
- Added recognizing the flow in both directions when seen the first time, as suggested by liujunhui74
- Cleaned up debugging output to be consistent, and added milliseconds to the timestamp
- Update shutdown process to have all threads stop processing, then shutdown. In high PPS testing, there would occasionally be a race condition in shutting down that would result in a use-after-free error which this resolves.
- Updated the hashing for PacketHeader classes to extend std::hash instead of providing their own additional classes to std::unordered_map for cleaner operation.
- Reserve 3 GENEVE header options by default when processing a GENEVE packet, avoiding an unnecessary realloc due to dynamic vector expansion.
- Fixed an issue where in high PPS testing, the UDP thread would take a long time to shutdown (due to not checking for the shutdown requested flag in the inner packet processing loop)
- Replaced some ```sprintf```s with ```snprintf```s in ```hexDump()``` for safety

## 2022.05.13 Release:
- Initial version
