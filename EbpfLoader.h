// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWLBTUN_EBPFLOADER_H
#define GWLBTUN_EBPFLOADER_H

#include <string>
#include <unordered_map>
#include <memory>
#include <atomic>
#include "EbpfHelpers.h"
#include "HealthCheck.h"

// Forward declarations
struct bpf_object;
struct bpf_map;
struct bpf_program;


class EbpfLoaderHealthCheck : public HealthCheck {
public:
    EbpfLoaderHealthCheck(bool, std::array<uint64_t, RCV_CODES_COUNT>, std::array<uint64_t, EGR_CODES_COUNT>,
                          uint64_t ingressMapFull = 0, uint64_t egressMapFull = 0);
    std::string output_str();
    json output_json();

private:
    bool active;
    std::array<uint64_t, RCV_CODES_COUNT> recv_counters;
    std::array<uint64_t, EGR_CODES_COUNT> egr_counters;
    // Learn-time map-full (E2BIG) events: the flow map was full so the flow could not be
    // programmed and fell back to userspace. Non-zero => raise the flow reserve/size.
    uint64_t ingressMapFull;
    uint64_t egressMapFull;

    // Operator-facing disposition buckets, derived from recv_counters.
    struct Disposition {
        uint64_t accelerated;   // decapped + redirected in-kernel
        uint64_t punted;        // new/unknown flows sent to userspace
        uint64_t malformed;     // GENEVE present but malformed
        uint64_t notGwlb;       // not GWLB traffic, passed to the normal stack
        uint64_t total;         // every packet the program saw
    };
    Disposition ingressDisposition() const;

    // Egress (gwo) disposition buckets, derived from egr_counters.
    struct EgressDisposition {
        uint64_t accelerated;   // re-encapsulated + redirected to GWLB in-kernel
        uint64_t punted;        // couldn't encap -> left for userspace
        uint64_t noMatch;       // no egress map entry -> userspace fallback
        uint64_t noL2;          // flow matched but return L2 not cached yet -> userspace fallback
        uint64_t total;         // every packet the egress program saw
    };
    EgressDisposition egressDisposition() const;
};

class EbpfLoader {
public:
    EbpfLoader();
    ~EbpfLoader();

    // Load the eBPF program from the object file. The three max_entries values size the
    // flow maps from the --reserve config (0 = keep the object's compile-time default):
    // ingressMax -> ingress_rt_map (1 entry/flow), ipv4Max/ipv6Max -> ipv4/ipv6_flows_map
    // (2 entries/flow). Applied between bpf_object__open and __load.
    bool loadProgram(const std::string& objectPath,
                     uint32_t ingressMax = 0, uint32_t ipv4Max = 0, uint32_t ipv6Max = 0);

    // Attach the program to an interface
    bool attachIngressProgram(const std::string& interfaceName);

    // Resolve a kernel interface index by name (0 if not found or eBPF disabled).
    // Wrapper around if_nametoindex, kept here so callers don't need <net/if.h>
    // (which conflicts with <linux/if.h> included elsewhere).
    uint32_t ifIndexForName(const std::string& interfaceName);

    // Detach the program from an interface
    bool detachFromInterface(const std::string& interfaceName);

    // Attach the egress (re-encap) program to a gwo interface as a tc clsact-egress
    // ACTION CHAIN: `action bpf <egress prog> action mirred egress redirect dev <phys>`.
    // The program builds the full return frame and returns TC_ACT_PIPE; act_mirred
    // transmits it natively out the GWLB-facing physical NIC. The physical NIC name is
    // the one recorded by attachIngressProgram.
    bool attachEgressProgram(const std::string& interfaceName);

    // Update the ingress routing map
    bool updateIngressRoute(const struct EbpfIngressRTKey& key, uint32_t ifindex);

    // Remove an entry from the ingress routing map
    bool removeIngressRoute(const struct EbpfIngressRTKey& key);

    // Egress flow map management (gwo re-encap). Keys must identify {ifindex,5-tuple}.
    bool updateEgressRouteV4(const struct EbpfEgressMapKeyV4& key, const struct EbpfEgressMapValue& value);
    bool updateEgressRouteV6(const struct EbpfEgressMapKeyV6& key, const struct EbpfEgressMapValue& value);
    bool removeEgressRouteV4(const struct EbpfEgressMapKeyV4& key);
    bool removeEgressRouteV6(const struct EbpfEgressMapKeyV6& key);

    // Whether the egress fast path is available (egress program + maps were found).
    bool egressAvailable() const { return egressEnabled; }

    // Get counter values
    uint64_t getCounter(rcv_counters_key counter);
    uint64_t getEgressCounter(uint32_t code);

    // GC support: read a flow's liveness timestamp from the maps (0 if absent).
    uint64_t ingressLastSeen(const struct EbpfIngressRTKey& key);
    uint64_t egressLastSentV4(const struct EbpfEgressMapKeyV4& key);
    uint64_t egressLastSentV6(const struct EbpfEgressMapKeyV6& key);

    // Check if eBPF is enabled and working
    bool isEnabled() const { return enabled; }

    // Get status information
    EbpfLoaderHealthCheck check();

private:
    bool enabled;
    struct bpf_object* bpfObj;
    struct bpf_program* ingressProg;
    struct bpf_program* egressProg;
    std::unordered_map<std::string, int> attachedInterfaces;        // tc clsact ingress: ifname -> ifindex
    std::unordered_map<std::string, int> attachedEgressInterfaces;  // tc clsact egress:   ifname -> ifindex

    // GWLB-facing physical NIC name, recorded at ingress attach. The egress action
    // chain hands re-encapped frames to this NIC via `mirred egress redirect dev <name>`.
    std::string physInterfaceName;

    // The egress program is pinned once under bpffs so every gwo's `action bpf
    // object-pinned <path>` references the SAME loaded program (and therefore the same
    // maps userspace updates). Empty until the first successful egress attach.
    std::string egressPinPath;

    // Map file descriptors
    int ingressRtMapFd;
    int countersMapFd;
    int ipv4FlowsMapFd;
    int ipv6FlowsMapFd;
    int egressCountersMapFd;
    bool egressEnabled;        // egress program + maps present in the object

    // Learn-time map-full counters. When a flow map is full the kernel returns -E2BIG on
    // insert; the flow then stays on the userspace path. These make that visible (and are
    // the signal that the flow reserve/size needs raising) instead of a silent fallback.
    std::atomic<uint64_t> ingressMapFullCount{0};
    std::atomic<uint64_t> egressMapFullCount{0};

    // Helper methods
    bool findMaps();
    bool loadObject(const std::string& path, uint32_t ingressMax, uint32_t ipv4Max, uint32_t ipv6Max);
    bool ensureEgressProgPinned();  // pin egressProg under bpffs (idempotent)
    // Count + rate-limit-log a learn-time map-update failure. E2BIG (map full) bumps
    // counter and logs occasionally; any other errno is a real error and always logs.
    void noteMapUpdateFailure(std::atomic<uint64_t>& counter, int err, const char* which);
};

#endif // GWLBTUN_EBPFLOADER_H