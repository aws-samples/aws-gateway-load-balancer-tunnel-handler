// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#include "EbpfLoader.h"
#include "Logger.h"
#include <stdexcept>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <vector>
#include <ctime>
#include <cerrno>

#ifdef ENABLE_EBPF
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <unistd.h>
#endif

using namespace std::string_literals;

#ifdef ENABLE_EBPF
// Monotonic nanoseconds, matching the clock the XDP program stamps with
// (bpf_ktime_get_ns, i.e. CLOCK_MONOTONIC). Used to seed last_seen_ns on insert
// and, later, to age entries during the GC sweep.
static uint64_t monotonicNs()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// tc filter priority we install our own filters at. Chosen high (low priority) and
// fixed so teardown can remove exactly our filter without touching operator filters
// that may coexist on the same clsact qdisc. We never destroy the clsact qdisc.
static const unsigned int GWLBTUN_TC_PRIO = 49152;

// Where the egress program is pinned under bpffs. Shared by every gwo's action chain.
static const char* GWLBTUN_EGRESS_PIN = "/sys/fs/bpf/gwlbtun_egress_prog";

// Run a shell command, logging it and its exit status. Returns true on exit code 0.
// Used for the tc filter/qdisc manipulation that libbpf's bpf_tc API cannot express
// (action chains: `action bpf ... action mirred ...`).
static bool runCommand(const std::string& cmd)
{
    LOG(LS_EBPF, LL_DEBUG, "exec: "s + cmd);
    int rc = system(cmd.c_str());
    if (rc != 0)
        LOG(LS_EBPF, LL_IMPORTANT, "command returned "s + std::to_string(rc) + ": "s + cmd);
    return rc == 0;
}
#endif

EbpfLoader::EbpfLoader() : enabled(false), bpfObj(nullptr), ingressProg(nullptr), egressProg(nullptr),
                           ingressRtMapFd(-1), countersMapFd(-1),
                           ipv4FlowsMapFd(-1), ipv6FlowsMapFd(-1),
                           egressCountersMapFd(-1), egressEnabled(false) {
}

EbpfLoader::~EbpfLoader() {
#ifdef ENABLE_EBPF
    // Tear down egress action chains. Remove ONLY our filter (at our fixed priority) --
    // never destroy the clsact qdisc, which would also wipe any operator filters sharing
    // it. gwo is normally ours alone, but the GWLB-facing physical NIC that act_mirred
    // feeds is frequently not, so we keep the same confined-teardown discipline everywhere.
    for (auto& it : attachedEgressInterfaces) {
        runCommand("tc filter del dev "s + it.first + " egress prio "s
                   + std::to_string(GWLBTUN_TC_PRIO) + " 2>/dev/null");
        LOG(LS_EBPF, LL_INFO, "Detached tc egress action chain from "s + it.first);
    }
    attachedEgressInterfaces.clear();

    // Remove the shared pinned egress program (if we pinned it).
    if (!egressPinPath.empty()) {
        unlink(egressPinPath.c_str());
        egressPinPath.clear();
    }

    // Use a safe iteration pattern since detachFromInterface modifies the container
    while (!attachedInterfaces.empty()) {
        auto it = attachedInterfaces.begin();
        std::string ifname = it->first;  // Copy the interface name
        detachFromInterface(ifname);     // This will erase the element
    }

    // Close the BPF object
    if (bpfObj) {
        bpf_object__close(bpfObj);
        LOG(LS_EBPF, LL_IMPORTANT, "eBPF program closed");
    }
#endif
}

bool EbpfLoader::loadProgram(const std::string& objectPath,
                            uint32_t ingressMax, uint32_t ipv4Max, uint32_t ipv6Max) {
#ifdef ENABLE_EBPF
    if (!std::filesystem::exists(objectPath)) {
        LOG(LS_EBPF, LL_CRITICAL, "eBPF object file not found: "s + objectPath);
        return false;
    }

    if (!loadObject(objectPath, ingressMax, ipv4Max, ipv6Max)) {
        return false;
    }

    // Find the ingress program
    ingressProg = bpf_object__find_program_by_name(bpfObj, "gwlbtun_ingress_prog");
    if (!ingressProg) {
        LOG(LS_EBPF, LL_CRITICAL, "Failed to find gwlbtun_ingress_prog in eBPF object");
        bpf_object__close(bpfObj);
        bpfObj = nullptr;
        return false;
    }

    // Find the egress program (optional: absent in NO_RETURN_TRAFFIC builds). If it
    // or its maps are missing, the egress fast path is simply unavailable.
    egressProg = bpf_object__find_program_by_name(bpfObj, "gwlbtun_egress_prog");
    if (!egressProg) {
        LOG(LS_EBPF, LL_INFO, "gwlbtun_egress_prog not present; egress acceleration disabled");
    }

    // Find and get file descriptors for maps
    if (!findMaps()) {
        bpf_object__close(bpfObj);
        bpfObj = nullptr;
        return false;
    }

    enabled = true;
    LOG(LS_EBPF, LL_IMPORTANT, "eBPF program loaded successfully from "s + objectPath);
    return true;
#else
    LOG(LS_EBPF, LL_IMPORTANT, "Attempted to load eBPF program but eBPF support is not enabled");
    return false;
#endif
}

#ifdef ENABLE_EBPF
// Resize one map's max_entries before load (bpf_map__set_max_entries is only valid
// between bpf_object__open and bpf_object__load). maxEntries==0 keeps the object's
// compile-time default. Best-effort: a missing map or resize failure logs and leaves
// the default rather than aborting the load.
static void resizeMap(struct bpf_object* obj, const char* name, uint32_t maxEntries)
{
    if (maxEntries == 0) return;
    struct bpf_map* m = bpf_object__find_map_by_name(obj, name);
    if (!m) return;   // absent in this build (e.g. NO_RETURN_TRAFFIC) -> nothing to size
    unsigned int cur = bpf_map__max_entries(m);
    if (cur == maxEntries) return;
    int err = bpf_map__set_max_entries(m, maxEntries);
    if (err)
        LOG(LS_EBPF, LL_IMPORTANT, "Could not resize "s + name + " to "s + std::to_string(maxEntries)
            + " (keeping "s + std::to_string(cur) + "): "s + strerror(-err));
    else
        LOG(LS_EBPF, LL_IMPORTANT, "Sized "s + name + " = "s + std::to_string(maxEntries) + " entries (was "s + std::to_string(cur) + ")");
}
#endif

bool EbpfLoader::loadObject(const std::string& path, uint32_t ingressMax, uint32_t ipv4Max, uint32_t ipv6Max) {
#ifdef ENABLE_EBPF
    // Open (parse) the object without loading into the kernel yet.
    bpfObj = bpf_object__open(path.c_str());
    if (!bpfObj) {
        LOG(LS_EBPF, LL_CRITICAL, "Failed to open eBPF object file: "s + path + ", error: "s + strerror(errno));
        return false;
    }

    // Size the flow maps from the --reserve config BEFORE loading (only valid pre-load).
    resizeMap(bpfObj, "ingress_rt_map", ingressMax);
    resizeMap(bpfObj, "ipv4_flows_map", ipv4Max);
    resizeMap(bpfObj, "ipv6_flows_map", ipv6Max);

    // Load the BPF object into the kernel
    int err = bpf_object__load(bpfObj);
    if (err) {
        LOG(LS_EBPF, LL_CRITICAL, "Failed to load eBPF object: "s + strerror(-err));
        bpf_object__close(bpfObj);
        bpfObj = nullptr;
        return false;
    }

    return true;
#else
    (void)path; (void)ingressMax; (void)ipv4Max; (void)ipv6Max;
    return false;
#endif
}

bool EbpfLoader::findMaps() {
#ifdef ENABLE_EBPF
    // Get the ingress routing map
    struct bpf_map* ingressRtMap = bpf_object__find_map_by_name(bpfObj, "ingress_rt_map");
    if (!ingressRtMap) {
        LOG(LS_EBPF, LL_CRITICAL, "Failed to find ingress_rt_map");
        return false;
    }
    ingressRtMapFd = bpf_map__fd(ingressRtMap);

    // Get the counters map
    struct bpf_map* countersMap = bpf_object__find_map_by_name(bpfObj, "counters_map");
    if (!countersMap) {
        LOG(LS_EBPF, LL_CRITICAL, "Failed to find counters_map");
        return false;
    }
    countersMapFd = bpf_map__fd(countersMap);

    // Egress maps are optional (absent in NO_RETURN_TRAFFIC builds). Egress
    // acceleration is enabled only if the program and all its maps are present.
    struct bpf_map* ipv4FlowsMap = bpf_object__find_map_by_name(bpfObj, "ipv4_flows_map");
    struct bpf_map* ipv6FlowsMap = bpf_object__find_map_by_name(bpfObj, "ipv6_flows_map");
    struct bpf_map* egressCountersMap = bpf_object__find_map_by_name(bpfObj, "egress_counters_map");
    if (egressProg && ipv4FlowsMap && ipv6FlowsMap && egressCountersMap) {
        ipv4FlowsMapFd = bpf_map__fd(ipv4FlowsMap);
        ipv6FlowsMapFd = bpf_map__fd(ipv6FlowsMap);
        egressCountersMapFd = bpf_map__fd(egressCountersMap);
        egressEnabled = true;
        LOG(LS_EBPF, LL_IMPORTANT, "eBPF egress acceleration enabled (egress program + all maps found)."s);
    } else {
        LOG(LS_EBPF, LL_IMPORTANT, "eBPF egress acceleration disabled: not all egress objects found "s
            + "(egressProg="s + (egressProg?"y":"n") + " ipv4_flows_map="s + (ipv4FlowsMap?"y":"n")
            + " ipv6_flows_map="s + (ipv6FlowsMap?"y":"n") + " egress_counters_map="s + (egressCountersMap?"y":"n")
            + ")."s);
        egressEnabled = false;
    }

    return true;
#else
    return false;
#endif
}

bool EbpfLoader::attachIngressProgram(const std::string& interfaceName) {
#ifdef ENABLE_EBPF
    if (!enabled) {
        LOG(LS_EBPF, LL_IMPORTANT, "Cannot attach eBPF program: eBPF not enabled");
        return false;
    }

    // Get the interface index
    unsigned int ifindex = if_nametoindex(interfaceName.c_str());
    if (ifindex == 0) {
        LOG(LS_EBPF, LL_CRITICAL, "Failed to get interface index for "s + interfaceName + ": "s + strerror(errno));
        return false;
    }

    // Get the program file descriptor
    int progFd = bpf_program__fd(ingressProg);
    if (progFd < 0) {
        LOG(LS_EBPF, LL_CRITICAL, "Failed to get program file descriptor");
        return false;
    }

    // Ingress runs as a tc clsact-INGRESS classifier on the physical NIC (NOT XDP;
    // see the long rationale block above gwlbtun_ingress_prog in EbpfHelpers.c --
    // XDP cannot redirect into gwi's RX, and ENA won't do native XDP at the GWLB
    // jumbo MTU). This mirrors the egress clsact attach on each gwo.
    struct bpf_tc_hook hook;
    memset(&hook, 0, sizeof(hook));
    hook.sz = sizeof(hook);
    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_INGRESS;

    // Create the clsact qdisc (idempotent: -EEXIST means it already exists).
    int err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        LOG(LS_EBPF, LL_CRITICAL, "Failed to create tc clsact hook on "s + interfaceName + ": "s + strerror(-err));
        return false;
    }

    struct bpf_tc_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.sz = sizeof(opts);
    opts.prog_fd = progFd;
    // Pin our filter at a fixed handle+priority so teardown can remove exactly this
    // filter (bpf_tc_detach) instead of destroying the whole clsact qdisc.
    opts.handle = 1;
    opts.priority = GWLBTUN_TC_PRIO;

    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        LOG(LS_EBPF, LL_CRITICAL, "Failed to attach tc ingress program to "s + interfaceName + ": "s + strerror(-err));
        return false;
    }

    attachedInterfaces[interfaceName] = ifindex;
    LOG(LS_EBPF, LL_IMPORTANT, "Attached tc ingress program to "s + interfaceName);
    // This ingress interface is also the GWLB-facing physical NIC. Record its NAME so
    // the egress action chain can transmit re-encapped frames back out it via
    // `mirred egress redirect dev <name>`. (Single GWLB-facing NIC assumed; last attach
    // wins -- revisit if multiple ingress interfaces are ever supported.)
    physInterfaceName = interfaceName;
    return true;
#else
    return false;
#endif
}

bool EbpfLoader::detachFromInterface(const std::string& interfaceName) {
#ifdef ENABLE_EBPF
    auto it = attachedInterfaces.find(interfaceName);
    if (it == attachedInterfaces.end()) {
        LOG(LS_EBPF, LL_IMPORTANT, "Interface "s + interfaceName + " not found in attached interfaces");
        return false;
    }

    // Remove ONLY our ingress filter (bpf_tc_detach at our fixed handle+priority),
    // NOT the clsact qdisc. The physical NIC may carry operator filters we must not
    // disturb; destroying the qdisc would take them with it.
    struct bpf_tc_hook hook;
    memset(&hook, 0, sizeof(hook));
    hook.sz = sizeof(hook);
    hook.ifindex = it->second;
    hook.attach_point = BPF_TC_INGRESS;

    struct bpf_tc_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.sz = sizeof(opts);
    opts.handle = 1;
    opts.priority = GWLBTUN_TC_PRIO;
    opts.prog_fd = 0;           // detach: match by handle+priority, no prog fd
    opts.prog_id = 0;
    int err = bpf_tc_detach(&hook, &opts);
    if (err)
        LOG(LS_EBPF, LL_IMPORTANT, "bpf_tc_detach on "s + interfaceName + " returned "s + strerror(-err));

    attachedInterfaces.erase(it);
    LOG(LS_EBPF, LL_INFO, "Detached tc ingress program from "s + interfaceName);
    return true;
#else
    return false;
#endif
}

bool EbpfLoader::ensureEgressProgPinned() {
#ifdef ENABLE_EBPF
    if (!egressPinPath.empty())
        return true;   // already pinned this run
    // Clear any stale pin left by a previous (crashed) run so the pin succeeds.
    unlink(GWLBTUN_EGRESS_PIN);
    int err = bpf_program__pin(egressProg, GWLBTUN_EGRESS_PIN);
    if (err) {
        LOG(LS_EBPF, LL_CRITICAL, "Failed to pin egress program at "s + GWLBTUN_EGRESS_PIN + ": "s + strerror(-err));
        return false;
    }
    egressPinPath = GWLBTUN_EGRESS_PIN;
    LOG(LS_EBPF, LL_IMPORTANT, "Pinned egress program at "s + egressPinPath);
    return true;
#else
    return false;
#endif
}

bool EbpfLoader::attachEgressProgram(const std::string& interfaceName) {
#ifdef ENABLE_EBPF
    LOG(LS_EBPF, LL_IMPORTANT, "attachEgressProgram("s + interfaceName + "): entering (enabled="s
        + (enabled?"y":"n") + " egressEnabled="s + (egressEnabled?"y":"n") + " egressProg="s + (egressProg?"y":"n")
        + " phys="s + (physInterfaceName.empty()?"<none>":physInterfaceName) + ")"s);
    if (!enabled || !egressEnabled || !egressProg) {
        LOG(LS_EBPF, LL_IMPORTANT, "Egress acceleration unavailable; not attaching to "s + interfaceName);
        return false;
    }

    // The egress action chain transmits via `mirred egress redirect dev <phys NIC>`.
    // Without a known GWLB-facing NIC (recorded at ingress attach) there is nowhere to
    // send the re-encapped frame, so leave this gwo on the userspace egress path.
    if (physInterfaceName.empty()) {
        LOG(LS_EBPF, LL_CRITICAL, "No GWLB-facing physical interface recorded; cannot attach egress chain to "s
            + interfaceName + ". Egress for this ENI falls back to userspace."s);
        return false;
    }

    unsigned int ifindex = if_nametoindex(interfaceName.c_str());
    if (ifindex == 0) {
        LOG(LS_EBPF, LL_CRITICAL, "Failed to get interface index for "s + interfaceName + ": "s + strerror(errno));
        return false;
    }

    // Pin the egress program once so every gwo's `object-pinned` reference resolves to
    // the SAME loaded program instance -- and therefore the same maps userspace writes
    // (an `object-file` reference would load a second copy with independent maps).
    if (!ensureEgressProgPinned())
        return false;

    // Install the egress action chain with tc. libbpf's bpf_tc_* API only attaches a
    // single SCHED_CLS program in direct-action mode; it cannot express an action chain
    // (`action bpf ... action mirred ...`), so we drive tc(8) directly.
    //
    //   1. clsact qdisc on gwo (idempotent; we never destroy it on teardown).
    //   2. a filter at our fixed priority whose action chain is:
    //        action bpf object-pinned <prog>  -> builds frame, returns TC_ACT_PIPE
    //        action mirred egress redirect dev <phys> -> native transmit toward GWLB
    //   "basic" (cls_basic with an empty ematch tree) matches every packet and short-
    //   circuits without extracting a key -- cheaper in the softirq path than
    //   "u32 match u32 0 0", which runs the u32 classifier (key fetch + mask) per
    //   packet. cls_matchall would be ideal but is not compiled into the AL2023 6.1
    //   kernel (CONFIG_NET_CLS_MATCHALL unset); cls_basic is present and equivalent here.
    runCommand("tc qdisc add dev "s + interfaceName + " clsact 2>/dev/null");
    // Remove any stale filter of ours first so re-attach is clean.
    runCommand("tc filter del dev "s + interfaceName + " egress prio "s
               + std::to_string(GWLBTUN_TC_PRIO) + " 2>/dev/null");
    std::string add = "tc filter add dev "s + interfaceName + " egress"
        + " prio "s + std::to_string(GWLBTUN_TC_PRIO)
        + " protocol all basic"
        + " action bpf object-pinned "s + egressPinPath
        + " action mirred egress redirect dev "s + physInterfaceName;
    if (!runCommand(add)) {
        LOG(LS_EBPF, LL_CRITICAL, "Failed to install egress action chain on "s + interfaceName
            + " (phys "s + physInterfaceName + "); egress for this ENI falls back to userspace."s);
        return false;
    }

    attachedEgressInterfaces[interfaceName] = ifindex;
    LOG(LS_EBPF, LL_IMPORTANT, "Attached egress action chain on "s + interfaceName
        + " -> mirred to "s + physInterfaceName);
    return true;
#else
    (void)interfaceName;
    return false;
#endif
}

bool EbpfLoader::updateEgressRouteV4(const struct EbpfEgressMapKeyV4& key, const struct EbpfEgressMapValue& value) {
#ifdef ENABLE_EBPF
    if (!enabled || ipv4FlowsMapFd < 0) {
        return false;
    }
    // Zero the key (incl. padding) so it matches the key the tc program builds.
    EbpfEgressMapKeyV4 k;
    std::memset(&k, 0, sizeof(k));
    k.ifindex = key.ifindex;
    k.src = key.src;
    k.dst = key.dst;
    k.srcpt = key.srcpt;
    k.dstpt = key.dstpt;
    k.prot = key.prot;
    int err = bpf_map_update_elem(ipv4FlowsMapFd, &k, &value, BPF_ANY);
    if (err) {
        noteMapUpdateFailure(egressMapFullCount, err, "IPv4 egress");
        return false;
    }
    return true;
#else
    (void)key; (void)value;
    return false;
#endif
}

bool EbpfLoader::updateEgressRouteV6(const struct EbpfEgressMapKeyV6& key, const struct EbpfEgressMapValue& value) {
#ifdef ENABLE_EBPF
    if (!enabled || ipv6FlowsMapFd < 0) {
        return false;
    }
    EbpfEgressMapKeyV6 k;
    std::memset(&k, 0, sizeof(k));
    k.ifindex = key.ifindex;
    std::memcpy(k.src, key.src, sizeof(k.src));
    std::memcpy(k.dst, key.dst, sizeof(k.dst));
    k.srcpt = key.srcpt;
    k.dstpt = key.dstpt;
    k.prot = key.prot;
    int err = bpf_map_update_elem(ipv6FlowsMapFd, &k, &value, BPF_ANY);
    if (err) {
        noteMapUpdateFailure(egressMapFullCount, err, "IPv6 egress");
        return false;
    }
    return true;
#else
    (void)key; (void)value;
    return false;
#endif
}

bool EbpfLoader::removeEgressRouteV4(const struct EbpfEgressMapKeyV4& key) {
#ifdef ENABLE_EBPF
    if (!enabled || ipv4FlowsMapFd < 0) {
        return false;
    }
    EbpfEgressMapKeyV4 k;
    std::memset(&k, 0, sizeof(k));
    k.ifindex = key.ifindex;
    k.src = key.src;
    k.dst = key.dst;
    k.srcpt = key.srcpt;
    k.dstpt = key.dstpt;
    k.prot = key.prot;
    int err = bpf_map_delete_elem(ipv4FlowsMapFd, &k);
    if (err && err != -ENOENT) {
        LOG(LS_EBPF, LL_IMPORTANT, "Failed to remove IPv4 egress map entry: "s + strerror(-err));
        return false;
    }
    return true;
#else
    (void)key;
    return false;
#endif
}

bool EbpfLoader::removeEgressRouteV6(const struct EbpfEgressMapKeyV6& key) {
#ifdef ENABLE_EBPF
    if (!enabled || ipv6FlowsMapFd < 0) {
        return false;
    }
    EbpfEgressMapKeyV6 k;
    std::memset(&k, 0, sizeof(k));
    k.ifindex = key.ifindex;
    std::memcpy(k.src, key.src, sizeof(k.src));
    std::memcpy(k.dst, key.dst, sizeof(k.dst));
    k.srcpt = key.srcpt;
    k.dstpt = key.dstpt;
    k.prot = key.prot;
    int err = bpf_map_delete_elem(ipv6FlowsMapFd, &k);
    if (err && err != -ENOENT) {
        LOG(LS_EBPF, LL_IMPORTANT, "Failed to remove IPv6 egress map entry: "s + strerror(-err));
        return false;
    }
    return true;
#else
    (void)key;
    return false;
#endif
}

uint32_t EbpfLoader::ifIndexForName(const std::string& interfaceName) {
#ifdef ENABLE_EBPF
    return if_nametoindex(interfaceName.c_str());
#else
    (void)interfaceName;
    return 0;
#endif
}

void EbpfLoader::noteMapUpdateFailure(std::atomic<uint64_t>& counter, int err, const char* which)
{
#ifdef ENABLE_EBPF
    // -E2BIG means the (preallocated) hash map is full: a NEW flow couldn't be programmed
    // and will keep taking the userspace path. This is a capacity signal, not a bug, so
    // count it and rate-limit the log (log the first hit, then every 1000th) to avoid
    // flooding when running at the cap. Any other errno is a real failure -> always log.
    if (err == -E2BIG) {
        uint64_t n = counter.fetch_add(1, std::memory_order_relaxed) + 1;
        if (n == 1 || (n % 1000) == 0)
            LOG(LS_EBPF, LL_IMPORTANT, std::string(which) + " flow map full (E2BIG): flow left on the "
                "userspace path. Raise the flow reserve/size to accelerate more flows. (occurrence #"s
                + std::to_string(n) + ")"s);
    } else {
        LOG(LS_EBPF, LL_IMPORTANT, std::string(which) + " map update failed: "s + strerror(-err));
    }
#else
    (void)counter; (void)err; (void)which;
#endif
}

bool EbpfLoader::updateIngressRoute(const struct EbpfIngressRTKey& key, uint32_t ifindex) {
#ifdef ENABLE_EBPF
    if (!enabled || ingressRtMapFd < 0) {
        return false;
    }

    // ingress_rt_map is a PERCPU_HASH, so bpf_map_update_elem expects a value
    // buffer sized for every possible CPU. Seed each CPU's slot with the same
    // {ifindex, now}; the XDP program then refreshes last_seen_ns on whichever
    // CPU handles the flow.
    unsigned int nCpus = libbpf_num_possible_cpus();
    if (nCpus == 0) nCpus = 1;
    EbpfIngressRTValue seed{};
    seed.disposition = DISP_REDIRECT;   // only disposition userspace sets today
    seed.ifindex = ifindex;
    seed.last_seen_ns = monotonicNs();
    std::vector<EbpfIngressRTValue> values(nCpus, seed);

    // Zero the key (including trailing padding) so it matches the key the XDP
    // program builds via __builtin_memset — otherwise the hash lookup can miss.
    EbpfIngressRTKey k;
    std::memset(&k, 0, sizeof(k));
    k.gwlbeEniId = key.gwlbeEniId;
    k.flowCookie = key.flowCookie;

    int err = bpf_map_update_elem(ingressRtMapFd, &k, values.data(), BPF_ANY);
    if (err) {
        noteMapUpdateFailure(ingressMapFullCount, err, "ingress");
        return false;
    }

    return true;
#else
    return false;
#endif
}

bool EbpfLoader::removeIngressRoute(const struct EbpfIngressRTKey& key) {
#ifdef ENABLE_EBPF
    if (!enabled || ingressRtMapFd < 0) {
        return false;
    }

    // Match the zeroed-padding key used on insert.
    EbpfIngressRTKey k;
    std::memset(&k, 0, sizeof(k));
    k.gwlbeEniId = key.gwlbeEniId;
    k.flowCookie = key.flowCookie;

    int err = bpf_map_delete_elem(ingressRtMapFd, &k);
    if (err) {
        LOG(LS_EBPF, LL_IMPORTANT, "Failed to remove ingress route map entry: "s + strerror(-err));
        return false;
    }

    return true;
#else
    return false;
#endif
}

uint64_t EbpfLoader::getCounter(rcv_counters_key counter) {
#ifdef ENABLE_EBPF
    if (!enabled || countersMapFd < 0) {
        return 0;
    }

    // counters_map is a BPF_MAP_TYPE_PERCPU_ARRAY: the kernel returns one value
    // per possible CPU, so we must hand it a buffer sized for every CPU and then
    // sum the per-CPU slots. (Reading into a single uint64_t overflows the buffer
    // and only captures one CPU's count.)
    unsigned int nCpus = libbpf_num_possible_cpus();
    if (nCpus == 0) nCpus = 1;
    std::vector<uint64_t> values(nCpus, 0);
    int err = bpf_map_lookup_elem(countersMapFd, &counter, values.data());
    if (err) {
        LOG(LS_EBPF, LL_DEBUG, "Failed to get counter "s + std::to_string(counter) + ": "s + strerror(-err));
        return 0;
    }

    uint64_t total = 0;
    for (unsigned int i = 0; i < nCpus; i++)
        total += values[i];
    return total;
#else
    return 0;
#endif
}

uint64_t EbpfLoader::ingressLastSeen(const struct EbpfIngressRTKey& key) {
#ifdef ENABLE_EBPF
    if (!enabled || ingressRtMapFd < 0) {
        return 0;
    }
    EbpfIngressRTKey k;
    std::memset(&k, 0, sizeof(k));
    k.gwlbeEniId = key.gwlbeEniId;
    k.flowCookie = key.flowCookie;
    unsigned int nCpus = libbpf_num_possible_cpus();
    if (nCpus == 0) nCpus = 1;
    std::vector<EbpfIngressRTValue> vals(nCpus);
    if (bpf_map_lookup_elem(ingressRtMapFd, &k, vals.data()) != 0) {
        return 0;
    }
    uint64_t m = 0;
    for (unsigned int i = 0; i < nCpus; i++)
        if (vals[i].last_seen_ns > m) m = vals[i].last_seen_ns;
    return m;
#else
    (void)key;
    return 0;
#endif
}

uint64_t EbpfLoader::egressLastSentV4(const struct EbpfEgressMapKeyV4& key) {
#ifdef ENABLE_EBPF
    if (!enabled || ipv4FlowsMapFd < 0) {
        return 0;
    }
    EbpfEgressMapKeyV4 k;
    std::memset(&k, 0, sizeof(k));
    k.ifindex = key.ifindex;
    k.src = key.src; k.dst = key.dst;
    k.srcpt = key.srcpt; k.dstpt = key.dstpt; k.prot = key.prot;
    EbpfEgressMapValue v;
    if (bpf_map_lookup_elem(ipv4FlowsMapFd, &k, &v) != 0) {
        return 0;
    }
    return v.last_sent_ns;
#else
    (void)key;
    return 0;
#endif
}

uint64_t EbpfLoader::egressLastSentV6(const struct EbpfEgressMapKeyV6& key) {
#ifdef ENABLE_EBPF
    if (!enabled || ipv6FlowsMapFd < 0) {
        return 0;
    }
    EbpfEgressMapKeyV6 k;
    std::memset(&k, 0, sizeof(k));
    k.ifindex = key.ifindex;
    std::memcpy(k.src, key.src, sizeof(k.src));
    std::memcpy(k.dst, key.dst, sizeof(k.dst));
    k.srcpt = key.srcpt; k.dstpt = key.dstpt; k.prot = key.prot;
    EbpfEgressMapValue v;
    if (bpf_map_lookup_elem(ipv6FlowsMapFd, &k, &v) != 0) {
        return 0;
    }
    return v.last_sent_ns;
#else
    (void)key;
    return 0;
#endif
}

uint64_t EbpfLoader::getEgressCounter(uint32_t code) {
#ifdef ENABLE_EBPF
    if (!enabled || egressCountersMapFd < 0) {
        return 0;
    }
    unsigned int nCpus = libbpf_num_possible_cpus();
    if (nCpus == 0) nCpus = 1;
    std::vector<uint64_t> values(nCpus, 0);
    int err = bpf_map_lookup_elem(egressCountersMapFd, &code, values.data());
    if (err) {
        return 0;
    }
    uint64_t total = 0;
    for (unsigned int i = 0; i < nCpus; i++)
        total += values[i];
    return total;
#else
    (void)code;
    return 0;
#endif
}

EbpfLoaderHealthCheck EbpfLoader::check()  {
    std::array<uint64_t, RCV_CODES_COUNT> recv_counters;
    for (int i = 0; i < RCV_CODES_COUNT; i++) {
        recv_counters[i] = this->getCounter(static_cast<rcv_counters_key>(i));
    }
    std::array<uint64_t, EGR_CODES_COUNT> egr_counters;
    for (int i = 0; i < EGR_CODES_COUNT; i++) {
        egr_counters[i] = this->getEgressCounter(static_cast<uint32_t>(i));
    }
    return { enabled, recv_counters, egr_counters,
             ingressMapFullCount.load(std::memory_order_relaxed),
             egressMapFullCount.load(std::memory_order_relaxed) };
}

/**
 * Perform a health check of the GeneveHandler and all components it is using.
 *
 * @return A human-readable string of the health status.
 */
EbpfLoaderHealthCheck::EbpfLoaderHealthCheck(bool active, std::array<uint64_t,RCV_CODES_COUNT> recv_counters, std::array<uint64_t,EGR_CODES_COUNT> egr_counters,
                                             uint64_t ingressMapFull, uint64_t egressMapFull) :
    active(active), recv_counters(std::move(recv_counters)), egr_counters(std::move(egr_counters)),
    ingressMapFull(ingressMapFull), egressMapFull(egressMapFull)
{
}

EbpfLoaderHealthCheck::Disposition EbpfLoaderHealthCheck::ingressDisposition() const
{
    Disposition d{};
    d.accelerated = recv_counters[RCV_VALID_GENEVE];
    d.punted      = recv_counters[RCV_UNKNOWN_FLOW];
    d.malformed   = recv_counters[RCV_NO_GENEVE_HDR] + recv_counters[RCV_BAD_GENEVE_VER]
                  + recv_counters[RCV_BAD_GENEVE_VNI] + recv_counters[RCV_BAD_GENEVE_OPTS];
    d.notGwlb     = recv_counters[RCV_NO_ETHER_HDR] + recv_counters[RCV_WRONG_ETHER_PROT]
                  + recv_counters[RCV_NO_IP_HDR]    + recv_counters[RCV_NOT_UDP]
                  + recv_counters[RCV_NO_UDP_HDR]   + recv_counters[RCV_WRONG_UDP_PORT];
    for (int i = 0; i < RCV_CODES_COUNT; i++)
        d.total += recv_counters[i];
    return d;
}

EbpfLoaderHealthCheck::EgressDisposition EbpfLoaderHealthCheck::egressDisposition() const
{
    EgressDisposition d{};
    d.accelerated = egr_counters[EGR_REENCAP];
    d.punted      = egr_counters[EGR_TOO_BIG];
    d.noMatch     = egr_counters[EGR_UNKNOWN_FLOW];
    d.noL2        = egr_counters[EGR_NO_L2];
    for (int i = 0; i < EGR_CODES_COUNT; i++)
        d.total += egr_counters[i];
    return d;
}

std::string EbpfLoaderHealthCheck::output_str()
{
    if(!active)
        return "eBPF acceleration is not active.\n"s;

    auto in = ingressDisposition();
    std::string ret = "eBPF acceleration is active.\n"s;
    ret += "  Ingress (packets on the GWLB-facing interface):\n"s;
    ret += "    accelerated in-kernel : "s + std::to_string(in.accelerated) + "   (decapped + redirected to gwi)\n"s;
    ret += "    punted to userspace   : "s + std::to_string(in.punted)      + "   (new/unknown flows)\n"s;
    ret += "    malformed GENEVE      : "s + std::to_string(in.malformed)   + "   (bad version/VNI/options)\n"s;
    ret += "    not GWLB traffic      : "s + std::to_string(in.notGwlb)     + "   (passed to normal stack)\n"s;
    ret += "    total seen            : "s + std::to_string(in.total)       + "\n"s;
    auto eg = egressDisposition();
    ret += "  Egress (packets on gwo interfaces):\n"s;
    ret += "    re-encapsulated in-kernel : "s + std::to_string(eg.accelerated) + "\n"s;
    ret += "    punted to userspace       : "s + std::to_string(eg.punted)      + "\n"s;
    ret += "    no flow match             : "s + std::to_string(eg.noMatch)     + "\n"s;
    ret += "    return L2 not cached yet  : "s + std::to_string(eg.noL2)        + "\n"s;
    ret += "    total seen                : "s + std::to_string(eg.total)       + "\n"s;
    ret += "  Flow-map pressure (E2BIG; non-zero => raise the flow reserve/size):\n"s;
    ret += "    ingress map full : "s + std::to_string(ingressMapFull) + "\n"s;
    ret += "    egress  map full : "s + std::to_string(egressMapFull)  + "\n"s;
    return ret;
}

json EbpfLoaderHealthCheck::output_json()
{
    auto in = ingressDisposition();
    auto eg = egressDisposition();
    json ret = {
        {"active", active},
        {"ingress", {
            {"accelerated",      in.accelerated},
            {"punted_userspace", in.punted},
            {"malformed_geneve", in.malformed},
            {"not_gwlb_traffic", in.notGwlb},
            {"total",            in.total}
        }},
        {"egress", {
            {"accelerated",      eg.accelerated},
            {"punted_userspace", eg.punted},
            {"no_flow_match",    eg.noMatch},
            {"no_l2_cached",     eg.noL2},
            {"total",            eg.total}
        }},
        {"map_full", {
            {"ingress", ingressMapFull},
            {"egress",  egressMapFull}
        }}
    };
    return ret;
}



