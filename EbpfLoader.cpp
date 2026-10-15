// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * Loads and attaches gwlbtun's eBPF datapath, and wraps its maps. See EbpfLoader.h and EbpfHelpers.c.
 */

#include "EbpfLoader.h"
#include "GwlbtunConfig.h"
#include "Logger.h"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <stdexcept>

#ifdef ENABLE_EBPF
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <csignal>
#include <fcntl.h>
#include <net/if.h>
#include <spawn.h>
#include <sys/statfs.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

using namespace std::string_literals;

#ifdef ENABLE_EBPF
extern char **environ;
#endif

uint64_t EbpfLoader::nowNs()
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &t);
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

uint32_t EbpfLoader::ifindex(const std::string &name)
{
#ifdef ENABLE_EBPF
    return if_nametoindex(name.c_str());
#else
    (void)name;
    return 0;
#endif
}

bool EbpfLoader::handlesIngress(int ifindexValue) const
{
    return std::find(ingressIfindexes.begin(), ingressIfindexes.end(), (uint32_t)ifindexValue) != ingressIfindexes.end();
}

namespace {

const char *const INGRESS_CODE_NAMES[ING_CODES_COUNT] = {
    "accelerated", "noEtherHdr", "wrongEtherProt", "noIpHdr", "notUdp", "noUdpHdr", "wrongUdpPort",
    "noGeneveHdr", "badGeneveVer", "badGeneveVni", "badGeneveOpts", "unsupported", "unknownFlow", "flowMismatch",
    "decapFailed",
};
const char *const EGRESS_CODE_NAMES[EGR_CODES_COUNT] = {
    "accelerated", "notIp", "unsupported", "unknownFlow", "otherInterface", "noL2", "encapFailed",
};

#ifdef ENABLE_EBPF
// Where the egress program is pinned, briefly, for tc(8) to find it (see attachEgress).
const char *const BPFFS = "/sys/fs/bpf";
const char *const PIN_PREFIX = "gwlbtun-";
constexpr long BPF_FS_MAGIC_VALUE = 0xcafe4a11;
// Priority of the egress filter on gwo-: the lowest, so filters an operator's hooks add run first.
const char *const EGRESS_FILTER_PRIO = "49152";

// libbpf's own messages (including the verifier's log on a load failure, which can be long) go to gwlbtun's
// log, a line at a time.
int libbpfPrint(enum libbpf_print_level level, const char *fmt, va_list ap)
{
    va_list ap2;
    va_copy(ap2, ap);
    const int n = vsnprintf(nullptr, 0, fmt, ap2);
    va_end(ap2);
    if(n <= 0)
        return 0;
    std::string msg((size_t)n + 1, '\0');
    vsnprintf(msg.data(), msg.size(), fmt, ap);
    msg.resize((size_t)n);
    const LogLevel ll = level == LIBBPF_WARN ? LL_IMPORTANT : LL_DEBUG;
    size_t start = 0;
    while(start < msg.size())
    {
        size_t nl = msg.find('\n', start);
        if(nl == std::string::npos)
            nl = msg.size();
        if(nl > start)
            LOG(LS_EBPF, ll, msg.substr(start, nl - start));
        start = nl + 1;
    }
    return 0;
}

// " This kernel is X.Y; ..." if it's older than tcx (6.6), else "".
std::string kernelHint()
{
    struct utsname u;
    if(uname(&u) != 0)
        return ""s;
    int major = 0, minor = 0;
    if(sscanf(u.release, "%d.%d", &major, &minor) == 2 && (major < 6 || (major == 6 && minor < 6)))
        return " This kernel is "s + u.release + "; gwlbtun's eBPF datapath needs Linux 6.6 or later (tcx)."s;
    return ""s;
}

/**
 * Run tc with these arguments (argv[0] is "tc", found on PATH), without a shell. Returns true if it exited 0;
 * otherwise logs what it printed on stderr. Every fd gwlbtun holds is close-on-exec, so tc inherits none.
 */
bool runTc(const std::vector<std::string> &args)
{
    std::vector<char *> argv;
    std::string cmdline;
    for(const auto &a : args)
    {
        argv.push_back(const_cast<char *>(a.c_str()));
        cmdline += (cmdline.empty() ? ""s : " "s) + a;
    }
    argv.push_back(nullptr);
    LOG(LS_EBPF, LL_DEBUG, "Running: "s + cmdline);

    int pipeFds[2];
    if(pipe2(pipeFds, O_CLOEXEC) != 0)
    {
        const int err = errno;
        LOG(LS_EBPF, LL_IMPORTANT, "Unable to run "s + cmdline + ": "s + errText(err));
        return false;
    }
    UniqueFd readEnd(pipeFds[0]), writeEnd(pipeFds[1]);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_adddup2(&fa, writeEnd.get(), STDERR_FILENO);
    pid_t pid;
    const int rc = posix_spawnp(&pid, "tc", &fa, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&fa);
    writeEnd.reset();
    if(rc != 0)
    {
        LOG(LS_EBPF, LL_IMPORTANT, "Unable to run "s + cmdline + ": "s + errText(rc) + (rc == ENOENT ? " (is iproute-tc installed?)"s : ""s));
        return false;
    }
    std::string output;
    char buf[512];
    for(;;)
    {
        const ssize_t n = read(readEnd.get(), buf, sizeof(buf));
        if(n > 0)
            output.append(buf, (size_t)n);
        else if(n == 0 || errno != EINTR)
            break;
    }
    int status = 0;
    while(waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    if(WIFEXITED(status) && WEXITSTATUS(status) == 0)
        return true;
    while(!output.empty() && (output.back() == '\n' || output.back() == '\r'))
        output.pop_back();
    LOG(LS_EBPF, LL_IMPORTANT, cmdline + " failed"s + (output.empty() ? "."s : ": "s + output));
    return false;
}

#ifndef NO_RETURN_TRAFFIC
// Remove egress pins left by gwlbtun processes that died between pinning and unpinning.
void removeStalePins()
{
    std::error_code ec;
    for(const auto &entry : std::filesystem::directory_iterator(BPFFS, ec))
    {
        const std::string name = entry.path().filename().string();
        if(name.rfind(PIN_PREFIX, 0) != 0)
            continue;
        const long pid = strtol(name.c_str() + strlen(PIN_PREFIX), nullptr, 10);
        if(pid > 0 && kill((pid_t)pid, 0) != 0 && errno == ESRCH)
            unlink(entry.path().c_str());
    }
}
#endif

std::string mapFdError(const char *name)
{
    return "eBPF object has no map "s + name + " (is it the gwlbtun-ebpf.o built with this gwlbtun?)."s;
}

int mapFd(struct bpf_object *obj, const char *name)
{
    struct bpf_map *m = bpf_object__find_map_by_name(obj, name);
    if(!m || bpf_map__fd(m) < 0)
        throw std::runtime_error(mapFdError(name));
    return bpf_map__fd(m);
}

uint32_t sizeMap(struct bpf_object *obj, const char *name, size_t entries)
{
    struct bpf_map *m = bpf_object__find_map_by_name(obj, name);
    if(!m)
        throw std::runtime_error(mapFdError(name));
    const uint32_t n = (uint32_t)std::max<size_t>(1, std::min<size_t>(entries, UINT32_MAX));
    if(int err = bpf_map__set_max_entries(m, n); err != 0)
        throw std::runtime_error("Unable to size eBPF map "s + name + " to "s + std::to_string(n) + " entries: "s + errText(-err));
    return n;
}

// Sum a per-CPU counter array.
template<size_t N> std::array<uint64_t, N> readCounters(int fd)
{
    std::array<uint64_t, N> out{};
    if(fd < 0)
        return out;
    const int ncpu = libbpf_num_possible_cpus();
    if(ncpu <= 0)
        return out;
    std::vector<uint64_t> values((size_t)ncpu);
    for(uint32_t i = 0; i < N; i++)
        if(bpf_map_lookup_elem(fd, &i, values.data()) == 0)
            for(auto v : values)
                out[i] += v;
    return out;
}
#endif

} // namespace

EbpfLoader::EbpfLoader(const GwlbtunConfig &cfg)
{
#ifdef ENABLE_EBPF
    try {
        load(cfg);
    } catch(...) {
        close();
        throw;
    }
#else
    (void)cfg;
    throw std::runtime_error("This gwlbtun was built without eBPF support, so -e/--ebpf can't be used.");
#endif
}

EbpfLoader::~EbpfLoader()
{
    close();
    if(!ingressInterfaces.empty())
        LOG(LS_EBPF, LL_IMPORTANT, "eBPF datapath detached.");
}

void EbpfLoader::close() noexcept
{
#ifdef ENABLE_EBPF
    for(auto *link : ingressLinks)
        bpf_link__destroy(link);
    ingressLinks.clear();
    if(obj)
        bpf_object__close(obj);
    obj = nullptr;
#endif
}

void EbpfLoader::load(const GwlbtunConfig &cfg)
{
#ifdef ENABLE_EBPF
    libbpf_set_print(libbpfPrint);

    // The interfaces GWLB's traffic arrives on: -I, or else the one holding the default route.
    std::vector<std::string> interfaces = cfg.interfaces;
    if(interfaces.empty() && !cfg.udpPlan.empty() && !cfg.udpPlan.front().detectedOn.empty())
        interfaces.push_back(cfg.udpPlan.front().detectedOn);
    if(interfaces.empty())
        throw std::runtime_error("eBPF (-e): there's no default route, so gwlbtun can't tell which interface GWLB's traffic arrives on. Name it with -I."s);

    obj = bpf_object__open_file(cfg.ebpfObject.c_str(), nullptr);
    if(!obj)
    {
        const int err = errno;
        throw std::runtime_error("Unable to open eBPF object "s + cfg.ebpfObject + ": "s + errText(err));
    }

    // Size the flow maps before loading (only possible then). Each flow has one ingress entry and two egress
    // entries (one per direction).
    const auto flows = cfg.ebpfFlows();
    ingressMapSize = sizeMap(obj, "ingress_map", flows[0] + flows[1]);
#ifndef NO_RETURN_TRAFFIC
    egressV4MapSize = sizeMap(obj, "egress_v4_map", 2 * flows[0]);
    egressV6MapSize = sizeMap(obj, "egress_v6_map", 2 * flows[1]);
#else
    sizeMap(obj, "egress_v4_map", 1);
    sizeMap(obj, "egress_v6_map", 1);
#endif

    if(int err = bpf_object__load(obj); err != 0)
        throw std::runtime_error("Unable to load eBPF object "s + cfg.ebpfObject + ": "s + errText(-err) +
                                 (err == -EPERM ? " (gwlbtun needs root, or CAP_BPF and CAP_NET_ADMIN)."s : "."s) + kernelHint());

    struct bpf_program *ingressProg = bpf_object__find_program_by_name(obj, "gwlbtun_ingress");
    egressProg = bpf_object__find_program_by_name(obj, "gwlbtun_egress");
    if(!ingressProg || !egressProg)
        throw std::runtime_error("eBPF object "s + cfg.ebpfObject + " is missing gwlbtun's programs (is it the gwlbtun-ebpf.o built with this gwlbtun?)."s);
    ingressMapFd = mapFd(obj, "ingress_map");
    egressV4MapFd = mapFd(obj, "egress_v4_map");
    egressV6MapFd = mapFd(obj, "egress_v6_map");
    ingressCountersFd = mapFd(obj, "ingress_counters_map");
    egressCountersFd = mapFd(obj, "egress_counters_map");

#ifndef NO_RETURN_TRAFFIC
    // The egress action sends to the first GWLB-facing interface. tc(8) attaches it (see attachEgress), and needs
    // bpffs to find the program.
    struct statfs fs;
    if(statfs(BPFFS, &fs) != 0 || fs.f_type != BPF_FS_MAGIC_VALUE)
        throw std::runtime_error("eBPF (-e) needs the BPF filesystem mounted at "s + BPFFS + " (mount -t bpf bpf "s + BPFFS + ")."s);
    removeStalePins();
    if(!runTc({ "tc", "-V" }))
        throw std::runtime_error("eBPF (-e) needs tc(8) (the iproute-tc package) to attach its egress program."s);
    mirredInterface = interfaces.front();
    EbpfEgressConfig ec{};
    ec.mirredIfindex = if_nametoindex(mirredInterface.c_str());
    const uint32_t zero = 0;
    if(ec.mirredIfindex == 0 || bpf_map_update_elem(mapFd(obj, "egress_config_map"), &zero, &ec, BPF_ANY) != 0)
        throw std::runtime_error("Unable to configure the eBPF egress program for interface "s + mirredInterface + "."s);
    mirredIfindexValue = ec.mirredIfindex;
    egressOn = true;
#endif

    for(const auto &ifname : interfaces)
    {
        const unsigned ifindex = if_nametoindex(ifname.c_str());
        if(ifindex == 0)
            throw std::runtime_error("eBPF (-e): no interface named "s + ifname + "."s);
        LIBBPF_OPTS(bpf_tcx_opts, opts);
        struct bpf_link *link = bpf_program__attach_tcx(ingressProg, (int)ifindex, &opts);
        if(!link)
        {
            const int err = errno;
            throw std::runtime_error("Unable to attach the eBPF ingress program to "s + ifname + ": "s + errText(err) + "."s + kernelHint());
        }
        ingressLinks.push_back(link);
        ingressInterfaces.push_back(ifname);
        ingressIfindexes.push_back(ifindex);
    }

    std::string list;
    for(const auto &i : ingressInterfaces)
        list += (list.empty() ? ""s : ", "s) + i;
    LOG(LS_EBPF, LL_IMPORTANT, "eBPF datapath loaded from "s + cfg.ebpfObject + ": ingress on "s + list +
        (egressOn ? "; egress to GWLB via "s + mirredInterface : "; no egress (receive-only build)"s) +
        ". Map sizes: ingress "s + std::to_string(ingressMapSize) + ", egress IPv4 "s + std::to_string(egressV4MapSize) +
        ", egress IPv6 "s + std::to_string(egressV6MapSize) + " entries (flows: IPv4 "s + std::to_string(flows[0]) +
        ", IPv6 "s + std::to_string(flows[1]) + ", all endpoints together; see --ebpf-reserve)."s);
    if(ingressInterfaces.size() > 1 && egressOn)
        LOG(LS_EBPF, LL_IMPORTANT, "Replies to flows arriving on interfaces other than "s + mirredInterface +
            " are returned to GWLB by userspace, not the eBPF egress path."s);
#else
    (void)cfg;
#endif
}

/**
 * Attach the egress action chain to gwo-: `action bpf <gwlbtun_egress> action mirred egress redirect dev <nic>`.
 * libbpf can't express an action chain, so tc(8) installs it. tc needs the program pinned in bpffs; the pin
 * is removed as soon as tc has attached (the filter holds its own reference), so nothing is left behind
 * if gwlbtun dies. The filter goes away with the gwo- interface.
 */
bool EbpfLoader::attachEgress(const std::string &gwoName)
{
#ifdef ENABLE_EBPF
    if(!egressOn)
        return false;
    std::lock_guard<std::mutex> lk(egressAttachMutex);
    const std::string pin = BPFFS + "/"s + PIN_PREFIX + std::to_string(getpid()) + "-"s + std::to_string(egressPinCount++);
    unlink(pin.c_str());
    if(int err = bpf_obj_pin(bpf_program__fd(egressProg), pin.c_str()); err != 0)
    {
        LOG(LS_EBPF, LL_IMPORTANT, "Unable to pin the eBPF egress program at "s + pin + ": "s + errText(-err) +
            ". Return traffic for "s + gwoName + " stays in userspace."s);
        return false;
    }
    runTc({ "tc", "qdisc", "add", "dev", gwoName, "clsact" });   // fails harmlessly if it's already there
    const bool ok = runTc({ "tc", "filter", "add", "dev", gwoName, "egress", "prio", EGRESS_FILTER_PRIO, "protocol", "all", "basic",
                            "action", "bpf", "object-pinned", pin, "action", "mirred", "egress", "redirect", "dev", mirredInterface });
    unlink(pin.c_str());
    if(ok)
        LOG(LS_EBPF, LL_INFO, "eBPF egress attached to "s + gwoName + "."s);
    else
        LOG(LS_EBPF, LL_IMPORTANT, "Unable to attach the eBPF egress program to "s + gwoName + "; its return traffic stays in userspace."s);
    return ok;
#else
    (void)gwoName;
    return false;
#endif
}

void EbpfLoader::noteUpdateFailure(std::atomic<uint64_t> &fullCount, int err, const char *which) const
{
    // E2BIG: the map is full, so the flow stays on the userspace path. Expected at capacity: count it, and log
    // the first and every 4096th. Anything else is unexpected.
    if(err == -E2BIG)
    {
        const uint64_t n = fullCount.fetch_add(1, std::memory_order_relaxed);
        if((n & 0xFFF) == 0)
            LOG(LS_EBPF, LL_IMPORTANT, "eBPF "s + which + " map is full, so new flows stay on the userspace path (flows so far: "s +
                std::to_string(n + 1) + ", logging the first and every 4096th). Raise --ebpf-reserve to accelerate more."s);
        return;
    }
    static std::atomic<uint64_t> failures{0};
    if((failures.fetch_add(1, std::memory_order_relaxed) & 0xFFF) == 0)
        LOG(LS_EBPF, LL_IMPORTANT, "Unable to update the eBPF "s + which + " map: "s + errText(-err) + " (logging the first and every 4096th)."s);
}

EbpfLoader::InsertResult EbpfLoader::insertIngress(const EbpfIngressKey &key, const EbpfIngressValue &value)
{
#ifdef ENABLE_EBPF
    const int err = bpf_map_update_elem(ingressMapFd, &key, &value, BPF_NOEXIST);
    if(err == 0)
        return InsertResult::Inserted;
    if(err == -EEXIST)
        return InsertResult::Exists;
    noteUpdateFailure(ingressMapFull, err, "ingress");
    return err == -E2BIG ? InsertResult::Full : InsertResult::Failed;
#else
    (void)key; (void)value;
    return InsertResult::Failed;
#endif
}

bool EbpfLoader::lookupIngress(const EbpfIngressKey &key, EbpfIngressValue &value) const
{
#ifdef ENABLE_EBPF
    return bpf_map_lookup_elem(ingressMapFd, &key, &value) == 0;
#else
    (void)key; (void)value;
    return false;
#endif
}

void EbpfLoader::removeIngress(const EbpfIngressKey &key)
{
#ifdef ENABLE_EBPF
    bpf_map_delete_elem(ingressMapFd, &key);   // ENOENT is fine: already gone
#else
    (void)key;
#endif
}

#ifdef ENABLE_EBPF
#define EGRESS_OPS(KEY, FD, WHICH) \
    bool EbpfLoader::updateEgress(const KEY &key, const EbpfEgressValue &value) \
    { \
        const int err = bpf_map_update_elem(FD, &key, &value, BPF_ANY); \
        if(err != 0) noteUpdateFailure(egressMapFull, err, WHICH); \
        return err == 0; \
    } \
    bool EbpfLoader::lookupEgress(const KEY &key, EbpfEgressValue &value) const { return bpf_map_lookup_elem(FD, &key, &value) == 0; } \
    void EbpfLoader::removeEgress(const KEY &key) { bpf_map_delete_elem(FD, &key); }
#else
#define EGRESS_OPS(KEY, FD, WHICH) \
    bool EbpfLoader::updateEgress(const KEY &, const EbpfEgressValue &) { return false; } \
    bool EbpfLoader::lookupEgress(const KEY &, EbpfEgressValue &) const { return false; } \
    void EbpfLoader::removeEgress(const KEY &) {}
#endif
EGRESS_OPS(EbpfEgressKeyV4, egressV4MapFd, "IPv4 egress")
EGRESS_OPS(EbpfEgressKeyV6, egressV6MapFd, "IPv6 egress")
#undef EGRESS_OPS

EbpfHealthCheck EbpfLoader::check() const
{
    EbpfHealthCheck h;
    h.ingressInterfaces = ingressInterfaces;
    h.mirredInterface = mirredInterface;
#ifdef ENABLE_EBPF
    h.ingress = readCounters<ING_CODES_COUNT>(ingressCountersFd);
    h.egress = readCounters<EGR_CODES_COUNT>(egressCountersFd);
#endif
    h.ingressMapFull = ingressMapFull.load(std::memory_order_relaxed);
    h.egressMapFull = egressMapFull.load(std::memory_order_relaxed);
    h.ingressMapSize = ingressMapSize;
    h.egressV4MapSize = egressV4MapSize;
    h.egressV6MapSize = egressV6MapSize;
    return h;
}

std::string EbpfHealthCheck::output_str() const
{
    std::string list;
    for(const auto &i : ingressInterfaces)
        list += (list.empty() ? ""s : ", "s) + i;
    const auto notGeneve = ingress[ING_NO_ETHER_HDR] + ingress[ING_WRONG_ETHER_PROT] + ingress[ING_NO_IP_HDR] + ingress[ING_NOT_UDP] +
                           ingress[ING_NO_UDP_HDR] + ingress[ING_WRONG_UDP_PORT];
    const auto malformed = ingress[ING_NO_GENEVE_HDR] + ingress[ING_BAD_GENEVE_VER] + ingress[ING_BAD_GENEVE_VNI] + ingress[ING_BAD_GENEVE_OPTS];
    std::string s = "eBPF datapath: ingress on "s + list + (mirredInterface.empty() ? ", no egress.\n"s : ", egress to GWLB via "s + mirredInterface + ".\n"s);
    s += "  Ingress: "s + std::to_string(ingress[ING_ACCELERATED]) + " packets delivered in the kernel; to userspace: "s +
         std::to_string(ingress[ING_UNKNOWN_FLOW]) + " new flows, "s + std::to_string(ingress[ING_FLOW_MISMATCH]) + " cookie/flow mismatches, "s +
         std::to_string(ingress[ING_UNSUPPORTED]) + " unsupported layouts, "s + std::to_string(ingress[ING_DECAP_FAILED]) + " decapsulation failures, "s +
         std::to_string(malformed) + " malformed GENEVE; "s + std::to_string(notGeneve) + " not GENEVE.\n"s;
    if(!mirredInterface.empty())
        s += "  Egress: "s + std::to_string(egress[EGR_REENCAP]) + " packets sent in the kernel; to userspace: "s +
             std::to_string(egress[EGR_UNKNOWN_FLOW]) + " unknown flows, "s + std::to_string(egress[EGR_OTHER_NIC]) + " for other interfaces, "s +
             std::to_string(egress[EGR_NO_L2]) + " without a return Ethernet header yet, "s +
             std::to_string(egress[EGR_UNSUPPORTED] + egress[EGR_NOT_IP]) + " unsupported, "s + std::to_string(egress[EGR_ENCAP_FAILED]) +
             " encapsulation failures.\n"s;
    s += "  Maps: ingress "s + std::to_string(ingressMapSize) + ", egress IPv4 "s + std::to_string(egressV4MapSize) + ", egress IPv6 "s +
         std::to_string(egressV6MapSize) + " entries; flows that didn't fit: ingress "s + std::to_string(ingressMapFull) + ", egress "s +
         std::to_string(egressMapFull) + ".\n"s;
    return s;
}

json EbpfHealthCheck::output_json() const
{
    json in = json::object(), eg = json::object();
    for(size_t i = 0; i < ING_CODES_COUNT; i++)
        in[INGRESS_CODE_NAMES[i]] = ingress[i];
    for(size_t i = 0; i < EGR_CODES_COUNT; i++)
        eg[EGRESS_CODE_NAMES[i]] = egress[i];
    return {
        {"ingressInterfaces", ingressInterfaces},
        {"mirredInterface", mirredInterface},
        {"ingress", std::move(in)},
        {"egress", std::move(eg)},
        {"mapSizes", {{"ingress", ingressMapSize}, {"egressV4", egressV4MapSize}, {"egressV6", egressV6MapSize}}},
        {"mapFull", {{"ingress", ingressMapFull}, {"egress", egressMapFull}}},
    };
}
