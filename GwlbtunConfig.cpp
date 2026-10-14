// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * Command-line and configuration-file parsing for gwlbtun. One table of options (OPTIONS below) drives
 * both getopt_long() and the YAML file, so every option works the same way in both places.
 */

#include <yaml.h>   // libyaml, vendored in third_party/libyaml
#include "GwlbtunConfig.h"
#include "Logger.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <charconv>
#include <climits>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <getopt.h>
#include <net/if.h>
#include <sched.h>
#include <set>
#include <sstream>
#include <string_view>
#include <unistd.h>

using namespace std::string_literals;

int numCores()
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    if(sched_getaffinity(0, sizeof(cpuset), &cpuset) == 0)
        if(int n = CPU_COUNT(&cpuset); n > 0)
            return n;
    // More CPUs than cpu_set_t holds (sched_getaffinity fails with EINVAL), or no affinity support.
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
}

namespace {

struct OptionDef {
    const char *name;    // long option and configuration-file key
    char shortName;      // 0 = long only
    bool takesValue;     // false = a flag (true/false in the file)
    bool repeatable;     // values accumulate
    bool inFile;         // allowed in a configuration file
    // Options resolved together. On the command line, the first occurrence of any option in a set clears
    // what the file said for every option in it: --udpthreads beats udpaffinity in the file, and -I replaces
    // the file's interface list rather than adding to it. nullptr = the command line simply overrides.
    const char *resetSet = nullptr;
};

const OptionDef OPTIONS[] = {
    {"config",      'f', true,  false, false},
    {"cmdnew",      'c', true,  false, true},
    {"cmddel",      'r', true,  false, true},
    {"timeout",     't', true,  false, true},
    {"idle",        'i', true,  false, true},
    {"port",        'p', true,  false, true},
    {"interface",   'I', true,  true,  true,  "interface"},
    {"json",        'j', false, false, true},
    {"simple",      's', false, false, true},
    {"debug",       'd', false, false, true,  "logging"},
    {"logging",     0,   true,  false, true,  "logging"},
    {"udpthreads",  0,   true,  false, true,  "udp"},
    {"udpaffinity", 0,   true,  false, true,  "udp"},
#ifndef NO_RETURN_TRAFFIC
    {"tunthreads",  0,   true,  false, true,  "tun"},
    {"tunaffinity", 0,   true,  false, true,  "tun"},
    {"sndbuf",      0,   true,  false, true},
#endif
    {"rcvbuf",      0,   true,  false, true},
    {"busypoll",    0,   true,  false, true},
    {"reserve",     0,   true,  true,  true,  "reserve"},
    {"show-config", 0,   false, false, false},
    {"help",        'h', false, false, false},
};

const OptionDef *findOption(const std::string &name)
{
    for(const auto &o : OPTIONS)
        if(name == o.name)
            return &o;
    return nullptr;
}

// Largest flow-cache reserve accepted per table.
constexpr std::size_t MAX_RESERVE = 100000000;

// Strict number parse: the whole of s, digits only (an optional leading '-' for signed T). No whitespace,
// no '+', no trailing text, no overflow.
template<class T> bool parseNumber(std::string_view s, T &out, int base = 10)
{
    if(s.empty())
        return false;
    auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), out, base);
    return ec == std::errc() && end == s.data() + s.size();
}

long parseLong(const std::string &v, long min, long max, const std::string &where, const char *what)
{
    long n = 0;
    if(!parseNumber(v, n) || n < min || n > max)
        throw ConfigError("Invalid "s + where + " '"s + v + "': expected "s + what + "."s);
    return n;
}

std::string reserveText(const std::array<std::size_t, 6> &r)
{
    std::string out;
    for(size_t i = 0; i < r.size(); i++)
        out += (i ? ","s : ""s) + std::to_string(r[i]);
    return out;
}

bool parseBool(const std::string &v, const std::string &where)
{
    std::string l = v;
    std::transform(l.begin(), l.end(), l.begin(), ::tolower);
    if(l == "true" || l == "yes" || l == "on" || l == "1")
        return true;
    if(l == "false" || l == "no" || l == "off" || l == "0")
        return false;
    throw ConfigError("Invalid "s + where + " '"s + v + "': expected true or false."s);
}

// -p: PORT, ADDR:PORT (IPv4, or [IPv6]:PORT) or IFNAME:PORT. Port 0 = no health listener.
void parseHealthListen(const std::string &a, const std::string &where, GwlbtunConfig &c)
{
    std::string host, portStr, address, interface;
    bool ok = true;
    if(!a.empty() && a[0] == '[')
    {
        auto close = a.find("]:");
        struct in6_addr a6;
        if(close == std::string::npos || inet_pton(AF_INET6, a.substr(1, close - 1).c_str(), &a6) != 1)
            ok = false;
        else
        {
            address = a.substr(1, close - 1);
            portStr = a.substr(close + 2);
        }
    }
    else if(auto colon = a.rfind(':'); colon != std::string::npos)
    {
        host = a.substr(0, colon);
        portStr = a.substr(colon + 1);
        struct in_addr a4;
        if(inet_pton(AF_INET, host.c_str(), &a4) == 1)
            address = host;
        else if(!host.empty() && host.size() < IFNAMSIZ && if_nametoindex(host.c_str()) != 0)
            interface = host;
        else
            ok = false;
    }
    else
        portStr = a;
    int p = -1;
    if(!ok || !parseNumber(portStr, p) || p < 0 || p > 65535)
        throw ConfigError("Invalid "s + where + " '"s + a + "'. Expected PORT, ADDR:PORT ([IPv6]:PORT for IPv6) or IFNAME:PORT."s);
    c.healthPort = p;
    c.healthAddress = address;
    c.healthInterface = interface;
}

// --reserve: "n,n,n,n,n,n" (default for all endpoints) or "vpce-<hex>:n,n,n,n,n,n" (one endpoint),
// in order [v4TCP,v4UDP,v4Other,v6TCP,v6UDP,v6Other].
void parseReserve(const std::string &arg, const std::string &where, GwlbtunConfig &c)
{
    auto fail = [&]() {
        return ConfigError("Invalid "s + where + " '"s + arg + "'. Expected six comma-separated counts "
                           "(v4TCP,v4UDP,v4Other,v6TCP,v6UDP,v6Other), each 0 to "s + std::to_string(MAX_RESERVE) +
                           ", optionally prefixed with 'vpce-<id>:' for a per-endpoint override."s);
    };
    std::string nums = arg;
    bool isGlobal = true;
    gwlbeid_t key = 0;
    auto colon = arg.find(':');
    if(colon != std::string::npos)
    {
        std::string k = arg.substr(0, colon);
        nums = arg.substr(colon + 1);
        if(k.rfind("vpce-", 0) == 0) k = k.substr(5);
        else if(k.rfind("eni-", 0) == 0) k = k.substr(4);
        if(!parseNumber(k, key, 16)) throw fail();
        isGlobal = false;
    }
    std::array<std::size_t, 6> vals{};
    std::size_t idx = 0, start = 0;
    for(std::size_t i = 0; i <= nums.size(); i++)
    {
        if(i == nums.size() || nums[i] == ',')
        {
            if(idx >= 6 || !parseNumber(std::string_view(nums).substr(start, i - start), vals[idx]) || vals[idx] > MAX_RESERVE)
                throw fail();
            idx++; start = i + 1;
        }
    }
    if(idx != 6) throw fail();
    if(isGlobal) c.defaultReserve = vals;
    else c.perEndpointReserve[key] = vals;
}

// --- CPU lists and host topology, for resolving the thread layout ------------------------------------

/**
 * Parse a CPU list ("1-2,4,7-8"), as --udpaffinity/--tunaffinity take and sysfs uses. strict (user input):
 * anything malformed throws ConfigError, naming `what`; core numbers CPU_SET() can't represent (it holds
 * CPU_SETSIZE bits, and setting one beyond that is undefined behaviour) are rejected. Not strict (sysfs):
 * malformed parts are skipped.
 */
std::vector<int> parseCpuList(const std::string &list, bool strict, const std::string &what = "CPU list"s)
{
    std::vector<int> out;
    auto bad = [&](const std::string &msg) { if(strict) throw ConfigError(msg); };
    auto num = [&](const std::string &s, int &v) {
        if(!parseNumber(s, v) || v < 0)
        {
            bad("Invalid core number '"s + s + "' in "s + what + " '"s + list + "'."s);
            return false;
        }
        if(v >= CPU_SETSIZE)
        {
            bad("Core number "s + std::to_string(v) + " in "s + what + " '"s + list + "' is beyond the largest supported core ("s +
                std::to_string(CPU_SETSIZE - 1) + ")."s);
            return false;
        }
        return true;
    };
    std::stringstream ss(list);
    std::string part;
    while(std::getline(ss, part, ','))
    {
        int a = 0, b = 0;
        auto dash = part.find('-');
        if(dash == std::string::npos)
        {
            if(!num(part, a))
                continue;
            b = a;
        }
        else
        {
            if(!num(part.substr(0, dash), a) || !num(part.substr(dash + 1), b))
                continue;
            if(b < a)
            {
                bad("Core range '"s + part + "' in "s + what + " '"s + list + "' runs backwards."s);
                continue;
            }
        }
        for(int c = a; c <= b; c++)
            out.push_back(c);
    }
    if(out.empty())
        bad(what + " '"s + list + "' lists no cores."s);
    return out;
}

// First line of a (sysfs/procfs) file, or "" if it can't be read.
std::string readLine(const std::string &path)
{
    std::ifstream f(path);
    std::string line;
    std::getline(f, line);
    return line;
}

std::string defaultRouteInterface()
{
    std::ifstream f("/proc/net/route");
    std::string line, iface, dest;
    std::getline(f, line);   // header
    while(std::getline(f, line))
    {
        std::istringstream ss(line);
        if(ss >> iface >> dest && dest == "00000000")
            return iface;
    }
    return "";
}

/**
 * CPUs servicing the RX queues of an interface (the one holding the default route if ifname is empty), in
 * queue order, read from /proc/interrupts ("<ifname>-Tx-Rx-<q>", as ENA names them) and each IRQ's effective
 * affinity. Empty if nothing is found. *ifnameOut receives the interface used.
 */
std::vector<int> detectRxQueueCpus(const std::string &ifnameIn, std::string *ifnameOut)
{
    std::string ifname = ifnameIn.empty() ? defaultRouteInterface() : ifnameIn;
    if(ifnameOut)
        *ifnameOut = ifname;
    std::vector<std::pair<int, int>> queues;   // (queue number, cpu)
    if(ifname.empty())
        return {};
    const std::string tag = ifname + "-Tx-Rx-";
    std::ifstream f("/proc/interrupts");
    std::string line;
    while(std::getline(f, line))
    {
        auto pos = line.find(tag);
        if(pos == std::string::npos)
            continue;
        int irq = atoi(line.c_str());
        int q = atoi(line.c_str() + pos + tag.size());
        std::string aff;
        for(const char *name : {"effective_affinity_list", "smp_affinity_list"})
            if(!(aff = readLine("/proc/irq/" + std::to_string(irq) + "/" + name)).empty())
                break;
        if(!aff.empty())
            if(auto cpus = parseCpuList(aff, false); !cpus.empty())
                queues.emplace_back(q, cpus.front());   // first CPU of the list
    }
    std::sort(queues.begin(), queues.end());
    std::vector<int> cpus;
    for(auto &qc : queues)
        cpus.push_back(qc.second);
    return cpus;
}

// Caches CPU `cpu` belongs to: (level, CPUs sharing it), from sysfs.
std::vector<std::pair<int, std::vector<int>>> cpuCaches(int cpu)
{
    std::vector<std::pair<int, std::vector<int>>> out;
    for(int idx = 0; idx < 8; idx++)
    {
        const std::string base = "/sys/devices/system/cpu/cpu"s + std::to_string(cpu) + "/cache/index"s + std::to_string(idx) + "/"s;
        std::ifstream lf(base + "level");
        int level = 0;
        if(!(lf >> level))
            break;
        out.emplace_back(level, parseCpuList(readLine(base + "shared_cpu_list"), false));
    }
    return out;
}

/**
 * --udpaffinity nearest: for each RX queue CPU (in order), the closest CPU that isn't a queue CPU (of any
 * interface, in `avoid`) and isn't already taken (`taken`, updated): one sharing a cache at level 2 or below
 * (a hyperthread sibling), else one sharing a cache at any level (an L3 / core complex), else one on the same
 * NUMA node, else -1 (that thread stays unpinned). Only CPUs this process may run on are used. Topology comes
 * from /sys/devices/system/cpu. `why` receives, per queue, how the CPU was chosen ("L2", "L3", "node", "none").
 */
struct NearCpu { int cpu; std::string why; };
std::vector<NearCpu> nearestFreeCpus(const std::vector<int> &queueCpus, const cpu_set_t &avoid, cpu_set_t &taken)
{
    // rank 0: shares a cache at level <= 2 (hyperthread sibling); 1: shares any cache (L3); 2: same node.
    static const char *const RANK_NAME[] = { "L2", "L3", "node", "none" };
    constexpr int NONE = 3;

    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    if(sched_getaffinity(0, sizeof(allowed), &allowed) != 0)
        return std::vector<NearCpu>(queueCpus.size(), NearCpu{ -1, RANK_NAME[NONE] });

    // NUMA node of every CPU, read once.
    std::vector<int> nodeOf(CPU_SETSIZE, -1);
    for(int node = 0; node < 64; node++)
        for(int c : parseCpuList(readLine("/sys/devices/system/node/node"s + std::to_string(node) + "/cpulist"s), false))
            nodeOf[c] = node;   // parseCpuList keeps only cores below CPU_SETSIZE

    std::vector<NearCpu> out;
    for(int q : queueCpus)
    {
        std::vector<int> rankOf(CPU_SETSIZE, NONE);
        for(auto &[level, cpus] : cpuCaches(q))
            for(int c : cpus)
                rankOf[c] = std::min(rankOf[c], level <= 2 ? 0 : 1);
        int bestCpu = -1, bestRank = NONE;
        for(int c = 0; c < CPU_SETSIZE && bestRank > 0; c++)
        {
            if(!CPU_ISSET(c, &allowed) || c == q || CPU_ISSET(c, &avoid) || CPU_ISSET(c, &taken))
                continue;
            int rank = rankOf[c];
            if(rank == NONE && nodeOf[q] >= 0 && nodeOf[c] == nodeOf[q])
                rank = 2;
            if(rank < bestRank)
            {
                bestRank = rank;
                bestCpu = c;
            }
        }
        if(bestCpu >= 0)
            CPU_SET(bestCpu, &taken);
        out.push_back({ bestCpu, RANK_NAME[bestRank] });
    }
    return out;
}

/**
 * Work out the UDP receiver threads for each interface gwlbtun receives on (-I, or all interfaces).
 *  - --udpaffinity nearest (the default): one thread per receive queue, each pinned on the closest CPU that
 *    services no queue (see nearestFreeCpus); unpinned where there's none, as when every CPU services a queue.
 *  - --udpthreads N / --udpaffinity LIST: those threads, for each interface.
 * Where an interface's queues can't be found, nearest falls back to one unpinned thread per core. Messages
 * for the log go to c.resolveLog (the logger doesn't exist yet).
 */
void resolveUdpPlan(GwlbtunConfig &c, const std::vector<int> &explicitCores)
{
    const std::vector<std::string> ifaces = c.interfaces.empty() ? std::vector<std::string>{""} : c.interfaces;
    c.udpPlan.clear();
    c.maxRxQueues = 0;
    for(const auto &iface : ifaces)
    {
        UdpInterfacePlan p;
        p.name = iface;
        p.queueCpus = detectRxQueueCpus(iface, &p.detectedOn);
        c.maxRxQueues = std::max(c.maxRxQueues, p.queueCpus.size());
        if(!c.udpAffinityNearest)
            p.cores = explicitCores;
        else if(p.queueCpus.empty())
            p.cores.assign((size_t)numCores(), -1);
        else
            p.cores.assign(p.queueCpus.size(), -1);
        c.udpPlan.push_back(std::move(p));
    }
    if(!c.udpAffinityNearest)
        return;

    cpu_set_t avoid, taken;
    CPU_ZERO(&avoid);
    CPU_ZERO(&taken);
    for(const auto &p : c.udpPlan)
        for(int q : p.queueCpus)
            CPU_SET(q, &avoid);   // detectRxQueueCpus' CPUs are all below CPU_SETSIZE
    for(auto &p : c.udpPlan)
    {
        if(p.queueCpus.empty())
            continue;   // the "Receiving GENEVE" line says the queues weren't found
        auto near = nearestFreeCpus(p.queueCpus, avoid, taken);
        std::string map;
        size_t pinned = 0;
        for(size_t i = 0; i < near.size(); i++)
        {
            p.cores[i] = near[i].cpu;
            if(near[i].cpu >= 0)
                pinned++;
            map += (map.empty() ? ""s : ", "s) + "q"s + std::to_string(i) + ":"s + std::to_string(p.queueCpus[i]) + "->"s +
                   (near[i].cpu < 0 ? "unpinned"s : std::to_string(near[i].cpu) + "("s + near[i].why + ")"s);
        }
        if(pinned == 0)
            c.resolveLog.emplace_back(LL_INFO, "UDP threads on "s + p.detectedOn + " are unpinned: every CPU near its receive queues services a queue itself."s);
        else
        {
            c.resolveLog.emplace_back(LL_IMPORTANT, "UDP threads on "s + p.detectedOn + " pinned near their receive queues (queue:CPU->UDP thread CPU): "s + map);
            if(pinned < near.size())
                c.resolveLog.emplace_back(LL_IMPORTANT, std::to_string(near.size() - pinned) + " of "s + std::to_string(near.size()) + " UDP threads on "s +
                                          p.detectedOn + " have no free CPU near their queue and are unpinned."s);
        }
    }
}

class Builder {
public:
    GwlbtunConfig c;

    /**
     * Apply one option. `where` names it for error messages ("--udpthreads", or "file.yaml:12: udpthreads").
     * Flags take "true"/"false". From the command line, the first occurrence of a repeatable option or of a
     * group member clears what the configuration file set for it.
     */
    void apply(const OptionDef &o, const std::string &v, bool fromCli, const std::string &where)
    {
        const std::string name = o.name;
        if(fromCli && o.resetSet && resetDone.insert(o.resetSet).second)
            for(const auto &m : OPTIONS)
                if(m.resetSet && strcmp(m.resetSet, o.resetSet) == 0)
                    clear(m.name);

        if(name == "cmdnew") c.createHook = v;
        else if(name == "cmddel") c.destroyHook = v;
        else if(name == "timeout") c.tunnelTimeout = (int)parseLong(v, 0, INT_MAX, where, "a number of seconds, 0 or more");
        else if(name == "idle") c.tcpCacheTimeout = (int)parseLong(v, 1, INT_MAX, where, "a number of seconds, 1 or more");
        else if(name == "port") parseHealthListen(v, where, c);
        else if(name == "interface")
        {
            std::stringstream list(v);
            std::string ifname;
            while(std::getline(list, ifname, ','))
            {
                if(ifname.empty())
                    continue;
                if(ifname.size() >= IFNAMSIZ || if_nametoindex(ifname.c_str()) == 0)
                    throw ConfigError("Invalid "s + where + " '"s + v + "': no network interface named '"s + ifname + "'."s);
                c.interfaces.push_back(ifname);
            }
        }
        else if(name == "json") c.jsonHealth = parseBool(v, where);
        else if(name == "simple") c.detailedHealth = !parseBool(v, where);
        else if(name == "debug") { if(parseBool(v, where)) c.logging = "all=debug"; }
        else if(name == "logging") c.logging = v;
        else if(name == "udpthreads") { udpThreadsN = (size_t)parseLong(v, 1, CPU_SETSIZE, where, ("a whole number of threads, 1 to "s + std::to_string(CPU_SETSIZE)).c_str()); c.udpThreadsArg = v; }
        else if(name == "udpaffinity") c.udpAffinityArg = v;
        else if(name == "tunthreads") { tunThreadsN = (size_t)parseLong(v, 1, TUN_MAX_THREADS, where, ("a whole number of threads, 1 to "s + std::to_string(TUN_MAX_THREADS)).c_str()); c.tunThreadsArg = v; }
        else if(name == "tunaffinity") c.tunAffinityArg = v;
        else if(name == "sndbuf") c.sndBufSizeMB = (int)parseLong(v, 1, 1024, where, "a size in megabytes, 1 to 1024");
        else if(name == "rcvbuf") c.rcvBufSizeMB = (int)parseLong(v, 1, 2047, where, "a size in megabytes, 1 to 2047");
        else if(name == "busypoll") c.busyPollUsec = (int)parseLong(v, 0, 1000000, where, "microseconds, 0 to 1000000");
        else if(name == "reserve") { parseReserve(v, where, c); c.reserveArgs.push_back(v); }
        else if(name == "show-config") c.showConfigRequested = parseBool(v, where);
        else if(name == "help") c.helpRequested = true;
    }

    // Resolve the thread layout and normalise lists, once everything has been applied.
    void finish()
    {
        std::sort(c.interfaces.begin(), c.interfaces.end());
        c.interfaces.erase(std::unique(c.interfaces.begin(), c.interfaces.end()), c.interfaces.end());

        c.udpAffinityNearest = c.udpAffinityArg == "nearest" || (c.udpAffinityArg.empty() && c.udpThreadsArg.empty());
        try {
            std::vector<int> udpCores;
            if(!c.udpAffinityNearest)
                udpCores = c.udpAffinityArg.empty() ? std::vector<int>(udpThreadsN, -1)
                                                    : parseCpuList(c.udpAffinityArg, true, "--udpaffinity"s);
            resolveUdpPlan(c, udpCores);
            const size_t cores = (size_t)numCores();
            for(const auto &p : c.udpPlan)
                if(p.cores.size() > cores)
                    c.resolveLog.emplace_back(LL_IMPORTANT, std::to_string(p.cores.size()) + " UDP threads requested"s +
                                              (p.name.empty() ? ""s : " for "s + p.name) + ", more than the "s + std::to_string(cores) +
                                              " CPUs available: this is untested. Continuing with "s + std::to_string(p.cores.size()) + "."s);
#ifndef NO_RETURN_TRAFFIC
            // Default: one tunnel thread per core, leaving room on each gwi- device for the writers the UDP
            // layout wants (a tun device has 256 queues in all; see gwiWriterCount).
            const size_t writersWanted = gwiWritersWanted(c.udpThreadCount(), c.maxRxQueues);
            const size_t defaultTunThreads = std::max<size_t>(1, std::min({ cores, (size_t)TUN_MAX_THREADS, 256 - std::min<size_t>(255, writersWanted) }));
            c.tunThreads.cfg = !c.tunAffinityArg.empty() ? parseCpuList(c.tunAffinityArg, true, "--tunaffinity"s)
                                                         : std::vector<int>(c.tunThreadsArg.empty() ? defaultTunThreads : tunThreadsN, -1);
            if(c.tunThreads.cfg.size() > TUN_MAX_THREADS)
                throw ConfigError("Linux allows at most "s + std::to_string(TUN_MAX_THREADS) + " tunnel threads per tun interface ("s +
                                  std::to_string(c.tunThreads.cfg.size()) + " requested with --tunthreads/--tunaffinity)."s);
            const size_t tunThreads = c.tunThreads.cfg.size();
            const size_t onePerCore = std::min(cores, (size_t)TUN_MAX_THREADS);
            if(c.tunAffinityArg.empty() && c.tunThreadsArg.empty() && defaultTunThreads < onePerCore)
                c.resolveLog.emplace_back(LL_IMPORTANT,
                                          "Tunnel threads default to "s + std::to_string(defaultTunThreads) + " per interface rather than "s +
                                          std::to_string(onePerCore) + ", to leave room on each gwi- device for the "s + std::to_string(writersWanted) +
                                          " writers this UDP layout wants."s);
            if(tunThreads > cores)
                c.resolveLog.emplace_back(LL_IMPORTANT, std::to_string(tunThreads) + " tunnel threads per interface requested, more than the "s +
                                          std::to_string(cores) + " CPUs available: this is untested. Continuing with "s + std::to_string(tunThreads) + "."s);
            const size_t writers = gwiWriterCount(c.udpThreadCount(), c.maxRxQueues, tunThreads);
            if(writers < writersWanted)
                c.resolveLog.emplace_back(LL_IMPORTANT, std::to_string(tunThreads) + " tunnel threads leave room for "s + std::to_string(writers) + " of the "s +
                                          std::to_string(writersWanted) + " gwi- writers this UDP layout wants (a tun device has 256 queues), so forwarded "s +
                                          "traffic leaving the gwi- devices uses at most "s + std::to_string(writers) + " transmit queue(s) unless XPS is set up. "s +
                                          "Use fewer tunnel threads to avoid this."s);
#else
            c.tunThreads.cfg.clear();   // receive-only: nothing reads the tun devices
#endif
        } catch(const ConfigError &) {
            throw;
        } catch(const std::exception &e) {
            throw ConfigError("Invalid thread configuration: "s + e.what());
        }
    }

private:
    std::set<std::string> resetDone;   // resetSets already cleared by a command-line option
    size_t udpThreadsN = 0, tunThreadsN = 0;   // --udpthreads / --tunthreads, parsed

    void clear(const std::string &name)
    {
        if(name == "interface") c.interfaces.clear();
        else if(name == "reserve") { c.defaultReserve = GwlbtunConfig::DEFAULT_RESERVE; c.perEndpointReserve.clear(); c.reserveArgs.clear(); }
        else if(name == "udpthreads") { c.udpThreadsArg.clear(); udpThreadsN = 0; }
        else if(name == "udpaffinity") c.udpAffinityArg.clear();
        else if(name == "tunthreads") { c.tunThreadsArg.clear(); tunThreadsN = 0; }
        else if(name == "tunaffinity") c.tunAffinityArg.clear();
        else if(name == "debug" || name == "logging") c.logging.clear();
    }
};

// libyaml's document and parser, released however loadFile() leaves.
struct YamlDocument {
    yaml_parser_t parser;
    yaml_document_t doc;
    bool parserReady = false, docReady = false;
    ~YamlDocument()
    {
        if(docReady) yaml_document_delete(&doc);
        if(parserReady) yaml_parser_delete(&parser);
    }
};

std::string scalarText(const yaml_node_t *n)
{
    return std::string(reinterpret_cast<const char *>(n->data.scalar.value), n->data.scalar.length);
}

// A plain (unquoted) empty, ~ or null scalar: "key:" with nothing after it.
bool isNull(const yaml_node_t *n)
{
    if(n->type != YAML_SCALAR_NODE || n->data.scalar.style != YAML_PLAIN_SCALAR_STYLE)
        return false;
    const std::string v = scalarText(n);
    return v.empty() || v == "~" || v == "null" || v == "Null" || v == "NULL";
}

/**
 * Read a configuration file: a YAML mapping of option names to values. Lists (`interface: [ens5, ens6]`, or
 * one `- item` per line) are for options that can be given more than once.
 */
void loadFile(Builder &b, const std::string &path)
{
    std::ifstream f(path);
    if(!f)
        throw ConfigError("Unable to read configuration file "s + path + ": "s + std::strerror(errno));
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string text = ss.str();

    YamlDocument y;
    if(!yaml_parser_initialize(&y.parser))
        throw ConfigError("Unable to read configuration file "s + path + ": out of memory."s);
    y.parserReady = true;
    yaml_parser_set_input_string(&y.parser, reinterpret_cast<const unsigned char *>(text.data()), text.size());
    if(!yaml_parser_load(&y.parser, &y.doc))
    {
        // libyaml's marks are 0-based.
        const yaml_mark_t &m = y.parser.problem_mark;
        std::string msg = "Invalid YAML in "s + path + ":"s + std::to_string(m.line + 1) + ":"s + std::to_string(m.column + 1) + ": "s +
                          (y.parser.problem ? y.parser.problem : "parse error");
        if(y.parser.context)
            msg += " ("s + y.parser.context + " at line "s + std::to_string(y.parser.context_mark.line + 1) + ")"s;
        throw ConfigError(msg);
    }
    y.docReady = true;

    yaml_node_t *root = yaml_document_get_root_node(&y.doc);
    if(!root || isNull(root))
        return;   // empty file
    if(root->type != YAML_MAPPING_NODE)
        throw ConfigError("Invalid configuration file "s + path + ": expected a mapping of option names to values (e.g. 'udpthreads: 8')."s);

    for(yaml_node_pair_t *pair = root->data.mapping.pairs.start; pair < root->data.mapping.pairs.top; pair++)
    {
        yaml_node_t *k = yaml_document_get_node(&y.doc, pair->key);
        yaml_node_t *v = yaml_document_get_node(&y.doc, pair->value);
        const std::string line = std::to_string(k->start_mark.line + 1);
        if(k->type != YAML_SCALAR_NODE)
            throw ConfigError("Invalid configuration file "s + path + ":"s + line + ": option names must be plain words."s);
        const std::string key = scalarText(k);
        const std::string where = path + ":"s + line + ": "s + key;
        const OptionDef *o = findOption(key);
        if(!o)
            throw ConfigError("Unknown option '"s + key + "' in "s + path + ":"s + line + "."s);
        if(!o->inFile)
            throw ConfigError("Option '"s + key + "' is not allowed in a configuration file ("s + path + ":"s + line + "); give it on the command line."s);
        auto value = [&](const yaml_node_t *n) {
            if(n->type != YAML_SCALAR_NODE)
                throw ConfigError(where + ": list items must be single values."s);
            if(isNull(n))
                throw ConfigError(where + ": needs a value."s);
            return scalarText(n);
        };
        if(v->type == YAML_SEQUENCE_NODE)
        {
            if(!o->repeatable)
                throw ConfigError(where + ": takes a single value, not a list."s);
            for(yaml_node_item_t *item = v->data.sequence.items.start; item < v->data.sequence.items.top; item++)
                b.apply(*o, value(yaml_document_get_node(&y.doc, *item)), false, where);
        }
        else if(v->type == YAML_MAPPING_NODE)
            throw ConfigError(where + ": expected a value, not a mapping."s);
        else
            b.apply(*o, value(v), false, where);
    }
}

std::string yamlQuote(const std::string &s)
{
    std::string out = "\"";
    for(char ch : s)
    {
        if(ch == '"' || ch == '\\') out += '\\';
        out += ch;
    }
    return out + "\"";
}

} // namespace

GwlbtunConfig GwlbtunConfig::fromCommandLine(int argc, char *argv[])
{
    // getopt_long tables from OPTIONS. Long-only options get values from 256 up, so they can't collide
    // with a short option.
    std::vector<struct option> longOpts;
    std::string shortOpts = "?";
    for(size_t i = 0; i < sizeof(OPTIONS) / sizeof(OPTIONS[0]); i++)
    {
        const auto &o = OPTIONS[i];
        longOpts.push_back({ o.name, o.takesValue ? required_argument : no_argument, nullptr, o.shortName ? o.shortName : (int)(256 + i) });
        if(o.shortName)
            shortOpts += std::string(1, o.shortName) + (o.takesValue ? ":" : "");
    }
    longOpts.push_back({ nullptr, 0, nullptr, 0 });
    // -x: the hex-dump option of earlier versions. Accepted and ignored, so existing unit files keep working.
    shortOpts += "x";

    // Collect the command line first, so the file it names (-f) can be applied before it.
    std::vector<std::pair<const OptionDef *, std::string>> cli;
    std::string file;
    Builder b;
    int ch;
    optind = 1;
    while((ch = getopt_long(argc, argv, shortOpts.c_str(), longOpts.data(), nullptr)) != -1)
    {
        if(ch == 'x')
        {
            b.c.resolveLog.emplace_back(LL_IMPORTANT, "-x is no longer used and is ignored; use --logging (for example --logging geneve=debugdetail) "s +
                                        "for packet hex dumps. It will be removed in a future version."s);
            continue;
        }
        const OptionDef *o = nullptr;
        if(ch >= 256 && (size_t)(ch - 256) < sizeof(OPTIONS) / sizeof(OPTIONS[0]))
            o = &OPTIONS[ch - 256];
        else
            for(const auto &d : OPTIONS)
                if(d.shortName == ch)
                    o = &d;
        if(!o)
        {
            b.c.helpRequested = true;   // '?': getopt has printed what was wrong
            continue;
        }
        if(std::string(o->name) == "config")
            file = optarg;
        else
            cli.emplace_back(o, o->takesValue ? std::string(optarg) : "true"s);
    }
    if(optind < argc)
        throw ConfigError("Unexpected argument '"s + argv[optind] + "'. Options start with - or --; see -h."s);

    if(!file.empty())
    {
        loadFile(b, file);
        b.c.configFile = file;
    }
    for(const auto &[o, v] : cli)
        b.apply(*o, v, true, o->shortName ? "-"s + o->shortName + "/--"s + o->name : "--"s + o->name);
    b.finish();
    return b.c;
}

std::string GwlbtunConfig::toYaml() const
{
    std::stringstream y;
    y << "# gwlbtun configuration (effective values";
    if(!configFile.empty())
        y << ", from " << configFile << " and the command line";
    y << "). Usable with -f.\n";
    auto line = [&y](const char *k, const std::string &v) { y << k << ": " << v << "\n"; };
    auto comment = [&y](const char *k, const std::string &v) { y << "# " << k << ": " << v << "\n"; };
    if(!createHook.empty()) line("cmdnew", yamlQuote(createHook)); else comment("cmdnew", "(none)");
    if(!destroyHook.empty()) line("cmddel", yamlQuote(destroyHook)); else comment("cmddel", "(none)");
    line("timeout", std::to_string(tunnelTimeout));
#ifndef NO_RETURN_TRAFFIC
    line("idle", std::to_string(tcpCacheTimeout));
#endif
    std::string port = std::to_string(healthPort);
    if(!healthAddress.empty())
        port = (healthAddress.find(':') != std::string::npos ? "["s + healthAddress + "]"s : healthAddress) + ":"s + port;
    else if(!healthInterface.empty())
        port = healthInterface + ":"s + port;
    line("port", yamlQuote(port));
    if(interfaces.empty())
        comment("interface", "(all interfaces)");
    else
    {
        std::string l = "[";
        for(size_t i = 0; i < interfaces.size(); i++)
            l += (i ? ", "s : ""s) + yamlQuote(interfaces[i]);
        line("interface", l + "]");
    }
    line("json", jsonHealth ? "true" : "false");
    line("simple", detailedHealth ? "false" : "true");
    if(!logging.empty()) line("logging", yamlQuote(logging)); else comment("logging", "(default)");
    if(!udpThreadsArg.empty()) line("udpthreads", udpThreadsArg);
    if(!udpAffinityArg.empty()) line("udpaffinity", yamlQuote(udpAffinityArg));
    if(udpThreadsArg.empty() && udpAffinityArg.empty())
        comment("udpaffinity", "nearest (default: one UDP thread per receive queue of each interface, pinned near its queue)");
    for(const auto &p : udpPlan)
    {
        std::string cores;
        for(size_t i = 0; i < p.cores.size(); i++)
            cores += (i ? ","s : ""s) + (p.cores[i] < 0 ? "-"s : std::to_string(p.cores[i]));
        y << "#   resolved for " << (p.name.empty() ? "all interfaces"s : p.name) << ": " << p.cores.size() << " UDP threads on CPUs ["
          << cores << "] (- = unpinned); " << (p.queueCpus.empty() ? "no receive queues found for "s + (p.detectedOn.empty() ? "the default-route interface"s : p.detectedOn)
                                                                  : p.detectedOn + " has "s + std::to_string(p.queueCpus.size()) + " receive queues"s)
          << (p.tiedToQueues() ? ", one thread tied to each" : "") << "\n";
    }
#ifndef NO_RETURN_TRAFFIC
    if(!tunThreadsArg.empty()) line("tunthreads", tunThreadsArg);
    if(!tunAffinityArg.empty()) line("tunaffinity", yamlQuote(tunAffinityArg));
    if(tunThreadsArg.empty() && tunAffinityArg.empty())
        comment("tunthreads", std::to_string(tunThreads.cfg.size()) + " (default: one per core, leaving room for the gwi- writers)"s);
    line("sndbuf", std::to_string(sndBufSizeMB));
#endif
    line("rcvbuf", std::to_string(rcvBufSizeMB));
    line("busypoll", std::to_string(busyPollUsec));
    if(reserveArgs.empty())
        comment("reserve", "(default) "s + reserveText(DEFAULT_RESERVE));
    else
    {
        y << "reserve:\n";
        for(const auto &r : reserveArgs)
            y << "  - " << yamlQuote(r) << "\n";
    }
    return y.str();
}

void GwlbtunConfig::logResults() const
{
    for(const auto &[level, text] : resolveLog)
        LOG(LS_UDP, (LogLevel)level, text);
    for(const auto &p : udpPlan)
    {
        const std::string where = p.name.empty() ? "all interfaces"s : "interface "s + p.name;
        if(p.tiedToQueues())
            LOG(LS_UDP, LL_IMPORTANT, "Receiving GENEVE on "s + where + " with "s + ts(p.cores.size()) + " UDP threads, one per receive queue of "s +
                p.detectedOn + " (each queue's packets go to its own thread on Linux 6.2+)."s);
        else
            LOG(LS_UDP, LL_IMPORTANT, "Receiving GENEVE on "s + where + " with "s + ts(p.cores.size()) + " UDP threads"s +
                (p.queueCpus.empty() ? " (no receive queues found for "s + (p.detectedOn.empty() ? "the default-route interface"s : p.detectedOn) + ")."s
                                     : "; "s + p.detectedOn + " has "s + ts(p.queueCpus.size()) + " receive queues."s));
    }
}

std::string GwlbtunConfig::helpText(const char *progname)
{
    const char *fmt =
            "AWS Gateway Load Balancer Tunnel Handler v%d.%d (%s)\n"
            "Built: %s\n"
            "Usage: %s [options]\n"
            "Example: %s\n"
            "\n"
            "  -h         Print this help\n"
            "  -f FILE    Read options from the YAML configuration file FILE (--config). Keys are the long option names,\n"
            "             e.g. 'udpthreads: 8' or 'interface: [ens5, ens6]'; flags take true or false. Options given on the\n"
            "             command line override the file (for -I and --reserve, they replace the file's list).\n"
            "  --show-config  Print the effective configuration as a YAML configuration file, and exit.\n"
            "  -c FILE    Command to execute when a new tunnel has been built. See below for arguments passed. (--cmdnew)\n"
            "  -r FILE    Command to execute when a tunnel times out and is about to be destroyed. See below for arguments passed. (--cmddel)\n"
            "  -t TIME    Minimum time in seconds between last packet seen and to consider the tunnel timed out. Set to 0 (the default) to never time out tunnels.\n"
            "             Note the actual time between last packet and the destroy call may be longer than this time. (--timeout)\n"
#ifndef NO_RETURN_TRAFFIC
            "  -i TIME    Idle timeout for the TCP flow cache. Set this to match what GWLB is configured for. Defaults to 350 seconds. UDP and Other flow caches use a fixed 120 second idle timeout. (--idle)\n"
#endif
            "  -p [ADDR:|IFNAME:]PORT  Listen to TCP port PORT and provide a health status report on it. By default it\n"
            "             listens on every address; prefix an address (10.0.1.5:80, [fd00::5]:80) or an interface name\n"
            "             (ens6:80) to listen only there. (--port)\n"
            "  -I IFNAME  Receive GENEVE traffic only on interface IFNAME. Repeat, or give a comma-separated list, for\n"
            "             several interfaces; each gets its own set of UDP receiver threads. Default: all interfaces.\n"
            "             Several gwlbtun processes can run in one network namespace if each uses -I with\n"
            "             different interfaces; a process without -I must be the only one. (--interface)\n"
            "  -j         For health check detailed statistics, output as JSON instead of text. (--json)\n"
            "  -s         Only return simple health check status (only the HTTP response code), instead of detailed statistics. (--simple)\n"
            "  -d         Enable debugging output. Short version of --logging all=debug. (--debug)\n"
            "\n"
            "Threading options:\n"
            "  --udpthreads NUM         Generate NUM threads for the UDP receiver.\n"
            "  --udpaffinity AFFIN      Generate threads for the UDP receiver, pinned to the cores listed. Takes precedence over udpthreads.\n"
            "  --udpaffinity nearest    The default: one UDP thread per receive queue, each pinned to the closest CPU that services\n"
            "                           no queue (its queue CPU's hyperthread sibling, else a CPU sharing its L3 cache, else its\n"
            "                           NUMA node). Threads with no such CPU, as when every CPU services a queue, are unpinned.\n"
#ifndef NO_RETURN_TRAFFIC
            "  --tunthreads NUM         Generate NUM threads for each tunnel processor.\n"
            "  --tunaffinity AFFIN      Generate threads for each tunnel processor, pinned to the cores listed. Takes precedence over tunthreads.\n"
#endif
            "\n"
            "Performance options:\n"
            "  --rcvbuf SIZE            Socket receive buffer size in megabytes (1 to 2047). Default is 128MB.\n"
            "                           For 50+ Gbps throughput, use 128-256MB. Requires net.core.rmem_max sysctl >= SIZE*1024*1024.\n"
            "  --busypoll USEC          Busy-poll the NIC up to USEC microseconds per receive (lower latency, higher CPU).\n"
            "                           Default 0 (disabled). Try 50 for latency-sensitive high packet rates.\n"
#ifndef NO_RETURN_TRAFFIC
            "  --sndbuf SIZE            Send buffer in megabytes for each raw socket returning traffic to GWLB (one per tunnel\n"
            "                           thread). Default %dMB.\n"
#endif
            "  --reserve RESV           Pre-size the flow caches to avoid rehash stalls under high flow counts.\n"
            "                           RESV is six comma-separated entry counts in order v4TCP,v4UDP,v4Other,v6TCP,v6UDP,v6Other\n"
            "                           (0 = don't pre-size that cache; at most %zu each). Default %s.\n"
            "                           Prefix with 'vpce-<id>:' to override a specific GWLB endpoint; repeat for several.\n"
            "                           e.g. --reserve 5000000,50000,50000,20,20,20 --reserve vpce-0abc...:2000000,2000000,1024,1024,1024,1024\n"
            "\n"
            "AFFIN arguments take a comma separated list of cores or range of cores, e.g. 1-2,4,7-8.\n"
            "By default (--udpaffinity nearest) gwlbtun starts one UDP thread per receive queue of each interface it receives\n"
            "on, pinned near its queue (or one unpinned thread per core, %d, if it can't find the queues). Whenever an interface\n"
            "has exactly one UDP thread per receive queue, gwlbtun asks the kernel (Linux 6.2+) to hand each queue's packets to\n"
            "its own thread: thread i gets queue i's packets.\n"
#ifndef NO_RETURN_TRAFFIC
            "--tunthreads defaults to one per core, less any needed to leave room for the gwi- writers: Linux allows 256 queues\n"
            "per tun interface, shared by the tunnel threads and the writers (at least one per receive queue). At most 255.\n"
#endif
            "\n"
            "Logging options:\n"
            "  --logging CONFIG         Set the logging configuration, as described below.\n"
#ifdef NO_RETURN_TRAFFIC
            "\nThis version of GWLBTun has been compiled with NO_RETURN_TRAFFIC defined.\n"
#endif
            "---------------------------------------------------------------------------------------------------------\n"
            "Hook scripts arguments:\n"
            "These arguments are provided when gwlbtun calls the hook scripts (the -c <FILE> and/or -r <FILE> command options).\n"
            "On gwlbtun startup, it will automatically create gwi-<X> and gwo-<X> interfaces upon seeing the first packet from a specific GWLBE, and the hook scripts are invoked when interfaces are created or destroyed. You should at least disable rpf_filter for the gwi-<X> tunnel interface with the hook scripts.\n"
            "The hook scripts will be called with the following arguments:\n"
            "1: The string 'CREATE' or 'DESTROY', depending on which operation is occurring.\n"
            "2: The interface name of the ingress interface (gwi-<X>).\n"
            "3: The interface name of the egress interface (gwo-<X>).  Packets can be sent out via in the ingress\n"
            "   as well, but having two different interfaces makes routing and iptables easier.\n"
            "4: The ID of the GWLB endpoint associated with this tunnel, as 17 hex digits without the 'vpce-' prefix\n"
            "   (e.g. '0123456789abcdef0' for endpoint vpce-0123456789abcdef0).\n"
            "\n"
            "The <X> in the interface name is replaced with the GWLB endpoint ID encoded in base 60 (to fit inside the\n"
            "15 character device name limit). With -I, <X> is instead a hash of the endpoint ID and the -I interface\n"
            "list, so processes serving the same endpoint on different interfaces get different devices.\n"
            "---------------------------------------------------------------------------------------------------------\n";
    const std::string reserveDefault = reserveText(DEFAULT_RESERVE);
    auto format = [&](char *buf, size_t len) {
        return snprintf(buf, len, fmt, VERSION_MAJOR, VERSION_MINOR, GIT_DESCRIBE, BUILD_TIMESTAMP, progname, progname,
#ifndef NO_RETURN_TRAFFIC
                        DEFAULT_SNDBUF_MB,
#endif
                        MAX_RESERVE, reserveDefault.c_str(), numCores());
    };
    int n = format(nullptr, 0);
    std::string out(n > 0 ? (size_t)n : 0, '\0');
    if(n > 0)
        format(out.data(), out.size() + 1);
    return out + Logger::help();
}
