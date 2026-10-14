// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWLBTUN_GWLBTUNCONFIG_H
#define GWLBTUN_GWLBTUNCONFIG_H

#include "utils.h"   // ThreadConfig, gwlbeid_t
#include <array>
#include <cstddef>
#include <stdexcept>
#include <unordered_map>
#include <string>
#include <utility>
#include <vector>

// The UDP receiver layout for one interface gwlbtun receives on, as GwlbtunConfig resolved it.
struct UdpInterfacePlan {
    std::string name;             // -I interface; empty = all interfaces
    std::string detectedOn;       // interface whose receive queues were read (the default-route one if name is empty)
    std::vector<int> queueCpus;   // CPU servicing each receive queue, in queue order; empty if none were found
    std::vector<int> cores;       // one entry per UDP thread: the CPU to pin it to, or -1 for unpinned
    // With exactly one thread per receive queue, thread i's socket is tied to queue i (SO_INCOMING_CPU).
    bool tiedToQueues() const { return !queueCpus.empty() && cores.size() == queueCpus.size(); }
};

/**
 * Runtime configuration for gwlbtun, from the command line and an optional YAML configuration file
 * (-f FILE). Built once by fromCommandLine() and then treated as immutable for the lifetime of the
 * process: main() uses the process-level settings, and GeneveHandler keeps a const copy.
 *
 * Every option has the same name in the file as its long command-line form (`udpaffinity: 32-95` is
 * `--udpaffinity 32-95`). Command-line values override the file; for options that can be given more
 * than once (interface, reserve), any command-line occurrence replaces the file's list.
 */
struct GwlbtunConfig {
    // --- Data path (GeneveHandler) ---
    int tunnelTimeout = 0;          // -t: ENI idle-destroy timeout (seconds; 0 = never reap)
    int tcpCacheTimeout = 350;      // -i: TCP flow-cache idle timeout (seconds)
    int udpCacheTimeout = 120;      // UDP flow-cache idle timeout (seconds, fixed)
    int otherCacheTimeout = 120;    // Other-protocol flow-cache idle timeout (seconds, fixed)
    std::vector<UdpInterfacePlan> udpPlan;   // UDP receiver threads per interface, from --udpthreads/--udpaffinity and the host's queues
    size_t maxRxQueues = 0;         // most receive queues found on any interface in udpPlan
    ThreadConfig tunThreads;        // tunnel threads/affinity per tun interface, from --tunthreads/--tunaffinity
    int rcvBufSizeMB = 128;         // --rcvbuf: UDP socket receive buffer size (MB)
    int busyPollUsec = 0;           // --busypoll: SO_BUSY_POLL microseconds per receive (0 = disabled)
    std::vector<std::string> interfaces;   // -I: receive GENEVE only on these (sorted, unique); empty = all interfaces
    bool udpAffinityNearest = true;    // --udpaffinity nearest (the default): one per RX queue, pinned next to the queue's CPU
    int sndBufSizeMB = DEFAULT_SNDBUF_MB;   // --sndbuf: raw send socket buffer (MB) for traffic back to GWLB

    // Flow-cache reserve (entries) per protocol cache, in health-output order:
    // [v4TCP, v4UDP, v4Other, v6TCP, v6UDP, v6Other]. 0 = don't pre-size that cache.
    static constexpr std::array<std::size_t, 6> DEFAULT_RESERVE{16384, 16384, 1024, 1024, 1024, 1024};
    std::array<std::size_t, 6> defaultReserve = DEFAULT_RESERVE;
    // Optional per-GWLB-endpoint overrides, keyed by endpoint (vpce-) id.
    std::unordered_map<gwlbeid_t, std::array<std::size_t, 6>> perEndpointReserve;

    // Reserve vector for a given endpoint: its override if present, else the default.
    const std::array<std::size_t, 6>& reserveFor(gwlbeid_t id) const {
        auto it = perEndpointReserve.find(id);
        return it != perEndpointReserve.end() ? it->second : defaultReserve;
    }

    // --- Process (main) ---
    std::string createHook;         // -c: run when an endpoint's interfaces are created
    std::string destroyHook;        // -r: run before an endpoint's interfaces are destroyed
    int healthPort = 0;             // -p: health check port; 0 = no health listener
    std::string healthAddress;      // -p ADDR:PORT; empty = all addresses
    std::string healthInterface;    // -p IFNAME:PORT; empty = all interfaces
    bool detailedHealth = true;     // -s/--simple clears: status code only
    bool jsonHealth = false;        // -j/--json
    std::string logging;            // --logging (-d = all=debug)
    std::string configFile;         // -f/--config, if one was read

    size_t udpThreadCount() const { size_t n = 0; for(const auto &p : udpPlan) n += p.cores.size(); return n; }

    // As given, for --show-config (the resolved forms are udpPlan/tunThreads above).
    std::string udpThreadsArg, udpAffinityArg, tunThreadsArg, tunAffinityArg;
    std::vector<std::string> reserveArgs;

    // What main() should do instead of running, if anything.
    bool helpRequested = false;     // -h/--help, or an unknown command-line option
    bool showConfigRequested = false;   // --show-config

    /**
     * Build the configuration from the command line and the file it names with -f, if any.
     * @throws ConfigError with a message for the user, for any invalid option, value or file.
     */
    static GwlbtunConfig fromCommandLine(int argc, char *argv[]);
    // The -h text.
    static std::string helpText(const char *progname);
    // The effective configuration, as a YAML configuration file.
    std::string toYaml() const;
    // Log what resolving the configuration decided (the UDP thread layout). The configuration is built
    // before the logger exists, so main() calls this once the logger is running.
    void logResults() const;

    // Messages for logResults(): (log level, text).
    std::vector<std::pair<int, std::string>> resolveLog;
};

// An invalid option, value or configuration file. what() is the message to show the user.
class ConfigError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Number of CPUs this process may run on.
int numCores();

#endif //GWLBTUN_GWLBTUNCONFIG_H
