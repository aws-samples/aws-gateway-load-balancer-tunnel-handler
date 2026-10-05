// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWLBTUN_GWLBTUNCONFIG_H
#define GWLBTUN_GWLBTUNCONFIG_H

#include "utils.h"   // ThreadConfig, gwlbeid_t
#include <array>
#include <cstddef>
#include <unordered_map>

/**
 * Runtime configuration for gwlbtun. Populated once from the command line in
 * main() and then treated as immutable for the lifetime of the process - it is
 * passed as a const GwlbtunConfig to GeneveHandler, which keeps a const copy.
 * Centralizes settings that were previously threaded through as individual
 * constructor arguments; new tunables (e.g. flow-cache reserve) are added here.
 */
struct GwlbtunConfig {
    int tunnelTimeout = 0;          // ENI idle-destroy timeout (seconds; 0 = never reap)
    int tcpCacheTimeout = 350;      // TCP flow-cache idle timeout (seconds)
    int udpCacheTimeout = 120;      // UDP flow-cache idle timeout (seconds)
    int otherCacheTimeout = 120;    // Other-protocol flow-cache idle timeout (seconds)
    ThreadConfig udpThreads;        // UDP ingress receiver thread/affinity config
    ThreadConfig tunThreads;        // TUN return-path thread/affinity config
    int rcvBufSizeMB = 128;         // UDP socket receive buffer size (MB)
    int busyPollUsec = 0;           // SO_BUSY_POLL microseconds per receive (0 = disabled)

    // Flow-cache reserve (entries) per protocol cache, in health-output order:
    // [v4TCP, v4UDP, v4Other, v6TCP, v6UDP, v6Other]. 0 = don't pre-size that cache.
    std::array<std::size_t, 6> defaultReserve{16384, 16384, 1024, 1024, 1024, 1024};
    // Optional per-GWLB-endpoint overrides, keyed by endpoint (vpce-) id.
    std::unordered_map<gwlbeid_t, std::array<std::size_t, 6>> perEndpointReserve;

    // Reserve vector for a given endpoint: its override if present, else the default.
    const std::array<std::size_t, 6>& reserveFor(gwlbeid_t id) const {
        auto it = perEndpointReserve.find(id);
        return it != perEndpointReserve.end() ? it->second : defaultReserve;
    }
};

#endif //GWLBTUN_GWLBTUNCONFIG_H
