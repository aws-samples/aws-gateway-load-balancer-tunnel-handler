// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWLBTUN_GWLBTUNCONFIG_H
#define GWLBTUN_GWLBTUNCONFIG_H

#include "utils.h"   // ThreadConfig

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
};

#endif //GWLBTUN_GWLBTUNCONFIG_H
