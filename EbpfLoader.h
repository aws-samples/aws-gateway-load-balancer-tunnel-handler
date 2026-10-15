// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWLBTUN_EBPFLOADER_H
#define GWLBTUN_EBPFLOADER_H

#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>
#include "EbpfHelpers.h"
#include "HealthCheck.h"

struct GwlbtunConfig;
struct bpf_object;
struct bpf_program;
struct bpf_link;

// A snapshot of the eBPF datapath, for the health check.
struct EbpfHealthCheck {
    std::vector<std::string> ingressInterfaces;   // where the ingress program is attached
    std::string mirredInterface;                  // where the egress action sends; empty if egress isn't used
    std::array<uint64_t, ING_CODES_COUNT> ingress{};
    std::array<uint64_t, EGR_CODES_COUNT> egress{};
    uint64_t ingressMapFull = 0, egressMapFull = 0;   // flows that didn't fit in the maps
    uint32_t ingressMapSize = 0, egressV4MapSize = 0, egressV6MapSize = 0;

    std::string output_str() const;
    json output_json() const;
};

/**
 * gwlbtun's eBPF datapath (-e): loads gwlbtun-ebpf.o (see EbpfHelpers.c), attaches the ingress program to the
 * interfaces gwlbtun receives GENEVE on, attaches the egress action to each endpoint's gwo- interface, and gives
 * gwlbtun access to the maps. Constructing it loads and attaches everything, and throws std::runtime_error if
 * that fails; destroying it detaches the ingress program (the egress actions go with their gwo- interfaces).
 *
 * The ingress program is attached with tcx (Linux 6.6 and later), as a link owned by this process: if gwlbtun
 * exits for any reason, including being killed, the kernel detaches it, so a program that would deliver
 * packets to interfaces that no longer exist is never left behind.
 *
 * Without eBPF support compiled in (ENABLE_EBPF), the constructor throws; GwlbtunConfig rejects -e first.
 *
 * Thread safety: the map functions and check() can be called from any thread; attachEgress() serialises itself.
 */
class EbpfLoader {
public:
    explicit EbpfLoader(const GwlbtunConfig &cfg);
    ~EbpfLoader();
    EbpfLoader(const EbpfLoader &) = delete;
    EbpfLoader &operator=(const EbpfLoader &) = delete;

    // Whether gwo- interfaces get the egress action (not in NO_RETURN_TRAFFIC builds).
    bool egressEnabled() const { return egressOn; }
    // Whether the ingress program is attached to this interface.
    bool handlesIngress(int ifindex) const;
    // The interface the egress action sends to (0 without egress).
    uint32_t mirredIfindex() const { return mirredIfindexValue; }
    // An interface's index, 0 if there's none by that name.
    static uint32_t ifindex(const std::string &name);

    // Attach the egress action to a gwo- interface. Returns false (logged) if it couldn't be attached, in which
    // case that endpoint's return traffic stays on the userspace path.
    bool attachEgress(const std::string &gwoName);

    enum class InsertResult { Inserted, Exists, Full, Failed };
    // Add an ingress entry if there's none for the key yet.
    InsertResult insertIngress(const EbpfIngressKey &key, const EbpfIngressValue &value);
    bool lookupIngress(const EbpfIngressKey &key, EbpfIngressValue &value) const;
    void removeIngress(const EbpfIngressKey &key);
    // Add or replace an egress entry. Returns false (counted, logged) if it couldn't be stored.
    bool updateEgress(const EbpfEgressKeyV4 &key, const EbpfEgressValue &value);
    bool updateEgress(const EbpfEgressKeyV6 &key, const EbpfEgressValue &value);
    bool lookupEgress(const EbpfEgressKeyV4 &key, EbpfEgressValue &value) const;
    bool lookupEgress(const EbpfEgressKeyV6 &key, EbpfEgressValue &value) const;
    void removeEgress(const EbpfEgressKeyV4 &key);
    void removeEgress(const EbpfEgressKeyV6 &key);

    EbpfHealthCheck check() const;

    // CLOCK_MONOTONIC_COARSE in nanoseconds: the clock the programs stamp entries with.
    static uint64_t nowNs();

private:
    struct bpf_object *obj = nullptr;
    struct bpf_program *egressProg = nullptr;
    std::vector<struct bpf_link *> ingressLinks;
    std::vector<std::string> ingressInterfaces;
    std::vector<uint32_t> ingressIfindexes;
    std::string mirredInterface;
    uint32_t mirredIfindexValue = 0;
    bool egressOn = false;

    int ingressMapFd = -1, egressV4MapFd = -1, egressV6MapFd = -1, ingressCountersFd = -1, egressCountersFd = -1;
    uint32_t ingressMapSize = 0, egressV4MapSize = 0, egressV6MapSize = 0;

    mutable std::atomic<uint64_t> ingressMapFull{0}, egressMapFull{0};
    std::mutex egressAttachMutex;
    unsigned egressPinCount = 0;   // guarded by egressAttachMutex

    void load(const GwlbtunConfig &cfg);
    void close() noexcept;
    void noteUpdateFailure(std::atomic<uint64_t> &fullCount, int err, const char *which) const;
};

#endif // GWLBTUN_EBPFLOADER_H
