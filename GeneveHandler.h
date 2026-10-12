// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWLBTUN_GENEVEHANDLER_H
#define GWLBTUN_GENEVEHANDLER_H

#include <array>
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <boost/unordered/concurrent_flat_map.hpp>
#include "UDPPacketReceiver.h"
#include "TunInterface.h"
#include "GenevePacket.h"
#include "PacketHeaderV4.h"
#include "PacketHeaderV6.h"
#include "FlowCache.h"
#include "utils.h"
#include "GwlbtunConfig.h"
#include "HealthCheck.h"
#include "HookScripts.h"

constexpr uint16_t GENEVE_PORT = 6081;   // UDP port number that GENEVE uses by standard

// Data we need to send with the packet back to GWLB: the GENEVE header and the outer addresses and ports the
// flow arrived with, and the interface it arrived on. The flow caches' value type.
class GwlbData {
public:
    GwlbData(GeneveHeader header, struct in_addr srcAddr, uint16_t srcPort, struct in_addr dstAddr, uint16_t dstPort, int ifindex) :
        header(std::move(header)), srcAddr(srcAddr), dstAddr(dstAddr), srcPort(srcPort), dstPort(dstPort), ifindex(ifindex) {}

    GeneveHeader header;   // Copy of the Geneve header to put back on packets
    struct in_addr srcAddr;
    struct in_addr dstAddr;
    uint16_t srcPort;
    uint16_t dstPort;
    int ifindex;           // Interface the GENEVE packet arrived on; replies are sent out of it.

    bool operator==(const GwlbData& o) const {
        return srcPort == o.srcPort && dstPort == o.dstPort && ifindex == o.ifindex &&
               srcAddr.s_addr == o.srcAddr.s_addr && dstAddr.s_addr == o.dstAddr.s_addr &&
               header == o.header;
    }

    std::string text() const;
};

// A snapshot of one GWLB endpoint's handler, for the health check.
struct GeneveHandlerENIHealthCheck {
    bool healthy;
    std::string eniStr;
    uint64_t pktsOut, bytesOut, pktsDropped;
    std::chrono::steady_clock::time_point lastPacketOut;
    TunInterfaceHealthCheck tunnelIn;
#ifndef NO_RETURN_TRAFFIC
    TunInterfaceHealthCheck tunnelOut;
    std::array<FlowCacheHealthCheck, 3> v4Caches;   // TCP, UDP, Other
    std::array<FlowCacheHealthCheck, 3> v6Caches;
#endif

    std::string output_str() const;
    json output_json() const;
};

/**
 * Everything gwlbtun holds for one GWLB endpoint: its gwi-/gwo- interfaces and their threads, the flow caches,
 * and the CREATE/DESTROY hook pair. Constructing it builds all of that and runs CREATE; destroying it runs
 * DESTROY and takes it all down again. If construction fails part-way, the members built so far are destroyed
 * in reverse order (stopping any threads already started) and no hook runs.
 */
class GeneveHandlerENI {
public:
    // cfg and hookScripts are only read during construction (the handler keeps neither): GeneveHandler's copy
    // of the configuration is destroyed before its endpoints are.
    GeneveHandlerENI(gwlbeid_t eni, const GwlbtunConfig &cfg, const HookScripts &hookScripts);
    GeneveHandlerENI(const GeneveHandlerENI &) = delete;
    GeneveHandlerENI &operator=(const GeneveHandlerENI &) = delete;
    // A decapsulated packet from GWLB (pkt is the whole GENEVE payload; gd describes its header).
    void udpReceiverCallback(const GwlbData &gd, const unsigned char *pkt, ssize_t pktlen) __attribute__((hot));
    // A packet read from gwi-/gwo-, to send back to GWLB.
    void tunReceiverCallback(unsigned char *pktbuf, ssize_t pktlen) __attribute__((hot));
    GeneveHandlerENIHealthCheck check() const;
    void sweepCaches();      // evict expired flow-cache entries (off the health path)
    bool hasGoneIdle(int timeout) const;

    // File descriptors one endpoint holds, for the open-file limit check at startup.
    static size_t fdsPerEndpoint(const GwlbtunConfig &cfg);

    // Set by the reaper when it removes this handler from the endpoint map. Packet threads that
    // still reach it through their thread-local cache treat it as gone and take the slow path,
    // which either reuses it (traffic came back before teardown) or drops their packets until teardown
    // has finished.
    std::atomic<bool> retired{false};

private:
    // ORDER MATTERS. Members are constructed top to bottom and destroyed bottom to top (also when the
    // constructor throws part-way), and that order is what makes start-up and teardown safe:
    //   - The flow caches, gwi- writers and shared send socket come before the tunnels: tunnel threads use
    //     them (tunReceiverCallback), so they must exist before those threads start and outlive them.
    //   - gwiWriters creates gwi-; tunnelIn then attaches its reader queues to it.
    //   - tunnelOut creates gwo-.
    //   - hooks is LAST: CREATE runs once both interfaces exist, DESTROY runs first on teardown, while
    //     both still exist and before any thread stops, and neither runs if construction failed.
    const gwlbeid_t eni;
    const std::string eniStr;

    const std::string devInName;
    const std::string devOutName;

    // Hot per-packet counters on their own cache line, so these writes don't
    // invalidate lines holding read-mostly fields touched on every packet
    // (sendingSock, flow caches) - i.e. avoid false sharing.
    struct alignas(64) HotCounters {
        std::atomic<uint64_t> pktsOut{0};
        std::atomic<uint64_t> bytesOut{0};
        std::atomic<uint64_t> pktsDropped{0};
        std::atomic<std::chrono::steady_clock::time_point> lastPacketOut{std::chrono::steady_clock::now()};
        uint32_t lastPacketOutCoarse = UINT32_MAX;   // coarseTime() of the last lastPacketOut update (none yet); only its own thread uses it
    };
    // One slot per UDP receiver thread (plus one for any other caller), each on its own cache line,
    // so the per-packet counter updates never bounce a line between cores. Readers sum the slots.
    const size_t hotSlots;
    std::unique_ptr<HotCounters[]> hot;
    HotCounters &hotSlot() { return hot[std::min((size_t)t_udpThreadIndex, hotSlots - 1)]; }   // -1 (not a UDP thread) wraps to the last slot
    void writeToTun(const unsigned char *pkt, ssize_t pktlen) __attribute__((hot));
    void countDrop() { hotSlot().pktsDropped.fetch_add(1, std::memory_order_relaxed); }

#ifndef NO_RETURN_TRAFFIC
    ProtocolFlowCache<PacketHeaderV4, GwlbData> v4Flows;
    ProtocolFlowCache<PacketHeaderV6, GwlbData> v6Flows;
#endif

    // Sockets to write to our associated tunnel (gwi-); the first creates the device. See GWI_WRITER_SHARE
    // in utils.h and makeWriters().
    std::vector<TunSocket> gwiWriters;
    static std::vector<TunSocket> makeWriters(const std::string &devname, const std::string &eniStr, size_t nWriters);

#ifndef NO_RETURN_TRAFFIC
    // Raw socket for sending traffic back to GWLB, used by tunnel threads that couldn't open their own.
    UniqueFd sendingSock;
#endif

    TunInterface tunnelIn;    // readers on gwi- (created by gwiWriters)
#ifndef NO_RETURN_TRAFFIC
    TunInterface tunnelOut;   // creates gwo-
#endif

    HookScripts::Endpoint hooks;   // LAST
};

// A snapshot of the whole GeneveHandler, for the health check.
class GeneveHandlerHealthCheck {
public:
    GeneveHandlerHealthCheck(bool healthy, UDPPacketReceiverHealthCheck udp, std::vector<GeneveHandlerENIHealthCheck> enis) :
        healthy(healthy), udp(std::move(udp)), enis(std::move(enis)) {}
    std::string output_str() const;
    json output_json() const;
    bool isHealthy() const { return healthy; }

private:
    bool healthy;
    UDPPacketReceiverHealthCheck udp;
    std::vector<GeneveHandlerENIHealthCheck> enis;
};

class GeneveHandler {
    // There is one GeneveHandler per process: the UDP threads' endpoint caches (tlsEniCache), the
    // device-name scope and the raw-socket buffer size are process-wide, so a second one would share and
    // corrupt them. Declared first, so it's built before anything else (constructing a second handler throws
    // at once) and released last. Its constructor also applies the process-wide settings from the
    // configuration, which must be in place before the first UDP thread starts.
    struct OnlyInstance {
        explicit OnlyInstance(const GwlbtunConfig &cfg);
        ~OnlyInstance();
        OnlyInstance(const OnlyInstance &) = delete;
        OnlyInstance &operator=(const OnlyInstance &) = delete;
        static std::atomic<bool> exists;
    } onlyInstance;

public:
    // Starts the UDP receiver threads; endpoints are then built as their traffic arrives. hookScripts must
    // outlive this object.
    GeneveHandler(const GwlbtunConfig& cfg, const HookScripts &hookScripts);
    // Not copyable or movable: UDP threads and endpoint handlers hold pointers to this object.
    GeneveHandler(const GeneveHandler &) = delete;
    GeneveHandler &operator=(const GeneveHandler &) = delete;
    GeneveHandler(GeneveHandler &&) = delete;
    GeneveHandler &operator=(GeneveHandler &&) = delete;
    void udpReceiverCallback(unsigned char *pkt, ssize_t pktlen, struct in_addr *srcAddr, uint16_t srcPort, struct in_addr *dstAddr, uint16_t dstPort, int ifindex);
    GeneveHandlerHealthCheck check() const;
    void sweep();            // evict expired flow entries + reap idle ENIs (periodic)

private:
    // Endpoint lifecycle. lifecycle->mutex orders the packet slow path setting an endpoint up against the
    // reaper tearing one down, so a new handler for an endpoint (same gwi-/gwo- names, same hooks) is never
    // built while another for it is being built or torn down. It guards `destroying` and the containers
    // below. It's held only to read and update that state: never while a handler is built or destroyed,
    // and never while dropping an endpoint reference (the deleter takes it).
    //   creating:   being built, outside the lock, by one UDP thread (see CreatingReservation); packets
    //               for it on other threads are dropped.
    //   retiring:   removed from eniHandlers, not yet destroyed; reused if traffic returns first.
    //   destroying: being destroyed; packets for these endpoints are dropped. Cleared by the endpoint's
    //               deleter once the handler is gone, on whichever thread released it last.
    //   createRetryAfter: endpoints whose handler failed to set up, and when to try again.
    // `lifecycle` is shared with every endpoint's deleter, so it outlives any endpoint, and is declared
    // before everything that holds endpoints.
    struct EndpointLifecycle {
        std::mutex mutex;
        std::unordered_set<gwlbeid_t> destroying;
    };
    const std::shared_ptr<EndpointLifecycle> lifecycle;

    boost::concurrent_flat_map<gwlbeid_t, std::shared_ptr<GeneveHandlerENI>> eniHandlers;
    const HookScripts &hookScripts;
    const GwlbtunConfig config;

    std::unordered_set<gwlbeid_t> creating;
    std::unordered_map<gwlbeid_t, std::shared_ptr<GeneveHandlerENI>> retiring;
    std::unordered_map<gwlbeid_t, std::chrono::steady_clock::time_point> createRetryAfter;

    // Holds an endpoint id in `creating` while its handler is built. Construct it with lifecycle->mutex
    // held; its destructor takes the mutex and releases the id, however the build ends.
    class CreatingReservation {
    public:
        CreatingReservation(GeneveHandler &gh, gwlbeid_t id);
        ~CreatingReservation();
        CreatingReservation(const CreatingReservation &) = delete;
        CreatingReservation &operator=(const CreatingReservation &) = delete;
    private:
        GeneveHandler &gh;
        const gwlbeid_t id;
    };

    // Deletes an endpoint handler, then clears its id from lifecycle->destroying.
    struct EndpointDeleter {
        std::shared_ptr<EndpointLifecycle> lifecycle;
        gwlbeid_t id;
        void operator()(GeneveHandlerENI *e) const noexcept;
    };
    // Build an endpoint's handler (its interfaces, threads and CREATE hook). Throws if it can't be set up.
    std::shared_ptr<GeneveHandlerENI> makeEndpoint(gwlbeid_t id);

    // ORDER MATTERS: LAST. Its UDP threads use every member above (they create and look up endpoints), so it's
    // constructed last, once they all exist, and destroyed first: no UDP thread is left running when the
    // endpoints above are destroyed.
    UDPPacketReceiver udpRcvr;

    // Thread-local fast-path cache: each UDP thread's weak references to endpoint handlers, by endpoint ID.
    // An entry also holds a strong reference for the rest of the current recvmmsg() batch, so
    // weak_ptr::lock() -- an atomic on the endpoint's shared control block, written by every UDP
    // thread -- runs once per batch instead of once per packet. The UDP thread drops all held
    // references at the end of each batch (udpBatchEnd), so teardown is not delayed.
    struct TlsEniEntry {
        std::weak_ptr<GeneveHandlerENI> weak;
        std::shared_ptr<GeneveHandlerENI> held;
        // After a packet for this endpoint was dropped (being set up or torn down, or waiting to retry a
        // failed setup), drop this thread's packets for it without taking the lifecycle mutex until then.
        std::chrono::steady_clock::time_point skipUntil{};
    };
    static thread_local std::unordered_map<gwlbeid_t, TlsEniEntry> tlsEniCache;
    static thread_local std::vector<TlsEniEntry *> tlsHeld;
    // Passed to the UDP receiver as its end-of-batch callback: drops the references held in tlsHeld.
    static void udpBatchEnd();
};

std::string devname_make(gwlbeid_t eni, bool inbound);
void setDevnameScope(const std::vector<std::string> &interfaces);

#endif //GWLBTUN_GENEVEHANDLER_H
