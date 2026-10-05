// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWLBTUN_GENEVEHANDLER_H
#define GWLBTUN_GENEVEHANDLER_H

#include <future>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <atomic>
#include "UDPPacketReceiver.h"
#include "TunInterface.h"
#include "GenevePacket.h"
#include "PacketHeaderV4.h"
#include "PacketHeaderV6.h"
#include "FlowCache.h"
#include "utils.h"
#include "GwlbtunConfig.h"
#include <linux/if.h>     // Needed for IFNAMSIZ define
#include <boost/unordered/concurrent_flat_map.hpp>
#include "HealthCheck.h"
#include "EbpfLoader.h"

typedef std::function<void(std::string inInt, std::string outInt, gwlbeid_t eniId)> ghCallback;

// Data we need to send with the packet back to GWLB, including the Geneve header and outer UDP header information.
class GwlbData {
public:
    GwlbData();
    GwlbData(GeneveHeader header, struct in_addr *srcAddr, uint16_t srcPort, struct in_addr *dstAddr, uint16_t dstPort);

    // Elements are arranged so that when doing sorting/searching, we get entropy early. This gives a slight
    // improvement to the lookup time.
    GeneveHeader header;   // Copy of the Geneve header to put back on packets
    struct in_addr srcAddr;
    struct in_addr dstAddr;
    uint16_t srcPort;
    uint16_t dstPort;

    bool operator==(const GwlbData& o) const {
        return srcPort == o.srcPort && dstPort == o.dstPort &&
               srcAddr.s_addr == o.srcAddr.s_addr && dstAddr.s_addr == o.dstAddr.s_addr &&
               header == o.header;
    }

    std::string text();
};


/**
 * For each ENI (GWLBe) that is detected, a copy of GeneveHandlerENI is created.
 */

class GeneveHandlerENIHealthCheck : public HealthCheck {
public:
    GeneveHandlerENIHealthCheck(bool, std::string, uint64_t pktsOut, uint64_t bytesOut, uint64_t pktsDropped, std::chrono::steady_clock::time_point lastPacketOut, TunInterfaceHealthCheck
#ifndef NO_RETURN_TRAFFIC
                                , TunInterfaceHealthCheck,
                                FlowCacheHealthCheck, FlowCacheHealthCheck, FlowCacheHealthCheck,
                                FlowCacheHealthCheck, FlowCacheHealthCheck, FlowCacheHealthCheck
#endif
                                , uint64_t ebpfRepunts = 0, uint64_t ebpfLateRepunts = 0
                                );
    std::string output_str() ;
    json output_json();
    bool isHealthy() const { return healthy; }

private:
    bool healthy;
    std::string eniStr;
    uint64_t pktsOut, bytesOut, pktsDropped, ebpfRepunts, ebpfLateRepunts;
    std::chrono::steady_clock::time_point lastPacketOut;

    TunInterfaceHealthCheck tunnelIn;
#ifndef NO_RETURN_TRAFFIC
    TunInterfaceHealthCheck tunnelOut;
    FlowCacheHealthCheck v4FlowCacheTcp;
    FlowCacheHealthCheck v4FlowCacheUdp;
    FlowCacheHealthCheck v4FlowCacheOther;
    FlowCacheHealthCheck v6FlowCacheTcp;
    FlowCacheHealthCheck v6FlowCacheUdp;
    FlowCacheHealthCheck v6FlowCacheOther;
#endif
};

// Per-flow eBPF state GeneveHandlerENI tracks so the GC sweep can age and remove map
// entries. Stores the forward egress key (reverse is derived by swapping); the ingress
// key is just {eni, cookie}. isV4 selects which egress key/map applies.
struct BpfFlow {
    bool isV4;
    EbpfEgressMapKeyV4 v4;
    EbpfEgressMapKeyV6 v6;
    std::chrono::steady_clock::time_point learnedAt;   // when this cookie was first learned; used to tell a
                                                       // benign warm-up-tail punt from a real established-flow re-punt
};

class GeneveHandlerENI {
public:
    GeneveHandlerENI(gwlbeid_t eni, int tcpCacheTimeout, int udpCacheTimeout, int otherCacheTimeout, const ThreadConfig& tunThreadConfig, const std::array<std::size_t,6>& reserve, ghCallback createCallback, ghCallback destroyCallback, EbpfLoader* ebpfLoader);
    ~GeneveHandlerENI();
    void udpReceiverCallback(GwlbData gd, uint32_t flowCookie, unsigned char *pkt, ssize_t pktlen) __attribute__((hot));
    void tunReceiverCallback(unsigned char *pktbuf, ssize_t pktlen) __attribute__((hot));
    GeneveHandlerENIHealthCheck check();
    void sweepCaches();      // evict expired flow-cache entries (off the health path)
    bool hasGoneIdle(int timeout);

private:
    const gwlbeid_t eni;
    const std::string eniStr;
    int tcpCacheTimeout, udpCacheTimeout, otherCacheTimeout;

    const std::string devInName;
    const std::string devOutName;

    std::unique_ptr<TunInterface> tunnelIn;
#ifndef NO_RETURN_TRAFFIC
    std::unique_ptr<TunInterface> tunnelOut;

    FlowCache<PacketHeaderV4, GwlbData> gwlbV4CookiesTcp;
    FlowCache<PacketHeaderV4, GwlbData> gwlbV4CookiesUdp;
    FlowCache<PacketHeaderV4, GwlbData> gwlbV4CookiesOther;
    FlowCache<PacketHeaderV6, GwlbData> gwlbV6CookiesTcp;
    FlowCache<PacketHeaderV6, GwlbData> gwlbV6CookiesUdp;
    FlowCache<PacketHeaderV6, GwlbData> gwlbV6CookiesOther;
#endif

    // Socket to write to our associated tunnel
    TunSocket gwiWriter;
    // Hot per-packet counters on their own cache line, so these writes don't
    // invalidate lines holding read-mostly fields touched on every packet
    // (sendingSock, flow caches, callbacks) - i.e. avoid false sharing.
    struct alignas(64) HotCounters {
        std::atomic<uint64_t> pktsOut{0};
        std::atomic<uint64_t> bytesOut{0};
        std::atomic<uint64_t> pktsDropped{0};
        std::atomic<std::chrono::steady_clock::time_point> lastPacketOut{std::chrono::steady_clock::now()};
    };
    HotCounters hot;
    void writeToTun(const unsigned char *pkt, ssize_t pktlen) __attribute__((hot));

    // Socket used by all threads for sending
    int sendingSock;
    const ghCallback createCallback;
    const ghCallback destroyCallback;

    // eBPF acceleration. ebpfLoader is non-owning (it lives on GeneveHandler).
    EbpfLoader* ebpfLoader;
    unsigned int gwiIfIndex{0};                        // ifindex of this ENI's gwi interface (0 = unresolved)
    unsigned int gwoIfIndex{0};                        // ifindex of this ENI's gwo interface (0 = unresolved)
    boost::concurrent_flat_map<uint32_t, BpfFlow> trackedFlows;  // learned flows, keyed by flow cookie
    std::atomic<uint64_t> lastBpfActivityNs{0};        // newest map liveness seen by the last GC sweep
    // Re-punt diagnostics (slow path only). A packet reaches userspace for a cookie that
    // is already learned either as the benign tail of first-packet learning (counted in
    // ebpfRepunts) or, if it happens well after the flow was learned, because the in-kernel
    // entry was lost/evicted while the flow was still active (ebpfLateRepunts -- the alarm:
    // a non-zero value here means established flows are falling back to the slow path).
    std::atomic<uint64_t> ebpfRepunts{0};
    std::atomic<uint64_t> ebpfLateRepunts{0};
    bool ebpfTrackNewFlow(uint32_t flowCookie, BpfFlow& flow);   // true if newly learned; else counts the re-punt
    void ebpfInsertIngress(uint32_t flowCookie);                                                      // ingress map insert
    void ebpfLearnV4(uint32_t flowCookie, const GwlbData& gd, const unsigned char* inner, ssize_t innerLen);  // gate + ingress + egress
    void ebpfLearnV6(uint32_t flowCookie, const GwlbData& gd, const unsigned char* inner, ssize_t innerLen);
    void ebpfGc(uint64_t nowNs);                       // age + remove stale map entries, update lastBpfActivityNs
    int  perProtoTimeout(uint8_t proto) const;         // tcp/udp/other cache timeout in seconds
};

 /**
  * Simple class wrapper for GeneveHandlerENI that leverages shared_ptr to keep things intact. Class is needed
  * to prevent unnecessary early construction/destruction in the concurrent_flat_map try_emplace calls and to
  * allow safe thread-local weak caching without extending lifetime unnecessarily.
  */
 class GeneveHandlerENIPtr {
 public:
    GeneveHandlerENIPtr(gwlbeid_t eni, int tcpCacheTimeout, int udpCacheTimeout, int otherCacheTimeout, const ThreadConfig& tunThreadConfig, const std::array<std::size_t,6>& reserve, ghCallback createCallback, ghCallback destroyCallback, EbpfLoader* ebpfLoader);
    std::shared_ptr<GeneveHandlerENI> ptr;
 };

class GeneveHandlerHealthCheck : public HealthCheck {
public:
    GeneveHandlerHealthCheck(bool, UDPPacketReceiverHealthCheck, std::list<GeneveHandlerENIHealthCheck>, EbpfLoaderHealthCheck);
    std::string output_str() ;
    json output_json();

private:
    bool healthy;
    UDPPacketReceiverHealthCheck udp;
    std::list<GeneveHandlerENIHealthCheck> enis;
    EbpfLoaderHealthCheck ebpfLoader;
};

class GeneveHandler {
public:
    GeneveHandler(ghCallback createCallback, ghCallback destroyCallback, const GwlbtunConfig& cfg);
    void udpReceiverCallback(unsigned char *pkt, ssize_t pktlen, struct in_addr *srcAddr, uint16_t srcPort, struct in_addr *dstAddr, uint16_t dstPort);
    GeneveHandlerHealthCheck check();
    void sweep();            // evict expired flow entries + reap idle ENIs (periodic)
    bool healthy;                  // Updated by check()

private:
    boost::concurrent_flat_map<gwlbeid_t, GeneveHandlerENIPtr> eniHandlers;
    ghCallback createCallback;
    ghCallback destroyCallback;
    const GwlbtunConfig config;
    UDPPacketReceiver udpRcvr;
    EbpfLoader ebpfLoader;

    // Thread-local fast-path cache: per-thread weak references to ENI handlers, keyed by this instance
    static thread_local std::unordered_map<const GeneveHandler*, std::unordered_map<gwlbeid_t, std::weak_ptr<GeneveHandlerENI>>> tlsEniCache;

};




std::string devname_make(gwlbeid_t eni, bool inbound);

#endif //GWLBTUN_GENEVEHANDLER_H
