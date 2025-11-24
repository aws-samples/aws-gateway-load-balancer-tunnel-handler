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
#include <linux/if.h>     // Needed for IFNAMSIZ define
#include <boost/unordered/concurrent_flat_map.hpp>
#include "HealthCheck.h"

typedef std::function<void(std::string inInt, std::string outInt, eniid_t eniId)> ghCallback;

// Data we need to send with the packet back to GWLB, including the Geneve header and outer UDP header information.
class GwlbData {
public:
    GwlbData();
    GwlbData(GeneveHeader header, struct in_addr *srcAddr, uint16_t srcPort, struct in_addr *dstAddr, uint16_t dstPort);

    // Elements are arranged so that when doing sorting/searching, we get entropy early. This gives a slight
    // improvement to the lookup time.
    struct in_addr srcAddr;
    struct in_addr dstAddr;
    uint16_t srcPort;
    uint16_t dstPort;
    GeneveHeader header;   // Copy of the Geneve header to put back on packets

    std::string text();
};


/**
 * For each ENI (GWLBe) that is detected, a copy of GeneveHandlerENI is created.
 */

class GeneveHandlerENIHealthCheck : public HealthCheck {
public:
    GeneveHandlerENIHealthCheck(std::string, uint64_t pktsOut, uint64_t bytesOut, std::chrono::steady_clock::time_point lastPacketOut, TunInterfaceHealthCheck
#ifndef NO_RETURN_TRAFFIC
                                , TunInterfaceHealthCheck, FlowCacheHealthCheck, FlowCacheHealthCheck
#endif
                                );
    std::string output_str() ;
    json output_json();

private:
    std::string eniStr;
    uint64_t pktsOut, bytesOut;
    std::chrono::steady_clock::time_point lastPacketOut;

    TunInterfaceHealthCheck tunnelIn;
#ifndef NO_RETURN_TRAFFIC
    TunInterfaceHealthCheck tunnelOut;
    FlowCacheHealthCheck v4FlowCache;
    FlowCacheHealthCheck v6FlowCache;
#endif
};

class GeneveHandlerENI {
public:
    GeneveHandlerENI(eniid_t eni, int cacheTimeout, ThreadConfig& tunThreadConfig, ghCallback createCallback, ghCallback destroyCallback);
    ~GeneveHandlerENI();
    void udpReceiverCallback(GwlbData gd, unsigned char *pkt, ssize_t pktlen) __attribute__((hot));
    void tunReceiverCallback(unsigned char *pktbuf, ssize_t pktlen) __attribute__((hot));
    GeneveHandlerENIHealthCheck check();
    bool hasGoneIdle(int timeout);

private:
    const eniid_t eni;
    const std::string eniStr;
    int cacheTimeout;

    const std::string devInName;
    const std::string devOutName;

    std::unique_ptr<TunInterface> tunnelIn;
#ifndef NO_RETURN_TRAFFIC
    std::unique_ptr<TunInterface> tunnelOut;

    FlowCache<PacketHeaderV4, GwlbData> gwlbV4Cookies;
    FlowCache<PacketHeaderV6, GwlbData> gwlbV6Cookies;
#endif

    // Socket to write to our associated tunnel
    TunSocket gwiWriter;
    std::atomic<uint64_t> pktsOut{0}; 
    std::atomic<uint64_t> bytesOut{0}; 
    std::atomic<std::chrono::steady_clock::time_point> lastPacketOut;

    // Socket used by all threads for sending
    int sendingSock;
    const ghCallback createCallback;
    const ghCallback destroyCallback;
};

 /**
  * Simple class wrapper for GeneveHandlerENI that leverages shared_ptr to keep things intact. Class is needed
  * to prevent unnecessary early construction/destruction in the concurrent_flat_map try_emplace calls and to
  * allow safe thread-local weak caching without extending lifetime unnecessarily.
  */
 class GeneveHandlerENIPtr {
 public:
    GeneveHandlerENIPtr(eniid_t eni, int idleTimeout, ThreadConfig& tunThreadConfig, ghCallback createCallback, ghCallback destroyCallback);
    std::shared_ptr<GeneveHandlerENI> ptr;
 };

class GeneveHandlerHealthCheck : public HealthCheck {
public:
    GeneveHandlerHealthCheck(bool, UDPPacketReceiverHealthCheck, std::list<GeneveHandlerENIHealthCheck>);
    std::string output_str() ;
    json output_json();

private:
    bool healthy;
    UDPPacketReceiverHealthCheck udp;
    std::list<GeneveHandlerENIHealthCheck> enis;
};

class GeneveHandler {
public:
    GeneveHandler(ghCallback createCallback, ghCallback destroyCallback, int destroyTimeout, int cacheTimeout, ThreadConfig udpThreads, ThreadConfig tunThreads);
    void udpReceiverCallback(unsigned char *pkt, ssize_t pktlen, struct in_addr *srcAddr, uint16_t srcPort, struct in_addr *dstAddr, uint16_t dstPort);
    GeneveHandlerHealthCheck check();
    bool healthy;                  // Updated by check()

private:
    boost::concurrent_flat_map<eniid_t, GeneveHandlerENIPtr> eniHandlers;
    ghCallback createCallback;
    ghCallback destroyCallback;
    int eniDestroyTimeout;
    int cacheTimeout;
    ThreadConfig tunThreadConfig;
    UDPPacketReceiver udpRcvr;

    // Thread-local fast-path cache: per-thread weak references to ENI handlers, keyed by this instance
    static thread_local std::unordered_map<const GeneveHandler*, std::unordered_map<eniid_t, std::weak_ptr<GeneveHandlerENI>>> tlsEniCache;

};




std::string devname_make(eniid_t eni, bool inbound);

#endif //GWLBTUN_GENEVEHANDLER_H
