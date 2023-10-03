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
#include <net/if.h>     // Needed for IFNAMSIZ define
#include <boost/unordered/concurrent_flat_map.hpp>

typedef std::function<void(std::string inInt, std::string outInt, eniid_t eniId)> ghCallback;

// Data we need to send with the packet back to GWLB, including the Geneve header and outer UDP header information.
class GwlbData {
public:
    GwlbData();
    GwlbData(GenevePacket &gp, struct in_addr *srcAddr, uint16_t srcPort, struct in_addr *dstAddr, uint16_t dstPort);

    // Elements are arranged so that when doing sorting/searching, we get entropy early. This gives a slight
    // improvement to the lookup time.
    GenevePacket gp;
    struct in_addr srcAddr;
    uint16_t srcPort;
    struct in_addr dstAddr;
    uint16_t dstPort;
};

/**
 * For each ENI (GWLBe) that is detected, a copy of GeneveHandlerENI is created.
 */
class GeneveHandlerENI {
public:
    GeneveHandlerENI(eniid_t eni, ThreadConfig& tunThreadConfig, ghCallback createCallback, ghCallback destroyCallback);
    ~GeneveHandlerENI();
    void udpReceiverCallback(const GwlbData &gd, unsigned char *pkt, ssize_t pktlen);
    void tunReceiverCallback(unsigned char *pktbuf, ssize_t pktlen);
    std::string check();
    bool hasGoneIdle(int timeout);

private:
    const eniid_t eni;
    const std::string eniStr;

    const std::string devInName;
    const std::string devOutName;

    std::unique_ptr<TunInterface> tunnelIn;
#ifndef NO_RETURN_TRAFFIC
    std::unique_ptr<TunInterface> tunnelOut;

    FlowCache<PacketHeaderV4, GwlbData> gwlbV4Cookies;
    FlowCache<PacketHeaderV6, GwlbData> gwlbV6Cookies;
#endif
    // Socket used by all threads for sending
    int sendingSock;
    const ghCallback createCallback;
    const ghCallback destroyCallback;
};

/**
 * Simple class wrapper for GeneveHandlerENI that leverages unique_ptr to keep things intact. Class is needed
 * to prevent unnecessary early construction/destruction in the concurrent_flat_map try_emplace calls.
 */
 class GeneveHandlerENIPtr {
 public:
    GeneveHandlerENIPtr(eniid_t eni, ThreadConfig& tunThreadConfig, ghCallback createCallback, ghCallback destroyCallback);
    std::unique_ptr<GeneveHandlerENI> ptr;
 };

class GeneveHandler {
public:
    GeneveHandler(ghCallback createCallback, ghCallback destroyCallback, int destroyTimeout, ThreadConfig udpThreads, ThreadConfig tunThreads);
    void udpReceiverCallback(unsigned char *pkt, ssize_t pktlen, struct in_addr *srcAddr, uint16_t srcPort, struct in_addr *dstAddr, uint16_t dstPort);
    std::string check();
    bool healthy;                  // Updated by check()

private:
    boost::concurrent_flat_map<eniid_t, GeneveHandlerENIPtr> eniHandlers;
    ghCallback createCallback;
    ghCallback destroyCallback;
    int eniDestroyTimeout;
    ThreadConfig tunThreadConfig;
    UDPPacketReceiver udpRcvr;

};

std::string devname_make(eniid_t eni, bool inbound);

#endif //GWLBTUN_GENEVEHANDLER_H
