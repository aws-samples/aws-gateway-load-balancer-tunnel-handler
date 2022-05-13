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
#include "PacketHeader.h"

typedef std::function<void(std::string inInt, std::string outInt, uint64_t eniId)> ghCallback;

// Data we need to send with the packet back to GWLB, including the Geneve header and outer UDP header information.
class GwlbData {
public:
    GwlbData(GenevePacket &gp, struct in_addr *srcAddr, uint16_t srcPort, struct in_addr *dstAddr, uint16_t dstPort);

    struct in_addr srcAddr;
    uint16_t srcPort;
    struct in_addr dstAddr;
    uint16_t dstPort;
    GenevePacket gp;

    int seenCount;
    time_t lastSeen;
};

class GeneveHandler {
public:
    GeneveHandler(ghCallback createCallback, ghCallback destroyCallback, int destroyTimeout);
    ~GeneveHandler();
    std::string check();
    bool healthy;                  // Updated by check()

private:
    // Storage, keyed by ENI id.
    std::shared_mutex eniIdLock;   // Used to access elements of the 3 unordered maps below.
    std::unordered_map<uint64_t, std::unique_ptr<TunInterface>> tunnelIn;
    std::unordered_map<uint64_t, std::unique_ptr<TunInterface>> tunnelOut;
    std::unordered_map<uint64_t, std::unique_ptr<std::shared_mutex>> gwlbCookiesMutex;   // These mutexes protect the gwlbCookies below.
    std::unordered_map<uint64_t, std::unordered_map<PacketHeader, GwlbData, PacketHeaderHash>> gwlbCookies;

    // Callback functions for our threads
    void udpReceiverCallback(unsigned char *pktbuf, ssize_t pktlen, struct in_addr *srcAddr, uint16_t srcPort, struct in_addr *dstAddr, uint16_t dstPort);
    void tunReceiverCallback(uint64_t, unsigned char *pktbuf, ssize_t pktlen);

    class UDPPacketReceiver udpRcvr;
    std::vector<class TunInterface> tunints;

    ghCallback createCallback;
    ghCallback destroyCallback;
    int destroyTimeout;
};

#endif //GWLBTUN_GENEVEHANDLER_H
