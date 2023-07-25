// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * Handles all of our Geneve tunnel functions:
 * - Launches a UDPPacketReceiver to receive packets on port 6081
 * - For each VNI received, it starts a new Tun interface named gwi-<VNI>, and does a callback
 * - For each packet received over the UDPPacketReceiver, decode, store the resulting flowCookie, and send to the gwi-<VNI> tunnel interface to the OS
 * - For each packet received via a Tun interface, encode if possible, and send to GWLB.
 *
 * Also provides the GwlbData class, which stores PacketHeaders with their matching GenevePacket so that the GENEVE
 * options can be reapplied to matching traffic.
 */

#include "GeneveHandler.h"
#include "utils.h"
#include <arpa/inet.h>
#include <cstring>
#include <map>
#include <net/if.h>     // Needed for IFNAMSIZ define

using namespace std::string_literals;

#define GWLB_MTU           8500         // MTU of customer payload packets that can be processed
#define GWLB_CACHE_EXPIRE  350          // After many seconds of a flow being idle do we consider it inactive
#define GENEVE_PORT        6081         // UDP port number that GENEVE uses by standard

/**
 * Build a GwlbData structure. Stores the data, and sets the lastSeen timer to now.
 *
 * @param gp GenevePacket to store
 * @param srcAddr Source address of the GENEVE packet
 * @param srcPort Source port of the GENEVE packet
 * @param dstAddr Destination address of the GENEVE packet
 * @param dstPort Destination port of the GENEVE packet
 */
GwlbData::GwlbData(GenevePacket &gp, struct in_addr *srcAddr, uint16_t srcPort, struct in_addr *dstAddr, uint16_t dstPort) :
         srcAddr(*srcAddr), srcPort(srcPort), dstAddr(*dstAddr), dstPort(dstPort), gp(gp), seenCount(1)
{
    lastSeen = time(nullptr);
}

/**
 * Starts the GeneveHandler. Builds a UDPPacketReceiver on port 6081 with callbacks in this class to handle packets
 * as they come in.
 *
 * @param createCallback Function to call when a new endpoint is seen.
 * @param destroyCallback Function to call when an endpoint has gone away and we need to clean up.
 * @param destroyTimeout How long to wait for an endpoint to be idle before calling destroyCallback.
 */
GeneveHandler::GeneveHandler(ghCallback createCallback, ghCallback destroyCallback, int destroyTimeout, ThreadConfig udpThreads, ThreadConfig tunThreads)
        : healthy(true),
          createCallback(std::move(createCallback)), destroyCallback(std::move(destroyCallback)), destroyTimeout(destroyTimeout),
          tunThreadConfig(std::move(tunThreads))
{
    // Set up UDP receiver threads.
#ifndef NO_RETURN_TRAFFIC
    sendingSock = socket(AF_INET,SOCK_RAW, IPPROTO_RAW);
    if(sendingSock == -1)
        throw std::runtime_error("Unable to allocate a socket for sending UDP traffic.");
#endif
    udpRcvr.setup(udpThreads, GENEVE_PORT, std::bind(&GeneveHandler::udpReceiverCallback, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6));
}

/**
 * Perform a health check of the GeneveHandler and all components it is using.
 *
 * @return A human-readable string of the health status.
 */
std::string GeneveHandler::check()
{
    if(debug) *debugout << currentTime() << ": GeneveHandler check running" << std::endl;
    std::string ret;
    std::vector<uint64_t> enisToDelete;
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - std::chrono::duration<int, std::ratio<1,1>>(destroyTimeout);
    healthy = udpRcvr.healthCheck();
    ret += udpRcvr.status();

    // Add to our return string some stats on the tunnels, and mark tunnels for cleanup if they've timed out.
    // Check their cookie caches as well, and purge stale entries.
    time_t expireTime = time(nullptr) - GWLB_CACHE_EXPIRE;

    for (auto &ti : tunnelIn)
    {
        ret += ti.second->status();
        if(!ti.second->healthCheck())
        {
            if(debug) *debugout << currentTime() << ": Status unhealthy due to Tunnel In for " << ti.second->devname << " health check returning False." << std::endl;
            healthy = false;
        }
#ifndef NO_RETURN_TRAFFIC
        ret += tunnelOut[ti.first]->status();
        if(!tunnelOut[ti.first]->healthCheck())
        {
            if(debug) *debugout << currentTime() << ": Status unhealthy due to Tunnel Out for " << ti.second->devname << " health check returning False." << std::endl;
            healthy = false;
        }
#endif

#ifdef NO_RETURN_TRAFFIC
        if ((destroyTimeout > 0) && (ti.second->lastPacketTime() < cutoff))
        {
            std::string delMsg = "The interface  "s + ti.second->devname + " has timed out and are being deleted.\n"s;
            std::cout << currentTime() << ": " << delMsg;
            ret += delMsg;
            enisToDelete.push_back(ti.first);
        }
#else
        if ((destroyTimeout > 0) && (ti.second->lastPacketTime() < cutoff) && (tunnelOut[ti.first]->lastPacketTime() < cutoff))
        {
            std::string delMsg = "The interface pair "s + ti.second->devname + " and "s + tunnelOut[ti.first]->devname + " have timed out and are being deleted.\n"s;
            std::cout << currentTime() << ": " << delMsg;
            ret += delMsg;
            enisToDelete.push_back(ti.first);
        }

        int cookieCount = 0;
        int purgeCount = 0;
        std::unique_lock V4cookieULock(*gwlbV4CookiesMutex[ti.first]);
        auto itV4 = gwlbV4Cookies[ti.first].begin();
        while(itV4 != gwlbV4Cookies[ti.first].end())
        {
            if(itV4->second.lastSeen < expireTime)
            {
                itV4= gwlbV4Cookies[ti.first].erase(itV4);
                purgeCount ++;
            } else {
                itV4++;
                cookieCount ++;
            }
        }
        if(debug >= DEBUG_ON)
        {
            std::map<unsigned long, int> bs;
            ret += "  IPv4 flow cache "s + std::to_string(ti.first) + " is size "s + std::to_string(gwlbV4Cookies[ti.first].size()) +
                   ", bucket count "s + std::to_string(gwlbV4Cookies[ti.first].bucket_count()) +
                   ", load factor "s + std::to_string(gwlbV4Cookies[ti.first].load_factor()) + "\n"s;
            for(unsigned long bc=0; bc < gwlbV4Cookies[ti.first].bucket_count(); bc ++)
            {
                unsigned long s = gwlbV4Cookies[ti.first].bucket_size(bc);
                if(bs.count(s))
                    bs[s] = bs[s] + 1;
                else
                    bs[s] = 1;
            }
            for(auto bsiter = bs.begin(); bsiter != bs.end(); bsiter ++)
            {
                ret += "   There are "s + std::to_string(bsiter->second) + " buckets with "s + std::to_string(bsiter->first) +" elements.\n"s;
            }
        }

        V4cookieULock.unlock();
        ret += "IPv4 flow cache now contains "s + std::to_string(cookieCount) + " records - "s + std::to_string(purgeCount) + " were just purged.\n"s;

        cookieCount = 0;
        purgeCount = 0;
        std::unique_lock V6cookieULock(*gwlbV6CookiesMutex[ti.first]);
        auto itV6 = gwlbV6Cookies[ti.first].begin();
        while(itV6 != gwlbV6Cookies[ti.first].end())
        {
            if(itV6->second.lastSeen < expireTime)
            {
                itV6 = gwlbV6Cookies[ti.first].erase(itV6);
                purgeCount ++;
            } else {
                itV6++;
                cookieCount ++;
            }
        }
        if(debug >= DEBUG_ON)
        {
            std::map<unsigned long, int> bs;
            ret += "  IPv6 flow cache "s + std::to_string(ti.first) + " is size "s + std::to_string(gwlbV6Cookies[ti.first].size()) +
                   ", bucket count "s + std::to_string(gwlbV6Cookies[ti.first].bucket_count()) +
                   ", load factor "s + std::to_string(gwlbV6Cookies[ti.first].load_factor()) + "\n"s;
            for(unsigned long bc=0; bc < gwlbV6Cookies[ti.first].bucket_count(); bc ++)
            {
                unsigned long s = gwlbV6Cookies[ti.first].bucket_size(bc);
                if(bs.count(s))
                    bs[s] = bs[s] + 1;
                else
                    bs[s] = 1;
            }
            for(auto bsiter = bs.begin(); bsiter != bs.end(); bsiter ++)
            {
                ret += "   There are "s + std::to_string(bsiter->second) + " buckets with "s + std::to_string(bsiter->first) +" elements.\n"s;
            }
        }
        V6cookieULock.unlock();
        ret += "IPv6 flow cache now contains "s + std::to_string(cookieCount) + " records - "s + std::to_string(purgeCount) + " were just purged.\n"s;
#endif  // NO_RETURN_TRAFFIC
    }

    for (auto &eni : enisToDelete)
    {
        // Call the user-provided callback for interfaces being deleted.
#ifndef NO_RETURN_TRAFFIC
        destroyCallback(tunnelIn[eni]->devname, tunnelOut[eni]->devname, eni);
#else
        destroyCallback(tunnelIn[eni]->devname, "none", eni);
#endif
        tunnelIn.erase(eni);
#ifndef NO_RETURN_TRAFFIC
        tunnelOut.erase(eni);
#endif
    }

    return ret;
}

/**
 * Callback function passed to UDPPacketReceiver to handle GenevePackets. Parses the packet, builds a new TunInterface
 * if required, updates the tunnel's flow cache, and sends the packet out the tunnel's gwi interface.
 *
 * @param pkt The packet received.
 * @param pktlen Length of packet received.
 * @param srcAddr Source address the packet came from.
 * @param srcPort Source port the packet came from.
 * @param dstAddr Destination address the packet was sent to.
 * @param dstPort Destination port the packet was sent to.
 */
void GeneveHandler::udpReceiverCallback(unsigned char *pkt, ssize_t pktlen, struct in_addr *srcAddr, uint16_t srcPort, struct in_addr *dstAddr, uint16_t dstPort)
{
    if(debug >= DEBUG_ON)
    {
        *debugout << currentTime() << ": GWLB : Received a packet of " << pktlen << " bytes from " << inet_ntoa(*srcAddr) << " port " << srcPort;
        *debugout << " sent to " << inet_ntoa(*dstAddr) << " port " << dstPort << std::endl;
        if(debug >= DEBUG_VERBOSE) hexDump(*hexout, pkt, pktlen, true, currentTime() + ": GWLB Packet: ");
    }
    try {
        auto gp = GenevePacket(pkt, pktlen);
        auto gd = GwlbData(gp, srcAddr, srcPort, dstAddr, dstPort);

        // The GenevePacket class does sanity checks to ensure this was a Geneve packet. Verify the result of those checks.
        if(gp.status != GP_STATUS_OK)
        {
            if(debug) *debugout << currentTime() << ": GWLB : Geneve Header not OK" << std::endl;
            return;
        }

        if(!gp.gwlbeEniIdValid)
        {
            if(debug) *debugout << currentTime() << ": GWLB : GWLBe ENI ID not valid" << std::endl;
            return;
        }

        // Is this a new ENI ID?
        std::shared_lock eniLock(eniIdLock);
        auto foundEni = tunnelIn.find(gp.gwlbeEniId);
        eniLock.unlock();

        if(foundEni == tunnelIn.end()) {
            // Yes.  Create everything needed. Make the gwi- and gwo- tunnel interfaces.
            char devnamein[IFNAMSIZ], devnameout[IFNAMSIZ];
            snprintf(devnamein, IFNAMSIZ, "gwi-%s", toBase60(gp.gwlbeEniId).c_str());
            snprintf(devnameout, IFNAMSIZ, "gwo-%s", toBase60(gp.gwlbeEniId).c_str());
            std::unique_lock eniULock(eniIdLock);
            // Reverify we still need to create this tunnel - another thread may have done it between the shared lock and the unique lock.
            auto foundEni = tunnelIn.find(gp.gwlbeEniId);
            if(foundEni == tunnelIn.end())
            {
#ifndef NO_RETURN_TRAFFIC
                // Create our seen-flows data (cookies) for this ENI, along with a mutex for multithread data protection.
                gwlbV4CookiesMutex.emplace(gp.gwlbeEniId, new std::shared_mutex);
                gwlbV4Cookies.emplace(gp.gwlbeEniId, std::unordered_map<PacketHeaderV4, GwlbData>());
                gwlbV6CookiesMutex.emplace(gp.gwlbeEniId, new std::shared_mutex);
                gwlbV6Cookies.emplace(gp.gwlbeEniId, std::unordered_map<PacketHeaderV6, GwlbData>());
#endif

                // Now create the tunnels
                try {

                    tunnelIn.emplace(gp.gwlbeEniId, new TunInterface(devnamein, GWLB_MTU, tunThreadConfig, std::bind(&GeneveHandler::tunReceiverCallback, this, gp.gwlbeEniId, std::placeholders::_1, std::placeholders::_2)));
#ifndef NO_RETURN_TRAFFIC
                    tunnelOut.emplace(gp.gwlbeEniId, new TunInterface(devnameout, GWLB_MTU, tunThreadConfig, std::bind(&GeneveHandler::tunReceiverCallback, this, gp.gwlbeEniId, std::placeholders::_1, std::placeholders::_2)));
#endif
                }
                catch (std::exception& e) {
                    std::cerr << currentTime() << ": GWLB : Tunnel creation failed: " << e.what() << std::endl;
                }

                eniULock.unlock();
                if(debug) *debugout << currentTime() << ": GWLB : New ENI ID " << std::hex << gp.gwlbeEniId << std::dec << " detected.  New tunnel interfaces " << devnamein << " and " << devnameout << " created." << std::endl;

                // Call the user-provided callback for a new interface pair being created.
#ifndef NO_RETURN_TRAFFIC
                createCallback(devnamein, devnameout, gp.gwlbeEniId);
#else
                createCallback(devnamein, "none", gp.gwlbeEniId);
#endif
            }
        }

        if( (pktlen - gp.headerLen) > sizeof(struct ip) )
        {
            struct ip *iph = (struct ip *)(pkt + gp.headerLen);
            if(iph->ip_v == (unsigned int)4)
            {
                auto ph = PacketHeaderV4(pkt + gp.headerLen, pktlen - gp.headerLen);

#ifndef NO_RETURN_TRAFFIC
                // Is this a new flow?
                std::shared_lock cookieLock(*gwlbV4CookiesMutex[gp.gwlbeEniId]);
                auto foundCookie = gwlbV4Cookies[gp.gwlbeEniId].find(ph);
                cookieLock.unlock();

                if (foundCookie == gwlbV4Cookies[gp.gwlbeEniId].end()) {
                    // Yes. Add its seen data so we can add the header back on when this same flow leaves.
                    std::unique_lock cookieULock(*gwlbV4CookiesMutex[gp.gwlbeEniId]);
                    // Add forward direction
                    gwlbV4Cookies[gp.gwlbeEniId].insert(std::pair<PacketHeaderV4, GwlbData>(ph, gd));
                    // Add reverse direction if needed
#ifndef HASH_IS_SYMMETRICAL
                    gwlbV4Cookies[gp.gwlbeEniId].insert(std::pair<PacketHeaderV4, GwlbData>(ph.reverse(), gd));
#endif
                    cookieULock.unlock();

                    if(debug) *debugout << currentTime() << ": GWLB : IPv4 flow " << ph << " added:" << gp << std::endl;
                } else {
                    // Verify the flow cookie hasn't changed. If it has, replace this entry.
                    if(memcmp(&foundCookie->second.gp.header.front(), &gd.gp.header.front(), foundCookie->second.gp.headerLen))
                    {
                        std::unique_lock cookieULock(*gwlbV4CookiesMutex[gp.gwlbeEniId]);
                        gwlbV4Cookies[gp.gwlbeEniId].erase(foundCookie);
                        gwlbV4Cookies[gp.gwlbeEniId].insert(std::pair<PacketHeaderV4, GwlbData>(ph, gd));
                        cookieULock.unlock();
                        if(debug) *debugout << currentTime() << ": GWLB : IPv4 flow " << ph << " replaced:" << gp << std::endl;
                    } else {
                        foundCookie->second.seenCount ++;
                        foundCookie->second.lastSeen = time(nullptr);
                        if(debug) *debugout << currentTime() << ": GWLB : IPv4 flow " << ph << " exists. Seen " << foundCookie->second.seenCount << " times." << std::endl;
                    }
                }
#endif
                // Route the decap'ed packet to our tun interface.
                if(pktlen > gp.headerLen)
                    tunnelIn[gp.gwlbeEniId]->writePacket(pkt + gp.headerLen, pktlen - gp.headerLen);
            } else if(iph->ip_v == (unsigned int)6) {
                auto ph = PacketHeaderV6(pkt + gp.headerLen, pktlen - gp.headerLen);

#ifndef NO_RETURN_TRAFFIC
                // Is this a new flow?
                std::shared_lock cookieLock(*gwlbV6CookiesMutex[gp.gwlbeEniId]);
                auto foundCookie = gwlbV6Cookies[gp.gwlbeEniId].find(ph);
                cookieLock.unlock();

                if (foundCookie == gwlbV6Cookies[gp.gwlbeEniId].end()) {
                    // Yes. Add its seen data so we can add the header back on when this same flow leaves.
                    std::unique_lock cookieULock(*gwlbV6CookiesMutex[gp.gwlbeEniId]);
                    gwlbV6Cookies[gp.gwlbeEniId].insert(std::pair<PacketHeaderV6, GwlbData>(ph, gd));
                    cookieULock.unlock();
                    if(debug) *debugout << currentTime() << ": GWLB : IPv6 flow " << ph << " added:" << gp << std::endl;
                } else {
                    // Verify the flow cookie hasn't changed. If it has, replace this entry.
                    if(memcmp(&foundCookie->second.gp.header.front(), &gd.gp.header.front(), foundCookie->second.gp.headerLen))
                    {
                        std::unique_lock cookieULock(*gwlbV6CookiesMutex[gp.gwlbeEniId]);
                        gwlbV6Cookies[gp.gwlbeEniId].erase(foundCookie);
                        // Add this flow
                        gwlbV6Cookies[gp.gwlbeEniId].insert(std::pair<PacketHeaderV6, GwlbData>(ph, gd));
                        // Add reverse direction if needed
#ifndef HASH_IS_SYMMETRICAL
                        gwlbV6Cookies[gp.gwlbeEniId].insert(std::pair<PacketHeaderV6, GwlbData>(ph.reverse(), gd));
#endif
                        cookieULock.unlock();
                        if(debug) *debugout << currentTime() << ": GWLB : IPv6 flow " << ph << " replaced:" << gp << std::endl;
                    } else {
                        foundCookie->second.seenCount ++;
                        foundCookie->second.lastSeen = time(nullptr);
                        if(debug) *debugout << currentTime() << ": GWLB : IPv6 flow " << ph << " exists. Seen " << foundCookie->second.seenCount << " times." << std::endl;
                    }
                }
#endif
                // Route the decap'ed packet to our tun interface.
                if(pktlen > gp.headerLen)
                    tunnelIn[gp.gwlbeEniId]->writePacket(pkt + gp.headerLen, pktlen - gp.headerLen);
            } else {
                if(debug) *debugout << currentTime() << ": GWLB : Got a strange IP protocol version - " << std::to_string(iph->ip_v) << " at offset " << std::to_string(gp.headerLen) << ". Dropping packet." << std::endl;
            }
        }
    } catch(std::invalid_argument& err) {
        if(debug) *debugout << currentTime() << ": GWLB : Packet processor has a malformed packet: " << err.what() << std::endl;
        return;
    }
}

/**
 * Shut down the GeneveHandler. Call all the tunnel destructors first, then shut down our threads.
 */
GeneveHandler::~GeneveHandler()
{
    for (auto &ti : tunnelIn)
    {
#ifndef NO_RETURN_TRAFFIC
        destroyCallback(ti.second->devname, tunnelOut[ti.first]->devname, ti.first);
#else
        destroyCallback(ti.second->devname, "none", ti.first);
#endif
    }
    udpRcvr.shutdown();
    tunnelIn.clear();
#ifndef NO_RETURN_TRAFFIC
    tunnelOut.clear();
#endif
}

/**
 * Callback function passed to TunInterface to handle packets coming back in from the OS to either the gwi- or the
 * gwo- interface. Attempts to match the packet header to a seen flow (outptus a message and returns if none is found)
 * and then sends the packet correctly formed back to GWLB.
 *
 * @param eniId The ENI ID of the TUN interface
 * @param pkt The packet received.
 * @param pktlen Length of packet received.
 */
void GeneveHandler::tunReceiverCallback(uint64_t eniId, unsigned char *pktbuf, ssize_t pktlen)
{
    if(debug) *debugout << currentTime() << ": Tun : Received a packet of " << pktlen << " bytes for ENI Id:" << std::hex << eniId << std::dec << std::endl;
    if(debug >= DEBUG_VERBOSE) hexDump(*hexout, pktbuf, pktlen, true, currentTime() + ": Tun Packet: ");

#ifdef NO_RETURN_TRAFFIC
    if(debug) *debugout << currentTime() << ": Tun : Received a packet, but NO_RETURN_TRAFFIC is defined. Discarding." << std::endl;
    return;
#else
    // Ignore packets that are not IPv4 or IPv6, or aren't at least long enough to have those sized headers.
    if( pktlen < 20 )
    {
        if(debug) *debugout << currentTime() << ": Tun : Packet is not long enough to have an IP header, ignoring." << std::endl;
        return;
    }
    try
    {
        switch( (pktbuf[0] & 0xF0) >> 4)
        {
            case 4:
            {
                auto ph = PacketHeaderV4(pktbuf, pktlen);

                std::shared_lock cookieLock(*gwlbV4CookiesMutex[eniId]);
                auto got = gwlbV4Cookies[eniId].find(ph);
                cookieLock.unlock();
                if (got == gwlbV4Cookies[eniId].end()) {
                    if(debug) *debugout << currentTime() << ": Tun : Flow " << ph << " has not been seen coming in from GWLB - dropping.  (Remember - GWLB is for inline inspection only - you cannot source new flows from this device into it.)" << std::endl;
                } else {
                    // Build the packet to send back to GWLB.
                    // Following as per https://aws.amazon.com/blogs/networking-and-content-delivery/integrate-your-custom-logic-or-appliance-with-aws-gateway-load-balancer/
                    unsigned char *genevePkt = new unsigned char[pktlen + got->second.gp.headerLen];

                    if(debug) *debugout << currentTime() << ": Tun : Flow " << ph << " recognized - forwarding to GWLB with header " << got->second.gp << std::endl;

                    // Encapsulate this packet with the original Geneve header
                    memcpy(genevePkt, &got->second.gp.header.front(), got->second.gp.headerLen);
                    // Copy the packet in after the Geneve header.
                    memcpy(genevePkt + got->second.gp.headerLen, pktbuf, pktlen);
                    // Swap source and destination IP addresses, but preserve ports, and send back to GWLB.
                    sendUdp(sendingSock, got->second.dstAddr, got->second.srcPort, got->second.srcAddr, got->second.dstPort, genevePkt,
                            pktlen + got->second.gp.headerLen);

                    delete [] genevePkt;
                }
                return;
            }
            case 6:
            {
                auto ph = PacketHeaderV6(pktbuf, pktlen);

                std::shared_lock cookieLock(*gwlbV6CookiesMutex[eniId]);
                auto got = gwlbV6Cookies[eniId].find(ph);
                cookieLock.unlock();
                if (got == gwlbV6Cookies[eniId].end()) {
                    if(debug) *debugout << currentTime() << ": Tun : Flow " << ph << " has not been seen coming in from GWLB - dropping.  (Remember - GWLB is for inline inspection only - you cannot source new flows from this device into it.)" << std::endl;
                } else {
                    // Build the packet to send back to GWLB.
                    // Following as per https://aws.amazon.com/blogs/networking-and-content-delivery/integrate-your-custom-logic-or-appliance-with-aws-gateway-load-balancer/
                    unsigned char *genevePkt = new unsigned char[pktlen + got->second.gp.headerLen];

                    if(debug) *debugout << currentTime() << ": Tun : Flow " << ph << " recognized - forwarding to GWLB with header " << got->second.gp << std::endl;

                    // Encapsulate this packet with the original Geneve header
                    memcpy(genevePkt, &got->second.gp.header.front(), got->second.gp.headerLen);
                    // Copy the packet in after the Geneve header.
                    memcpy(genevePkt + got->second.gp.headerLen, pktbuf, pktlen);
                    // Swap source and destination IP addresses, but preserve ports, and send back to GWLB.
                    sendUdp(sendingSock, got->second.dstAddr, got->second.srcPort, got->second.srcAddr, got->second.dstPort, genevePkt,
                            pktlen + got->second.gp.headerLen);

                    delete [] genevePkt;
                }
                return;
            }
            default:
            {
                if(debug) *debugout << currentTime() << ": Tun : Received a packet that wasn't IPv4 or IPv6. Ignoring." << std::endl;
                return;
            }
        }
    } catch(std::invalid_argument& err) {
        if(debug) *debugout << currentTime() << ": Tun : Packet processor has a malformed packet: " << err.what() << std::endl;
        return;
    }
#endif
}