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
        gp(gp), srcAddr(*srcAddr), srcPort(srcPort), dstAddr(*dstAddr), dstPort(dstPort), seenCount(1)
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
GeneveHandler::GeneveHandler(ghCallback createCallback, ghCallback destroyCallback, int destroyTimeout)
        : udpRcvr(GENEVE_PORT, std::bind(&GeneveHandler::udpReceiverCallback, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6)),
          createCallback(std::move(createCallback)), destroyCallback(std::move(destroyCallback)), destroyTimeout(destroyTimeout), healthy(true)
{

}

/**
 * Perform a health check of the GeneveHandler and all components it is using.
 *
 * @return A human-readable string of the health status.
 */
std::string GeneveHandler::check()
{
    std::string ret;
    std::vector<uint64_t> enisToDelete;
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - std::chrono::duration<int, std::ratio<1,1>>(destroyTimeout);
    healthy = true;

    // check our receive handler
    ret += udpRcvr.status();
    if(!udpRcvr.healthCheck()) healthy = false;

    // Add to our return string some stats on the tunnels, and mark tunnels for cleanup if they've timed out.
    // Check their cookie caches as well, and purge stale entries.
    int cookieCount = 0;
    int purgeCount = 0;
    time_t expireTime = time(nullptr) - GWLB_CACHE_EXPIRE;

    for (auto &ti : tunnelIn)
    {
        ret += ti.second->status();
        if(!ti.second->healthCheck()) healthy = false;
        ret += tunnelOut[ti.first]->status();
        if(!tunnelOut[ti.first]->healthCheck()) healthy = false;

        if ((destroyTimeout > 0) && (ti.second->lastPacket.load() < cutoff) && (tunnelOut[ti.first]->lastPacket.load() < cutoff))
        {
            std::string delMsg = "The interface pair "s + ti.second->devname + " and " + tunnelOut[ti.first]->devname + " have timed out and are being deleted.\n";
            std::cout << currentTime() << ": " << delMsg;
            ret += delMsg;
            enisToDelete.push_back(ti.first);
        }

        std::unique_lock cookieULock(*gwlbCookiesMutex[ti.first]);
        auto it = gwlbCookies[ti.first].begin();
        while(it != gwlbCookies[ti.first].end())
        {
            if(it->second.lastSeen < expireTime)
            {
                it = gwlbCookies[ti.first].erase(it);
                purgeCount ++;
            } else {
                it++;
                cookieCount ++;
            }
        }
        cookieULock.unlock();
    }

    for (auto &eni : enisToDelete)
    {
        // Call the user-provided callback for interfaces being deleted.
        destroyCallback(tunnelIn[eni]->devname, tunnelOut[eni]->devname, eni);
        tunnelIn.erase(eni);
        tunnelOut.erase(eni);
    }

    ret += "Flow Cache contains "s + std::to_string(cookieCount) + " records - "s + std::to_string(purgeCount) + " were just purged."s;

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
        if(debug >= DEBUG_VERBOSE) hexDump(*hexout, pkt, pktlen, true, currentTime() + "GWLB Packet: ");
    }
    try {
        auto gp = GenevePacket(pkt, pktlen);
        auto ph = PacketHeader(pkt + gp.headerLen, pktlen - gp.headerLen);
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
            tunnelIn.emplace(gp.gwlbeEniId, new TunInterface(devnamein, GWLB_MTU, std::bind(&GeneveHandler::tunReceiverCallback, this, gp.gwlbeEniId, std::placeholders::_1, std::placeholders::_2)));
            tunnelOut.emplace(gp.gwlbeEniId, new TunInterface(devnameout, GWLB_MTU, std::bind(&GeneveHandler::tunReceiverCallback, this, gp.gwlbeEniId, std::placeholders::_1, std::placeholders::_2)));

            // Create our seen-flows data (cookies) for this ENI, along with a mutex for multithread data protection.
            gwlbCookiesMutex.emplace(gp.gwlbeEniId, new std::shared_mutex);
            gwlbCookies.emplace(gp.gwlbeEniId, std::unordered_map<PacketHeader, GwlbData, PacketHeaderHash>());
            eniULock.unlock();
            if(debug) *debugout << currentTime() << ": GWLB : New ENI ID " << std::hex << gp.gwlbeEniId << std::dec << " detected.  New tunnel interfaces " << devnamein << " and " << devnameout << " created." << std::endl;

            // Call the user-provided callback for a new interface pair being created.
            createCallback(devnamein, devnameout, gp.gwlbeEniId);
        }

        // Is this a new flow?
        std::shared_lock cookieLock(*gwlbCookiesMutex[gp.gwlbeEniId]);
        auto foundCookie = gwlbCookies[gp.gwlbeEniId].find(ph);
        cookieLock.unlock();

        if (foundCookie == gwlbCookies[gp.gwlbeEniId].end()) {
            // Yes. Add its seen data so we can add the header back on when this same flow leaves.
            std::unique_lock cookieULock(*gwlbCookiesMutex[gp.gwlbeEniId]);
            gwlbCookies[gp.gwlbeEniId].insert(std::pair<PacketHeader, GwlbData>(ph, gd));
            cookieULock.unlock();
            if(debug) *debugout << currentTime() << ": GWLB : Flow " << ph << " added:" << gp << std::endl;
        } else {
            // Verify the flow cookie hasn't changed. If it has, replace this entry.
            if(memcmp(&foundCookie->second.gp.header.front(), &gd.gp.header.front(), foundCookie->second.gp.headerLen))
            {
                std::unique_lock cookieULock(*gwlbCookiesMutex[gp.gwlbeEniId]);
                gwlbCookies[gp.gwlbeEniId].erase(foundCookie);
                gwlbCookies[gp.gwlbeEniId].insert(std::pair<PacketHeader, GwlbData>(ph, gd));
                cookieULock.unlock();
                if(debug) *debugout << currentTime() << ": GWLB : Flow " << ph << " replaced:" << gp << std::endl;
            } else {
                foundCookie->second.seenCount ++;
                foundCookie->second.lastSeen = time(nullptr);
                if(debug) *debugout << currentTime() << ": GWLB : Flow exists. Seen " << foundCookie->second.seenCount << " times." << std::endl;
            }
        }

        // Route the decap'ed packet to our tun interface.
        if(pktlen > gp.headerLen)
            tunnelIn[gp.gwlbeEniId]->writePacket(pkt + gp.headerLen, pktlen - gp.headerLen);
    } catch (...) {
        // Something was bad - generally the PacketHeader was not OK. Ignore this packet.
        return;
    }
}

/**
 * Shut down the GeneveHandler. Call all the tunnel destructors first, before letting normal object cleanup occur.
 */
GeneveHandler::~GeneveHandler()
{
    for (auto &ti : tunnelIn)
    {
        destroyCallback(ti.second->devname, tunnelOut[ti.first]->devname, ti.first);
    }
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
    if(debug >= DEBUG_VERBOSE) hexDump(*hexout, pktbuf, pktlen, true, "Tun Packet: ");

    // Ignore packets that cannot contain at least an IPv4 header (20 bytes), and anything besides IPv4 packets.
    // Linux sends out IPv6 Router Solicitation and other things on occasion.
    if( (pktlen < 20) || ((pktbuf[0] & 0xF0) >> 4) != 4) {
        if(debug) *debugout << currentTime() << ": Tun : Packet is not an IPv4 packet, ignoring." << std::endl;
        return;
    }

    // See if we have a matching flow record.  If we don't, or the packet is bad, drop this packet.
    try {
        auto ph = PacketHeader(pktbuf, pktlen);

        std::shared_lock cookieLock(*gwlbCookiesMutex[eniId]);
        auto got = gwlbCookies[eniId].find(ph);
        cookieLock.unlock();
        if (got == gwlbCookies[eniId].end()) {
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
            sendUdp(got->second.dstAddr, got->second.srcPort, got->second.srcAddr, got->second.dstPort, genevePkt,
                    pktlen + got->second.gp.headerLen);

            delete [] genevePkt;
        }
    } catch(...) {
        // PacketHeader failed to parse.
        if(debug) *debugout << currentTime() << ": Tun : Received a malformed packet, ignoring." << std::endl;
        return;
    }
}