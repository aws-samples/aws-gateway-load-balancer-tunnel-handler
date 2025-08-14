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
#include <map>
#include <utility>
#include "Logger.h"

using namespace std::string_literals;

#define GWLB_MTU           8500         // MTU of customer payload packets that can be processed
#define GENEVE_PORT        6081         // UDP port number that GENEVE uses by standard

/**
 * Empty GwlbData initializer. Needed as we move-assign on occasion.
 */
GwlbData::GwlbData() {}

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
        gp(gp), srcAddr(*srcAddr), srcPort(srcPort), dstAddr(*dstAddr), dstPort(dstPort)
{
}

/**
 * Starts the GeneveHandler. Builds a UDPPacketReceiver on port 6081 with callbacks in this class to handle packets
 * as they come in.
 *
 * @param createCallback Function to call when a new endpoint is seen.
 * @param destroyCallback Function to call when an endpoint has gone away and we need to clean up.
 * @param destroyTimeout How long to wait for an endpoint to be idle before calling destroyCallback.
 */
GeneveHandler::GeneveHandler(ghCallback createCallback, ghCallback destroyCallback, int destroyTimeout, int cacheTimeout, ThreadConfig udpThreads, ThreadConfig tunThreads)
        : healthy(true),
          createCallback(std::move(createCallback)), destroyCallback(std::move(destroyCallback)), eniDestroyTimeout(destroyTimeout), cacheTimeout(cacheTimeout),
          tunThreadConfig(std::move(tunThreads))
{
    // Set up UDP receiver threads.
    udpRcvr.setup(udpThreads, GENEVE_PORT, std::bind(&GeneveHandler::udpReceiverCallback, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6));
}

/**
 * Perform a health check of the GeneveHandler and all components it is using.
 *
 * @return A human-readable string of the health status.
 */
GeneveHandlerHealthCheck::GeneveHandlerHealthCheck(bool healthy, UDPPacketReceiverHealthCheck udp, std::list<GeneveHandlerENIHealthCheck> enis) :
    healthy(healthy), udp(std::move(udp)), enis(std::move(enis))
{
}

std::string GeneveHandlerHealthCheck::output_str()
{
    std::string ret;
    ret += udp.output_str();

    for(auto &eni : enis)
        ret += eni.output_str();

    return ret;
}

json GeneveHandlerHealthCheck::output_json()
{
    json ret;

    ret = { {"udp", udp.output_json()}, {"enis", json::array()} };

    for(auto &eni : enis)
        ret["enis"].push_back(eni.output_json());

    return ret;
}

GeneveHandlerHealthCheck GeneveHandler::check()
{
    LOG(LS_HEALTHCHECK, LL_DEBUG, "Health check starting");

    std::list<GeneveHandlerENIHealthCheck> enis;

    // Clean up any ENI handlers that have apparently gone idle, if we're not keeping them around forever.
    if(eniDestroyTimeout > 0)
        eniHandlers.erase_if([&](auto& eniHandler) { return (*eniHandler.second.ptr).hasGoneIdle(eniDestroyTimeout); });

    // Check remaining handlers.
    eniHandlers.visit_all([&enis](auto& eniHandler) { enis.push_back( (*eniHandler.second.ptr).check() );  ; });

    return { udpRcvr.healthCheck(), udpRcvr.status(), enis };
}

/**
 * Callback function passed to UDPPacketReceiver to handle GenevePackets. Detemrine which GeneveHandlerENI this packet
 * is for (creating a new one if needed), and pass to that class.
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
    if(IS_LOGGING(LS_GENEVE, LL_DEBUG))
    {
        LOG(LS_GENEVE, LL_DEBUG, "Received a packet of "s + ts(pktlen) + " bytes from " + inet_ntoa(*srcAddr) + " port " + ts(srcPort) + " sent to " + inet_ntoa(*dstAddr) + " port " + ts(dstPort));
        LOGHEXDUMP(LS_GENEVE, LL_DEBUGDETAIL, "GWLB Packet", pkt, pktlen);
    }
    try {
        auto gp = GenevePacket(pkt, pktlen);
        auto gd = GwlbData(gp, srcAddr, srcPort, dstAddr, dstPort);

        // The GenevePacket class does sanity checks to ensure this was a Geneve packet. Verify the result of those checks.
        if(gp.status != GP_STATUS_OK)
        {
            LOG(LS_GENEVE, LL_DEBUG, "Geneve Header not OK");
            return;
        }

        if(!gp.gwlbeEniIdValid)
        {
            LOG(LS_GENEVE, LL_DEBUG, "GWLBe ENI ID not valid");
            return;
        }

        // Figure out which GeneveHandlerENI this needs to dispatch to, creating if necessary
        if(eniHandlers.try_emplace_or_cvisit(gp.gwlbeEniId, gp.gwlbeEniId, cacheTimeout, tunThreadConfig, createCallback, destroyCallback, [&](const auto& eniHandler)
            {
                (*eniHandler.second.ptr).udpReceiverCallback(gd, pkt, pktlen);
            }))
        {
            // We did a create - redo the visit to do the call.
            eniHandlers.cvisit(gp.gwlbeEniId, [&](const auto& eniHandler)
            {
                (*eniHandler.second.ptr).udpReceiverCallback(gd, pkt, pktlen);
            });
        }
    }
    catch (std::exception& e) {
        LOG(LS_TUNNEL, LL_CRITICAL, "Tunnel or ENI creation failed:"s + e.what());
    }
}


/**
 * GeneveHandlerENI handles all aspects of handling for a given ENI. It is separated out this way to make dealing with
 * keeping all the resources needed on a per ENI basis easier.
 */
GeneveHandlerENI::GeneveHandlerENI(eniid_t eni, int cacheTimeout, ThreadConfig& tunThreadConfig, ghCallback createCallback, ghCallback destroyCallback) :
        eni(eni), eniStr(MakeENIStr(eni)), cacheTimeout(cacheTimeout),
        devInName(devname_make(eni, true)),
#ifndef NO_RETURN_TRAFFIC
        devOutName(devname_make(eni, false)),
        gwlbV4Cookies("IPv4 Flow Cache for ENI " + eniStr, cacheTimeout), gwlbV6Cookies("IPv6 Flow Cache for ENI " + eniStr, cacheTimeout),
#else
    devOutName("none"s),
#endif
        createCallback(std::move(createCallback)), destroyCallback(std::move(destroyCallback))
{
    // Set up a socket we use for sending traffic out for ENI.
    tunnelIn = std::make_unique<TunInterface>(devInName, GWLB_MTU, tunThreadConfig, std::bind(&GeneveHandlerENI::tunReceiverCallback, this, std::placeholders::_1, std::placeholders::_2));
#ifndef NO_RETURN_TRAFFIC
    tunnelOut = std::make_unique<TunInterface>(devOutName, GWLB_MTU, tunThreadConfig, std::bind(&GeneveHandlerENI::tunReceiverCallback, this, std::placeholders::_1, std::placeholders::_2));
    sendingSock = socket(AF_INET,SOCK_RAW, IPPROTO_RAW);
    if(sendingSock == -1)
        throw std::runtime_error("Unable to allocate a socket for sending UDP traffic.");
#endif
    this->createCallback(devInName, devOutName, this->eni);
}

GeneveHandlerENI::~GeneveHandlerENI()
{
    this->destroyCallback(devInName, devOutName, this->eni);
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
void GeneveHandlerENI::tunReceiverCallback(unsigned char *pktbuf, ssize_t pktlen)
{
    LOG(LS_TUNNEL, LL_DEBUG, "Received a packet of " + ts(pktlen) + " bytes for ENI Id:" + eniStr);
    LOGHEXDUMP(LS_TUNNEL, LL_DEBUGDETAIL, "Tun Packet", pktbuf, pktlen);

#ifdef NO_RETURN_TRAFFIC
    LOG(LS_TUNNEL, LL_DEBUG, "Received a packet, but NO_RETURN_TRAFFIC is defined. Discarding.");
    return;
#else
    // Ignore packets that are not IPv4 or IPv6, or aren't at least long enough to have those sized headers.
    if( pktlen < 20 )
    {
        LOG(LS_TUNNEL, LL_DEBUG, "Received a packet that is not long enough to have an IP header, ignoring.");
        return;
    }
    try
    {
        GwlbData gd;

        switch( (pktbuf[0] & 0xF0) >> 4)
        {
            case 4:
            {
                auto ph = PacketHeaderV4(pktbuf, pktlen);
                try {
                    gd = gwlbV4Cookies.lookup(ph);
                }
                catch (std::invalid_argument &e) {
                    LOG(LS_TUNNEL, LL_DEBUG, "Flow " + ph.text() + " has not been seen coming in from GWLB - dropping.  (Remember - GWLB is for inline inspection only - you cannot source new flows from this device into it.)");
                    return;
                }
                LOG(LS_TUNNEL, LL_DEBUGDETAIL, "Resolved packet header " + ph.text() + " to options " + gd.gp.text());
                break;
            }
            case 6:
            {
                auto ph = PacketHeaderV6(pktbuf, pktlen);
                try {
                    gd = gwlbV6Cookies.lookup(ph);
                }
                catch (std::invalid_argument &e) {
                    LOG(LS_TUNNEL, LL_DEBUG, "Flow " + ph.text() + " has not been seen coming in from GWLB - dropping.  (Remember - GWLB is for inline inspection only - you cannot source new flows from this device into it.)");
                    return;
                }
                LOG(LS_TUNNEL, LL_DEBUGDETAIL, "Resolved packet header " + ph.text() + " to options " + gd.gp.text());
                break;
            }
            default:
            {
                LOG(LS_TUNNEL, LL_DEBUG, "Received a packet that wasn't IPv4 or IPv6. Ignoring.");
                return;
            }
        }

        // Build the packet to send back to GWLB.
        // Following as per https://aws.amazon.com/blogs/networking-and-content-delivery/integrate-your-custom-logic-or-appliance-with-aws-gateway-load-balancer/
        unsigned char *genevePkt = new unsigned char[pktlen + gd.gp.headerLen];
        // Encapsulate this packet with the original Geneve header
        memcpy(genevePkt, &gd.gp.header.front(), gd.gp.headerLen);
        // Copy the packet in after the Geneve header.
        memcpy(genevePkt + gd.gp.headerLen, pktbuf, pktlen);
        // Swap source and destination IP addresses, but preserve ports, and send back to GWLB.
        sendUdp(sendingSock, gd.dstAddr, gd.srcPort, gd.srcAddr, gd.dstPort, genevePkt, pktlen + gd.gp.headerLen);
        delete[] genevePkt;
    } catch(std::invalid_argument& err) {
        LOG(LS_TUNNEL, LL_DEBUG, "Packet processor has a malformed packet: "s + err.what());
        return;
    }
#endif
}

/**
 * Callback function passed to UDPPacketReceiver to handle GenevePackets. Called by GeneveHandler once the ENI
 * has been determined (creating this class if needed)
 *
 * @param gd The GwlbData (it was processed by GeneveHandler to do its work)
 * @param pkt The packet received.
 * @param pktlen Length of packet received.
 */
void GeneveHandlerENI::udpReceiverCallback(const GwlbData &gd, unsigned char *pkt, ssize_t pktlen)
{
    try {
        if( (pktlen - gd.gp.headerLen) > (ssize_t)sizeof(struct ip) )
        {
            struct ip *iph = (struct ip *)(pkt + gd.gp.headerLen);
            if(iph->ip_v == (unsigned int)4)
            {
#ifndef NO_RETURN_TRAFFIC
                auto ph = PacketHeaderV4(pkt + gd.gp.headerLen, pktlen - gd.gp.headerLen);
                // Ensure flow is in flow cache.
                gwlbV4Cookies.insert(std::move(ph), std::move(gd));
#endif
                // Route the decap'ed packet to our tun interface.
                (*tunnelIn).writePacket(pkt + gd.gp.headerLen, pktlen - gd.gp.headerLen);
            } else if(iph->ip_v == (unsigned int)6) {
#ifndef NO_RETURN_TRAFFIC
                auto ph = PacketHeaderV6(pkt + gd.gp.headerLen, pktlen - gd.gp.headerLen);
                // Ensure flow is in flow cache.
                gwlbV6Cookies.insert(std::move(ph), std::move(gd));
#endif
                // Route the decap'ed packet to our tun interface.
                (*tunnelIn).writePacket(pkt + gd.gp.headerLen, pktlen - gd.gp.headerLen);
            } else {
                LOG(LS_UDP, LL_DEBUG, "Got a strange IP protocol version - "s  + ts(iph->ip_v) + " at offset " + ts(gd.gp.headerLen) + ". Dropping packet.");
            }
        }
    } catch(std::invalid_argument& err) {
        LOG(LS_UDP, LL_DEBUG, "Packet processor has a malformed packet: "s + err.what());
        return;
    }
}

/**
 * Perform a health check on this ENI, and return some information.
 * @return
 */
#ifndef NO_RETURN_TRAFFIC
GeneveHandlerENIHealthCheck::GeneveHandlerENIHealthCheck(std::string eniStr, TunInterfaceHealthCheck tunnelIn, TunInterfaceHealthCheck tunnelOut, FlowCacheHealthCheck v4FlowCache, FlowCacheHealthCheck v6FlowCache) :
        eniStr(eniStr), tunnelIn(std::move(tunnelIn)), tunnelOut(std::move(tunnelOut)), v4FlowCache(std::move(v4FlowCache)), v6FlowCache(std::move(v6FlowCache))
{
}
#else
GeneveHandlerENIHealthCheck::GeneveHandlerENIHealthCheck(std::string eniStr, TunInterfaceHealthCheck tunnelIn) :
    eniStr(eniStr), tunnelIn(std::move(tunnelIn))
{
}
#endif

std::string GeneveHandlerENIHealthCheck::output_str()
{
    std::stringstream ret;

    ret << "Handler for ENI " << eniStr << std::endl;

    ret << tunnelIn.output_str();
#ifndef NO_RETURN_TRAFFIC
    ret << tunnelOut.output_str();
    ret << v4FlowCache.output_str();
    ret << v6FlowCache.output_str();
#endif

    return ret.str();
}

json GeneveHandlerENIHealthCheck::output_json()
{
#ifndef NO_RETURN_TRAFFIC
    return {{"eniStr", eniStr}, {"tunnelIn", tunnelIn.output_json()}, {"tunnelOut", tunnelOut.output_json()}, {"v4FlowCache", v4FlowCache.output_json()}, {"v6FlowCache", v6FlowCache.output_json()}};
#else
    return {{"eniStr", eniStr}, {"tunnelIn", tunnelIn.output_json()}};
#endif
    // TODO.
}

GeneveHandlerENIHealthCheck GeneveHandlerENI::check()
{
#ifndef NO_RETURN_TRAFFIC
    return { eniStr, tunnelIn->status(), tunnelOut->status(), gwlbV4Cookies.check(), gwlbV6Cookies.check()};
#else
    return { eniStr, tunnelIn->status() };
#endif
}

/**
 * Check to see if we haven't seen traffic in timeout seconds.
 *
 * @return True if we haven't seen a packet in timeout seconds, false otherwise.
 */
bool GeneveHandlerENI::hasGoneIdle(int timeout)
{
    std::chrono::steady_clock::time_point expireTime = std::chrono::steady_clock::now() - std::chrono::seconds(timeout);

    if(tunnelIn->lastPacketTime() > expireTime) return false;
#ifndef NO_RETURN_TRAFFIC
    if(tunnelOut->lastPacketTime() > expireTime) return false;
#endif
    return true;
}

/**
 * GeneveHandlerENI unique_ptr wrapper class
 */
GeneveHandlerENIPtr::GeneveHandlerENIPtr(eniid_t eni, int cacheTimeout, ThreadConfig &tunThreadConfig, ghCallback createCallback, ghCallback destroyCallback)
{
    ptr = std::make_unique<GeneveHandlerENI>(eni, cacheTimeout, tunThreadConfig, createCallback, destroyCallback);
}


std::string devname_make(eniid_t eni, bool inbound) {
    if(inbound)
        return "gwi-"s + toBase60(eni);
    else
        return "gwo-"s + toBase60(eni);
}


