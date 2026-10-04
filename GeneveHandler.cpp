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
#include <utility>
#include "Logger.h"
#include <system_error>
#include <cerrno>

using namespace std::string_literals;

#define GWLB_MTU           8500         // MTU of inner/decapsulated packets (TUN interface)
#define GENEVE_PORT        6081         // UDP port number that GENEVE uses by standard

// Define the thread-local cache declared in the header
thread_local std::unordered_map<const GeneveHandler*, std::unordered_map<gwlbeid_t, std::weak_ptr<GeneveHandlerENI>>> GeneveHandler::tlsEniCache;

/**
 * Empty GwlbData initializer. Needed as we move-assign on occasion.
 */
GwlbData::GwlbData() {}

/**
 * Build a GwlbData structure. Stores the data, and sets the lastSeen timer to now.
 *
 * @param header GeneveHeader to store
 * @param srcAddr Source address of the GENEVE packet
 * @param srcPort Source port of the GENEVE packet
 * @param dstAddr Destination address of the GENEVE packet
 * @param dstPort Destination port of the GENEVE packet
 */
GwlbData::GwlbData(GeneveHeader header, struct in_addr *srcAddr, uint16_t srcPort, struct in_addr *dstAddr, uint16_t dstPort) :
       header(std::move(header)), srcAddr(*srcAddr), dstAddr(*dstAddr), srcPort(srcPort), dstPort(dstPort)
{
}

std::string GwlbData::text()
{
    auto gp = GenevePacket(header.data(), header.size());
    return gp.text();
}

/**
 * Starts the GeneveHandler. Builds a UDPPacketReceiver on port 6081 with callbacks in this class to handle packets
 * as they come in.
 *
 * @param createCallback Function to call when a new endpoint is seen.
 * @param destroyCallback Function to call when an endpoint has gone away and we need to clean up.
 * @param cfg Immutable runtime configuration (timeouts, thread configs, socket buffer, busy-poll).
 */
GeneveHandler::GeneveHandler(ghCallback createCallback, ghCallback destroyCallback, const GwlbtunConfig& cfg)
        : healthy(true),
          createCallback(std::move(createCallback)), destroyCallback(std::move(destroyCallback)),
          config(cfg)
{
    // Set up UDP receiver threads.
    udpRcvr.setup(config.udpThreads, GENEVE_PORT, std::bind(&GeneveHandler::udpReceiverCallback, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6), config.rcvBufSizeMB, config.busyPollUsec);
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

    // Calculate aggregate totals
    uint64_t totalPktsIn = 0, totalBytesIn = 0;
    uint64_t totalPktsOut = 0, totalBytesOut = 0, totalPktsDropped = 0;
    
    // Sum UDP receiver stats (packets in)
    auto udpJson = udp.output_json();
    if(udpJson.contains("UDPPacketReceiver") && udpJson["UDPPacketReceiver"].contains("threads"))
    {
        for(auto& thread : udpJson["UDPPacketReceiver"]["threads"])
        {
            if(thread.contains("pktsIn")) totalPktsIn += thread["pktsIn"].get<uint64_t>();
            if(thread.contains("bytesIn")) totalBytesIn += thread["bytesIn"].get<uint64_t>();
        }
    }
    
    // Sum ENI stats (packets out to OS)
    for(auto &eni : enis)
    {
        auto eniJson = eni.output_json();
        if(eniJson.contains("pktsOut")) totalPktsOut += eniJson["pktsOut"].get<uint64_t>();
        if(eniJson.contains("bytesOut")) totalBytesOut += eniJson["bytesOut"].get<uint64_t>();
        if(eniJson.contains("pktsDropped")) totalPktsDropped += eniJson["pktsDropped"].get<uint64_t>();
    }

    ret = { 
        {"summary", {
            {"totalPktsIn", totalPktsIn},
            {"totalBytesIn", totalBytesIn},
            {"totalPktsOut", totalPktsOut},
            {"totalBytesOut", totalBytesOut},
            {"totalPktsDropped", totalPktsDropped},
            {"eniCount", enis.size()}
        }},
        {"udp", udpJson}, 
        {"enis", json::array()} 
    };

    for(auto &eni : enis)
        ret["enis"].push_back(eni.output_json());

    return ret;
}

GeneveHandlerHealthCheck GeneveHandler::check()
{
    LOG(LS_HEALTHCHECK, LL_DEBUG, "Health check starting");

    std::list<GeneveHandlerENIHealthCheck> enis;

    // Report-only: no eviction here (see sweep()).
    eniHandlers.visit_all([&enis](auto& eniHandler) { enis.push_back( (*eniHandler.second.ptr).check() ); });

    // Aggregate overall health: UDP receiver threads plus every ENI's tunnel threads. Previously
    // this->healthy was never written, so main.cpp's health endpoint always reported 200 OK.
    bool enisHealthy = true;
    for(auto &eni : enis)
        if(!eni.isHealthy())
            enisHealthy = false;
    this->healthy = udpRcvr.healthCheck() && enisHealthy;

    return { this->healthy, udpRcvr.status(), enis };
}

void GeneveHandler::sweep()
{
    // Evict expired flow-cache entries, then reap ENI handlers idle past the
    // tunnel timeout. Decoupled from check()/health reporting so a health poll
    // never triggers the O(N) cache scan.
    eniHandlers.visit_all([](auto& eniHandler) { (*eniHandler.second.ptr).sweepCaches(); });
    if(config.tunnelTimeout > 0)
        eniHandlers.erase_if([&](auto& eniHandler) { return (*eniHandler.second.ptr).hasGoneIdle(config.tunnelTimeout); });
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
        // The GenevePacket class does sanity checks to ensure this was a Geneve packet. Verify the result of those checks.
        if(gp.status != GP_STATUS_OK)
        {
            LOG(LS_GENEVE, LL_DEBUG, "Geneve Header not OK");
            return;
        }

        if(!gp.gwlbeEndpointIdValid)
        {
            LOG(LS_GENEVE, LL_DEBUG, "GWLBe endpoint ID not valid");
            return;
        }

        auto gwlbeEndpointId = gp.gwlbeEndpointId;
        auto header = GeneveHeader(pkt, pkt + gp.headerLen);
        auto gd = GwlbData(std::move(header), srcAddr, srcPort, dstAddr, dstPort);

        // Fast path: check thread-local weak cache first
        auto &localCache = tlsEniCache[this];
        if (auto it = localCache.find(gwlbeEndpointId); it != localCache.end()) {
            if (auto sp = it->second.lock()) {
                sp->udpReceiverCallback(std::move(gd), pkt, pktlen);
                return;
            } else {
                localCache.erase(it);
            }
        }

        // Slow path: concurrent map and possible construction
        std::shared_ptr<GeneveHandlerENI> resolvedHandler;
        auto cb = [&](const auto& eniHandler) {
            resolvedHandler = eniHandler.second.ptr;
        };
        if(eniHandlers.try_emplace_or_cvisit(gwlbeEndpointId, gwlbeEndpointId, config.tcpCacheTimeout, config.udpCacheTimeout, config.otherCacheTimeout, config.tunThreads, createCallback, destroyCallback, cb))
        {
            // We did a create - redo the visit to capture ptr
            eniHandlers.cvisit(gwlbeEndpointId, cb);
        }

        // Store in thread-local cache and dispatch
        if (resolvedHandler) {
            localCache.emplace(gwlbeEndpointId, std::weak_ptr<GeneveHandlerENI>(resolvedHandler));
            resolvedHandler->udpReceiverCallback(std::move(gd), pkt, pktlen);
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
GeneveHandlerENI::GeneveHandlerENI(gwlbeid_t eni, int tcpCacheTimeout, int udpCacheTimeout, int otherCacheTimeout, const ThreadConfig& tunThreadConfig, ghCallback createCallback, ghCallback destroyCallback) :
        eni(eni), eniStr(MakeGwlbeStr(eni)), tcpCacheTimeout(tcpCacheTimeout), udpCacheTimeout(udpCacheTimeout), otherCacheTimeout(otherCacheTimeout),
        devInName(devname_make(eni, true)),
#ifndef NO_RETURN_TRAFFIC
        devOutName(devname_make(eni, false)),
        gwlbV4CookiesTcp("IPv4 TCP Flow Cache for GWLBe vpce-" + eniStr, tcpCacheTimeout),
        gwlbV4CookiesUdp("IPv4 UDP Flow Cache for GWLBe vpce-" + eniStr, udpCacheTimeout),
        gwlbV4CookiesOther("IPv4 Other Flow Cache for GWLBe vpce-" + eniStr, otherCacheTimeout),
        gwlbV6CookiesTcp("IPv6 TCP Flow Cache for GWLBe vpce-" + eniStr, tcpCacheTimeout),
        gwlbV6CookiesUdp("IPv6 UDP Flow Cache for GWLBe vpce-" + eniStr, udpCacheTimeout),
        gwlbV6CookiesOther("IPv6 Other Flow Cache for GWLBe vpce-" + eniStr, otherCacheTimeout),
#else
    devOutName("none"s),
#endif
        gwiWriter(devname_make(eni, true)),
        lastPacketOut(std::chrono::steady_clock::now()),
        sendingSock(-1),
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
    try {
        this->createCallback(devInName, devOutName, this->eni);
    } catch(...) {
#ifndef NO_RETURN_TRAFFIC
        close(sendingSock);
#endif
        throw;
    }
}

GeneveHandlerENI::~GeneveHandlerENI()
{
#ifndef NO_RETURN_TRAFFIC
    if(sendingSock != -1)
        close(sendingSock);
#endif
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
thread_local unsigned char genevePktBuffer[16000];

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
                std::optional<GwlbData> found;
                switch(ph.prot)
                {
                    case IPPROTO_TCP: found = gwlbV4CookiesTcp.lookup(ph); break;
                    case IPPROTO_UDP: found = gwlbV4CookiesUdp.lookup(ph); break;
                    default:          found = gwlbV4CookiesOther.lookup(ph); break;
                }
                if(!found) {
                    LOG(LS_TUNNEL, LL_DEBUG, "Flow " + ph.text() + " has not been seen coming in from GWLB - dropping.  (Remember - GWLB is for inline inspection only - you cannot source new flows from this device into it.)");
                    return;
                }
                gd = std::move(*found);
                LOG(LS_TUNNEL, LL_DEBUGDETAIL, "Resolved packet header " + ph.text() + " to options " + gd.text());
                break;
            }
            case 6:
            {
                auto ph = PacketHeaderV6(pktbuf, pktlen);
                std::optional<GwlbData> found;
                switch(ph.prot)
                {
                    case IPPROTO_TCP: found = gwlbV6CookiesTcp.lookup(ph); break;
                    case IPPROTO_UDP: found = gwlbV6CookiesUdp.lookup(ph); break;
                    default:          found = gwlbV6CookiesOther.lookup(ph); break;
                }
                if(!found) {
                    LOG(LS_TUNNEL, LL_DEBUG, "Flow " + ph.text() + " has not been seen coming in from GWLB - dropping.  (Remember - GWLB is for inline inspection only - you cannot source new flows from this device into it.)");
                    return;
                }
                gd = std::move(*found);
                LOG(LS_TUNNEL, LL_DEBUGDETAIL, "Resolved packet header " + ph.text() + " to options " + gd.text());
                break;
            }
            default:
            {
                LOG(LS_TUNNEL, LL_DEBUG, "Received a packet that wasn't IPv4 or IPv6. Ignoring.");
                return;
            }
        }

        // Build scatter-gather array pointing to existing data
        struct iovec payload[2];
        payload[0].iov_base = (void*)&gd.header.front();  // Geneve header (already in memory)
        payload[0].iov_len = gd.header.size();
        payload[1].iov_base = pktbuf;                    // Original packet (already in memory)
        payload[1].iov_len = pktlen;

        // Send scatter-gather
        sendUdpSG(sendingSock, gd.dstAddr, gd.srcPort, gd.srcAddr, gd.dstPort, payload, 2);
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
// Rate-limited notice for the rare case where an established flow's stored GWLB
// cookie changes (e.g. GWLB re-balanced the flow). Logs the first occurrence and
// then every 4096th, so a genuine problem is visible without flooding.
static void logCookieChanged(const std::string& eniStr)
{
    static std::atomic<uint64_t> n{0};
    uint64_t c = n.fetch_add(1, std::memory_order_relaxed);
    if((c & 0xFFF) == 0)
        LOG(LS_UDP, LL_IMPORTANT, "GWLB flow cookie changed for an established flow on GWLBe vpce-" + eniStr + " (occurrences=" + std::to_string(c + 1) + "). Usually benign; investigate if frequent (e.g. a gwlbtun/GWLB idle-timeout mismatch).");
}

void GeneveHandlerENI::udpReceiverCallback(GwlbData gd, unsigned char *pkt, ssize_t pktlen)
{
    auto headerLen = gd.header.size();
    try {
        if(__builtin_expect((pktlen - headerLen) > (ssize_t)sizeof(struct ip), 1))
        {
            struct ip *iph = (struct ip *)(pkt + headerLen);
            if(__builtin_expect(iph->ip_v == (unsigned int)4, 1))
            {
#ifndef NO_RETURN_TRAFFIC
                auto ph = PacketHeaderV4(pkt + headerLen, pktlen - headerLen);
                // Insert the flow if new, otherwise just refresh its idle timer.
                bool cookieChanged = false;
                switch(ph.prot)
                {
                    case IPPROTO_TCP: cookieChanged = gwlbV4CookiesTcp.insert(std::move(ph), std::move(gd)); break;
                    case IPPROTO_UDP: cookieChanged = gwlbV4CookiesUdp.insert(std::move(ph), std::move(gd)); break;
                    default:          cookieChanged = gwlbV4CookiesOther.insert(std::move(ph), std::move(gd)); break;
                }
                if(__builtin_expect(cookieChanged, 0))
                    logCookieChanged(eniStr);
#endif
                // Route the decap'ed packet to our tun interface, accounting for drops.
                writeToTun(pkt + headerLen, pktlen - headerLen);
            } else if(__builtin_expect(iph->ip_v == (unsigned int)6, 0)) {
#ifndef NO_RETURN_TRAFFIC
                auto ph = PacketHeaderV6(pkt + headerLen, pktlen - headerLen);
                // Insert the flow if new, otherwise just refresh its idle timer.
                bool cookieChanged = false;
                switch(ph.prot)
                {
                    case IPPROTO_TCP: cookieChanged = gwlbV6CookiesTcp.insert(std::move(ph), std::move(gd)); break;
                    case IPPROTO_UDP: cookieChanged = gwlbV6CookiesUdp.insert(std::move(ph), std::move(gd)); break;
                    default:          cookieChanged = gwlbV6CookiesOther.insert(std::move(ph), std::move(gd)); break;
                }
                if(__builtin_expect(cookieChanged, 0))
                    logCookieChanged(eniStr);
#endif
                // Route the decap'ed packet to our tun interface, accounting for drops.
                writeToTun(pkt + headerLen, pktlen - headerLen);
            } else {
                LOG(LS_UDP, LL_DEBUG, "Got a strange IP protocol version - "s  + ts(iph->ip_v) + " at offset " + ts(headerLen) + ". Dropping packet.");
            }
        }
    } catch(std::invalid_argument& err) {
        LOG(LS_UDP, LL_DEBUG, "Packet processor has a malformed packet: "s + err.what());
        return;
    }
}

/**
 * Write a decapsulated packet to the ingress tun interface, counting a successful
 * write toward pktsOut/bytesOut, or a write error / short write toward pktsDropped.
 */
void GeneveHandlerENI::writeToTun(const unsigned char *pkt, ssize_t pktlen)
{
    ssize_t written = gwiWriter.write(pkt, pktlen);
    lastPacketOut = std::chrono::steady_clock::now();
    if(__builtin_expect(written == pktlen, 1))
    {
        pktsOut++;
        bytesOut += pktlen;
    }
    else
    {
        pktsDropped++;
        if(written < 0)
            LOG(LS_UDP, LL_IMPORTANT, "Failed to write "s + ts(pktlen) + " byte packet to "s + devInName + ": "s + std::error_code{errno, std::generic_category()}.message());
        else
            LOG(LS_UDP, LL_IMPORTANT, "Partial write to "s + devInName + ": only "s + ts(written) + " of "s + ts(pktlen) + " bytes written; dropping packet."s);
    }
}

/**
 * Perform a health check on this ENI, and return some information.
 * @return
 */
GeneveHandlerENIHealthCheck::GeneveHandlerENIHealthCheck(bool healthy, std::string eniStr,
                                                         uint64_t pktsOut, uint64_t bytesOut, uint64_t pktsDropped, std::chrono::steady_clock::time_point lastPacketOut,
                                                         TunInterfaceHealthCheck tunnelIn
#ifndef NO_RETURN_TRAFFIC
                                                         , TunInterfaceHealthCheck tunnelOut,
                                                         FlowCacheHealthCheck v4FlowCacheTcp, FlowCacheHealthCheck v4FlowCacheUdp, FlowCacheHealthCheck v4FlowCacheOther,
                                                         FlowCacheHealthCheck v6FlowCacheTcp, FlowCacheHealthCheck v6FlowCacheUdp, FlowCacheHealthCheck v6FlowCacheOther
#endif
                                                         ) :
        healthy(healthy), eniStr(eniStr), pktsOut(pktsOut), bytesOut(bytesOut), pktsDropped(pktsDropped), lastPacketOut(lastPacketOut), tunnelIn(std::move(tunnelIn))
#ifndef NO_RETURN_TRAFFIC
        , tunnelOut(std::move(tunnelOut)),
        v4FlowCacheTcp(std::move(v4FlowCacheTcp)), v4FlowCacheUdp(std::move(v4FlowCacheUdp)), v4FlowCacheOther(std::move(v4FlowCacheOther)),
        v6FlowCacheTcp(std::move(v6FlowCacheTcp)), v6FlowCacheUdp(std::move(v6FlowCacheUdp)), v6FlowCacheOther(std::move(v6FlowCacheOther))
#endif
{
}

std::string GeneveHandlerENIHealthCheck::output_str()
{
    std::stringstream ret;

    ret << "Handler for GWLBe vpce-" << eniStr << " is " << (healthy ? "healthy" : "UNHEALTHY") << std::endl;
    ret << std::to_string(pktsOut) << " packets out to OS, " << std::to_string(bytesOut) << " bytes out to OS, " << std::to_string(pktsDropped) << " packets dropped on write, " << timepointDeltaString(std::chrono::steady_clock::now(), lastPacketOut) + " since last packet.\n";
    ret << tunnelIn.output_str();
#ifndef NO_RETURN_TRAFFIC
    ret << tunnelOut.output_str();
    ret << v4FlowCacheTcp.output_str();
    ret << v4FlowCacheUdp.output_str();
    ret << v4FlowCacheOther.output_str();
    ret << v6FlowCacheTcp.output_str();
    ret << v6FlowCacheUdp.output_str();
    ret << v6FlowCacheOther.output_str();
#endif

    return ret.str();
}

json GeneveHandlerENIHealthCheck::output_json()
{
    return {{"healthy", healthy}, {"gwlbEndpointId", "vpce-" + eniStr}, {"pktsOut", pktsOut}, {"bytesOut", bytesOut}, {"pktsDropped", pktsDropped}, {"secsSinceLastPacket", timepointDeltaDouble(std::chrono::steady_clock::now(), lastPacketOut)}, {"tunnelIn", tunnelIn.output_json()}
#ifndef NO_RETURN_TRAFFIC
    , {"tunnelOut", tunnelOut.output_json()},
    {"v4FlowCacheTcp", v4FlowCacheTcp.output_json()}, {"v4FlowCacheUdp", v4FlowCacheUdp.output_json()}, {"v4FlowCacheOther", v4FlowCacheOther.output_json()},
    {"v6FlowCacheTcp", v6FlowCacheTcp.output_json()}, {"v6FlowCacheUdp", v6FlowCacheUdp.output_json()}, {"v6FlowCacheOther", v6FlowCacheOther.output_json()}
#endif
    };
}

GeneveHandlerENIHealthCheck GeneveHandlerENI::check()
{
#ifndef NO_RETURN_TRAFFIC
    bool healthy = tunnelIn->healthCheck() && tunnelOut->healthCheck();
#else
    bool healthy = tunnelIn->healthCheck();
#endif
    return { healthy, eniStr, pktsOut.load(), bytesOut.load(), pktsDropped.load(), lastPacketOut.load(), tunnelIn->status()
#ifndef NO_RETURN_TRAFFIC
             , tunnelOut->status(),
             gwlbV4CookiesTcp.stats(), gwlbV4CookiesUdp.stats(), gwlbV4CookiesOther.stats(),
             gwlbV6CookiesTcp.stats(), gwlbV6CookiesUdp.stats(), gwlbV6CookiesOther.stats()
#endif
    };
}

void GeneveHandlerENI::sweepCaches()
{
#ifndef NO_RETURN_TRAFFIC
    gwlbV4CookiesTcp.sweep(); gwlbV4CookiesUdp.sweep(); gwlbV4CookiesOther.sweep();
    gwlbV6CookiesTcp.sweep(); gwlbV6CookiesUdp.sweep(); gwlbV6CookiesOther.sweep();
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

    if(lastPacketOut.load() > expireTime) return false;
#ifndef NO_RETURN_TRAFFIC
    if(tunnelIn->lastPacketTime() > expireTime) return false;
    if(tunnelOut->lastPacketTime() > expireTime) return false;
#endif
    return true;
}

/**
 * GeneveHandlerENI shared pointer wrapper class
 */
GeneveHandlerENIPtr::GeneveHandlerENIPtr(gwlbeid_t eni, int tcpCacheTimeout, int udpCacheTimeout, int otherCacheTimeout, const ThreadConfig &tunThreadConfig, ghCallback createCallback, ghCallback destroyCallback)
{
    ptr = std::make_shared<GeneveHandlerENI>(eni, tcpCacheTimeout, udpCacheTimeout, otherCacheTimeout, tunThreadConfig, createCallback, destroyCallback);
}


std::string devname_make(gwlbeid_t eni, bool inbound) {
    if(inbound)
        return "gwi-"s + toBase60(eni);
    else
        return "gwo-"s + toBase60(eni);
}


