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
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <ctime>

using namespace std::string_literals;

#define GWLB_MTU           8500         // MTU of inner/decapsulated packets (TUN interface)
#define GENEVE_PORT        6081         // UDP port number that GENEVE uses by standard

// Monotonic nanoseconds (CLOCK_MONOTONIC), same clock as the eBPF maps' last_seen_ns /
// last_sent_ns (bpf_ktime_get_ns), so ages can be compared directly.
static uint64_t nowNs()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

#ifdef ENABLE_EBPF
// Auto-detect the GWLB-facing physical interface to attach the XDP ingress program to.
// GWLB delivers GENEVE traffic over the instance's primary network path, so the interface
// that owns the IPv4 default route is the one we want. Parse /proc/net/route for the entry
// whose destination and mask are both 0.0.0.0 and return its interface name. Returns an
// empty string if no default route can be found (caller then logs and skips attach rather
// than guessing a name).
static std::string detectIngressInterface()
{
    FILE *f = fopen("/proc/net/route", "r");
    if(!f)
    {
        LOG(LS_EBPF, LL_IMPORTANT, "Could not open /proc/net/route to auto-detect the ingress interface: "s + strerror(errno));
        return ""s;
    }

    char iface[32];
    unsigned long dest, mask;
    int flags;
    std::string result;
    char line[256];

    // Skip the header line.
    if(fgets(line, sizeof(line), f))
    {
        // Columns: Iface Destination Gateway Flags RefCnt Use Metric Mask ...
        while(fgets(line, sizeof(line), f))
        {
            if(sscanf(line, "%31s %lx %*x %x %*d %*d %*d %lx", iface, &dest, &flags, &mask) == 4)
            {
                // Default route: destination 0.0.0.0, mask 0.0.0.0, route is up (RTF_UP = 0x1).
                if(dest == 0 && mask == 0 && (flags & 0x1))
                {
                    result = iface;
                    break;
                }
            }
        }
    }
    fclose(f);

    if(result.empty())
        LOG(LS_EBPF, LL_IMPORTANT, "Could not find a default route in /proc/net/route; unable to auto-detect the GWLB-facing ingress interface."s);
    return result;
}
#endif

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
    // Set up eBPF acceleration FIRST, if we were given a path to a compiled object file.
    // This must happen before the UDP receiver starts, because the first GENEVE packet
    // creates a GeneveHandlerENI whose constructor attaches the per-ENI egress (gwo) tc
    // program -- and that attach is gated on the loader already being enabled. If the
    // receiver started first, an ENI created in the gap would never get its egress program
    // attached (and, being long-lived, would never retry), so return traffic silently
    // falls back to userspace. Ingress (physical NIC) is attached here too.
    if(!config.ebpfObjectPath.empty()) {
#ifdef ENABLE_EBPF
        // Size the global eBPF flow maps from the --reserve config. These maps are shared
        // across all GWLB endpoints, so the budget is the default reserve plus each explicit
        // per-endpoint override, summed per address family. Egress stores 2 entries per flow
        // (forward + reverse 5-tuple); ingress 1 per flow. Floors keep a sane minimum when
        // reserves are small or zero. This replaces the old hardcoded 2048/512 egress caps.
        std::size_t v4budget = config.defaultReserve[0] + config.defaultReserve[1] + config.defaultReserve[2];
        std::size_t v6budget = config.defaultReserve[3] + config.defaultReserve[4] + config.defaultReserve[5];
        for (const auto& kv : config.perEndpointReserve) {
            v4budget += kv.second[0] + kv.second[1] + kv.second[2];
            v6budget += kv.second[3] + kv.second[4] + kv.second[5];
        }
        std::size_t ipv4Max = 2 * v4budget;        if (ipv4Max   < 2048) ipv4Max   = 2048;
        std::size_t ipv6Max = 2 * v6budget;        if (ipv6Max   < 512)  ipv6Max   = 512;
        std::size_t ingressMax = v4budget + v6budget; if (ingressMax < 4096) ingressMax = 4096;
        LOG(LS_EBPF, LL_IMPORTANT, "eBPF flow-map sizing from --reserve: ipv4_flows_map="s + ts(ipv4Max)
            + " ipv6_flows_map="s + ts(ipv6Max) + " ingress_rt_map="s + ts(ingressMax)
            + " (budget: v4="s + ts(v4budget) + " v6="s + ts(v6budget) + " flows)"s);
        if (!ebpfLoader.loadProgram(config.ebpfObjectPath, (uint32_t)ingressMax, (uint32_t)ipv4Max, (uint32_t)ipv6Max)) {
            LOG(LS_EBPF, LL_CRITICAL, "Failed to load eBPF program from "s + config.ebpfObjectPath);
            exit(EXIT_FAILURE);
        }
        // Attach the eBPF program to the ingress (physical) interface. If the operator
        // named one explicitly (e.g. a dedicated GWLB-data ENI distinct from the primary
        // management ENI), honor it; otherwise auto-detect the NIC owning the default route.
        std::string ingressIface = config.ebpfIngressInterface;
        if(ingressIface.empty()) {
            ingressIface = detectIngressInterface();
            if(!ingressIface.empty())
                LOG(LS_EBPF, LL_IMPORTANT, "Auto-detected GWLB-facing ingress interface "s + ingressIface + " (default route). Override with --ebpf-interface if GWLB traffic uses a different ENI."s);
        } else {
            LOG(LS_EBPF, LL_IMPORTANT, "Using operator-specified eBPF ingress interface "s + ingressIface);
        }
        if(ingressIface.empty()) {
            LOG(LS_EBPF, LL_CRITICAL, "Could not determine a GWLB-facing ingress interface; eBPF ingress acceleration will be unavailable. Specify one with --ebpf-interface."s);
        } else {
            ebpfLoader.attachIngressProgram(ingressIface);
        }
#else
        LOG(LS_EBPF, LL_IMPORTANT, "eBPF acceleration was requested, but this build of gwlbtun was compiled without eBPF support. Continuing; all packets will be processed in userspace."s);
#endif
    }

    // Set up UDP receiver threads. Done AFTER eBPF load so the loader is ready before the
    // first packet creates an ENI handler (see above).
    udpRcvr.setup(config.udpThreads, GENEVE_PORT, std::bind(&GeneveHandler::udpReceiverCallback, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6), config.rcvBufSizeMB, config.busyPollUsec);
}

/**
 * Perform a health check of the GeneveHandler and all components it is using.
 *
 * @return A human-readable string of the health status.
 */
GeneveHandlerHealthCheck::GeneveHandlerHealthCheck(bool healthy, UDPPacketReceiverHealthCheck udp, std::list<GeneveHandlerENIHealthCheck> enis, EbpfLoaderHealthCheck ebpfLoader) :
    healthy(healthy), udp(std::move(udp)), enis(std::move(enis)), ebpfLoader(std::move(ebpfLoader))
{
}

std::string GeneveHandlerHealthCheck::output_str()
{
    std::string ret;
    ret += udp.output_str();

    for(auto &eni : enis)
        ret += eni.output_str();

    ret += ebpfLoader.output_str();

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
        {"enis", json::array()},
        {"ebpf", ebpfLoader.output_json()}
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

    return { this->healthy, udpRcvr.status(), enis, ebpfLoader.check() };
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
                sp->udpReceiverCallback(std::move(gd), gp.flowCookie, pkt, pktlen);
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
        if(eniHandlers.try_emplace_or_cvisit(gwlbeEndpointId, gwlbeEndpointId, config.tcpCacheTimeout, config.udpCacheTimeout, config.otherCacheTimeout, config.tunThreads, config.reserveFor(gwlbeEndpointId), createCallback, destroyCallback, &ebpfLoader, cb))
        {
            // We did a create - redo the visit to capture ptr
            eniHandlers.cvisit(gwlbeEndpointId, cb);
        }

        // Store in thread-local cache and dispatch
        if (resolvedHandler) {
            localCache.emplace(gwlbeEndpointId, std::weak_ptr<GeneveHandlerENI>(resolvedHandler));
            resolvedHandler->udpReceiverCallback(std::move(gd), gp.flowCookie, pkt, pktlen);
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
GeneveHandlerENI::GeneveHandlerENI(gwlbeid_t eni, int tcpCacheTimeout, int udpCacheTimeout, int otherCacheTimeout, const ThreadConfig& tunThreadConfig, const std::array<std::size_t,6>& reserve, ghCallback createCallback, ghCallback destroyCallback, EbpfLoader* ebpfLoader) :
        eni(eni), eniStr(MakeGwlbeStr(eni)), tcpCacheTimeout(tcpCacheTimeout), udpCacheTimeout(udpCacheTimeout), otherCacheTimeout(otherCacheTimeout),
        devInName(devname_make(eni, true)),
#ifndef NO_RETURN_TRAFFIC
        devOutName(devname_make(eni, false)),
        gwlbV4CookiesTcp("IPv4 TCP Flow Cache for GWLBe vpce-" + eniStr, tcpCacheTimeout, reserve[0]),
        gwlbV4CookiesUdp("IPv4 UDP Flow Cache for GWLBe vpce-" + eniStr, udpCacheTimeout, reserve[1]),
        gwlbV4CookiesOther("IPv4 Other Flow Cache for GWLBe vpce-" + eniStr, otherCacheTimeout, reserve[2]),
        gwlbV6CookiesTcp("IPv6 TCP Flow Cache for GWLBe vpce-" + eniStr, tcpCacheTimeout, reserve[3]),
        gwlbV6CookiesUdp("IPv6 UDP Flow Cache for GWLBe vpce-" + eniStr, udpCacheTimeout, reserve[4]),
        gwlbV6CookiesOther("IPv6 Other Flow Cache for GWLBe vpce-" + eniStr, otherCacheTimeout, reserve[5]),
#else
    devOutName("none"s),
#endif
        gwiWriter(devname_make(eni, true)),
        sendingSock(-1),
        createCallback(std::move(createCallback)), destroyCallback(std::move(destroyCallback)), ebpfLoader(ebpfLoader)
{
    // Set up a socket we use for sending traffic out for ENI.
    tunnelIn = std::make_unique<TunInterface>(devInName, GWLB_MTU, tunThreadConfig, std::bind(&GeneveHandlerENI::tunReceiverCallback, this, std::placeholders::_1, std::placeholders::_2));
    // The gwi interface now exists in the kernel; resolve its ifindex for the XDP
    // redirect target. Stays 0 (acceleration disabled for this ENI) if unresolved.
    gwiIfIndex = ebpfLoader ? ebpfLoader->ifIndexForName(devInName) : 0;
    if(ebpfLoader && ebpfLoader->isEnabled() && gwiIfIndex == 0)
        LOG(LS_EBPF, LL_IMPORTANT, "Could not resolve ifindex for "s + devInName + "; eBPF ingress acceleration disabled for this ENI."s);
#ifndef NO_RETURN_TRAFFIC
    tunnelOut = std::make_unique<TunInterface>(devOutName, GWLB_MTU, tunThreadConfig, std::bind(&GeneveHandlerENI::tunReceiverCallback, this, std::placeholders::_1, std::placeholders::_2));
    sendingSock = socket(AF_INET,SOCK_RAW, IPPROTO_RAW);
    if(sendingSock == -1)
        throw std::runtime_error("Unable to allocate a socket for sending UDP traffic.");
    // The gwo interface now exists; resolve its ifindex and attach the egress
    // (re-encap) tc program to it so return traffic can be accelerated.
    gwoIfIndex = ebpfLoader ? ebpfLoader->ifIndexForName(devOutName) : 0;
    if(ebpfLoader && ebpfLoader->isEnabled())
        LOG(LS_EBPF, LL_IMPORTANT, "eBPF egress setup for "s + devOutName + ": egressAvailable="s
            + (ebpfLoader->egressAvailable()?"y":"n") + " gwoIfIndex="s + ts(gwoIfIndex));
    if(ebpfLoader && ebpfLoader->egressAvailable()) {
        if(gwoIfIndex == 0)
            LOG(LS_EBPF, LL_IMPORTANT, "Could not resolve ifindex for "s + devOutName + "; eBPF egress acceleration disabled for this ENI."s);
        else
            ebpfLoader->attachEgressProgram(devOutName);
    }
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
    LOG(LS_EBPF, LL_IMPORTANT, "Tearing down ENI handler for "s + eniStr + " (gwi="s + devInName + " gwo="s + devOutName + "). eBPF-accelerated flows on this ENI lose their map entries and the gwo clsact goes with the interface."s);
    // Stop the tunnel worker threads FIRST. These threads run tunReceiverCallback(),
    // which looks up our flow caches on every return packet. tunnelIn/tunnelOut are
    // declared ahead of the flow-cache members, so normal member destruction would
    // free the caches first and leave the still-running tun threads reading freed
    // memory -- a use-after-free (benign-looking with a small heap cache, but a
    // reliable segfault once --reserve makes the cache a large mmap that gets
    // unmapped on free). ~TunInterface signals and joins its threads, so once these
    // resets return no tun callback can still be in flight against the caches.
    tunnelIn.reset();
#ifndef NO_RETURN_TRAFFIC
    tunnelOut.reset();
#endif

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

void GeneveHandlerENI::udpReceiverCallback(GwlbData gd, uint32_t flowCookie, unsigned char *pkt, ssize_t pktlen)
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
                FlowCache<PacketHeaderV4, GwlbData>* cache;
                switch(ph.prot)
                {
                    case IPPROTO_TCP: cache = &gwlbV4CookiesTcp; break;
                    case IPPROTO_UDP: cache = &gwlbV4CookiesUdp; break;
                    default:          cache = &gwlbV4CookiesOther; break;
                }
                if(ebpfLoader && ebpfLoader->isEnabled())
                    ebpfLearnV4(flowCookie, gd, pkt + headerLen, pktlen - headerLen);   // first-sight gated internally
                // No reverse-direction pre-seed needed: the cookie cache key is symmetric
                // (hashFunc + PacketHeaderV4::operator== treat a flow and its reverse as
                // equal), so the forward insert below already covers both directions.
                // Insert the flow if new, otherwise just refresh its idle timer in place.
                if(__builtin_expect(cache->insert(std::move(ph), std::move(gd)), 0))
                    logCookieChanged(eniStr);
#else
                if(ebpfLoader && ebpfLoader->isEnabled())
                    ebpfLearnV4(flowCookie, gd, pkt + headerLen, pktlen - headerLen);
#endif
                // Route the decap'ed packet to our tun interface, accounting for drops.
                writeToTun(pkt + headerLen, pktlen - headerLen);
            } else if(__builtin_expect(iph->ip_v == (unsigned int)6, 0)) {
#ifndef NO_RETURN_TRAFFIC
                auto ph = PacketHeaderV6(pkt + headerLen, pktlen - headerLen);
                FlowCache<PacketHeaderV6, GwlbData>* cache;
                switch(ph.prot)
                {
                    case IPPROTO_TCP: cache = &gwlbV6CookiesTcp; break;
                    case IPPROTO_UDP: cache = &gwlbV6CookiesUdp; break;
                    default:          cache = &gwlbV6CookiesOther; break;
                }
                if(ebpfLoader && ebpfLoader->isEnabled())
                    ebpfLearnV6(flowCookie, gd, pkt + headerLen, pktlen - headerLen);
                // No reverse-direction pre-seed needed: symmetric cookie cache key (see V4 path).
                // Insert the flow if new, otherwise just refresh its idle timer in place.
                if(__builtin_expect(cache->insert(std::move(ph), std::move(gd)), 0))
                    logCookieChanged(eniStr);
#else
                if(ebpfLoader && ebpfLoader->isEnabled())
                    ebpfLearnV6(flowCookie, gd, pkt + headerLen, pktlen - headerLen);
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
 * Push the ingress map entry for this flow so the XDP program takes over decap+redirect
 * for subsequent packets. Caller gates on first sight (seenCookies) + eBPF enabled.
 */
void GeneveHandlerENI::ebpfInsertIngress(uint32_t flowCookie)
{
    if(gwiIfIndex == 0)
        return;
    EbpfIngressRTKey key{};
    key.gwlbeEniId = eni;
    key.flowCookie = flowCookie;
    ebpfLoader->updateIngressRoute(key, gwiIfIndex);
}

// A re-punt observed more than this long after a flow was learned is treated as a real
// established-flow re-punt (the in-kernel entry was lost/evicted while active), rather
// than the benign tail of first-packet learning. Comfortably larger than any plausible
// socket-queue drain / ENI-setup stall, so warm-up tail is never miscounted as an alarm.
static const int kRepuntAlarmSecs = 5;

/**
 * Record a newly-learned flow, or account for a re-punt. Returns true if this cookie was
 * not previously tracked (caller then programs the maps); false if it was already learned
 * -- in which case this packet reached the slow path for an already-accelerated flow.
 * Such a packet is benign right after learning (in-flight first packets draining) but is
 * an alarm if it arrives long after (ebpfLateRepunts). Slow path only; never on the
 * accelerated path, which bypasses userspace entirely.
 */
bool GeneveHandlerENI::ebpfTrackNewFlow(uint32_t flowCookie, BpfFlow& flow)
{
    flow.learnedAt = std::chrono::steady_clock::now();
    if(trackedFlows.try_emplace(flowCookie, flow))
        return true;   // first sight -> learn it

    // Already tracked: a punt for an accelerated flow. Classify warm-up tail vs. real re-punt.
    ebpfRepunts.fetch_add(1, std::memory_order_relaxed);
    trackedFlows.cvisit(flowCookie, [this](const auto& kv) {
        auto age = std::chrono::steady_clock::now() - kv.second.learnedAt;
        if(age > std::chrono::seconds(kRepuntAlarmSecs))
            ebpfLateRepunts.fetch_add(1, std::memory_order_relaxed);
    });
    return false;
}

/**
 * Learn an IPv4 flow on first sight: record it, push the ingress map entry, and (in
 * return-traffic builds) build the encap blob and insert the egress map under both the
 * forward and reverse inner 5-tuples. Gated by trackedFlows so the map-update syscalls
 * stay off the per-packet path.
 */
void GeneveHandlerENI::ebpfLearnV4(uint32_t flowCookie, const GwlbData& gd, const unsigned char* inner, ssize_t innerLen)
{
    if(innerLen < (ssize_t)sizeof(struct ip))
        return;
    const struct ip* iph = (const struct ip*)inner;

    // Build the forward egress key (network order, matching what the tc program reads).
    BpfFlow flow{};
    memset(&flow.v4, 0, sizeof(flow.v4));   // zero key + padding for the map-key match
    flow.isV4 = true;
    flow.v4.ifindex = gwoIfIndex;
    flow.v4.src = iph->ip_src.s_addr;
    flow.v4.dst = iph->ip_dst.s_addr;
    flow.v4.prot = iph->ip_p;
    if((iph->ip_p == IPPROTO_TCP || iph->ip_p == IPPROTO_UDP) &&
       innerLen >= (ssize_t)(iph->ip_hl * 4 + 4))
    {
        const uint16_t* ports = (const uint16_t*)(inner + iph->ip_hl * 4);
        flow.v4.srcpt = ports[0];
        flow.v4.dstpt = ports[1];
    }

    if(!ebpfTrackNewFlow(flowCookie, flow))
        return;   // already learned (re-punt accounted inside)

    ebpfInsertIngress(flowCookie);

#ifndef NO_RETURN_TRAFFIC
    if(ebpfLoader->egressAvailable() && gwoIfIndex != 0)
    {
        EbpfEgressMapValue val;
        memset(&val, 0, sizeof(val));
        // src=appliance(gd.dstAddr), dst=GWLB(gd.srcAddr), ports preserved -- as sendUdpSG.
        size_t encLen = buildGwlbEncapBlob(val.encap, sizeof(val.encap),
                                           gd.dstAddr, gd.srcPort, gd.srcAddr, gd.dstPort,
                                           gd.header.data(), gd.header.size());
        if(encLen != GWLB_ENCAP_LEN)
        {
            LOG(LS_EBPF, LL_IMPORTANT, "Egress encap length "s + ts(encLen) + " != expected "s + ts(GWLB_ENCAP_LEN) + "; skipping egress acceleration for flow");
            return;
        }
        val.encap_len = (uint16_t)encLen;
        val.gwlbeEniId = eni;   // lets the egress program key return_eth_map for the L2 header

        // Program BOTH tuple directions into the eBPF egress map. Unlike the userspace
        // cookie cache (symmetric C++ key), the eBPF map is keyed by the raw
        // EbpfEgressMapKeyV4 bytes and hashed/compared in-kernel -- (A->B) and (B->A) are
        // distinct keys there, so both must be programmed for the egress program to match
        // either direction. (Do not "collapse" this to one insert.)
        EbpfEgressMapKeyV4 rev = flow.v4;
        rev.src = flow.v4.dst;      rev.dst = flow.v4.src;
        rev.srcpt = flow.v4.dstpt;  rev.dstpt = flow.v4.srcpt;

        ebpfLoader->updateEgressRouteV4(flow.v4, val);
        ebpfLoader->updateEgressRouteV4(rev, val);
    }
#else
    (void)gd;
#endif
}

/**
 * IPv6 counterpart of ebpfLearnV4.
 */
void GeneveHandlerENI::ebpfLearnV6(uint32_t flowCookie, const GwlbData& gd, const unsigned char* inner, ssize_t innerLen)
{
    if(innerLen < (ssize_t)sizeof(struct ip6_hdr))
        return;
    const struct ip6_hdr* ip6 = (const struct ip6_hdr*)inner;

    BpfFlow flow{};
    memset(&flow.v6, 0, sizeof(flow.v6));   // zero key + padding for the map-key match
    flow.isV4 = false;
    flow.v6.ifindex = gwoIfIndex;
    memcpy(flow.v6.src, &ip6->ip6_src, sizeof(flow.v6.src));
    memcpy(flow.v6.dst, &ip6->ip6_dst, sizeof(flow.v6.dst));
    uint8_t nexthdr = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    flow.v6.prot = nexthdr;
    if((nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP) &&
       innerLen >= (ssize_t)(sizeof(struct ip6_hdr) + 4))
    {
        const uint16_t* ports = (const uint16_t*)(inner + sizeof(struct ip6_hdr));
        flow.v6.srcpt = ports[0];
        flow.v6.dstpt = ports[1];
    }

    if(!ebpfTrackNewFlow(flowCookie, flow))
        return;   // already learned (re-punt accounted inside)

    ebpfInsertIngress(flowCookie);

#ifndef NO_RETURN_TRAFFIC
    if(ebpfLoader->egressAvailable() && gwoIfIndex != 0)
    {
        EbpfEgressMapValue val;
        memset(&val, 0, sizeof(val));
        size_t encLen = buildGwlbEncapBlob(val.encap, sizeof(val.encap),
                                           gd.dstAddr, gd.srcPort, gd.srcAddr, gd.dstPort,
                                           gd.header.data(), gd.header.size());
        if(encLen != GWLB_ENCAP_LEN)
        {
            LOG(LS_EBPF, LL_IMPORTANT, "Egress encap length "s + ts(encLen) + " != expected "s + ts(GWLB_ENCAP_LEN) + "; skipping egress acceleration for flow");
            return;
        }
        val.encap_len = (uint16_t)encLen;
        val.gwlbeEniId = eni;   // lets the egress program key return_eth_map for the L2 header

        // Both directions, same reason as the V4 path above (raw byte-keyed eBPF map).
        EbpfEgressMapKeyV6 rev = flow.v6;
        memcpy(rev.src, flow.v6.dst, sizeof(rev.src));
        memcpy(rev.dst, flow.v6.src, sizeof(rev.dst));
        rev.srcpt = flow.v6.dstpt;  rev.dstpt = flow.v6.srcpt;

        ebpfLoader->updateEgressRouteV6(flow.v6, val);
        ebpfLoader->updateEgressRouteV6(rev, val);
    }
#else
    (void)gd;
#endif
}

/**
 * Map a protocol to its configured idle timeout (seconds).
 */
int GeneveHandlerENI::perProtoTimeout(uint8_t proto) const
{
    switch(proto)
    {
        case IPPROTO_TCP: return tcpCacheTimeout;
        case IPPROTO_UDP: return udpCacheTimeout;
        default:          return otherCacheTimeout;
    }
}

/**
 * Periodic GC sweep: for each learned flow, read its liveness from the maps (ingress
 * last_seen and egress last_sent, both directions), and if idle beyond the flow's
 * per-protocol timeout, remove it from both maps and stop tracking it (freeing map
 * space and allowing a clean re-learn). Also records the newest activity across all
 * flows into lastBpfActivityNs so hasGoneIdle won't tear down a still-busy ENI.
 */
void GeneveHandlerENI::ebpfGc(uint64_t now)
{
    if(!ebpfLoader || !ebpfLoader->isEnabled())
        return;

    uint64_t newest = 0;
    trackedFlows.erase_if([&](auto& kv) -> bool {
        uint32_t cookie = kv.first;
        BpfFlow& f = kv.second;

        EbpfIngressRTKey ik{};
        ik.gwlbeEniId = eni;
        ik.flowCookie = cookie;
        uint64_t ts = ebpfLoader->ingressLastSeen(ik);
#ifndef NO_RETURN_TRAFFIC
        if(f.isV4)
        {
            EbpfEgressMapKeyV4 rev = f.v4;
            rev.src = f.v4.dst; rev.dst = f.v4.src; rev.srcpt = f.v4.dstpt; rev.dstpt = f.v4.srcpt;
            uint64_t s1 = ebpfLoader->egressLastSentV4(f.v4);
            uint64_t s2 = ebpfLoader->egressLastSentV4(rev);
            if(s1 > ts) ts = s1;
            if(s2 > ts) ts = s2;
        }
        else
        {
            EbpfEgressMapKeyV6 rev = f.v6;
            memcpy(rev.src, f.v6.dst, sizeof(rev.src));
            memcpy(rev.dst, f.v6.src, sizeof(rev.dst));
            rev.srcpt = f.v6.dstpt; rev.dstpt = f.v6.srcpt;
            uint64_t s1 = ebpfLoader->egressLastSentV6(f.v6);
            uint64_t s2 = ebpfLoader->egressLastSentV6(rev);
            if(s1 > ts) ts = s1;
            if(s2 > ts) ts = s2;
        }
#endif
        uint8_t proto = f.isV4 ? f.v4.prot : f.v6.prot;
        uint64_t timeoutNs = (uint64_t)perProtoTimeout(proto) * 1000000000ULL;

        if(ts == 0 || (now > ts && (now - ts) > timeoutNs))
        {
            ebpfLoader->removeIngressRoute(ik);
#ifndef NO_RETURN_TRAFFIC
            if(f.isV4)
            {
                EbpfEgressMapKeyV4 rev = f.v4;
                rev.src = f.v4.dst; rev.dst = f.v4.src; rev.srcpt = f.v4.dstpt; rev.dstpt = f.v4.srcpt;
                ebpfLoader->removeEgressRouteV4(f.v4);
                ebpfLoader->removeEgressRouteV4(rev);
            }
            else
            {
                EbpfEgressMapKeyV6 rev = f.v6;
                memcpy(rev.src, f.v6.dst, sizeof(rev.src));
                memcpy(rev.dst, f.v6.src, sizeof(rev.dst));
                rev.srcpt = f.v6.dstpt; rev.dstpt = f.v6.srcpt;
                ebpfLoader->removeEgressRouteV6(f.v6);
                ebpfLoader->removeEgressRouteV6(rev);
            }
#endif
            return true;   // stop tracking
        }
        if(ts > newest) newest = ts;
        return false;
    });

    lastBpfActivityNs.store(newest, std::memory_order_relaxed);
}

/**
 * Write a decapsulated packet to the ingress tun interface, counting a successful
 * write toward pktsOut/bytesOut, or a write error / short write toward pktsDropped.
 */
void GeneveHandlerENI::writeToTun(const unsigned char *pkt, ssize_t pktlen)
{
    ssize_t written = gwiWriter.write(pkt, pktlen);
    hot.lastPacketOut = std::chrono::steady_clock::now();
    if(__builtin_expect(written == pktlen, 1))
    {
        hot.pktsOut++;
        hot.bytesOut += pktlen;
    }
    else
    {
        hot.pktsDropped++;
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
                                                         , uint64_t ebpfRepunts, uint64_t ebpfLateRepunts
                                                         ) :
        healthy(healthy), eniStr(eniStr), pktsOut(pktsOut), bytesOut(bytesOut), pktsDropped(pktsDropped), ebpfRepunts(ebpfRepunts), ebpfLateRepunts(ebpfLateRepunts), lastPacketOut(lastPacketOut), tunnelIn(std::move(tunnelIn))
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
    ret << "eBPF slow-path re-punts: " << std::to_string(ebpfRepunts) << " total (incl. first-packet warm-up), " << std::to_string(ebpfLateRepunts) << " late (established-flow re-punt -- should be 0).\n";
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
    return {{"healthy", healthy}, {"gwlbEndpointId", "vpce-" + eniStr}, {"pktsOut", pktsOut}, {"bytesOut", bytesOut}, {"pktsDropped", pktsDropped}, {"ebpfRepunts", ebpfRepunts}, {"ebpfLateRepunts", ebpfLateRepunts}, {"secsSinceLastPacket", timepointDeltaDouble(std::chrono::steady_clock::now(), lastPacketOut)}, {"tunnelIn", tunnelIn.output_json()}
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
    return { healthy, eniStr, hot.pktsOut.load(), hot.bytesOut.load(), hot.pktsDropped.load(), hot.lastPacketOut.load(), tunnelIn->status()
#ifndef NO_RETURN_TRAFFIC
             , tunnelOut->status(),
             gwlbV4CookiesTcp.stats(), gwlbV4CookiesUdp.stats(), gwlbV4CookiesOther.stats(),
             gwlbV6CookiesTcp.stats(), gwlbV6CookiesUdp.stats(), gwlbV6CookiesOther.stats()
#endif
             , ebpfRepunts.load(), ebpfLateRepunts.load()
    };
}

void GeneveHandlerENI::sweepCaches()
{
#ifndef NO_RETURN_TRAFFIC
    gwlbV4CookiesTcp.sweep(); gwlbV4CookiesUdp.sweep(); gwlbV4CookiesOther.sweep();
    gwlbV6CookiesTcp.sweep(); gwlbV6CookiesUdp.sweep(); gwlbV6CookiesOther.sweep();
#endif
    // Age the eBPF maps on the same periodic reaper sweep. This also refreshes
    // lastBpfActivityNs, which the hasGoneIdle() check (run right after this in
    // GeneveHandler::sweep) consults so an ENI busy only in the eBPF fast path is
    // not reaped as idle. (No-op when eBPF is disabled.)
    ebpfGc(nowNs());
}

/**
 * Check to see if we haven't seen traffic in timeout seconds.
 *
 * @return True if we haven't seen a packet in timeout seconds, false otherwise.
 */
bool GeneveHandlerENI::hasGoneIdle(int timeout)
{
    std::chrono::steady_clock::time_point expireTime = std::chrono::steady_clock::now() - std::chrono::seconds(timeout);

    if(hot.lastPacketOut.load() > expireTime) return false;
#ifndef NO_RETURN_TRAFFIC
    if(tunnelIn->lastPacketTime() > expireTime) return false;
    if(tunnelOut->lastPacketTime() > expireTime) return false;
#endif
    // Traffic handled entirely in the eBPF fast path never touches the userspace
    // tun interfaces above, so consult the BPF-activity marker refreshed by ebpfGc().
    // Without this an ENI that is still busy in XDP/tc would look idle and get torn
    // down, ripping out its map entries and attached programs.
    if(ebpfLoader && ebpfLoader->isEnabled())
    {
        uint64_t lastActivity = lastBpfActivityNs.load(std::memory_order_relaxed);
        if(lastActivity != 0 && (nowNs() - lastActivity) < (uint64_t)timeout * 1000000000ULL)
            return false;
    }
    return true;
}

/**
 * GeneveHandlerENI shared pointer wrapper class
 */
GeneveHandlerENIPtr::GeneveHandlerENIPtr(gwlbeid_t eni, int tcpCacheTimeout, int udpCacheTimeout, int otherCacheTimeout, const ThreadConfig &tunThreadConfig, const std::array<std::size_t,6>& reserve, ghCallback createCallback, ghCallback destroyCallback, EbpfLoader* ebpfLoader)
{
    ptr = std::make_shared<GeneveHandlerENI>(eni, tcpCacheTimeout, udpCacheTimeout, otherCacheTimeout, tunThreadConfig, reserve, createCallback, destroyCallback, ebpfLoader);
}


std::string devname_make(gwlbeid_t eni, bool inbound) {
    if(inbound)
        return "gwi-"s + toBase60(eni);
    else
        return "gwo-"s + toBase60(eni);
}


