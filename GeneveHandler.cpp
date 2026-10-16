// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * Handles all of our Geneve tunnel functions:
 * - Launches a UDPPacketReceiver to receive packets on port 6081
 * - For each GWLB endpoint seen, builds a GeneveHandlerENI: its gwi-/gwo- tun interfaces (see devname_make),
 *   their threads, and its flow caches
 * - For each packet received over the UDPPacketReceiver, decode, store the flow's GENEVE header and outer
 *   addresses, and send the inner packet to the endpoint's gwi- interface
 * - For each packet received via a Tun interface, re-encapsulate if its flow is known, and send to GWLB.
 *
 * Also provides the GwlbData class, which holds the GENEVE header and outer addresses stored for each flow, so
 * they can be reapplied to matching traffic.
 */

#include "GeneveHandler.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <optional>
#include <sstream>
#include <thread>
#include <utility>
#include "Logger.h"

using namespace std::string_literals;

constexpr int GWLB_MTU = 8500;   // MTU of inner/decapsulated packets (TUN interface)

// The UDP threads' endpoint caches (see GeneveHandler.h). Keyed by endpoint alone: there is only ever
// one GeneveHandler (see OnlyInstance), so a thread's cache can only belong to it.
thread_local std::unordered_map<gwlbeid_t, GeneveHandler::TlsEniEntry> GeneveHandler::tlsEniCache;
thread_local std::vector<GeneveHandler::TlsEniEntry *> GeneveHandler::tlsHeld;

std::atomic<bool> GeneveHandler::OnlyInstance::exists{false};

GeneveHandler::OnlyInstance::OnlyInstance(const GwlbtunConfig &cfg)
{
    if(exists.exchange(true))
        throw std::logic_error("Only one GeneveHandler may exist at a time.");
    setDevnameScope(cfg.interfaces);
    setRawSendBufferSize(cfg.sndBufSizeMB);
}

GeneveHandler::OnlyInstance::~OnlyInstance()
{
    exists = false;
}

// Drop the strong endpoint references this UDP thread held during its last recvmmsg() batch.
void GeneveHandler::udpBatchEnd()
{
    for(auto *e : tlsHeld)
        e->held.reset();
    tlsHeld.clear();

    // Now and then, forget endpoints that are gone, so a thread doesn't keep an entry (and the endpoint's
    // shared_ptr control block) for every endpoint it has ever seen. Safe here: tlsHeld is empty, so nothing
    // points into the cache.
    static thread_local unsigned batches = 0;
    if(++batches % 65536 == 0)
        for(auto it = tlsEniCache.begin(); it != tlsEniCache.end();)
            it = it->second.weak.expired() ? tlsEniCache.erase(it) : std::next(it);
}

/**
 * Human-readable form for logs: the outer addresses and ports of the GENEVE packet, the interface it arrived on,
 * and the GWLB options from its GENEVE header.
 */
std::string GwlbData::text() const
{
    char src[INET_ADDRSTRLEN] = "?", dst[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &srcAddr, src, sizeof(src));
    inet_ntop(AF_INET, &dstAddr, dst, sizeof(dst));
    return " Outer: "s + src + ":" + std::to_string(srcPort) + " -> " + dst + ":" + std::to_string(dstPort) +
           " ifindex " + std::to_string(ifindex) + GenevePacket(header.data(), (ssize_t)header.size()).text();
}

/**
 * Starts the GeneveHandler: the members set up everything, the UDP receiver (port 6081) last.
 *
 * @param cfg Immutable runtime configuration (timeouts, thread configs, socket buffer, busy-poll).
 * @param hookScriptsParam The CREATE/DESTROY scripts each endpoint runs.
 */
GeneveHandler::GeneveHandler(const GwlbtunConfig& cfg, const HookScripts &hookScriptsParam)
        : onlyInstance(cfg),
          ebpfLoader(cfg.ebpfObject.empty() ? nullptr : std::make_unique<EbpfLoader>(cfg)),
          lifecycle(std::make_shared<EndpointLifecycle>()),
          hookScripts(hookScriptsParam),
          config(cfg),
          udpRcvr(config.udpPlan, GENEVE_PORT,
                  [this](unsigned char *pkt, ssize_t pktlen, struct in_addr *srcAddr, uint16_t srcPort, struct in_addr *dstAddr, uint16_t dstPort, int ifindex) {
                      udpReceiverCallback(pkt, pktlen, srcAddr, srcPort, dstAddr, dstPort, ifindex);
                  },
                  &GeneveHandler::udpBatchEnd, config.rcvBufSizeMB, config.busyPollUsec)
{
}

std::string GeneveHandlerHealthCheck::output_str() const
{
    std::string ret = udp.output_str();
    for(const auto &eni : enis)
        ret += eni.output_str();
    if(ebpf)
        ret += ebpf->output_str();
    return ret;
}

json GeneveHandlerHealthCheck::output_json() const
{
    // Totals come straight from the snapshot; each endpoint's JSON is built once.
    uint64_t totalPktsOut = 0, totalBytesOut = 0, totalPktsDropped = 0;
    json enisJson = json::array();
    for(const auto &eni : enis)
    {
        totalPktsOut += eni.pktsOut;
        totalBytesOut += eni.bytesOut;
        totalPktsDropped += eni.pktsDropped;
        enisJson.push_back(eni.output_json());
    }

    json j = {
        {"summary", {
            {"totalPktsIn", udp.totalPacketsIn()},
            {"totalBytesIn", udp.totalOctetsIn()},
            {"totalPktsOut", totalPktsOut},
            {"totalBytesOut", totalBytesOut},
            {"totalPktsDropped", totalPktsDropped},
            {"eniCount", enis.size()}
        }},
        {"udp", udp.output_json()},
        {"enis", std::move(enisJson)}
    };
    if(ebpf)
        j["ebpf"] = ebpf->output_json();
    return j;
}

GeneveHandlerHealthCheck GeneveHandler::check() const
{
    LOG(LS_HEALTHCHECK, LL_DEBUG, "Health check starting");

    // Report-only: no eviction here (see sweep()). Each endpoint's check() is short (counters and thread
    // states), so it's done under the map's shared lock.
    std::vector<GeneveHandlerENIHealthCheck> enis;
    eniHandlers.cvisit_all([&enis](const auto &kv) { enis.push_back(kv.second->check()); });

    // Healthy: every UDP receiver thread, and every endpoint's tunnel threads, still running.
    const bool healthy = udpRcvr.healthCheck() &&
                         std::all_of(enis.begin(), enis.end(), [](const auto &e) { return e.healthy; });
    return { healthy, udpRcvr.status(), std::move(enis), ebpfLoader ? std::optional<EbpfHealthCheck>(ebpfLoader->check()) : std::nullopt };
}

void GeneveHandler::sweep()
{
    // Evict expired flow-cache entries, then reap ENI handlers idle past the tunnel timeout. Decoupled from
    // check()/health reporting so a health poll never triggers the O(N) cache scan. The scans run on a
    // snapshot of the endpoints, not inside the map's visit (which would hold its locks, and so hold up the
    // packet slow path, for the whole scan). The snapshot's references are dropped here on the reaper thread,
    // before any teardown below waits for an endpoint's other references to go.
    {
        std::vector<std::shared_ptr<GeneveHandlerENI>> endpoints;
        eniHandlers.cvisit_all([&endpoints](const auto &kv) { endpoints.push_back(kv.second); });
        for(auto &e : endpoints)
            e->sweepCaches();
    }

    // Forget failed-setup retry times that have passed: an expired entry behaves the same as none.
    {
        const auto now = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> lk(lifecycle->mutex);
        for(auto it = createRetryAfter.begin(); it != createRetryAfter.end();)
            it = now >= it->second ? createRetryAfter.erase(it) : std::next(it);
    }

    if(config.tunnelTimeout <= 0)
        return;

    // Remove idle endpoints from the map. Their handlers are only moved aside here: destroying one
    // stops its tunnel threads and runs the DESTROY hook, which takes a second or more, and that
    // must not happen inside erase_if() (it holds a map lock that packet threads need) or on a
    // packet thread (which is where the last shared_ptr was often released before). The handler is moved
    // into `retiring`, so the map element erased under the mutex holds no reference.
    {
        std::lock_guard<std::mutex> lk(lifecycle->mutex);
        eniHandlers.erase_if([&](auto &kv) {
            if(!kv.second->hasGoneIdle(config.tunnelTimeout))
                return false;
            kv.second->retired = true;
            retiring.emplace(kv.first, std::move(kv.second));
            return true;
        });
    }

    // Destroy them here, on the reaper thread, one at a time. Each stays in `destroying` (so no new handler
    // for it is built) until its deleter has run, on whichever thread drops the last reference.
    for(;;)
    {
        gwlbeid_t id;
        std::shared_ptr<GeneveHandlerENI> victim;
        {
            std::lock_guard<std::mutex> lk(lifecycle->mutex);
            if(retiring.empty())
                break;
            auto it = retiring.begin();
            id = it->first;
            victim = std::move(it->second);
            retiring.erase(it);
            lifecycle->destroying.insert(id);
        }
        // A packet thread may hold a reference for the rest of one recvmmsg() batch; let it finish so the
        // destructor runs here rather than on that thread.
        for(int i = 0; victim.use_count() > 1 && i < 500; i++)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if(victim.use_count() > 1)
            LOG(LS_CORE, LL_INFO, "GWLB endpoint vpce-"s + MakeGwlbeStr(id) + " is still in use after 5 seconds; it will be torn down "s +
                "by the packet thread that releases it last."s);
        victim.reset();
    }
}

GeneveHandler::CreatingReservation::CreatingReservation(GeneveHandler &ghParam, gwlbeid_t idParam)
: gh(ghParam), id(idParam)
{
    gh.creating.insert(id);
}

GeneveHandler::CreatingReservation::~CreatingReservation()
{
    std::lock_guard<std::mutex> lk(gh.lifecycle->mutex);
    gh.creating.erase(id);
}

void GeneveHandler::EndpointDeleter::operator()(GeneveHandlerENI *e) const noexcept
{
    delete e;   // runs the DESTROY hook, stops the endpoint's threads and removes its interfaces
    std::lock_guard<std::mutex> lk(lifecycle->mutex);
    lifecycle->destroying.erase(id);
}

std::shared_ptr<GeneveHandlerENI> GeneveHandler::makeEndpoint(gwlbeid_t id)
{
    return std::shared_ptr<GeneveHandlerENI>(new GeneveHandlerENI(id, config, hookScripts, ebpfLoader.get()), EndpointDeleter{lifecycle, id});
}

/**
 * Callback function passed to UDPPacketReceiver to handle GenevePackets. Determine which GeneveHandlerENI this packet
 * is for (creating a new one if needed), and pass to that class. An exception (only running out of memory) is
 * logged by the UDP receiver thread.
 *
 * @param pkt The packet received.
 * @param pktlen Length of packet received.
 * @param srcAddr Source address the packet came from.
 * @param srcPort Source port the packet came from.
 * @param dstAddr Destination address the packet was sent to.
 * @param dstPort Destination port the packet was sent to.
 * @param ifindex Interface the packet arrived on.
 */
void GeneveHandler::udpReceiverCallback(unsigned char *pkt, ssize_t pktlen, struct in_addr *srcAddr, uint16_t srcPort, struct in_addr *dstAddr, uint16_t dstPort, int ifindex)
{
    if(IS_LOGGING(LS_GENEVE, LL_DEBUG))
    {
        // inet_ntop into separate buffers: two inet_ntoa() calls in one expression share its static
        // buffer, so the log could show the destination address as the source too.
        char src[INET_ADDRSTRLEN] = "?", dst[INET_ADDRSTRLEN] = "?";
        inet_ntop(AF_INET, srcAddr, src, sizeof(src));
        inet_ntop(AF_INET, dstAddr, dst, sizeof(dst));
        LOG(LS_GENEVE, LL_DEBUG, "Received a packet of "s + ts(pktlen) + " bytes from " + src + " port " + ts(srcPort) + " sent to " + dst + " port " + ts(dstPort));
        LOGHEXDUMP(LS_GENEVE, LL_DEBUGDETAIL, "GWLB Packet", pkt, pktlen);
    }

    // GenevePacket checks that this is a GENEVE packet from GWLB: status OK means all three GWLB options
    // (endpoint, attachment, flow cookie) were found.
    const GenevePacket gp(pkt, pktlen);
    if(gp.status != GP_STATUS_OK)
    {
        LOG(LS_GENEVE, LL_DEBUG, "Geneve Header not OK");
        return;
    }
    const gwlbeid_t gwlbeEndpointId = gp.gwlbeEndpointId;
    const GwlbData gd(GeneveHeader(pkt, pkt + gp.headerLen), *srcAddr, srcPort, *dstAddr, dstPort, ifindex);

    // Fast path: this thread's cached handler for the endpoint. A strong reference taken once is held for the
    // rest of the batch (see TlsEniEntry); a retired handler falls through to the slow path.
    auto &localEntry = tlsEniCache[gwlbeEndpointId];
    if(!localEntry.held && (localEntry.held = localEntry.weak.lock()))
        tlsHeld.push_back(&localEntry);
    if(localEntry.held && !localEntry.held->retired.load(std::memory_order_relaxed))
    {
        localEntry.held->udpReceiverCallback(gd, pkt, pktlen);
        return;
    }
    localEntry.held.reset();
    localEntry.weak.reset();
    const auto now = std::chrono::steady_clock::now();
    if(now < localEntry.skipUntil)
        return;   // dropped recently; see TlsEniEntry::skipUntil

    // Slow path: find the endpoint's handler, or build one. Taken on the first packet a thread sees for
    // an endpoint, so it is rare. The lifecycle mutex orders it against the reaper's teardown of the same
    // endpoint, but is held only to look up and update state, never while a handler is built (which
    // starts its threads and runs the CREATE hook): other UDP threads, the reaper and health checks
    // don't wait for that. No endpoint reference may be dropped while the mutex is held (the endpoint
    // deleter takes it).
    std::shared_ptr<GeneveHandlerENI> resolvedHandler;
    std::optional<CreatingReservation> reservation;
    // How long a drop decided under the mutex holds before this thread asks again: a short while while
    // the endpoint is set up or torn down (it should be usable soon), or until a failed setup's retry.
    const auto shortSkip = now + std::chrono::milliseconds(10);
    {
        std::lock_guard<std::mutex> lk(lifecycle->mutex);
        eniHandlers.cvisit(gwlbeEndpointId, [&](const auto &kv) { resolvedHandler = kv.second; });
        if(resolvedHandler)
        {
            // Already set up (by another thread).
        }
        else if(lifecycle->destroying.count(gwlbeEndpointId))
        {
            // The previous handler for this endpoint is still being torn down (its interfaces
            // and DESTROY hook). Creating a new one now would reuse the same interface names
            // and race with that hook, so drop the packet; the next ones will set it up again.
            LOG(LS_GENEVE, LL_DEBUG, "Dropping packet for GWLB endpoint vpce-"s + MakeGwlbeStr(gwlbeEndpointId) + ": idle teardown in progress.");
            localEntry.skipUntil = shortSkip;
            return;
        }
        else if(creating.count(gwlbeEndpointId))
        {
            // Another UDP thread is setting this endpoint up. Its interfaces aren't ready (the CREATE
            // hook may still be configuring them), so drop the packet.
            LOG(LS_GENEVE, LL_DEBUG, "Dropping packet for GWLB endpoint vpce-"s + MakeGwlbeStr(gwlbeEndpointId) + ": being set up.");
            localEntry.skipUntil = shortSkip;
            return;
        }
        else if(auto rit = retiring.find(gwlbeEndpointId); rit != retiring.end())
        {
            // Traffic came back after the reaper removed this endpoint but before it was torn
            // down. Put the existing handler back instead of building a second one.
            resolvedHandler = std::move(rit->second);
            retiring.erase(rit);
            resolvedHandler->retired = false;
            eniHandlers.emplace(gwlbeEndpointId, resolvedHandler);
            LOG(LS_CORE, LL_INFO, "Traffic resumed for GWLB endpoint vpce-"s + MakeGwlbeStr(gwlbeEndpointId) + " before its idle teardown; keeping its interfaces.");
        }
        else
        {
            // A failed setup (for example IFF_TUN_EXCL finding the device name taken) would
            // otherwise be retried, and logged, on every packet for the endpoint. Wait a few
            // seconds before trying again, dropping its packets meanwhile.
            if(auto fit = createRetryAfter.find(gwlbeEndpointId); fit != createRetryAfter.end())
            {
                if(now < fit->second)
                {
                    localEntry.skipUntil = fit->second;
                    return;
                }
                createRetryAfter.erase(fit);
            }
            reservation.emplace(*this, gwlbeEndpointId);
        }
    }

    if(reservation)
    {
        // Build the handler with no lock held, then publish it. The reservation keeps every other
        // thread from building a second one meanwhile, and is released (on any exit) only after the
        // handler is in the map or the failure is recorded.
        try {
            // ORDER MATTERS: `built` before `lk`. If publishing throws, the half-published handler is then
            // destroyed after the mutex is released (its deleter takes it), while the reservation still
            // keeps other threads from building another.
            auto built = makeEndpoint(gwlbeEndpointId);
            std::lock_guard<std::mutex> lk(lifecycle->mutex);
            eniHandlers.emplace(gwlbeEndpointId, built);
            resolvedHandler = std::move(built);
        } catch(const std::exception& e) {
            // Five seconds from now, not from when the attempt started: a failed build can take a while
            // (starting, then stopping, hundreds of threads).
            const auto retryAt = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            {
                std::lock_guard<std::mutex> lk(lifecycle->mutex);
                createRetryAfter[gwlbeEndpointId] = retryAt;
            }
            localEntry.skipUntil = retryAt;
            LOG(LS_TUNNEL, LL_CRITICAL, "Unable to set up GWLB endpoint vpce-"s + MakeGwlbeStr(gwlbeEndpointId) + ": "s + e.what() +
                ". Dropping its packets; retrying in 5 seconds."s);
            return;
        }
    }

    // Cache it for this thread (weakly, plus a strong reference for the rest of the batch), and dispatch.
    if(resolvedHandler)
    {
        localEntry.weak = resolvedHandler;
        tlsHeld.push_back(&localEntry);
        localEntry.held = std::move(resolvedHandler);
        localEntry.held->udpReceiverCallback(gd, pkt, pktlen);
    }
}


/**
 * Flow-cache reserve for one address family (first: 0 for IPv4, 3 for IPv6). Receive-only builds keep flows only
 * for the eBPF maps, so without -e their caches aren't pre-sized.
 */
static std::array<std::size_t, 3> cacheReserve(const GwlbtunConfig &cfg, gwlbeid_t eni, size_t first, const EbpfLoader *ebpf)
{
#ifdef NO_RETURN_TRAFFIC
    if(!ebpf)
        return { 0, 0, 0 };
#else
    (void)ebpf;
#endif
    const auto &r = cfg.reserveFor(eni);
    return { r[first], r[first + 1], r[first + 2] };
}

/**
 * Build everything for one GWLB endpoint (see the member list in GeneveHandler.h for the order).
 */
GeneveHandlerENI::GeneveHandlerENI(gwlbeid_t eni, const GwlbtunConfig &cfg, const HookScripts &hookScripts, EbpfLoader *ebpfParam) :
        eni(eni), eniStr(MakeGwlbeStr(eni)),
        devInName(devname_make(eni, true)),
#ifndef NO_RETURN_TRAFFIC
        devOutName(devname_make(eni, false)),
#else
        devOutName("none"s),
#endif
        ebpf(ebpfParam), tunnelTimeout(cfg.tunnelTimeout),
        hotSlots(cfg.udpThreadCount() + 1), hot(new HotCounters[hotSlots]),
        v4Flows("IPv4", "GWLBe vpce-" + eniStr, cfg.tcpCacheTimeout, cfg.udpCacheTimeout, cfg.otherCacheTimeout, cacheReserve(cfg, eni, 0, ebpfParam)),
        v6Flows("IPv6", "GWLBe vpce-" + eniStr, cfg.tcpCacheTimeout, cfg.udpCacheTimeout, cfg.otherCacheTimeout, cacheReserve(cfg, eni, 3, ebpfParam)),
        gwiWriters(makeWriters(devInName, eniStr, gwiWriterCount(cfg.udpThreadCount(), cfg.maxRxQueues, cfg.tunThreads.cfg.size()))),
#ifndef NO_RETURN_TRAFFIC
        sendingSock(openRawSendSocket()),
#endif
        tunnelIn(devInName, GWLB_MTU, cfg.tunThreads, [this](unsigned char *pkt, ssize_t len) { tunReceiverCallback(pkt, len); }),
#ifndef NO_RETURN_TRAFFIC
        tunnelOut(devOutName, GWLB_MTU, cfg.tunThreads, [this](unsigned char *pkt, ssize_t len) { tunReceiverCallback(pkt, len); }, true),
#endif
        ebpfAttachment(*this),
        hooks(hookScripts, devInName, devOutName, eni)
{
}

// ---- eBPF datapath (-e) -------------------------------------------------------------------------------------
//
// Each flow this endpoint learns from GWLB is also handed to the eBPF maps (ebpfLearn), so its later packets
// skip gwlbtun: an ingress entry (keyed by endpoint and flow cookie, holding the inner flow's digest) and two
// egress entries (the inner 5-tuple both ways, on this endpoint's gwo-). The flow cache stays the record of
// what's in the maps: each entry's tag says what it put there, entries leave the maps when they leave the cache
// (ebpfForget, from the sweep's eviction, a changed GENEVE header, or endpoint teardown), and the sweep keeps
// accelerated flows (whose packets the cache no longer sees) alive from the maps' timestamps (ebpfActivity).

namespace {
constexpr uint8_t TAG_INGRESS = 1;   // the ingress map holds this flow's cookie, for this flow
constexpr uint8_t TAG_EGRESS = 2;    // the egress maps hold this flow
// A packet for a flow that's already in the ingress map can still reach userspace for a moment after it was
// learned (it was queued before the entry went in). Later than this, the in-kernel entry is missing or not
// working: count it, and learn the flow again.
constexpr uint32_t REPUNT_LATE_SECS = 5;
// How often to try again for a flow that isn't (fully) in the maps, for example because a map was full or
// another flow holds its cookie.
constexpr uint32_t RELEARN_SECS = 30;

// Whether the eBPF programs can key this inner packet the way the flow cache does (see inner_flow_digest in
// EbpfHelpers.c): not a later fragment of a TCP or UDP packet, not IPv6 with extension headers.
bool ebpfKeyable(const unsigned char *ip, ssize_t len)
{
    if(len < 20)
        return false;
    const unsigned version = ip[0] >> 4;
    if(version == 4)
    {
        const uint8_t prot = ip[9];
        return !((prot == IPPROTO_TCP || prot == IPPROTO_UDP) && (be16toh_unaligned(ip + 6) & 0x1FFF));
    }
    if(version == 6 && len >= 40)
    {
        const uint8_t next = ip[6];
        return next != 0 && next != 43 && next != 44 && next != 60 && next != 51;
    }
    return false;
}

EbpfIngressKey ingressKey(gwlbeid_t eni, const GwlbData &gd)
{
    EbpfIngressKey k{};
    k.gwlbeId = eni;
    k.flowCookie = GenevePacket(gd.header.data(), (ssize_t)gd.header.size()).flowCookie;
    return k;
}

// The coarseTime() of a map timestamp (EbpfLoader::nowNs() clock), 0 for none.
uint32_t coarseFromNs(uint64_t ns)
{
    if(ns == 0)
        return 0;
    const uint64_t now = EbpfLoader::nowNs();
    const uint64_t age = now > ns ? (now - ns) / 1000000000ULL : 0;
    const uint32_t c = coarseTime();
    return age >= c ? 0 : c - (uint32_t)age;
}
} // namespace

struct GeneveHandlerENI::EbpfFlow {
    uint64_t digest;
    bool v6;
    EbpfEgressKeyV4 fwd4, rev4;
    EbpfEgressKeyV6 fwd6, rev6;
};

GeneveHandlerENI::EbpfFlow GeneveHandlerENI::ebpfFlowOf(const PacketHeaderV4 &ph) const
{
    EbpfFlow f{};
    const uint32_t src = htonl(ph.srcAddr()), dst = htonl(ph.dstAddr());
    const uint16_t sp = htons(ph.srcPort()), dp = htons(ph.dstPort());
    f.digest = gwlbtun_flow_digest(4, ph.prot, gwlbtun_flow_end(src, sp), gwlbtun_flow_end(dst, dp));
    f.fwd4.gwoIfindex = f.rev4.gwoIfindex = ebpfAttachment.gwoIfindex;
    f.fwd4.prot = f.rev4.prot = ph.prot;
    f.fwd4.src = f.rev4.dst = src;
    f.fwd4.dst = f.rev4.src = dst;
    f.fwd4.srcPort = f.rev4.dstPort = sp;
    f.fwd4.dstPort = f.rev4.srcPort = dp;
    return f;
}

GeneveHandlerENI::EbpfFlow GeneveHandlerENI::ebpfFlowOf(const PacketHeaderV6 &ph) const
{
    EbpfFlow f{};
    f.v6 = true;
    uint32_t src[4], dst[4];
    memcpy(src, &ph.srcAddr(), sizeof(src));
    memcpy(dst, &ph.dstAddr(), sizeof(dst));
    const uint16_t sp = htons(ph.srcPort()), dp = htons(ph.dstPort());
    f.digest = gwlbtun_flow_digest(6, ph.prot, gwlbtun_flow_end(gwlbtun_fold_v6(src), sp), gwlbtun_flow_end(gwlbtun_fold_v6(dst), dp));
    f.fwd6.gwoIfindex = f.rev6.gwoIfindex = ebpfAttachment.gwoIfindex;
    f.fwd6.prot = f.rev6.prot = ph.prot;
    memcpy(f.fwd6.src, src, sizeof(src)); memcpy(f.rev6.dst, src, sizeof(src));
    memcpy(f.fwd6.dst, dst, sizeof(dst)); memcpy(f.rev6.src, dst, sizeof(dst));
    f.fwd6.srcPort = f.rev6.dstPort = sp;
    f.fwd6.dstPort = f.rev6.srcPort = dp;
    return f;
}

/**
 * Insert a flow into the cache (as udpReceiverCallback does without eBPF), and decide what the eBPF maps need:
 *  - a new flow, or one whose GENEVE header or outer addresses changed (for example a new cookie, which we've
 *    observed when a flow returns after GWLB's idle timeout): learn it (after removing the old entries);
 *  - a packet of a flow already in the ingress map: normally the tail of packets queued before it was learned;
 *    REPUNT_LATE_SECS or more after, count it as late and learn the flow again;
 *  - a flow that isn't (fully) in the maps: try again every RELEARN_SECS.
 */
template<class PH> void GeneveHandlerENI::ebpfInsert(ProtocolFlowCache<PH, GwlbData> &cache, const PH &ph, const GwlbData &gd,
                                                      const unsigned char *inner, ssize_t innerLen)
{
    std::optional<GwlbData> previous;
    const FlowInsertResult r = cache.insert(ph, gd, &previous);
    if(r.kind == FlowInsertResult::Refreshed)
    {
        if(r.tag & TAG_INGRESS)
        {
            ebpfRepunts.fetch_add(1, std::memory_order_relaxed);
            if(r.tagAge < REPUNT_LATE_SECS)
                return;
            ebpfLateRepunts.fetch_add(1, std::memory_order_relaxed);
        }
        else if(r.tagAge < RELEARN_SECS)
            return;
    }
    else if(r.kind == FlowInsertResult::Changed && previous)
        ebpfForget(ph, *previous, TAG_INGRESS | TAG_EGRESS);
    if(!ebpfKeyable(inner, innerLen))
        return;   // the programs can't match this packet's flow; it stays in userspace
    cache.setTag(ph, ebpfLearn(ph, gd));
}

/**
 * Add a flow to the eBPF maps. Returns what was added (TAG_*). Only flows in GWLB's standard GENEVE layout,
 * arriving on an interface the ingress program is on, go in the ingress map; only those arriving on the egress
 * action's interface go in the egress maps (replies to others must leave by their own interface).
 */
template<class PH> uint8_t GeneveHandlerENI::ebpfLearn(const PH &ph, const GwlbData &gd)
{
    if(gd.header.size() != GWLB_GENEVE_LEN)
        return 0;
    const EbpfFlow f = ebpfFlowOf(ph);
    uint8_t tag = 0;
#ifndef NO_RETURN_TRAFFIC
    // Egress first, so return traffic for the first packets the kernel delivers is already handled there too.
    if(ebpfAttachment.egress && (uint32_t)gd.ifindex == ebpf->mirredIfindex())
    {
        // The same outer headers sendUdpSG() builds: from the address the flow arrived at, to GWLB, with GWLB's
        // ports swapped back, Don't Fragment and ID 0, TTL 2, no UDP checksum. The program fills in the lengths
        // and the IP checksum.
        EbpfEgressValue v{};
        unsigned char *p = v.encap;
        p[0] = 0x45;
        p[6] = 0x40;   // DF
        p[8] = 2;      // TTL
        p[9] = IPPROTO_UDP;
        memcpy(p + 12, &gd.dstAddr.s_addr, 4);
        memcpy(p + 16, &gd.srcAddr.s_addr, 4);
        const uint16_t sport = htons(gd.srcPort), dport = htons(gd.dstPort);
        memcpy(p + 20, &sport, 2);
        memcpy(p + 22, &dport, 2);
        memcpy(p + 28, gd.header.data(), GWLB_GENEVE_LEN);
        v.encapLen = GWLB_ENCAP_LEN;
        v.nicIfindex = (uint32_t)gd.ifindex;
        v.lastSentNs = EbpfLoader::nowNs();
        const bool ok = f.v6 ? ebpf->updateEgress(f.fwd6, v) && ebpf->updateEgress(f.rev6, v)
                             : ebpf->updateEgress(f.fwd4, v) && ebpf->updateEgress(f.rev4, v);
        if(ok)
            tag |= TAG_EGRESS;
        else if(f.v6) { ebpf->removeEgress(f.fwd6); ebpf->removeEgress(f.rev6); }
        else { ebpf->removeEgress(f.fwd4); ebpf->removeEgress(f.rev4); }
    }
#endif
    if(ebpfAttachment.gwiIfindex && ebpf->handlesIngress(gd.ifindex))
    {
        const EbpfIngressKey k = ingressKey(eni, gd);
        EbpfIngressValue v{};
        v.flowDigest = f.digest;
        v.lastSeenNs = EbpfLoader::nowNs();
        v.gwiIfindex = ebpfAttachment.gwiIfindex;
        v.disposition = DISP_REDIRECT;
        switch(ebpf->insertIngress(k, v))
        {
            case EbpfLoader::InsertResult::Inserted:
                tag |= TAG_INGRESS;
                break;
            case EbpfLoader::InsertResult::Exists:
            {
                // Already there: ours (learned again), or another flow's that GWLB gave the same cookie, which
                // keeps it (this flow then stays in userspace on the way in).
                EbpfIngressValue cur;
                if(ebpf->lookupIngress(k, cur) && cur.flowDigest == f.digest && cur.gwiIfindex == v.gwiIfindex)
                    tag |= TAG_INGRESS;
                break;
            }
            default:
                break;
        }
    }
    return tag;
}

// Remove what a flow put in the eBPF maps (tag says what it may have). The ingress entry goes only if it's still
// this flow's: another flow may have taken the cookie since.
template<class PH> void GeneveHandlerENI::ebpfForget(const PH &ph, const GwlbData &gd, uint8_t tag)
{
    const EbpfFlow f = ebpfFlowOf(ph);
#ifndef NO_RETURN_TRAFFIC
    if((tag & TAG_EGRESS) && ebpfAttachment.gwoIfindex)
    {
        if(f.v6) { ebpf->removeEgress(f.fwd6); ebpf->removeEgress(f.rev6); }
        else { ebpf->removeEgress(f.fwd4); ebpf->removeEgress(f.rev4); }
    }
#endif
    if((tag & TAG_INGRESS) && gd.header.size() == GWLB_GENEVE_LEN)
    {
        const EbpfIngressKey k = ingressKey(eni, gd);
        EbpfIngressValue cur;
        if(ebpf->lookupIngress(k, cur) && cur.flowDigest == f.digest && cur.gwiIfindex == ebpfAttachment.gwiIfindex)
            ebpf->removeIngress(k);
    }
}

// When the eBPF datapath last carried a packet of this flow (coarseTime()), 0 if never.
template<class PH> uint32_t GeneveHandlerENI::ebpfActivity(const PH &ph, const GwlbData &gd, uint8_t tag) const
{
    const EbpfFlow f = ebpfFlowOf(ph);
    uint64_t ns = 0;
    if((tag & TAG_INGRESS) && gd.header.size() == GWLB_GENEVE_LEN)
    {
        EbpfIngressValue v;
        if(ebpf->lookupIngress(ingressKey(eni, gd), v) && v.flowDigest == f.digest)
            ns = std::max<uint64_t>(ns, v.lastSeenNs);
    }
#ifndef NO_RETURN_TRAFFIC
    if(tag & TAG_EGRESS)
    {
        EbpfEgressValue v;
        if(f.v6 ? ebpf->lookupEgress(f.fwd6, v) : ebpf->lookupEgress(f.fwd4, v))
            ns = std::max<uint64_t>(ns, v.lastSentNs);
        if(f.v6 ? ebpf->lookupEgress(f.rev6, v) : ebpf->lookupEgress(f.rev4, v))
            ns = std::max<uint64_t>(ns, v.lastSentNs);
    }
#endif
    return coarseFromNs(ns);
}

GeneveHandlerENI::EbpfAttachment::EbpfAttachment(GeneveHandlerENI &ownerParam) : owner(ownerParam)
{
    if(!owner.ebpf)
        return;
    gwiIfindex = EbpfLoader::ifindex(owner.devInName);
    if(gwiIfindex == 0)
        LOG(LS_EBPF, LL_IMPORTANT, "Unable to find "s + owner.devInName + "; GWLB endpoint vpce-"s + owner.eniStr + "'s traffic stays in userspace."s);
#ifndef NO_RETURN_TRAFFIC
    gwoIfindex = EbpfLoader::ifindex(owner.devOutName);
    egress = gwoIfindex != 0 && owner.ebpf->egressEnabled() && owner.ebpf->attachEgress(owner.devOutName);
#endif
}

GeneveHandlerENI::EbpfAttachment::~EbpfAttachment()
{
    if(!owner.ebpf)
        return;
    size_t n = 0;
    auto forget = [&](const auto &ph, const GwlbData &gd, uint8_t tag) {
        if(tag)
        {
            owner.ebpfForget(ph, gd, tag);
            n++;
        }
    };
    try {
        owner.v4Flows.forEach(forget);
        owner.v6Flows.forEach(forget);
        LOG(LS_EBPF, LL_INFO, "Removed GWLB endpoint vpce-"s + owner.eniStr + "'s "s + std::to_string(n) + " flows from the eBPF maps."s);
    } catch(...) {
        // Only possible if building the log message runs out of memory.
    }
}

/**
 * Per endpoint: on gwi- and on gwo-, one tun queue, one raw send socket and one epoll set per tunnel thread, and
 * the interface's stop eventfd; the gwi- writers; and the endpoint's shared raw socket. Receive-only builds have no gwo- and no
 * tunnel threads: the writers and gwi-'s stop eventfd.
 */
size_t GeneveHandlerENI::fdsPerEndpoint(const GwlbtunConfig &cfg)
{
    const size_t tunThreads = cfg.tunThreads.cfg.size();
    const size_t writers = gwiWriterCount(cfg.udpThreadCount(), cfg.maxRxQueues, tunThreads);
#ifndef NO_RETURN_TRAFFIC
    return 6 * tunThreads + writers + 3;
#else
    return writers + 1;
#endif
}

/**
 * Open the gwi- writer fds (nWriters: one per GWI_WRITER_SHARE UDP threads and at least one per network receive
 * queue, within the room the reader threads leave; see gwiWriterCount in utils.h). The first creates the device
 * (exclusively), so these come before the reader threads.
 *
 * The kernel tags each packet written into a tun device with the writing queue's index, as if it were the
 * receive queue, and when the packet is forwarded out an interface with no XPS map, it sends it on that
 * transmit queue (modulo the queue count). So the writers need distinct indices, or forwarded traffic (two-arm
 * and NAT setups) all leaves on one transmit queue. Attaching gives writer i index i; detaching (see
 * TunSocket::detachQueue) then moves the device's last queue into the detached one's slot, so detach them
 * last-first: each keeps the index it was given.
 */
std::vector<TunSocket> GeneveHandlerENI::makeWriters(const std::string &devname, const std::string &eniStr, size_t nWriters)
{
    std::vector<TunSocket> writers;
    writers.reserve(nWriters);
    for(size_t i = 0; i < nWriters; i++)
        writers.emplace_back(devname, i == 0);   // the first creates the device (exclusively); the rest attach
    int detached = 0;
    for(size_t i = nWriters; i-- > 0;)
        if(writers[i].detachQueue())
            detached++;
    LOG(LS_TUNNEL, LL_DEBUG, "GWLB endpoint vpce-"s + eniStr + ": "s + std::to_string(nWriters) + " gwi writer(s), "s +
        std::to_string(detached) + " detached."s);
    return writers;
}

#ifndef NO_RETURN_TRAFFIC
// The stored GENEVE header and outer addresses for a packet read from a tun interface, or nullopt (logged) for a
// flow that never came from GWLB.
template<class PH> static std::optional<GwlbData> resolveFlow(ProtocolFlowCache<PH, GwlbData> &cache, const PH &ph)
{
    auto found = cache.lookup(ph);
    if(!found)
        LOG(LS_TUNNEL, LL_DEBUG, "Flow " + ph.text() + " has not been seen coming in from GWLB - dropping.  (Remember - GWLB is for inline inspection only - you cannot source new flows from this device into it.)");
    else
        LOG(LS_TUNNEL, LL_DEBUGDETAIL, "Resolved packet header " + ph.text() + " to options " + found->text());
    return found;
}
#endif

/**
 * Callback function passed to TunInterface to handle packets coming back in from the OS to either the gwi- or the
 * gwo- interface. Matches the packet's flow to one seen from GWLB (logs and returns if there is none) and sends
 * the packet, re-encapsulated with that flow's GENEVE header, back to GWLB.
 *
 * @param pktbuf The packet received.
 * @param pktlen Length of packet received.
 */
void GeneveHandlerENI::tunReceiverCallback(unsigned char *pktbuf, ssize_t pktlen)
{
    LOG(LS_TUNNEL, LL_DEBUG, "Received a packet of " + ts(pktlen) + " bytes for GWLB endpoint vpce-" + eniStr);
    LOGHEXDUMP(LS_TUNNEL, LL_DEBUGDETAIL, "Tun Packet", pktbuf, pktlen);

#ifdef NO_RETURN_TRAFFIC
    LOG(LS_TUNNEL, LL_DEBUG, "Received a packet, but NO_RETURN_TRAFFIC is defined. Discarding.");
#else
    // Ignore packets that are not IPv4 or IPv6, or aren't at least long enough to have those sized headers.
    if(pktlen < 20)
    {
        LOG(LS_TUNNEL, LL_DEBUG, "Received a packet that is not long enough to have an IP header, ignoring.");
        return;
    }
    try
    {
        std::optional<GwlbData> gd;
        switch(pktbuf[0] >> 4)
        {
            case 4: gd = resolveFlow(v4Flows, PacketHeaderV4(pktbuf, pktlen)); break;
            case 6: gd = resolveFlow(v6Flows, PacketHeaderV6(pktbuf, pktlen)); break;
            default:
                LOG(LS_TUNNEL, LL_DEBUG, "Received a packet that wasn't IPv4 or IPv6. Ignoring.");
                return;
        }
        if(!gd)
            return;
        sendUdpSG(t_rawSendSock >= 0 ? t_rawSendSock : sendingSock.get(), gd->dstAddr, gd->srcPort, gd->srcAddr, gd->dstPort,
                  gd->header.data(), gd->header.size(), pktbuf, (size_t)pktlen, gd->ifindex);
    } catch(const std::invalid_argument &err) {
        LOG(LS_TUNNEL, LL_DEBUG, "Packet processor has a malformed packet: "s + err.what());
    }
#endif
}

/**
 * Callback function passed to UDPPacketReceiver to handle GenevePackets. Called by GeneveHandler once the ENI
 * has been determined (creating this class if needed). Learns the inner flow (so its return traffic can be sent
 * back with this GENEVE header) and writes the inner packet to gwi-. An inner packet that can't be parsed is
 * dropped and counted.
 *
 * @param gd The packet's GENEVE header and outer addresses
 * @param pkt The GENEVE payload received (header, then the inner packet).
 * @param pktlen Length of packet received.
 */
void GeneveHandlerENI::udpReceiverCallback(const GwlbData &gd, const unsigned char *pkt, ssize_t pktlen)
{
    // GenevePacket has checked that the header fits in the packet, so innerLen is never negative.
    const unsigned char *inner = pkt + gd.header.size();
    const ssize_t innerLen = pktlen - (ssize_t)gd.header.size();
    if(__builtin_expect(innerLen < (ssize_t)sizeof(struct ip), 0))
    {
        countDrop();
        LOG(LS_UDP, LL_DEBUG, "Inner packet of "s + ts(innerLen) + " bytes is too short to be an IP packet. Dropping it.");
        return;
    }
    const unsigned version = inner[0] >> 4;
#ifdef NO_RETURN_TRAFFIC
    if(ebpf)   // receive-only builds keep flows only for the eBPF maps
#endif
    {
        try {
            // Insert the flow if new, otherwise just refresh its idle timer. With eBPF, also hand new flows to the
            // eBPF maps (see ebpfInsert).
            if(__builtin_expect(version == 4, 1))
            {
                const PacketHeaderV4 ph(inner, innerLen);
                if(ebpf) ebpfInsert(v4Flows, ph, gd, inner, innerLen); else v4Flows.insert(ph, gd);
            }
            else if(version == 6)
            {
                const PacketHeaderV6 ph(inner, innerLen);
                if(ebpf) ebpfInsert(v6Flows, ph, gd, inner, innerLen); else v6Flows.insert(ph, gd);
            }
        } catch(const std::invalid_argument &err) {
            countDrop();
            LOG(LS_UDP, LL_DEBUG, "Packet processor has a malformed packet: "s + err.what());
            return;
        }
    }
    if(__builtin_expect(version != 4 && version != 6, 0))
    {
        countDrop();
        LOG(LS_UDP, LL_DEBUG, "Got a strange IP protocol version - "s + ts(version) + " at offset " + ts(gd.header.size()) + ". Dropping packet.");
        return;
    }
    // Route the decap'ed packet to our tun interface, accounting for drops.
    writeToTun(inner, innerLen);
}

/**
 * Write a decapsulated packet to the ingress tun interface, counting a successful
 * write toward pktsOut/bytesOut, or a write error / short write toward pktsDropped.
 */
void GeneveHandlerENI::writeToTun(const unsigned char *pkt, ssize_t pktlen)
{
    // UDP thread t writes through writer t % writers: with one UDP thread per receive queue (the default),
    // queue i's packets go through writer i and, when forwarded, out of transmit queue i.
    const size_t w = t_udpThreadIndex >= 0 ? (size_t)t_udpThreadIndex % gwiWriters.size() : 0;
    const ssize_t written = gwiWriters[w].write(pkt, pktlen);
    const int err = errno;
    auto &h = hotSlot();
    // The last-packet time is used for idle detection and the health report, which work in seconds: stamp it
    // once per coarse second rather than reading the clock for every packet.
    if(const uint32_t now = coarseTime(); h.lastPacketOutCoarse != now)
    {
        h.lastPacketOutCoarse = now;
        h.lastPacketOut.store(std::chrono::steady_clock::now(), std::memory_order_relaxed);
    }
    if(__builtin_expect(written == pktlen, 1))
    {
        h.pktsOut.fetch_add(1, std::memory_order_relaxed);
        h.bytesOut.fetch_add(pktlen, std::memory_order_relaxed);
    }
    else
    {
        h.pktsDropped.fetch_add(1, std::memory_order_relaxed);
        if(written < 0)
            LOG(LS_UDP, LL_IMPORTANT, "Failed to write "s + ts(pktlen) + " byte packet to "s + devInName + ": "s + errText(err));
        else
            LOG(LS_UDP, LL_IMPORTANT, "Partial write to "s + devInName + ": only "s + ts(written) + " of "s + ts(pktlen) + " bytes written; dropping packet."s);
    }
}

#ifndef NO_RETURN_TRAFFIC
// Health JSON key for each flow cache, in GeneveHandlerENIHealthCheck's order (TCP, UDP, Other).
static const char *const v4CacheKeys[3] = { "v4FlowCacheTcp", "v4FlowCacheUdp", "v4FlowCacheOther" };
static const char *const v6CacheKeys[3] = { "v6FlowCacheTcp", "v6FlowCacheUdp", "v6FlowCacheOther" };
#endif

std::string GeneveHandlerENIHealthCheck::output_str() const
{
    std::stringstream ret;

    ret << "Handler for GWLBe vpce-" << eniStr << " is " << (healthy ? "healthy" : "UNHEALTHY") << std::endl;
    ret << pktsOut << " packets out to OS, " << bytesOut << " bytes out to OS, " << pktsDropped << " packets dropped, "
        << timepointDeltaString(std::chrono::steady_clock::now(), lastPacketOut) << " since last packet.\n";
    ret << tunnelIn.output_str();
#ifndef NO_RETURN_TRAFFIC
    ret << tunnelOut.output_str();
    for(const auto &c : v4Caches)
        ret << c.output_str();
    for(const auto &c : v6Caches)
        ret << c.output_str();
#endif
    if(ebpf)
        ret << "eBPF: " << ebpfRepunts << " packets of flows already in the eBPF maps reached gwlbtun, " << ebpfLateRepunts
            << " of them 5 or more seconds after the flow was learned.\n";
    return ret.str();
}

json GeneveHandlerENIHealthCheck::output_json() const
{
    json j = {{"healthy", healthy}, {"gwlbEndpointId", "vpce-" + eniStr}, {"pktsOut", pktsOut}, {"bytesOut", bytesOut}, {"pktsDropped", pktsDropped},
              {"secsSinceLastPacket", timepointDeltaDouble(std::chrono::steady_clock::now(), lastPacketOut)}, {"tunnelIn", tunnelIn.output_json()}};
#ifndef NO_RETURN_TRAFFIC
    j["tunnelOut"] = tunnelOut.output_json();
    for(size_t i = 0; i < 3; i++)
    {
        j[v4CacheKeys[i]] = v4Caches[i].output_json();
        j[v6CacheKeys[i]] = v6Caches[i].output_json();
    }
#endif
    if(ebpf)
        j["ebpf"] = {{"repunts", ebpfRepunts}, {"lateRepunts", ebpfLateRepunts}};
    return j;
}

GeneveHandlerENIHealthCheck GeneveHandlerENI::check() const
{
#ifndef NO_RETURN_TRAFFIC
    const bool healthy = tunnelIn.healthCheck() && tunnelOut.healthCheck();
#else
    const bool healthy = tunnelIn.healthCheck();
#endif
    uint64_t pktsOut = 0, bytesOut = 0, pktsDropped = 0;
    std::chrono::steady_clock::time_point lastOut{};
    for(size_t i = 0; i < hotSlots; i++)
    {
        pktsOut += hot[i].pktsOut.load(); bytesOut += hot[i].bytesOut.load(); pktsDropped += hot[i].pktsDropped.load();
        lastOut = std::max(lastOut, hot[i].lastPacketOut.load());
    }
    GeneveHandlerENIHealthCheck h{ healthy, eniStr, pktsOut, bytesOut, pktsDropped, lastOut, tunnelIn.status()
#ifndef NO_RETURN_TRAFFIC
             , tunnelOut.status(), v4Flows.stats(), v6Flows.stats()
#endif
    };
    h.ebpf = ebpf != nullptr;
    h.ebpfRepunts = ebpfRepunts.load(std::memory_order_relaxed);
    h.ebpfLateRepunts = ebpfLateRepunts.load(std::memory_order_relaxed);
    return h;
}

void GeneveHandlerENI::sweepCaches()
{
    if(ebpf)
    {
        // Ask the maps about accelerated flows the cache hasn't seen for a while (soon enough, with -t, for the
        // idle check below), keep them while the maps saw them, and take evicted flows out of the maps.
        const uint32_t checkAge = tunnelTimeout > 0 ? (uint32_t)tunnelTimeout : UINT32_MAX;
        auto activity = [this](const auto &ph, const GwlbData &gd, uint8_t tag) { return ebpfActivity(ph, gd, tag); };
        auto evict = [this](const auto &ph, const GwlbData &gd, uint8_t tag) { ebpfForget(ph, gd, tag); };
        lastFlowActivity.store(std::max(v4Flows.sweep(checkAge, activity, evict), v6Flows.sweep(checkAge, activity, evict)),
                               std::memory_order_relaxed);
        return;
    }
#ifndef NO_RETURN_TRAFFIC
    v4Flows.sweep();
    v6Flows.sweep();
#endif
}

/**
 * Check to see if we haven't seen traffic in timeout seconds.
 *
 * @return True if we haven't seen a packet in timeout seconds, false otherwise.
 */
bool GeneveHandlerENI::hasGoneIdle(int timeout) const
{
    const auto expireTime = std::chrono::steady_clock::now() - std::chrono::seconds(timeout);

    for(size_t i = 0; i < hotSlots; i++)
        if(hot[i].lastPacketOut.load() > expireTime) return false;
#ifndef NO_RETURN_TRAFFIC
    if(tunnelIn.lastPacketTime() > expireTime) return false;
    if(tunnelOut.lastPacketTime() > expireTime) return false;
#endif
    // Packets the eBPF datapath carries never reach the counters above; the last sweep recorded when it last
    // carried any of this endpoint's flows.
    if(ebpf)
        if(const uint32_t last = lastFlowActivity.load(std::memory_order_relaxed); last != 0 && coarseTime() - last < (uint32_t)timeout)
            return false;
    return true;
}

// Set once, before any endpoint exists (GeneveHandler's constructor), from the -I interface list.
static std::string g_devnameScope;

void setDevnameScope(const std::vector<std::string> &interfaces)
{
    g_devnameScope.clear();
    for(const auto &i : interfaces)
        g_devnameScope += i + "\n"s;
}

/**
 * Name of an endpoint's gwi-/gwo- device. With all interfaces (no -I) this is the endpoint id in base 60,
 * as in earlier versions. With -I, it's a 64-bit FNV-1a hash of the endpoint id and the interface list,
 * so gwlbtun processes serving different interfaces never pick the same names when one GWLB endpoint
 * reaches several of the instance's ENIs (for example IP targets with one ENI per process). Either way
 * the result fits the kernel's 15-character limit ("gwi-" + at most 11 base-60 digits). Hooks get the
 * endpoint id as an argument, so the name doesn't need to be reversible.
 */
std::string devname_make(gwlbeid_t eni, bool inbound) {
    uint64_t id = eni;
    if(!g_devnameScope.empty())
    {
        uint64_t h = 1469598103934665603ULL;               // FNV-1a 64-bit offset basis
        auto mix = [&h](unsigned char c) { h ^= c; h *= 1099511628211ULL; };
        for(int i = 0; i < 8; i++)
            mix((unsigned char)(eni >> (8 * i)));
        for(char c : g_devnameScope)
            mix((unsigned char)c);
        id = h;
    }
    return (inbound ? "gwi-"s : "gwo-"s) + toBase60(id);
}
