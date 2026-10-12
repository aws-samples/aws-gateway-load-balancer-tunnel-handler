// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * The flow caches: for each inner flow seen from GWLB, the GENEVE header and outer addresses to send its return
 * traffic with. FlowCache is one cache; ProtocolFlowCache is the TCP/UDP/Other trio an endpoint keeps per address
 * family, each with its own idle timeout. Used by GeneveHandler.
 */

#ifndef GWLBTUN_FLOWCACHE_H
#define GWLBTUN_FLOWCACHE_H

#include <array>
#include <atomic>
#include <boost/unordered/concurrent_flat_map.hpp>
#include <netinet/in.h>
#include <optional>
#include <string>
#include <utility>
#include "HealthCheck.h"
#include "utils.h"      // coarseTime()
#include "Logger.h"

// A snapshot of one cache's state, for the health check.
class FlowCacheHealthCheck {
public:
    FlowCacheHealthCheck(std::string cacheName, int cacheTimeout, size_t size, size_t timedOut) :
        cacheName(std::move(cacheName)), cacheTimeout(cacheTimeout), size(size), timedOut(timedOut) {}
    std::string output_str() const
    {
        return cacheName + " : Contains " + std::to_string(size) + " elements; the last sweep removed " + std::to_string(timedOut) +
               " idle elements (idle timeout is " + std::to_string(cacheTimeout) + " seconds).\n";
    }
    json output_json() const
    {
        return {{"cacheName", cacheName}, {"size", size}, {"timedOut", timedOut}, {"idleTimeoutSecs", cacheTimeout}};
    }

private:
    std::string cacheName;
    int cacheTimeout;
    size_t size;
    size_t timedOut;
};

/**
 * Cache entry: the value, and when the flow was last seen (coarse seconds, see coarseTime()).
 *
 * boost::concurrent_flat_map moves entries in place when it rehashes, using their move constructors. Keep the
 * entry a plain value: no atomics and no hand-written copy/move members. An earlier version made 'last' a
 * std::atomic with hand-written special members so it could be refreshed under cvisit's shared lock; that raced
 * with rehash relocation on the insert path and segfaulted under load. Every write to 'last' now happens under
 * the group's exclusive lock (visit, and try_emplace_or_visit's visit path), so a plain uint32_t is race-free.
 */
template <class V> class FlowCacheEntry {
public:
    explicit FlowCacheEntry(V entrydata) : last(coarseTime()), data(std::move(entrydata)) {}

    uint32_t last;
    V data;
};

/**
 * One flow cache.
 * @tparam K  Key type (PacketHeaderV4/V6: a flow and its reverse are the same key)
 * @tparam V  Value type (GwlbData)
 */
template <class K, class V> class FlowCache {
public:
    // cacheName names it in diagnostics; entries idle longer than cacheTimeout seconds are removed by sweep().
    FlowCache(std::string cacheName, int cacheTimeout, std::size_t reserve = 0) :
        cacheTimeout(cacheTimeout), cacheName(std::move(cacheName))
    {
        if(reserve > 0)
            cache.reserve(reserve);
    }

    // The value stored for key, refreshing its idle timer, or nullopt.
    std::optional<V> lookup(const K &key)
    {
        std::optional<V> ret;
        cache.visit(key, [&](auto &e) { touch(e.second); ret = e.second.data; });
        return ret;
    }

    // Store value for key. A new flow is inserted; a known one has its idle timer refreshed and, if the stored
    // value differs, it's replaced and the change reported (see reportValueChange).
    void insert(const K &key, const V &value)
    {
        // The stored value changes only rarely; the old one is copied out so the change can be reported after
        // the map's lock is released.
        std::optional<V> previous;
        cache.try_emplace_or_visit(key, value, [&](auto &e) {
            touch(e.second);
            if(!(e.second.data == value)) { previous = e.second.data; e.second.data = value; }
        });
        if(__builtin_expect(previous.has_value(), 0))
            reportValueChange(key, *previous, value);
    }

    // Cache status (name, timeout, current size) WITHOUT scanning or evicting: O(1).
    FlowCacheHealthCheck stats() const
    {
        return { cacheName, cacheTimeout, cache.size(), lastSweepRemoved.load(std::memory_order_relaxed) };
    }

    // Evict entries idle longer than cacheTimeout. O(N) full scan; called on a fixed cadence by the reaper.
    // Returns the number of entries removed.
    size_t sweep()
    {
        const uint32_t now = coarseTime();
        const uint32_t expireTime = (now > (uint32_t)cacheTimeout) ? (now - (uint32_t)cacheTimeout) : 0;
        const size_t removed = cache.erase_if([expireTime](auto &e) { return e.second.last < expireTime; });
        lastSweepRemoved.store(removed, std::memory_order_relaxed);
        return removed;
    }

private:
    const int cacheTimeout;
    const std::string cacheName;
    boost::concurrent_flat_map<K, FlowCacheEntry<V>> cache;
    std::atomic<size_t> lastSweepRemoved{0};    // Entries the most recent sweep() evicted
    std::atomic<uint64_t> valueChanges{0};      // Times insert() found a known flow with a different value

    // Refresh an entry's idle timer. Called under the group's exclusive lock. Written only when the coarse second
    // has changed, so a busy flow doesn't dirty its cache line on every packet.
    static void touch(FlowCacheEntry<V> &e)
    {
        const uint32_t now = coarseTime();
        if(e.last != now)
            e.last = now;
    }

    // Log that a known flow arrived with a different value than the one stored (for the GWLB caches: a different
    // GENEVE header, such as a new flow cookie, or different outer addresses, ports or interface). Logs the first
    // change in this cache and then every 4096th, so a recurring problem is visible without flooding the log.
    void reportValueChange(const K &key, const V &previous, const V &current)
    {
        const uint64_t c = valueChanges.fetch_add(1, std::memory_order_relaxed);
        if((c & 0xFFF) == 0)
            LOG(LS_UDP, LL_IMPORTANT, cacheName + ": GWLB data changed for an established flow (" + key.text() +
                                      "): was" + previous.text() + "; now" + current.text() + ". Occurrences in this cache: " +
                                      std::to_string(c + 1) + " (logging the first and every 4096th). Usually benign; investigate " +
                                      "if frequent (for example a gwlbtun/GWLB idle-timeout mismatch).");
    }
};

/**
 * One address family's flow caches: TCP, UDP and everything else, kept apart so each has its own idle timeout.
 * Every call picks the cache by the key's protocol.
 */
template <class K, class V> class ProtocolFlowCache {
public:
    // family ("IPv4"/"IPv6") and owner ("GWLBe vpce-...") name the caches; reserve sizes them (TCP, UDP, Other).
    ProtocolFlowCache(const std::string &family, const std::string &owner, int tcpTimeout, int udpTimeout, int otherTimeout,
                      const std::array<std::size_t, 3> &reserve) :
        tcp(family + " TCP Flow Cache for " + owner, tcpTimeout, reserve[0]),
        udp(family + " UDP Flow Cache for " + owner, udpTimeout, reserve[1]),
        other(family + " Other Flow Cache for " + owner, otherTimeout, reserve[2]) {}

    std::optional<V> lookup(const K &key) { return pick(key.prot).lookup(key); }
    void insert(const K &key, const V &value) { pick(key.prot).insert(key, value); }
    void sweep() { tcp.sweep(); udp.sweep(); other.sweep(); }
    std::array<FlowCacheHealthCheck, 3> stats() const { return { tcp.stats(), udp.stats(), other.stats() }; }

private:
    FlowCache<K, V> &pick(uint8_t prot) { return prot == IPPROTO_TCP ? tcp : prot == IPPROTO_UDP ? udp : other; }
    FlowCache<K, V> tcp, udp, other;
};

#endif //GWLBTUN_FLOWCACHE_H
