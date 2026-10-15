// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * The flow caches: for each inner flow seen from GWLB, the GENEVE header and outer addresses to send its return
 * traffic with. FlowCache is one cache; ProtocolFlowCache is the TCP/UDP/Other trio an endpoint keeps per address
 * family, each with its own idle timeout. Used by GeneveHandler.
 */

#ifndef GWLBTUN_FLOWCACHE_H
#define GWLBTUN_FLOWCACHE_H

#include <algorithm>
#include <array>
#include <atomic>
#include <boost/unordered/concurrent_flat_map.hpp>
#include <netinet/in.h>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>
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
    explicit FlowCacheEntry(V entrydata) : last(coarseTime()), tagTime(last), data(std::move(entrydata)) {}

    uint32_t last;
    uint32_t tagTime;   // coarseTime() when tag was last set (or the entry created)
    uint8_t tag = 0;    // The owner's per-flow state (GeneveHandlerENI: what the eBPF maps hold for the flow)
    V data;
};

// What FlowCache::insert() did.
struct FlowInsertResult {
    enum Kind : uint8_t { Inserted, Refreshed, Changed } kind;
    uint8_t tag = 0;          // Refreshed: the entry's tag (Inserted and Changed clear it)
    uint32_t tagAge = 0;      // Refreshed: seconds since the tag was set
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
    // value differs, it's replaced (clearing its tag) and the change reported (see reportValueChange). If
    // previousOut is given, it receives the value replaced.
    FlowInsertResult insert(const K &key, const V &value, std::optional<V> *previousOut = nullptr)
    {
        // The stored value changes only rarely; the old one is copied out so the change can be reported after
        // the map's lock is released.
        std::optional<V> previous;
        FlowInsertResult r{FlowInsertResult::Refreshed};
        const bool inserted = cache.try_emplace_or_visit(key, value, [&](auto &e) {
            touch(e.second);
            if(!(e.second.data == value))
            {
                previous = e.second.data;
                e.second.data = value;
                e.second.tag = 0;
                e.second.tagTime = e.second.last;
                r.kind = FlowInsertResult::Changed;
            }
            else
            {
                r.tag = e.second.tag;
                r.tagAge = e.second.last - e.second.tagTime;
            }
        });
        if(inserted)
            r.kind = FlowInsertResult::Inserted;
        if(__builtin_expect(previous.has_value(), 0))
        {
            reportValueChange(key, *previous, value);
            if(previousOut)
                *previousOut = std::move(previous);
        }
        return r;
    }

    // Set a flow's tag (and its tagTime to now). Returns false if the flow isn't in the cache.
    bool setTag(const K &key, uint8_t tag)
    {
        return cache.visit(key, [&](auto &e) { e.second.tag = tag; e.second.tagTime = coarseTime(); }) != 0;
    }

    // Call f(key, value, tag) for every entry, under the map's shared locks: f must not use this cache.
    template<class F> void forEach(F &&f) const
    {
        cache.cvisit_all([&](const auto &e) { f(e.first, e.second.data, e.second.tag); });
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

    /**
     * sweep() for a cache whose flows can be active without this cache seeing them (the eBPF datapath carries
     * their packets). Entries with a tag that this cache hasn't seen for checkAge seconds (at most the idle
     * timeout) are asked about first: activity(key, value, tag) returns the coarseTime() of the flow's last
     * activity elsewhere (0 = none), and the entry's timer is moved up to it. Then idle entries are evicted as
     * in sweep(), and onEvict(key, value, tag) is called for each one that had a tag, after the map's locks are
     * released. Neither callback is called with a lock held, so both may take their time.
     *
     * @return The newest activity (coarseTime()) of any entry left in the cache, 0 if it's empty.
     */
    template<class Activity, class Evict> uint32_t sweep(uint32_t checkAge, Activity &&activity, Evict &&onEvict)
    {
        const uint32_t now = coarseTime();
        checkAge = std::min(checkAge, (uint32_t)cacheTimeout);
        struct Candidate { K key; V value; uint32_t last; uint8_t tag; };
        std::vector<Candidate> candidates;
        uint32_t newest = 0;
        cache.cvisit_all([&](const auto &e) {
            if(e.second.tag && now - e.second.last >= checkAge)
                candidates.push_back({ e.first, e.second.data, e.second.last, e.second.tag });
            else
                newest = std::max(newest, e.second.last);
        });
        for(auto &c : candidates)
        {
            const uint32_t seen = activity(c.key, c.value, c.tag);
            if(seen > c.last)
                cache.visit(c.key, [seen](auto &e) { if(e.second.last < seen) e.second.last = seen; });
            if(now - std::max(seen, c.last) <= (uint32_t)cacheTimeout)
                newest = std::max(newest, std::max(seen, c.last));
        }

        const uint32_t expireTime = (now > (uint32_t)cacheTimeout) ? (now - (uint32_t)cacheTimeout) : 0;
        std::vector<std::tuple<K, V, uint8_t>> evicted;
        const size_t removed = cache.erase_if([&](auto &e) {
            if(e.second.last >= expireTime)
                return false;
            if(e.second.tag)
                evicted.emplace_back(e.first, e.second.data, e.second.tag);
            return true;
        });
        lastSweepRemoved.store(removed, std::memory_order_relaxed);
        for(auto &[k, v, t] : evicted)
            onEvict(k, v, t);
        return newest;
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
    FlowInsertResult insert(const K &key, const V &value, std::optional<V> *previousOut = nullptr) { return pick(key.prot).insert(key, value, previousOut); }
    bool setTag(const K &key, uint8_t tag) { return pick(key.prot).setTag(key, tag); }
    template<class F> void forEach(F &&f) const { tcp.forEach(f); udp.forEach(f); other.forEach(f); }
    void sweep() { tcp.sweep(); udp.sweep(); other.sweep(); }
    template<class Activity, class Evict> uint32_t sweep(uint32_t checkAge, Activity &&activity, Evict &&onEvict)
    {
        return std::max({ tcp.sweep(checkAge, activity, onEvict), udp.sweep(checkAge, activity, onEvict), other.sweep(checkAge, activity, onEvict) });
    }
    std::array<FlowCacheHealthCheck, 3> stats() const { return { tcp.stats(), udp.stats(), other.stats() }; }

private:
    FlowCache<K, V> &pick(uint8_t prot) { return prot == IPPROTO_TCP ? tcp : prot == IPPROTO_UDP ? udp : other; }
    FlowCache<K, V> tcp, udp, other;
};

#endif //GWLBTUN_FLOWCACHE_H
