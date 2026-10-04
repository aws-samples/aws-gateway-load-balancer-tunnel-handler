// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * Templated class to handle both our IPv4 and IPv6 flow caches. This is broken out to make experimenting with different
 * data structures in terms of performance much easier. Used by GeneveHandler.
 */

#ifndef GWLBTUN_FLOWCACHE_H
#define GWLBTUN_FLOWCACHE_H

#include <chrono>
#include <ctime>
#include <boost/unordered/concurrent_flat_map.hpp>
#include <utility>
#include <optional>
#include <stdexcept>
#include "HealthCheck.h"
#include "utils.h"      // coarseTime()

class FlowCacheHealthCheck : public HealthCheck {
public:
    FlowCacheHealthCheck(std::string, int, long unsigned int, long unsigned int);
    std::string output_str() ;
    json output_json();

private:
    std::string cacheName;
    int cacheTimeout;
    long unsigned int size;
    long unsigned int timedOut;
};

/**
 * Cache entry format.
 *
 * Kept deliberately trivially-copyable: 'last' is a plain uint32_t (coarse idle
 * timestamp) and 'data' is a trivially-copyable value. This matters because
 * boost::concurrent_flat_map RELOCATES mapped values in place during rehash;
 * a trivially-relocatable entry makes that relocation safe. An earlier version
 * made 'last' a std::atomic with hand-written copy/move/assign special members
 * so it could be refreshed under cvisit's shared lock -- that non-trivially-
 * relocatable value type raced with rehash relocation on the insert path and
 * segfaulted under load. All timer updates now happen under an exclusive group
 * lock (visit / try_emplace_or_visit's visit path), so a plain uint32_t is
 * race-free and no atomic is needed.
 */
template <class V> class FlowCacheEntry {
public:
    FlowCacheEntry(V entrydata);

    uint32_t last;
    V data;
};

/**
 * Cache entry functions
 */
template<class V> FlowCacheEntry<V>::FlowCacheEntry(V entrydata) :
        last(coarseTime()), data(std::move(entrydata))
{
}

/**
 * FlowCache itself
 * @tparam K  Key type
 * @tparam V  Value type
 */
template <class K, class V> class FlowCache {
public:
    FlowCache(std::string cacheName, int cacheTimeout, std::size_t reserve = 0);
    std::optional<V> lookup(K key);
    bool insert(K key, V value);
    FlowCacheHealthCheck stats() const;
    size_t sweep();
private:
    const int cacheTimeout;
    const std::string cacheName;
    boost::concurrent_flat_map<K, FlowCacheEntry<V>> cache;
};

/**
 * Initializer.
 * @param cacheName Human name of this cache, used for diagnostic outputs.
 */
template<class K, class V>
FlowCache<K, V>::FlowCache(std::string cacheName, int cacheTimeout, std::size_t reserve) :
         cacheTimeout(cacheTimeout), cacheName(std::move(cacheName))
{
    if(reserve > 0) cache.reserve(reserve);
}

/**
 * Look up a value for key K in our cache.
 *
 * @param key Key to lookup
 * @return The value if present, std::nullopt otherwise.
 */
template<class K, class V>std::optional<V> FlowCache<K, V>::lookup(K key)
{
    V ret;
    // visit takes the group's EXCLUSIVE lock, so the in-place idle-timer refresh
    // below is race-free with a plain uint32_t (no atomic needed). We refresh only
    // when the coarse second has actually changed, to avoid dirtying the cache
    // line on every packet of a busy flow.
    if(cache.visit(key, [&](auto& fce) {
            uint32_t now = coarseTime();
            if(fce.second.last != now)
                fce.second.last = now;
            ret = fce.second.data;
        }))
        return ret;
    else
        return std::nullopt;
}

/**
 * Insert a value for key K in our cache. If not present, insert with value V otherwise update the value.
 *
 * @param K Key to lookup
 * @param V Value to insert if K is not present.
 */
template<class K, class V>bool FlowCache<K, V>::insert(K key, V value)
{
    // Insert the flow if new; if it already exists, just refresh its idle timer
    // (coarse, store-if-changed) instead of rewriting the whole value on every
    // packet. The stored value changes only on the rare cookie change, which we
    // report back to the caller.
    bool changed = false;
    cache.try_emplace_or_visit(std::move(key), value,
        [&](auto& x) {
            uint32_t now = coarseTime();
            if(x.second.last != now)
                x.second.last = now;
            if(!(x.second.data == value)) { x.second.data = value; changed = true; }
        });
    return changed;
}

/**
 * Report cache status (name, timeout, current size) WITHOUT scanning or evicting.
 * O(1); safe to call on every health request. Eviction is done by sweep().
 */
template<class K, class V> FlowCacheHealthCheck FlowCache<K, V>::stats() const
{
    return { cacheName, cacheTimeout, cache.size(), 0 };
}

/**
 * Evict entries idle longer than cacheTimeout. O(N) full scan; call on a fixed
 * cadence off the health path. Returns the number of entries removed.
 */
template<class K, class V> size_t FlowCache<K, V>::sweep()
{
    uint32_t now = coarseTime();
    uint32_t expireTime = (now > (uint32_t)cacheTimeout) ? (now - (uint32_t)cacheTimeout) : 0;
    return cache.erase_if([expireTime](auto& fce) { return fce.second.last < expireTime; });
}

#endif //GWLBTUN_FLOWCACHE_H
