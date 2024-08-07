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
#include <boost/algorithm/string/predicate.hpp>
#include <utility>
#include <stdexcept>
#include "HealthCheck.h"

// Timeout for the flow cache in seconds. This is set a little longer than GWLB's timeout.
#define FLOWCACHE_TIMEOUT 360

class FlowCacheHealthCheck : public HealthCheck {
public:
    FlowCacheHealthCheck(std::string, long unsigned int, long unsigned int);
    std::string output_str() ;
    json output_json();

private:
    std::string cacheName;
    long unsigned int size;
    long unsigned int timedOut;
};

/**
 * Cache entry format
 */
template <class V> class FlowCacheEntry {
public:
    FlowCacheEntry(V entrydata);

    time_t last;
    uint32_t useCount;
    V data;
};

/**
 * Cache entry functions
 */
template<class V> FlowCacheEntry<V>::FlowCacheEntry(V entrydata) :
        last(time(NULL)), useCount(1), data(entrydata)
{
}

/**
 * FlowCache itself
 * @tparam K  Key type
 * @tparam V  Value type
 */
template <class K, class V> class FlowCache {
public:
    FlowCache(std::string cacheName, int cacheTimeout);
    V lookup(K key);
    V emplace_or_lookup(K key, V value);
    FlowCacheHealthCheck check();
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
FlowCache<K, V>::FlowCache(std::string cacheName, int cacheTimeout) :
         cacheTimeout(cacheTimeout), cacheName(std::move(cacheName))
{
}

/**
 * Look up a value for key K in our cache. Raises invalid_argument exception if key not present.
 *
 * @param key Key to lookup
 * @return Value if present, raises invalid_argument exception if key not present.
 */
template<class K, class V>V FlowCache<K, V>::lookup(K key)
{
    V ret;
    if(cache.visit(key, [&](auto& fce) { fce.second.last = time(NULL); fce.second.useCount ++; ret = fce.second.data; }))
        return ret;
    else
        throw std::invalid_argument("Key not found in FlowCache.");
}

/**
 * Looks up a value for key K in our cache. If not present, insert with value V.
 *
 * @param K Key to lookup
 * @param V Value to insert if K is not present.
 * @return Value (either the one looked up, or the inserted data, as appropriate).
 */
template<class K, class V>V FlowCache<K, V>::emplace_or_lookup(K key, V value)
{
    V ret;
    if(!(cache.emplace_or_visit(key, value, [&](auto& fce) { fce.second.last = time(NULL); fce.second.useCount ++; ret = fce.second.data; })))
        return ret;
    return value;
}

/**
 * Return diagnostic status of our cache. Needs to be called occasionally as it does cleanup as a side effect.
 *
 * @return String of diagnostic text.
 */
template<class K, class V> FlowCacheHealthCheck FlowCache<K, V>::check()
{
    long unsigned int timedOut;
    time_t expireTime = time(NULL) - cacheTimeout;

    timedOut = cache.erase_if([expireTime](auto& fce) { return fce.second.last < expireTime; });

    return { cacheName, cache.size(), timedOut };
}

#endif //GWLBTUN_FLOWCACHE_H
