/*
 * Copyright Amazon.com, Inc. or its affiliates. This material is AWS Content under the AWS Enterprise Agreement 
 * or AWS Customer Agreement (as applicable) and is provided under the AWS Intellectual Property License.
 */
#include "FlowCache.h"
#include "HealthCheck.h"

FlowCacheHealthCheck::FlowCacheHealthCheck(std::string cacheName, int cacheTimeout, long unsigned int size, long unsigned int timedOut) :
        cacheName(cacheName), cacheTimeout(cacheTimeout), size(size), timedOut(timedOut)
{
}

std::string FlowCacheHealthCheck::output_str()
{
    return cacheName + " : Contains " + std::to_string(size) + " elements, of which " + std::to_string(timedOut) + " were just timed out (idle timeout is " + std::to_string(cacheTimeout) + " seconds).\n";
}

json FlowCacheHealthCheck::output_json()
{
    return {{"cacheName", cacheName}, {"size", size}, {"timedOut", timedOut}, "idleTimeoutSecs", cacheTimeout };
}
