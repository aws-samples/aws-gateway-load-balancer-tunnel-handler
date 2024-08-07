// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#include "FlowCache.h"
#include "HealthCheck.h"

FlowCacheHealthCheck::FlowCacheHealthCheck(std::string cacheName, long unsigned int size, long unsigned int timedOut) :
        cacheName(cacheName), size(size), timedOut(timedOut)
{
}

std::string FlowCacheHealthCheck::output_str()
{
    return cacheName + " : Contains " + std::to_string(size) + " elements, of which " + std::to_string(timedOut) + " were just timed out.\n";
}

json FlowCacheHealthCheck::output_json()
{
    return { {"cacheName", cacheName}, {"size", size}, {"timedOut", timedOut} };
}
