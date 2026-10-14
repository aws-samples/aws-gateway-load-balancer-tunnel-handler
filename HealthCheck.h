// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// The JSON library used by every health check snapshot. Each snapshot class (FlowCacheHealthCheck,
// TunInterfaceHealthCheck, UDPPacketReceiverHealthCheck, GeneveHandlerENIHealthCheck, GeneveHandlerHealthCheck)
// is a plain value with output_str() and output_json(); they're always used by their concrete type.
#ifndef GWLBTUN_HEALTHCHECK_H
#define GWLBTUN_HEALTHCHECK_H

#include <json/json.hpp>
using json = nlohmann::json;

#endif //GWLBTUN_HEALTHCHECK_H
