// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// Base class for health check objects
#ifndef GWLBTUN_HEALTHCHECK_H
#define GWLBTUN_HEALTHCHECK_H

#include "json.hpp"
using json = nlohmann::json;

class HealthCheck {
public:
    virtual std::string output_str() = 0;
    virtual json output_json() = 0;
};

#endif //GWLBTUN_HEALTHCHECK_H
