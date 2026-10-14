// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWLBTUN_HOOKSCRIPTS_H
#define GWLBTUN_HOOKSCRIPTS_H

#include <string>
#include <sys/resource.h>
#include "GenevePacket.h"   // gwlbeid_t

/**
 * The user's CREATE (-c) and DESTROY (-r) scripts. One object for the process, built in main().
 *
 * Each endpoint holds a HookScripts::Endpoint: constructing it logs the new interfaces and runs CREATE,
 * destroying it logs their removal and runs DESTROY. GeneveHandlerENI declares it as its last member, so
 * CREATE runs only once both of the endpoint's interfaces exist, DESTROY runs while they still do, and an
 * endpoint that fails to build never runs either script.
 *
 * Scripts run synchronously and never throw: a script that can't be started, exits non-zero or is killed is
 * logged and otherwise ignored, so DESTROY still runs after a failed CREATE.
 */
class HookScripts {
public:
    // childFileLimit: the open-file soft limit to give the scripts (the one gwlbtun started with, before
    // raising its own), or RLIM_INFINITY to leave theirs as gwlbtun's.
    HookScripts(std::string createCmd, std::string destroyCmd, rlim_t childFileLimit = RLIM_INFINITY);
    HookScripts(const HookScripts &) = delete;
    HookScripts &operator=(const HookScripts &) = delete;

    class Endpoint {
    public:
        // hooks must outlive this object.
        Endpoint(const HookScripts &hooks, std::string ingressInt, std::string egressInt, gwlbeid_t eni);
        ~Endpoint();
        Endpoint(const Endpoint &) = delete;
        Endpoint &operator=(const Endpoint &) = delete;

    private:
        const HookScripts &hooks;
        const std::string ingressInt, egressInt;
        const gwlbeid_t eni;
    };

private:
    void run(const std::string &cmd, const char *mode, const std::string &ingressInt, const std::string &egressInt, gwlbeid_t eni) const noexcept;

    const std::string createCmd, destroyCmd;
    const rlim_t childFileLimit;
};

#endif //GWLBTUN_HOOKSCRIPTS_H
