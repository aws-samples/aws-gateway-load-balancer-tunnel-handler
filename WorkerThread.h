// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// Helpers shared by the UDP receiver and tunnel reader threads, which are started with std::async and joined
// by their owners' destructors.
#ifndef GWLBTUN_WORKERTHREAD_H
#define GWLBTUN_WORKERTHREAD_H

#include <chrono>
#include <cstdio>
#include <future>
#include <pthread.h>
#include <string>
#include "Logger.h"
#include "utils.h"

/**
 * Called first by a worker thread: name it "gwlbtun <kind><index>" (U for UDP, T for tunnel), then pin it to
 * `core`, or with core < 0 let it run on every CPU the process may use (a new thread inherits its creator's
 * affinity). A pinned thread is renamed "gwlbtun <kind>A<core>". Failing to pin is logged at failLevel; the
 * thread then keeps the affinity it has.
 */
inline void startWorkerThread(char kind, int index, int core, LogSection ls, LogLevel failLevel, const std::string &what)
{
    char name[16];   // the kernel's limit, including the terminator
    snprintf(name, sizeof(name), "gwlbtun %c%03d", kind, index);
    pthread_setname_np(pthread_self(), name);
    if(int err = setCurrentThreadAffinity(core); err != 0)
        LOG(ls, failLevel, (core >= 0 ? "Unable to pin " + what + " to core " + std::to_string(core) : "Unable to reset the CPU affinity of " + what) +
            ": " + errText(err) + ". It continues with the affinity it has.");
    else if(core >= 0)
    {
        snprintf(name, sizeof(name), "gwlbtun %cA%03u", kind, (unsigned)core % 10000u);   // cores < CPU_SETSIZE
        pthread_setname_np(pthread_self(), name);
    }
}

// Whether a worker started with std::async is still running. Its future is valid for the owner's whole life: it
// comes from std::async in the owner's constructor, and is never read (get()) or moved.
inline bool workerRunning(const std::future<int> &f)
{
    return f.wait_for(std::chrono::seconds(0)) == std::future_status::timeout;
}

// Wait for a worker that has been told to stop. Waiting is unbounded; after 2 seconds it's logged once a second,
// so a stuck thread shows up in the log.
inline void joinWorker(const std::future<int> &f, LogSection ls, const std::string &what)
{
    auto status = f.wait_for(std::chrono::seconds(2));
    while(status == std::future_status::timeout)
    {
        LOG(ls, LL_IMPORTANT, what + " has not yet shut down - waiting more.");
        status = f.wait_for(std::chrono::seconds(1));
    }
}

#endif //GWLBTUN_WORKERTHREAD_H
