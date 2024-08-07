// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWAPPLIANCE_TUNINTERFACE_H
#define GWAPPLIANCE_TUNINTERFACE_H

#include <future>
#include <functional>
#include <chrono>
#include <shared_mutex>
#include <list>
#include <unistd.h>
#include <boost/unordered/concurrent_flat_map.hpp>
#include "utils.h"
#include "HealthCheck.h"


typedef std::function<void(unsigned char *pktbuf, ssize_t pktlen)> tunCallback;

class TunInterfaceThreadHealthCheck : public HealthCheck {
public:
    TunInterfaceThreadHealthCheck(bool threadValid, bool healthy, int threadNumber, int threadId, uint64_t pktsIn, uint64_t bytesIn, std::chrono::steady_clock::time_point lastPacket);
    std::string output_str();
    json output_json();

private:
    bool threadValid, healthy;
    int threadNumber, threadId;
    uint64_t pktsIn, bytesIn;
    std::chrono::steady_clock::time_point lastPacket;
};

class TunInterfaceThread {
public:
    TunInterfaceThread();
    ~TunInterfaceThread();

    void setup(int threadNum, int coreNum, int fd, tunCallback recvDispatcher);
    bool healthCheck();
    TunInterfaceThreadHealthCheck status();
    void shutdown();
    bool setupCalled;
    std::chrono::steady_clock::time_point lastPacketTime();

private:
    std::atomic<std::chrono::steady_clock::time_point> lastPacket;
    std::atomic<uint64_t> pktsIn, pktsOut, bytesIn, bytesOut;
    tunCallback recvDispatcher;
    bool shutdownRequested;
    int fd;
    int threadNumber;
    int coreNumber;
    pid_t threadId;
    std::future<int> thread;
    int threadFunction();
};

class TunInterfaceHealthCheck : public HealthCheck {
public:
    TunInterfaceHealthCheck(std::string devname, uint64_t pktsOut, uint64_t bytesOut, std::chrono::steady_clock::time_point lastPacket, std::list<TunInterfaceThreadHealthCheck> thcs);
    std::string output_str();
    json output_json();

private:
    std::string devname;
    uint64_t pktsOut, bytesOut;
    std::chrono::steady_clock::time_point lastPacket;
    std::list<TunInterfaceThreadHealthCheck> thcs;
};

class TunInterface {
public:
    TunInterface(std::string devname, int mtu, ThreadConfig threadConfig, tunCallback recvDispatcher);
    ~TunInterface();

    void writePacket(unsigned char *pkt, ssize_t pktlen);
    TunInterfaceHealthCheck status();
    void shutdown();

    std::string devname;
    std::chrono::steady_clock::time_point lastPacketTime();

private:
    std::atomic<std::chrono::steady_clock::time_point> lastPacket;
    std::atomic<uint64_t> pktsOut, bytesOut;
    std::array<class TunInterfaceThread, MAX_THREADS> threads;
    boost::concurrent_flat_map<pthread_t, int> writerHandles;
    int allocateHandle();
};

#endif //GWAPPLIANCE_TUNINTERFACE_H
