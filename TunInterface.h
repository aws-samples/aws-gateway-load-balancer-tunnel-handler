// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWAPPLIANCE_TUNINTERFACE_H
#define GWAPPLIANCE_TUNINTERFACE_H

#include <future>
#include <functional>
#include <chrono>
#include <shared_mutex>
#include "utils.h"

typedef std::function<void(unsigned char *pktbuf, ssize_t pktlen)> tunCallback;

class TunThread {
public:
    TunThread();
    ~TunThread();

    void setup(int threadNum, int coreNum, int fd, tunCallback recvDispatcher);
    bool healthCheck();
    std::string status();
    void shutdown();
    bool setupCalled;
    bool isRunning;
    std::chrono::steady_clock::time_point lastPacketTime();

private:
    std::atomic<std::chrono::steady_clock::time_point> lastPacket;
    std::atomic<uint64_t> pktsIn, pktsOut, bytesIn, bytesOut;
    tunCallback recvDispatcher;
    bool shutdownRequested;
    int fd;
    int threadNumber;
    int coreNumber;
    std::future<int> thread;
    int recvThreadFunction();
};

class TunInterface {
public:
    TunInterface(std::string devname, int mtu, ThreadConfig threadConfig, tunCallback recvDispatcher);
    ~TunInterface();

    void writePacket(unsigned char *pkt, ssize_t pktlen);
    bool healthCheck();
    std::string status();
    std::string devname;
    std::chrono::steady_clock::time_point lastPacketTime();

private:
    std::atomic<std::chrono::steady_clock::time_point> lastPacket;
    std::atomic<uint64_t> pktsOut, bytesOut;
    bool shutdownRequested;
    std::array<class TunThread, MAX_THREADS> tunThreads;
    std::shared_mutex writerHandlesMutex;
    std::unordered_map<pthread_t, int> writerHandles;
    tunCallback recvDispatcher;
    int allocateHandle();
};


#endif //GWAPPLIANCE_TUNINTERFACE_H
