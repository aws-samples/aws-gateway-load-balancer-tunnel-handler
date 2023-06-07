// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWAPPLIANCE_UDPPACKETRECEIVER_H
#define GWAPPLIANCE_UDPPACKETRECEIVER_H

#include <future>
#include <functional>
#include <unistd.h>
#include "utils.h"

typedef std::function<void(unsigned char *pktBuf, ssize_t pktBufLen, struct in_addr *srcIp, uint16_t srcPort, struct in_addr *dstIp, uint16_t dstPort)> udpCallback;

class UDPPacketReceiverThread {
public:
    UDPPacketReceiverThread();
    ~UDPPacketReceiverThread();

    void setup(int threadNumberParam, int coreNumberParam, uint16_t portNumberParam, udpCallback recvDispatcherParam);
    bool healthCheck();
    std::string status();
    void shutdown();
    bool setupCalled;

private:
    int sock;
    uint16_t portNumber;
    int threadNumber;
    int coreNumber;
    bool shutdownRequested;
    pid_t threadId;
    std::future<int> thread;
    udpCallback recvDispatcher;
    int threadFunction();
    std::atomic<std::chrono::steady_clock::time_point> lastPacket;
    std::atomic<uint64_t> pktsIn, bytesIn;
};

class UDPPacketReceiver {
public:
    UDPPacketReceiver();
    ~UDPPacketReceiver();

    void setup(ThreadConfig threadConfig, uint16_t portNumberParam, udpCallback recvDispatcherParam);
    bool healthCheck();
    std::string status();
    void shutdown();

private:
    uint16_t portNumber;
    std::array<class UDPPacketReceiverThread, MAX_THREADS> threads;
};

#endif //GWAPPLIANCE_UDPPACKETRECEIVER_H
