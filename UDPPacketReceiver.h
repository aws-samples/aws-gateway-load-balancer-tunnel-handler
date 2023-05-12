// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWAPPLIANCE_UDPPACKETRECEIVER_H
#define GWAPPLIANCE_UDPPACKETRECEIVER_H

#include <future>
#include <functional>

typedef std::function<void(unsigned char *pktBuf, ssize_t pktBufLen, struct in_addr *srcIp, uint16_t srcPort, struct in_addr *dstIp, uint16_t dstPort)> udpCallback;

class UDPPacketReceiver {
public:
    UDPPacketReceiver();
    ~UDPPacketReceiver();

    void setup(int, int, uint16_t, udpCallback);
    bool healthCheck();
    std::string status();
    void shutdown();

    bool setupCalled;
    std::atomic<std::chrono::steady_clock::time_point> lastPacket;
    std::atomic<uint64_t> pktsIn, bytesIn;

private:
    bool shutdownRequested;
    int sock;
    int threadNumber;
    int coreNumber;
    uint16_t portNumber;
    std::future<int> recvThread;
    udpCallback recvDispatcher;
    int recvThreadFunction();
};


#endif //GWAPPLIANCE_UDPPACKETRECEIVER_H
