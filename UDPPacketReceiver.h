// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWAPPLIANCE_UDPPACKETRECEIVER_H
#define GWAPPLIANCE_UDPPACKETRECEIVER_H

#include <future>
#include <functional>

typedef std::function<void(unsigned char *pktBuf, ssize_t pktBufLen, struct in_addr *srcIp, uint16_t srcPort, struct in_addr *dstIp, uint16_t dstPort)> udpCallback;

class UDPPacketReceiver {
public:
    UDPPacketReceiver(uint16_t, udpCallback);
    ~UDPPacketReceiver();

    bool healthCheck();
    std::string status();

    std::atomic<std::chrono::steady_clock::time_point> lastPacket;
    std::atomic<uint64_t> pktsIn, bytesIn;

private:
    bool shutdownRequested;
    int sock;
    uint16_t portNumber;
    std::future<int> recvThread;
    udpCallback recvDispatcher;
    int recvThreadFunction();
};


#endif //GWAPPLIANCE_UDPPACKETRECEIVER_H
