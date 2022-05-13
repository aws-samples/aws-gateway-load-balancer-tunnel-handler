// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWAPPLIANCE_TUNINTERFACE_H
#define GWAPPLIANCE_TUNINTERFACE_H

#include <future>
#include <functional>
#include <chrono>

typedef std::function<void(unsigned char *pktbuf, ssize_t pktlen)> tunCallback;

class TunInterface {
public:
    TunInterface(std::string devname, int mtu, tunCallback recvDispatcher);
    ~TunInterface();

    void writePacket(unsigned char *pkt, ssize_t pktlen);
    bool healthCheck();
    std::string status();

    std::string devname;
    std::atomic<std::chrono::steady_clock::time_point> lastPacket;
    std::atomic<uint64_t> pktsIn, pktsOut, bytesIn, bytesOut;

private:
    bool shutdownRequested;
    int fd;
    std::future<int> recvThread;
    tunCallback recvDispatcher;
    int recvThreadFunction();
};


#endif //GWAPPLIANCE_TUNINTERFACE_H
