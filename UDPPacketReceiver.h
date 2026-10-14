// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWAPPLIANCE_UDPPACKETRECEIVER_H
#define GWAPPLIANCE_UDPPACKETRECEIVER_H

#include <future>
#include <functional>
#include <unistd.h>
#include <deque>
#include <vector>
#include "utils.h"
#include "GwlbtunConfig.h"   // UdpInterfacePlan
#include "HealthCheck.h"

typedef std::function<void(unsigned char *pktBuf, ssize_t pktBufLen, struct in_addr *srcIp, uint16_t srcPort, struct in_addr *dstIp, uint16_t dstPort, int ifindex)> udpCallback;
// Called on a receiver thread after it has dispatched every packet of one recvmmsg() batch.
typedef std::function<void()> udpBatchCallback;


// A snapshot of one UDP receiver thread, for the health check.
class UDPPacketReceiverThreadHealthCheck {
public:
    UDPPacketReceiverThreadHealthCheck(bool healthy, int threadNumber, int threadId, std::string interface, uint64_t pktsIn, uint64_t bytesIn, std::chrono::steady_clock::time_point lastPacket);
    std::string output_str() const;
    json output_json() const;
    uint64_t packetsIn() const { return pktsIn; }
    uint64_t octetsIn() const { return bytesIn; }

private:
    bool healthy;
    int threadNumber, threadId;
    std::string interface;
    uint64_t pktsIn, bytesIn;
    std::chrono::steady_clock::time_point lastPacket;
};

/**
 * One UDP receiver thread and the GENEVE socket it reads. Constructing it opens and binds the socket and
 * starts the thread; destroying it shuts the socket down (which wakes a blocked recvmmsg()) and joins the
 * thread. Not copyable or movable: the running thread uses `this`.
 */
class UDPPacketReceiverThread {
public:
    UDPPacketReceiverThread(int threadNumber, int coreNumber, uint16_t portNumber, udpCallback recvDispatcher, udpBatchCallback batchEnd,
                            int rcvBufSizeMB, int busyPollUsec, const std::string &interface, int incomingCpu);
    ~UDPPacketReceiverThread();
    UDPPacketReceiverThread(const UDPPacketReceiverThread &) = delete;
    UDPPacketReceiverThread &operator=(const UDPPacketReceiverThread &) = delete;

    bool healthCheck() const;
    UDPPacketReceiverThreadHealthCheck status() const;

private:
    friend class UDPPacketReceiver;
    // Make the thread's recvmmsg() return and the thread end (it's still joined by the destructor).
    void wake() noexcept;

    // ORDER MATTERS: members are built top to bottom and destroyed bottom to top. `thread` is last, so the
    // thread starts only once everything it uses exists, and has been joined before any of it goes away.
    const int threadNumber;
    const int coreNumber;
    const uint16_t portNumber;
    const std::string interface;   // Interface this thread's socket is bound to; empty = all interfaces
    const udpCallback recvDispatcher;
    const udpBatchCallback batchEnd;
    UniqueFd sock;
    std::atomic<bool> stopping{false};
    std::atomic<pid_t> threadId{0};
    std::atomic<std::chrono::steady_clock::time_point> lastPacket;
    std::atomic<uint64_t> pktsIn{0}, bytesIn{0};
    std::future<int> thread;   // LAST
    int threadFunction();
    static UniqueFd openSocket(int threadNumber, uint16_t portNumber, int rcvBufSizeMB, int busyPollUsec, const std::string &interface, int incomingCpu);
};

// A snapshot of every UDP receiver thread, for the health check.
class UDPPacketReceiverHealthCheck {
public:
    UDPPacketReceiverHealthCheck(uint16_t portNumber, std::vector<UDPPacketReceiverThreadHealthCheck> threadHealthChecks);
    std::string output_str() const;
    json output_json() const;
    uint64_t totalPacketsIn() const { uint64_t n = 0; for(auto &t : threadHealthChecks) n += t.packetsIn(); return n; }
    uint64_t totalOctetsIn() const { uint64_t n = 0; for(auto &t : threadHealthChecks) n += t.octetsIn(); return n; }

private:
    uint16_t portNumber;
    std::vector<UDPPacketReceiverThreadHealthCheck> threadHealthChecks;
};

/**
 * The GENEVE UDP receiver threads. Constructing it starts every thread in the plan (any failure throws, after
 * stopping the threads already started); destroying it stops and joins them all.
 */
class UDPPacketReceiver {
public:
    // Start the UDP threads laid out in plan (one set per interface; see GwlbtunConfig).
    UDPPacketReceiver(const std::vector<UdpInterfacePlan> &plan, uint16_t portNumber, const udpCallback &recvDispatcher, const udpBatchCallback &batchEnd,
                      int rcvBufSizeMB, int busyPollUsec);
    UDPPacketReceiver(const UDPPacketReceiver &) = delete;
    UDPPacketReceiver &operator=(const UDPPacketReceiver &) = delete;
    // Wakes every thread at once, so all stop receiving (and so creating endpoints) together; destroying
    // `threads` then joins them.
    ~UDPPacketReceiver();

    bool healthCheck() const;
    UDPPacketReceiverHealthCheck status() const;

private:
    const uint16_t portNumber;
    // A deque, so threads are constructed in place and never move (each running thread uses its own element).
    std::deque<UDPPacketReceiverThread> threads;
};


#endif //GWAPPLIANCE_UDPPACKETRECEIVER_H
