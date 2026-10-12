// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWAPPLIANCE_TUNINTERFACE_H
#define GWAPPLIANCE_TUNINTERFACE_H

#include <atomic>
#include <chrono>
#include <deque>
#include <functional>
#include <future>
#include <string>
#include <vector>
#include <sys/types.h>
#include "utils.h"
#include "HealthCheck.h"

typedef std::function<void(unsigned char *pktbuf, ssize_t pktlen)> tunCallback;

// A snapshot of one tunnel reader thread, for the health check.
class TunInterfaceThreadHealthCheck {
public:
    TunInterfaceThreadHealthCheck(bool healthy, int threadNumber, int threadId, uint64_t pktsIn, uint64_t bytesIn, std::chrono::steady_clock::time_point lastPacket);
    std::string output_str() const;
    json output_json() const;

private:
    bool healthy;
    int threadNumber, threadId;
    uint64_t pktsIn, bytesIn;
    std::chrono::steady_clock::time_point lastPacket;
};

// Wrapper class around our connections to /dev/net/tun to follow good RAII principles
class TunSocket {
public:
    // Open /dev/net/tun and attach this fd as a queue of the multi-queue device devname. Throws
    // std::system_error on failure.
    // exclusive: this open must create the device (IFF_TUN_EXCL) rather than attach a queue to an
    // existing one. Used for the first fd of each gwi-/gwo- device.
    // nonBlocking: reads return EAGAIN when the queue is empty (the reader threads drain it after poll()).
    explicit TunSocket(const std::string &devname, bool exclusive = false, bool nonBlocking = false);

    // Destructor - closes the fd, which detaches its queue. The device goes away with its last queue.
    ~TunSocket();

    // Delete copy operations (unique ownership)
    TunSocket(const TunSocket&) = delete;
    TunSocket& operator=(const TunSocket&) = delete;

    // Move construction (transfers ownership; needed to hold these in a std::vector)
    TunSocket(TunSocket&& other) noexcept = default;
    TunSocket& operator=(TunSocket&& other) = delete;

    int get() const { return fd.get(); }
    ssize_t write(const void *buf, size_t len) const { return ::write(fd.get(), buf, len); }

    // Detach this fd's queue from the multi-queue device: writes are still delivered, but the
    // queue receives nothing and writes skip the kernel's flow-table update. Returns false on failure.
    bool detachQueue();

private:
    std::string devname;   // Used for log messages
    UniqueFd fd;
};

/**
 * One reader thread of a TunInterface: owns one queue (TunSocket) of the device and the thread reading it.
 * Constructing it opens the queue and starts the thread; destroying it signals the interface's stop event
 * and joins the thread. Not copyable or movable: the running thread uses `this`.
 */
class TunInterfaceThread {
public:
    // stop: the owning TunInterface's stop event. It must outlive this object.
    TunInterfaceThread(int threadNumber, int coreNumber, const std::string &devname, tunCallback recvDispatcher,
                       const EventFd &stop, bool createDevice);
    ~TunInterfaceThread();
    TunInterfaceThread(const TunInterfaceThread &) = delete;
    TunInterfaceThread &operator=(const TunInterfaceThread &) = delete;

    bool healthCheck() const;
    TunInterfaceThreadHealthCheck status() const;
    std::chrono::steady_clock::time_point lastPacketTime() const { return lastPacket.load(std::memory_order_relaxed); }

private:
    // ORDER MATTERS: members are built top to bottom and destroyed bottom to top. `thread` is last, so the
    // thread starts only once everything it uses exists, and it has been joined (in the destructor, and by
    // std::future's destructor) before any of them goes away.
    const int threadNumber;
    const int coreNumber;
    const EventFd &stop;
    const tunCallback recvDispatcher;
    TunSocket tunSocket;
    UniqueFd waitSet;   // epoll set: tunSocket and stop (after tunSocket, which it watches)
    std::atomic<std::chrono::steady_clock::time_point> lastPacket;
    std::atomic<uint64_t> pktsIn{0}, bytesIn{0};
    std::atomic<pid_t> threadId{0};
    std::future<int> thread;   // LAST
    int threadFunction();
    static UniqueFd makeWaitSet(int tunFd, int stopFd);
};

// A snapshot of a tun interface's reader threads, for the health check.
class TunInterfaceHealthCheck {
public:
    TunInterfaceHealthCheck(std::string devname, std::vector<TunInterfaceThreadHealthCheck> thcs);
    std::string output_str() const;
    json output_json() const;

private:
    std::string devname;
    std::vector<TunInterfaceThreadHealthCheck> thcs;
};

/**
 * A multi-queue TUN device and the threads reading it. Constructing it opens one queue per configured thread
 * (the first creating the device, if createsDevice), starts the threads, and brings the device up; any failure
 * throws, after the threads already started are stopped. Destroying it stops and joins every thread, and
 * closing their queues removes the device unless something else (gwi-'s writers) still holds one open.
 */
class TunInterface {
public:
    // createsDevice: the first thread's open creates the device exclusively (see TunSocket).
    TunInterface(std::string devname, int mtu, const ThreadConfig &threadConfig, const tunCallback &recvDispatcher, bool createsDevice = false);
    ~TunInterface();
    TunInterface(const TunInterface &) = delete;
    TunInterface &operator=(const TunInterface &) = delete;

    bool healthCheck() const;
    TunInterfaceHealthCheck status() const;

    const std::string devname;
    std::chrono::steady_clock::time_point lastPacketTime() const;

private:
    // ORDER MATTERS: stop is declared before threads, so it outlives them; each thread's destructor signals
    // it (one signal wakes every reader of this interface) and then joins its thread.
    EventFd stop;
    // A deque, so threads are constructed in place and never move (each running thread uses its own element).
    std::deque<TunInterfaceThread> threads;
};

#endif //GWAPPLIANCE_TUNINTERFACE_H
