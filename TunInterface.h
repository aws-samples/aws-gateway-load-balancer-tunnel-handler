/*
 * Copyright Amazon.com, Inc. or its affiliates. This material is AWS Content under the AWS Enterprise Agreement 
 * or AWS Customer Agreement (as applicable) and is provided under the AWS Intellectual Property License.
 */
#ifndef GWAPPLIANCE_TUNINTERFACE_H
#define GWAPPLIANCE_TUNINTERFACE_H

#include <future>
#include <functional>
#include <chrono>
#include <shared_mutex>
#include <list>
#include <unistd.h>
#include <boost/unordered/concurrent_flat_map.hpp>
#include <fcntl.h>
#include "utils.h"
#include "HealthCheck.h"
#include "Logger.h"

using namespace std::string_literals;
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

// Wrapper class around our connections to /dev/net/tun to follow good RAII principles
class TunSocket {
public:
    // Constructor with the fd to take ownership for the move constructor
    explicit TunSocket(int fdParam);

    // Default constructor
    explicit TunSocket();

    // Connect the fd to a specific device name
    void connect(const std::string devname);

    // Constructor to open the fd and connect at the same time
    explicit TunSocket(const std::string devname);

    // Destructor - automatically closes the fd
    ~TunSocket();

    // Delete copy operations (unique ownership)
    TunSocket(const TunSocket&) = delete;
    TunSocket& operator=(const TunSocket&) = delete;

    // Move operations (transfer ownership)
    TunSocket(TunSocket&& other) noexcept;
    TunSocket& operator=(TunSocket&& other) noexcept;

    // Get the raw fd (for system calls)
    int get() const;

    // Write to the socket
    ssize_t write(const void *buf, size_t len) const;

private:
    int fd;
    std::string devname;   // Used for log messages
};

class TunInterfaceThread {
public:
    TunInterfaceThread();
    ~TunInterfaceThread();

    void setup(int threadNum, int coreNum, std::string devname, tunCallback recvDispatcher);
    bool healthCheck();
    TunInterfaceThreadHealthCheck status();
    void shutdown();
    bool setupCalled;
    std::chrono::steady_clock::time_point lastPacketTime();

private:
    std::atomic<std::chrono::steady_clock::time_point> lastPacket;
    std::atomic<uint64_t> pktsIn, pktsOut, bytesIn, bytesOut;
    tunCallback recvDispatcher;
    TunSocket tunSocket;
    bool shutdownRequested;
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

    boost::concurrent_flat_map<pthread_t, TunSocket> writerHandles;
};

#endif //GWAPPLIANCE_TUNINTERFACE_H
