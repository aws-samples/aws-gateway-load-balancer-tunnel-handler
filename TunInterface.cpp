// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * TunInterface handles creating and processing traffic received on TUN interfaces. This class:
 * - Creates the requested Tun interface
 * - Launches threads to service that interface
 * - Takes a callback function (recvDispatcher) which is called for each packet received by that interface.
 * - Provides a status() function that returns the packet counters and checks that the thread is still alive.
 */

#include "TunInterface.h"

#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include <sys/ioctl.h>
#include <unistd.h>
#include <exception>
#include <iostream>
#include <thread>
#include <utility>
#include "utils.h"
#include "Logger.h"

using namespace std::string_literals;

/**
 * Constructor. Build a TUN interface and start listening for packets on it.
 *
 * @param devname The name of the TUN itnerface to build.
 * @param mtu MTU to set the interface to.
 * @param recvDispatcher Function the thread should callback to on packets received.
 */
TunInterface::TunInterface(std::string devname, int mtu, ThreadConfig threadConfig, tunCallback recvDispatcherParam)
: lastPacket(std::chrono::steady_clock::now()),pktsOut(0),bytesOut(0)
{
    LOG(LS_TUNNEL, LL_DEBUG, "TunInterface creating for "s + devname);
    this->devname = devname;

    // Set up our threads as per threadConfig
    int tIndex = 0;
    for(int core : threadConfig.cfg)
    {
        threads[tIndex].setup(tIndex, core, devname, recvDispatcherParam);
        tIndex ++;
    }

    // Mark the tun device link up. We need a dummy socket to do this call.
    struct ifreq ifr;
    bzero(&ifr, sizeof(ifr));
    strncpy(ifr.ifr_name, devname.c_str(), IFNAMSIZ);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    int dummy = socket(PF_INET, SOCK_DGRAM, 0);
    if(ioctl(dummy, SIOCGIFFLAGS, (void *)&ifr) < 0)
        throw std::system_error(errno, std::generic_category(), "Unable to get device flags");

    ifr.ifr_flags |= IFF_UP;        // Set interface is up
    ifr.ifr_flags |= IFF_RUNNING;   // Interface is running
    ifr.ifr_flags &= ~IFF_POINTOPOINT;
    if(ioctl(dummy, SIOCSIFFLAGS, (void *)&ifr) < 0)
        throw std::system_error(errno, std::generic_category(), "Unable to set device flags");

    // Set the MTU to the GWLB standard (8500)
    ifr.ifr_mtu = mtu;
    if(ioctl(dummy, SIOCSIFMTU, (void *)&ifr) < 0)
        throw std::system_error(errno, std::generic_category(), "Unable to set MTU");
    close(dummy);
}

/**
 * Destructor. Signals the thread to stop, waits for it to shut down, destroys the TUN interface, and returns.
 */
TunInterface::~TunInterface()
{
    shutdown();
}

void TunInterface::shutdown()
{
    LOG(LS_TUNNEL, LL_DEBUG, "TunInterface destroying for "s + devname);

    // Signal all threads to shutdown down, then wait for all acks.
    for(auto &thread : threads)
    {
        thread.shutdown();
    }

    bool allgood = false;
    while(!allgood)
    {
        allgood = true;
        for(auto &thread : threads)
        {
            if(thread.setupCalled)
            {
                if(thread.healthCheck())
                    allgood = false;
            }
        }
        if(!allgood)
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

/**
 * Send a packet out the TUN interface. Updates internal counters as well.
 *
 * @param pkt Buffer pointing to the packet to send
 * @param pktlen Packet length
 */
void TunInterface::writePacket(unsigned char *pkt, ssize_t pktlen)
{
    if(!writerHandles.visit(pthread_self(), [&](auto& target) { target.second.write((void *)pkt, pktlen); }))
    {
        // Key wasn't found - create and send.
        writerHandles.try_emplace_or_visit(pthread_self(), devname, [&](auto& target) { target.second.write((void *)pkt, pktlen); });
    }
    lastPacket = std::chrono::steady_clock::now();
    pktsOut ++; bytesOut += pktlen;
}

/**
 * Human-readable status check of the module.
 *
 * @return A HealthCheck class
 */
TunInterfaceHealthCheck TunInterface::status()
{
    std::list<TunInterfaceThreadHealthCheck> thcs;
    for(auto &t : threads)
        thcs.push_back(t.status());

    return { devname, pktsOut, bytesOut, lastPacket, thcs };
}

/**
 * Return the last time any of our threads saw a packet.
 * @return
 */
std::chrono::steady_clock::time_point TunInterface::lastPacketTime()
{
    std::chrono::steady_clock::time_point ret = lastPacket.load();

    for(auto &t : threads)
    {
        auto r = t.lastPacketTime();
        if(r > ret) ret = r;
    }
    return ret;
}

/**
 * TunInterfaceThread class handles an individual thread assigned to processing packets coming in from the OS via the gwo interfaces.
 * Packets
 * - Launches a thread to service that interface
 * - Takes a callback function (recvDispatcher) which is called for each packet received by that interface.
 * - Provides a status() function that returns the packet counters and checks that the thread is still alive.
 */

TunInterfaceThread::TunInterfaceThread()
: setupCalled(false),lastPacket(std::chrono::steady_clock::now()),pktsIn(0),pktsOut(0),bytesIn(0),bytesOut(0),shutdownRequested(false)
{

}

TunInterfaceThread::~TunInterfaceThread() noexcept
{
    shutdownRequested = true;
    // If this thread has been setup and is running, signal shutdown and wait for it to complete.
    if(thread.valid())
    {
        auto status = thread.wait_for(std::chrono::seconds(2));
        while(status == std::future_status::timeout)
        {
            LOG(LS_TUNNEL, LL_INFO, "Tunnel thread "s + ts(threadNumber) + " has not yet shutdown - waiting more."s);
            status = thread.wait_for(std::chrono::seconds(1));
        }
    }
}

/**
 * Set up the tunnel handling thread and start it.
 * @param threadNum
 * @param coreNum
 * @param fd
 * @param recvDispatcher
 */
void TunInterfaceThread::setup(int threadNumberParam, int coreNumberParam, std::string devname, tunCallback recvDispatcherParam)
{
    threadNumber = threadNumberParam;
    coreNumber = coreNumberParam;
    recvDispatcher = std::move(recvDispatcherParam);
    tunSocket.connect(std::move(devname));
    setupCalled = true;
    thread = std::async(&TunInterfaceThread::threadFunction, this);
}

/**
 * Thread for the tunnel handler. Opens a new fd, waits for packets to come in, then calls recvDispatch.
 *
 * @return Never returns until termination signal is sent.
 */
int TunInterfaceThread::threadFunction()
{
    char threadName[16];
    threadId = gettid();
    snprintf(threadName, 15, "gwlbtun T%03d", threadNumber);
    pthread_setname_np(pthread_self(), threadName);
    LOG(LS_TUNNEL, LL_DEBUG, "Thread starting");

    // If a specific core was requested, attempt to set affinity.
    if(coreNumber != -1)
    {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(coreNumber, &cpuset);
        int s = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
        if(s != 0)
        {
            LOG(LS_TUNNEL, LL_INFO, "Unable to set TUN thread CPU affinity to core "s + ts(coreNumber) + ": "s + std::error_code{errno, std::generic_category()}.message() + ". Thread continuing to run with affinity unset."s);
        } else {
            snprintf(threadName, 15, "gwlbtun TA%03d", coreNumber);
            pthread_setname_np(pthread_self(), threadName);
        }
    }

    unsigned char *pktbuf;
    // Static packet processing buffer.
    pktbuf = new unsigned char[65535];

    // Receive packets and dispatch them. Additionally, ensure a check at least every second to make sure a
    // shutdown hasn't been requested.
    int fd = tunSocket.get();
    ssize_t msgLen;
    struct timeval tv;
    fd_set readfds;
    while(!shutdownRequested)
    {
        tv.tv_sec = 1; tv.tv_usec = 0;
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        select(fd + 1, &readfds, nullptr, nullptr, &tv);
        if(FD_ISSET(fd, &readfds))
        {
            // The tun interface has received packets. Drain all, dispatching each.
            msgLen = read(fd, pktbuf, 65534);   // Remember: TUN devices always return 1 and only 1 packet on read()
            lastPacket = std::chrono::steady_clock::now();
            try {
                recvDispatcher(pktbuf, msgLen);
            }
            catch (std::exception& e) {
                LOG(LS_TUNNEL, LL_IMPORTANT, "Packet dispatch function failed: "s + e.what());
            }
            pktsIn ++; bytesIn += msgLen;
        }
    }
    LOG(LS_TUNNEL, LL_DEBUG, "Thread stopping by request");
    delete [] pktbuf;
    return(0);
}


bool TunInterfaceThread::healthCheck()
{
    if(thread.valid())
    {
        auto status = thread.wait_for(std::chrono::seconds(0));
        if(status != std::future_status::timeout)
        {
            return false;
        }
        return true;
    }
    return false;
}

TunInterfaceThreadHealthCheck TunInterfaceThread::status()
{
    if(thread.valid())
      return {true, healthCheck(), threadNumber, threadId, pktsIn, bytesIn, lastPacket };
    else
      return { false, false, 0, 0, 0, 0, std::chrono::steady_clock::now() };
}

void TunInterfaceThread::shutdown()
{
    shutdownRequested = true;
}

std::chrono::steady_clock::time_point TunInterfaceThread::lastPacketTime()
{
    return lastPacket.load();
}

TunInterfaceThreadHealthCheck::TunInterfaceThreadHealthCheck(bool threadValid, bool healthy, int threadNumber,
                                                             int threadId, uint64_t pktsIn, uint64_t bytesIn,
                                                             std::chrono::steady_clock::time_point lastPacket) :
        threadValid(threadValid), healthy(healthy), threadNumber(threadNumber), threadId(threadId), pktsIn(pktsIn), bytesIn(bytesIn), lastPacket(lastPacket) {
}

std::string TunInterfaceThreadHealthCheck::output_str()
{
    std::string ret;
    if(threadValid)
    {
        ret = "Tunnel handler thread "s + std::to_string(threadNumber) + " (ID "s + std::to_string(threadId) + ")"s;

        if(healthy)
            ret += ": Healthy, "s;
        else {
            ret += ": NOT healthy, "s;
        }
        ret += std::to_string(pktsIn) + " packets in from OS, "s + std::to_string(bytesIn) + " bytes in from OS, "s;
        ret += timepointDeltaString(std::chrono::steady_clock::now(), lastPacket) + " since last packet.\n";
    }
    return ret;
}

json TunInterfaceThreadHealthCheck::output_json()
{
    return { {"valid", threadValid}, {"threadNumber", threadNumber}, {"threadId", threadId},
             {"healthy", healthy}, {"pktsIn", pktsIn}, {"bytesIn", bytesIn}, {"secsSincelastPacket", timepointDeltaDouble(std::chrono::steady_clock::now(), lastPacket)} };
}

TunInterfaceHealthCheck::TunInterfaceHealthCheck(std::string devname, uint64_t pktsOut, uint64_t bytesOut, std::chrono::steady_clock::time_point lastPacket, std::list<TunInterfaceThreadHealthCheck> thcs) :
        devname(devname), pktsOut(pktsOut), bytesOut(bytesOut), lastPacket(lastPacket), thcs(std::move(thcs))
{}

std::string TunInterfaceHealthCheck::output_str()
{
    std::string ret;

    ret += "Interface "s + devname + ":\n"s;

    ret += std::to_string(pktsOut) + " packets out to OS, "s + std::to_string(bytesOut) + " bytes out to OS, "s;
    ret += timepointDeltaString(std::chrono::steady_clock::now(), lastPacket) + " since last packet.\n";

    for(auto &t : thcs)
    {
        ret += t.output_str();
    }

    ret += "\n"s;

    return ret;
}

json TunInterfaceHealthCheck::output_json()
{
    json ret;

    ret = { {"devname", devname}, {"pktsOut", pktsOut}, {"bytesOut", bytesOut}, {"secsSincelastPacket", timepointDeltaDouble(std::chrono::steady_clock::now(), lastPacket)} ,
            {"threads", json::array()} };

    for(auto &t : thcs)
    {
        auto js = t.output_json();
        if(js["valid"] == true)
          ret["threads"].push_back(js);
    }

    return ret;
}

/**
* TunSocket implementations - RAII wrapper for TUN file descriptors
*/

TunSocket::TunSocket(int fdParam) : fd(fdParam) {}

TunSocket::TunSocket() : fd(-1) {}

void TunSocket::connect(const std::string devname)
{
    if(fd < 0)
        close(fd);

    if((fd = open("/dev/net/tun", O_RDWR)) < 0)
    {
        LOG(LS_TUNNEL, LL_CRITICAL, "Unable to open /dev/net/tun: "s + std::error_code{errno, std::generic_category()}.message());
        throw std::system_error(errno, std::generic_category(), "Unable to open /dev/net/tun");
    }

    // Set up a new multiqueue file handler to process our packets
    struct ifreq ifr;
    bzero(&ifr, sizeof(ifr));

    // Code adapted from Linux Documentation/networking/tuntap.txt to create the tun device.
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
    strncpy(ifr.ifr_name, devname.c_str(), IFNAMSIZ);

    if(ioctl(fd, TUNSETIFF, (void *)&ifr) < 0)
    {
        close(fd);
        fd = -1;
        LOG(LS_TUNNEL, LL_CRITICAL, "Unable to create TUN device " + devname + " (does this process have CAP_NET_ADMIN capability?) " + std::error_code{errno, std::generic_category()}.message());
        throw std::system_error(errno, std::generic_category(), "Unable to create TUN device (does this process have CAP_NET_ADMIN capability?)");
    }
}

TunSocket::TunSocket(const std::string devname) : fd(-1)
{
    this->connect(devname);
}

TunSocket::~TunSocket()
{
    if(fd >= 0)
        close(fd);
}

TunSocket::TunSocket(TunSocket&& other) noexcept : fd(other.fd)
{
    other.fd = -1;
}

TunSocket& TunSocket::operator=(TunSocket&& other) noexcept
{
    if (this != &other)
    {
        if(fd >= 0)
            close(fd);

        fd = other.fd;
        other.fd = -1;
    }
    return *this;
}

int TunSocket::get() const
{
    return fd;
}

ssize_t TunSocket::write(const void *buf, size_t len) const
{
    return ::write(fd, buf, len);
}
