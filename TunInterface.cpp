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
#include "utils.h"

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
    if(debug) *debugout << currentTime() << ": TunInterface creating for "s << devname << std::endl;
    this->devname = devname;

    // Set up our threads as per threadConfig
    int tIndex = 0;
    for(int core : threadConfig.cfg)
    {
        threads[tIndex].setup(tIndex, core, allocateHandle(), recvDispatcherParam);
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
    if(debug)
    {
        *debugout << currentTime() << ": TunInterface destroying for "s << devname << std::endl;
    }

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
    int targetfd;
    // We can create a new FD (because we're multi-queue) for the writers, and have one per thread to eliminate the
    // need for locking.
    std::shared_lock readLock(writerHandlesMutex);
    auto foundHandle = writerHandles.find(pthread_self());
    readLock.unlock();
    if(foundHandle == writerHandles.end())
    {
        // Get a write lock, and reverify we still need to create.
        std::unique_lock writeLock(writerHandlesMutex);
        foundHandle = writerHandles.find(pthread_self());
        if(foundHandle == writerHandles.end())
        {
            // Create.
            targetfd = allocateHandle();
            writerHandles.emplace(pthread_self(), targetfd);
        } else {
            targetfd = foundHandle->second;
        }
        writeLock.unlock();
    } else {
        targetfd = foundHandle->second;
    }

    // Write the packet.
    lastPacket = std::chrono::steady_clock::now();
    pktsOut ++; bytesOut += pktlen;
    write(targetfd, (void *)pkt, pktlen);
}

/**
 * Check on the status of the TUN receiver thread.
 *
 * @return true if the thread is still alive, false otherwise.
 */
bool TunInterface::healthCheck()
{
    bool status = true;

    for(auto &t : threads)
    {
        if(t.setupCalled)
        {
            if(!t.healthCheck())
                status = false;
        }
    }

    return status;
}

/**
 * Human-readable status check of the module.
 *
 * @return A string containing thread status and packet counters.
 */
std::string TunInterface::status()
{
    std::string ret;

    ret += "Interface "s + devname + ":\n"s;

    ret += std::to_string(pktsOut) + " packets out to OS, "s + std::to_string(bytesOut) + " bytes out to OS, "s;
    ret += timepointDelta(std::chrono::steady_clock::now(), lastPacket) + " since last packet.\n";

    for(auto &t : threads)
    {
        ret += t.status();
    }

    ret += "\n"s;

    return ret;
}

/**
 * Return the last time any of our threads saw a packet.
 * @return
 */
std::chrono::steady_clock::time_point TunInterface::lastPacketTime()
{
    std::chrono::steady_clock::time_point ret;

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
            std::cerr << currentTime() << ": Tunnel thread "s << std::to_string(threadNumber) << " has not yet shutdown - waiting more."s << std::endl;
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
void TunInterfaceThread::setup(int threadNumberParam, int coreNumberParam, int fdParam, tunCallback recvDispatcherParam)
{
    threadNumber = threadNumberParam;
    coreNumber = coreNumberParam;
    recvDispatcher = recvDispatcherParam;
    fd = fdParam;
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
    if(debug) *debugout << currentTime() << ": Tun Thread " << std::to_string(threadNumber) << ": Starting" << std::endl;
    threadId = gettid();
    snprintf(threadName, 15, "gwlbtun T%03d", threadNumber);
    pthread_setname_np(pthread_self(), threadName);

    // If a specific core was requested, attempt to set affinity.
    if(coreNumber != -1)
    {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(coreNumber, &cpuset);
        int s = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
        if(s != 0)
        {
            std::cerr << currentTime() << ": Tun Thread " << std::to_string(threadNumber) << ": Unable to set TUN thread CPU affinity to core "s << std::to_string(coreNumber) << ": "s << std::error_code{errno, std::generic_category()}.message() << ". Thread continuing to run with affinity unset."s << std::endl;
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
                std::cerr << currentTime() << ": Tun Thread " << std::to_string(threadNumber) << ": Packet dispatch function failed: " << e.what() << std::endl;
            }
            pktsIn ++; bytesIn += msgLen;
        }
    }
    if(debug) *debugout << currentTime() << ": Tun Thread " << std::to_string(threadNumber) << ": Stopping by request" << std::endl;
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

std::string TunInterfaceThread::status()
{
    std::string ret;
    if(thread.valid())
    {
        ret = "Tunnel handler thread "s + std::to_string(threadNumber) + " (ID "s + std::to_string(threadId) + ")"s;

        if(healthCheck())
            ret += ": Healthy, "s;
        else {
            ret += ": NOT healthy, "s;
        }
        ret += std::to_string(pktsIn) + " packets in from OS, "s + std::to_string(bytesIn) + " bytes in from OS, "s;
        ret += timepointDelta(std::chrono::steady_clock::now(), lastPacket) + " since last packet.\n";
    }
    return ret;
}

void TunInterfaceThread::shutdown()
{
    shutdownRequested = true;
}

std::chrono::steady_clock::time_point TunInterfaceThread::lastPacketTime()
{
    return lastPacket.load();
}

/*
 * Allocate a new fd for our tun device. May throw exceptions.
 *
 * @return The new file descriptor.
 */
int TunInterface::allocateHandle()
{
    int fd;

    // Set up a new multiqueue file handler to process our packets
    struct ifreq ifr;
    bzero(&ifr, sizeof(ifr));

    // Code adapted from Linux Documentation/networking/tuntap.txt to create the tun device.
    if((fd = open("/dev/net/tun", O_RDWR)) < 0)
    {
        std::cerr << currentTime() << ": Unable to open /dev/net/tun " << std::error_code{errno, std::generic_category()}.message() << std::endl;
        throw std::system_error(errno, std::generic_category(), "Unable to open /dev/net/tun");
    }

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
    strncpy(ifr.ifr_name, devname.c_str(), IFNAMSIZ);

    if(ioctl(fd, TUNSETIFF, (void *)&ifr) < 0)
    {
        std::cerr << currentTime() << ": Unable to create TUN device (does this process have CAP_NET_ADMIN capability?)" << std::error_code{errno, std::generic_category()}.message() << std::endl;
        throw std::system_error(errno, std::generic_category(), "Unable to create TUN device (does this process have CAP_NET_ADMIN capability?)");
    }

    return fd;
}