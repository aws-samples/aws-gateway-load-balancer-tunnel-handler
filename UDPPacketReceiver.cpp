// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * UDPPacketReceiver class handles monitoring a UDP port (6081 for GENEVE). It performs the following functions:
 * - Start a listener for the port
 * - Launch threads to listen for packets in on that port
 * - Call recvDispatcher for each packet received.
 * - Provides a status() function that returns the packet counters and checks that the thread is still alive.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include "UDPPacketReceiver.h"
#include <unistd.h>
#include <iostream>
#include <utility>
#include <thread>
#include "utils.h"

using namespace std::string_literals;

/**
 * Default constructor for array initialization.
 */
UDPPacketReceiver::UDPPacketReceiver()
        : portNumber(0)
{
    // Empty init. Need to set port and receive function with a setup() call.
}

/**
 * Destructor. Signals all threads to shut down, waits for that to finish.
 */
UDPPacketReceiver::~UDPPacketReceiver()
{
    shutdown();
}

void UDPPacketReceiver::shutdown()
{
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
 * Setup the receiver. Open a UDP receiver and starts the thread for it.
 *
 * @param portNumber UDP port number to listen to.
 * @param recvDispatcher Function to callback to on each packet received.
 */
void UDPPacketReceiver::setup(ThreadConfig threadConfig, uint16_t portNumberParam, udpCallback recvDispatcherParam)
{
    if(debug) *debugout << currentTime() << ": UDP receiver setting up on port "s << std::to_string(portNumberParam) << std::endl;
    portNumber = portNumberParam;

    // Set up our threads as per threadConfig
    int tIndex = 0;
    for(int core : threadConfig.cfg)
    {
        threads[tIndex].setup(tIndex, core, portNumberParam, recvDispatcherParam);
        tIndex ++;
    }
}

/**
 * Check on the status of the UDP receiver thread.
 *
 * @return true if the thread is still alive, false otherwise.
 */
bool UDPPacketReceiver::healthCheck()
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
std::string UDPPacketReceiver::status() {
    std::string ret;

    ret += "UDP receiver threads for port number "s + std::to_string(portNumber) + ":\n";

    for(auto &t : threads)
    {
        ret += t.status();
    }

    ret += "\n";

    return ret;
}

/**
* UDPPacketReceiverThread coordinates and holds the thread for one individual thread of UDP receiving.
*/
UDPPacketReceiverThread::UDPPacketReceiverThread()
    : setupCalled(false), sock(0), portNumber(0), threadNumber(0), coreNumber(0), shutdownRequested(false), lastPacket(std::chrono::steady_clock::now()), pktsIn(0), bytesIn(0)
{
    // Empty init, until setup is called.
}

UDPPacketReceiverThread::~UDPPacketReceiverThread()
{
    shutdownRequested = true;
    // If this thread has been setup and is running, signal shutdown and wait for it to complete.
    if(thread.valid())
    {
        auto status = thread.wait_for(std::chrono::seconds(2));
        while(status == std::future_status::timeout)
        {
            std::cerr << currentTime() << ": UDP receiver thread "s << std::to_string(threadNumber) << " has not yet shutdown - waiting more."s << std::endl;
            status = thread.wait_for(std::chrono::seconds(1));
        }
    }
}

void UDPPacketReceiverThread::setup(int threadNumberParam, int coreNumberParam, uint16_t portNumberParam,
                                    udpCallback recvDispatcherParam)
{
    int yes = 1;
    struct sockaddr_in address{};

    threadNumber = threadNumberParam;
    coreNumber = coreNumberParam;
    recvDispatcher = std::move(recvDispatcherParam);
    portNumber = portNumberParam;
    setupCalled = true;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == 0)
        throw std::system_error(errno, std::generic_category(), "Socket creation failed");

    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &yes, sizeof(yes)))
        throw std::system_error(errno, std::generic_category(), "Socket setsockopt() for port reuse failed");

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(portNumber);

    // Set up to receive the packet info
    yes = 1;
    if(setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &yes, sizeof(yes)))
        throw std::system_error(errno, std::generic_category(), "Socket setsockopt() for IP_PKTINFO failed");

    if(bind(sock, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) < 0)
        throw std::system_error(errno, std::generic_category(), "Port binding failed");

    thread = std::async(&UDPPacketReceiverThread::threadFunction, this);
}

/**
 * Thread for the UDP receiver. Waits for packets to come in, then calls our dispatcher.
 *
 * @return Never returns, until told to shutdown.
 */
int UDPPacketReceiverThread::threadFunction()
{
    struct sockaddr_storage src_addr{};
    struct sockaddr_in *src_addr4;
    struct msghdr mh{};
    struct cmsghdr *cmhdr;
    struct iovec iov[1];
    struct in_pktinfo *ipi;
    unsigned char *pktbuf, *control;
    char threadName[16];

    // Static packet processing buffers.
    pktbuf = new unsigned char[65535];
    control = new unsigned char[2048];
    threadId = gettid();
    snprintf(threadName, 15, "gwlbtun U%03d", threadNumber);
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
            std::cerr << "Unable to set UDP thread CPU affinity to core "s << std::to_string(coreNumber) << ": "s << std::error_code{errno, std::generic_category()}.message() << ". Thread continuing to run with affinity unset."s << std::endl;
        } else {
            snprintf(threadName, 15, "gwlbtun UA%03d", coreNumber);
            pthread_setname_np(pthread_self(), threadName);
        }
    }

    iov[0].iov_base = pktbuf;
    iov[0].iov_len = 65534;
    mh.msg_name = &src_addr;
    mh.msg_namelen = sizeof(src_addr);
    mh.msg_iov = iov;
    mh.msg_iovlen = 1;
    mh.msg_control = control;
    mh.msg_controllen = 2048;

    // Receive packets and dispatch them.  check every second to make sure a shutdown hasn't been requested.
    // printf("UDP receive thread active.\n");
    ssize_t msgLen;
    struct timeval tv{};
    fd_set readfds;
    while(!shutdownRequested)
    {
        // printf("tick\n");
        tv.tv_sec = 1; tv.tv_usec = 0;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        select(sock + 1, &readfds, nullptr, nullptr, &tv);
        if(FD_ISSET(sock, &readfds))
        {
            msgLen = recvmsg(sock, &mh, MSG_DONTWAIT);
            while(msgLen > 0 && !shutdownRequested) {
                if(src_addr.ss_family == AF_INET)
                {
                    // Cycle through the control data to get the IP address this was sent to, then call dispatch.
                    cmhdr = CMSG_FIRSTHDR(&mh);
                    while(cmhdr)
                    {
                        if(cmhdr->cmsg_level == IPPROTO_IP && cmhdr->cmsg_type == IP_PKTINFO)
                        {
                            ipi = (struct in_pktinfo *)CMSG_DATA(cmhdr);
                            src_addr4 = (struct sockaddr_in *)&src_addr;
                            lastPacket = std::chrono::steady_clock::now();
                            pktsIn ++;
                            bytesIn += msgLen;
                            try {
                                recvDispatcher(pktbuf, msgLen, &src_addr4->sin_addr, be16toh(src_addr4->sin_port), &ipi->ipi_spec_dst, portNumber);
                            }
                            catch (std::exception& e) {
                                std::cerr << currentTime() << ": UDP packet dispatch function failed: " << e.what() << std::endl;
                            }
                        }
                        cmhdr = CMSG_NXTHDR(&mh, cmhdr);
                    }
                }
                msgLen = recvmsg(sock, &mh, MSG_DONTWAIT);
            }
        }
    }
    // printf("UDP receive thread shutdown.\n");
    delete [] pktbuf;
    delete [] control;
    return(0);
}

bool UDPPacketReceiverThread::healthCheck()
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

std::string UDPPacketReceiverThread::status()
{
    std::string ret;
    if(thread.valid())
    {
        ret += "UDP receiver thread "s + std::to_string(threadNumber) + " (ID "s + std::to_string(threadId) + ")"s;
        if(healthCheck())
            ret += ": Healthy, "s;
        else {
            ret += ": NOT healthy, "s;
        }
        ret += std::to_string(pktsIn) + " packets in, "s + std::to_string(bytesIn) + " bytes in, "s;
        ret += timepointDelta(std::chrono::steady_clock::now(), lastPacket) + " since last packet.\n"s;
    }

    return ret;
}

void UDPPacketReceiverThread::shutdown() {
    shutdownRequested = true;
    // The std::async threads will see that boolean change within 1 second, then exit.
}
