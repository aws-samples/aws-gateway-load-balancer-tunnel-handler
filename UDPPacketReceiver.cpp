/*
 * Copyright Amazon.com, Inc. or its affiliates. This material is AWS Content under the AWS Enterprise Agreement 
 * or AWS Customer Agreement (as applicable) and is provided under the AWS Intellectual Property License.
 */
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
#include <fstream>
#include <utility>
#include <thread>
#include "utils.h"
#include "Logger.h"

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
    // Signal all threads to shutdown, then wait for all acks.
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
 * @param threadConfig Thread configuration specifying cores to use.
 * @param portNumberParam UDP port number to listen to.
 * @param recvDispatcherParam Function to callback to on each packet received.
 * @param rcvBufSizeMB Socket receive buffer size in megabytes (default 128MB).
 */
void UDPPacketReceiver::setup(ThreadConfig threadConfig, uint16_t portNumberParam, udpCallback recvDispatcherParam, int rcvBufSizeMB)
{
    LOG(LS_UDP, LL_DEBUG, "UDP receiver setting up on port "s + ts(portNumberParam) + " with "s + ts(rcvBufSizeMB) + "MB receive buffer"s);
    portNumber = portNumberParam;

    // Set up our threads as per threadConfig
    int tIndex = 0;
    for(int core : threadConfig.cfg)
    {
        threads[tIndex].setup(tIndex, core, portNumberParam, recvDispatcherParam, rcvBufSizeMB);
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
UDPPacketReceiverHealthCheck UDPPacketReceiver::status() {
    std::list<UDPPacketReceiverThreadHealthCheck> thcs;

    for(auto &t : threads)
    {
        thcs.push_back(t.status());
    }

    return {portNumber, thcs};
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
            LOG(LS_UDP, LL_DEBUG, "UDP receiver thread "s + ts(threadNumber) + " has not yet shutdown - waiting more."s);
            status = thread.wait_for(std::chrono::seconds(1));
        }
    }
    if(sock >= 0)
        close(sock);
}

void UDPPacketReceiverThread::setup(int threadNumberParam, int coreNumberParam, uint16_t portNumberParam,
                                    udpCallback recvDispatcherParam, int rcvBufSizeMB)
{
    int yes = 1;
    struct sockaddr_in address{};

    threadNumber = threadNumberParam;
    coreNumber = coreNumberParam;
    recvDispatcher = std::move(recvDispatcherParam);
    portNumber = portNumberParam;
    setupCalled = true;

    // Check kernel's rmem_max before attempting to set buffer size
    // Only check on first thread to avoid log spam
    if(threadNumber == 0)
    {
        long long rmemMax = 0;
        std::ifstream rmemFile("/proc/sys/net/core/rmem_max");
        if(rmemFile.is_open())
        {
            rmemFile >> rmemMax;
            rmemFile.close();
            
            long long requestedBytes = (long long)rcvBufSizeMB * 1024 * 1024;
            // Linux doubles the requested buffer size, so we need rmem_max >= requested * 2
            // But the actual buffer will be capped at rmem_max / 2
            if(rmemMax < requestedBytes)
            {
                long long recommendedRmemMax = requestedBytes * 2;  // Linux doubles the value
                LOG(LS_UDP, LL_CRITICAL, 
                    "WARNING: Kernel net.core.rmem_max ("s + ts(rmemMax / (1024*1024)) + "MB) is less than requested buffer size ("s + 
                    ts(rcvBufSizeMB) + "MB). Socket buffer will be limited to "s + ts(rmemMax / (2*1024*1024)) + "MB."s);
                LOG(LS_UDP, LL_CRITICAL,
                    "RECOMMENDATION: For optimal performance at high packet rates, run:"s);
                LOG(LS_UDP, LL_CRITICAL,
                    "  sudo sysctl -w net.core.rmem_max="s + ts(recommendedRmemMax));
                LOG(LS_UDP, LL_CRITICAL,
                    "  sudo sysctl -w net.core.rmem_default="s + ts(requestedBytes));
                LOG(LS_UDP, LL_CRITICAL,
                    "To make permanent, add to /etc/sysctl.d/99-gwlb-tuning.conf:"s);
                LOG(LS_UDP, LL_CRITICAL,
                    "  net.core.rmem_max = "s + ts(recommendedRmemMax));
                LOG(LS_UDP, LL_CRITICAL,
                    "  net.core.rmem_default = "s + ts(requestedBytes));
            }
            else
            {
                LOG(LS_UDP, LL_DEBUG, "Kernel net.core.rmem_max ("s + ts(rmemMax / (1024*1024)) + 
                    "MB) is sufficient for requested buffer size ("s + ts(rcvBufSizeMB) + "MB)"s);
            }
        }
        else
        {
            LOG(LS_UDP, LL_DEBUG, "Could not read /proc/sys/net/core/rmem_max to verify kernel buffer limits");
        }
    }

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == 0)
        throw std::system_error(errno, std::generic_category(), "Socket creation failed");

    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &yes, sizeof(yes)))
        throw std::system_error(errno, std::generic_category(), "Socket setsockopt() for port reuse failed");

    // Set socket receive buffer size for high throughput
    // This prevents packet loss during traffic bursts
    int rcvbuf = rcvBufSizeMB * 1024 * 1024;
    if(setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0)
        LOG(LS_UDP, LL_IMPORTANT, "Warning: Failed to set socket receive buffer to "s + ts(rcvBufSizeMB) + "MB: "s + 
            std::error_code{errno, std::generic_category()}.message() + 
            ". Performance may be degraded at high packet rates.");
    
    // Verify the actual buffer size that was set
    int actualBuf = 0;
    socklen_t optlen = sizeof(actualBuf);
    if(getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &actualBuf, &optlen) == 0)
    {
        // Linux reports double the actual buffer size
        int actualMB = actualBuf / (2 * 1024 * 1024);
        if(actualMB < rcvBufSizeMB && threadNumber == 0)
        {
            LOG(LS_UDP, LL_IMPORTANT, "Note: Actual socket buffer size is "s + ts(actualMB) + 
                "MB (requested "s + ts(rcvBufSizeMB) + "MB). Increase net.core.rmem_max for better performance."s);
        }
    }

    // Enable busy polling for lower latency (50 microseconds)
    // This reduces latency by polling the NIC more frequently
    int busy_poll = 50;
    if(setsockopt(sock, SOL_SOCKET, SO_BUSY_POLL, &busy_poll, sizeof(busy_poll)) < 0)
        LOG(LS_UDP, LL_DEBUG, "Note: SO_BUSY_POLL not supported on this kernel (requires Linux 3.11+)");

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(portNumber);

    // Set up to receive the packet info
    yes = 1;
    if(setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &yes, sizeof(yes)))
        throw std::system_error(errno, std::generic_category(), "Socket setsockopt() for IP_PKTINFO failed");

    if(bind(sock, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) < 0)
        throw std::system_error(errno, std::generic_category(), "Port binding failed");

    LOG(LS_UDP, LL_DEBUG, "UDP receiver thread "s + ts(threadNumber) + " configured with "s + ts(rcvBufSizeMB) + "MB receive buffer and busy polling"s);

    thread = std::async(&UDPPacketReceiverThread::threadFunction, this);
}

/**
 * Thread for the UDP receiver. Waits for packets to come in, then calls our dispatcher.
 * Uses recvmmsg() for batch packet processing to achieve high throughput (50+ Gbps).
 *
 * @return Never returns, until told to shutdown.
 */
int UDPPacketReceiverThread::threadFunction()
{
    char threadName[16];
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
            LOG(LS_UDP, LL_IMPORTANT, "Unable to set thread CPU affinity to core "s  + ts(coreNumber) + ": "s + std::error_code{errno, std::generic_category()}.message() + ". Thread continuing to run with affinity unset."s);
        } else {
            snprintf(threadName, 15, "gwlbtun UA%03d", coreNumber);
            pthread_setname_np(pthread_self(), threadName);
        }
    }

    // Batch receive configuration - receive up to 64 packets per syscall
    const int BATCH_SIZE = 64;
    struct mmsghdr msgs[BATCH_SIZE];
    struct iovec iovecs[BATCH_SIZE];
    struct sockaddr_storage src_addrs[BATCH_SIZE];
    unsigned char *pktbufs[BATCH_SIZE];
    unsigned char *controls[BATCH_SIZE];

    // Allocate buffers for batch processing
    for(int i = 0; i < BATCH_SIZE; i++)
    {
        pktbufs[i] = new unsigned char[65536];
        controls[i] = new unsigned char[2048];
        
        iovecs[i].iov_base = pktbufs[i];
        iovecs[i].iov_len = 65535;
        
        memset(&msgs[i], 0, sizeof(struct mmsghdr));
        msgs[i].msg_hdr.msg_name = &src_addrs[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(src_addrs[i]);
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_control = controls[i];
        msgs[i].msg_hdr.msg_controllen = 2048;
    }

    LOG(LS_UDP, LL_DEBUG, "UDP receiver thread "s + ts(threadNumber) + " starting with batch size "s + ts(BATCH_SIZE));

    // Receive loop - use recvmmsg() for batch processing, no select() overhead
    // MSG_WAITFORONE: return as soon as at least one packet is available
    struct timespec timeout;
    timeout.tv_sec = 1;
    timeout.tv_nsec = 0;
    
    while(!shutdownRequested)
    {
        // Receive batch of packets - blocks until at least one arrives or timeout
        int numPkts = recvmmsg(sock, msgs, BATCH_SIZE, MSG_WAITFORONE, &timeout);
        
        if(numPkts < 0)
        {
            if(errno == EINTR && shutdownRequested)
                break;
            if(errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            LOG(LS_UDP, LL_IMPORTANT, "recvmmsg error: "s + std::error_code{errno, std::generic_category()}.message());
            continue;
        }
        
        // Process all received packets in the batch
        for(int i = 0; i < numPkts; i++)
        {
            ssize_t msgLen = msgs[i].msg_len;
            auto& src_addr = src_addrs[i];
            
            if(src_addr.ss_family == AF_INET)
            {
                // Extract packet info from control message
                struct cmsghdr *cmhdr = CMSG_FIRSTHDR(&msgs[i].msg_hdr);
                while(cmhdr)
                {
                    if(cmhdr->cmsg_level == IPPROTO_IP && cmhdr->cmsg_type == IP_PKTINFO)
                    {
                        auto ipi = (struct in_pktinfo *)CMSG_DATA(cmhdr);
                        auto src_addr4 = (struct sockaddr_in *)&src_addr;
                        
                        lastPacket = std::chrono::steady_clock::now();
                        pktsIn++;
                        bytesIn += msgLen;
                        
                        try {
                            recvDispatcher(pktbufs[i], msgLen, &src_addr4->sin_addr, 
                                         be16toh(src_addr4->sin_port), &ipi->ipi_spec_dst, portNumber);
                        }
                        catch (std::exception& e) {
                            LOG(LS_UDP, LL_IMPORTANT, "UDP packet dispatch function failed: "s + e.what());
                        }
                        break;
                    }
                    cmhdr = CMSG_NXTHDR(&msgs[i].msg_hdr, cmhdr);
                }
            }
        }
    }

    LOG(LS_UDP, LL_DEBUG, "UDP receiver thread "s + ts(threadNumber) + " shutting down");
    
    // Clean up allocated buffers
    for(int i = 0; i < BATCH_SIZE; i++)
    {
        delete [] pktbufs[i];
        delete [] controls[i];
    }
    
    return 0;
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

UDPPacketReceiverThreadHealthCheck UDPPacketReceiverThread::status()
{
    if(thread.valid())
        return {true, healthCheck(), threadNumber, threadId, pktsIn, bytesIn, lastPacket};
    else
        return {false, false, 0, 0, 0, 0, std::chrono::steady_clock::now()};
}

void UDPPacketReceiverThread::shutdown()
{
    shutdownRequested = true;
    // The std::async threads will see that boolean change within 1 second, then exit.
}


UDPPacketReceiverThreadHealthCheck::UDPPacketReceiverThreadHealthCheck(bool threadValid, bool healthy, int threadNumber, int threadId, uint64_t pktsIn, uint64_t bytesIn, std::chrono::steady_clock::time_point lastPacket) :
        threadValid(threadValid), healthy(healthy), threadNumber(threadNumber), threadId(threadId), pktsIn(pktsIn), bytesIn(bytesIn), lastPacket(lastPacket)
{
}

std::string UDPPacketReceiverThreadHealthCheck::output_str()
{
    std::string ret;

    if(!threadValid)
        return "";

    ret += "UDP receiver thread "s + std::to_string(threadNumber) + " (ID "s + std::to_string(threadId) + ")"s;
    if(healthy)
        ret += ": Healthy, "s;
    else {
        ret += ": NOT healthy, "s;
    }
    ret += std::to_string(pktsIn) + " packets in, "s + std::to_string(bytesIn) + " bytes in, "s;
    ret += timepointDeltaString(std::chrono::steady_clock::now(), lastPacket) + " since last packet.\n"s;

    return ret;
}

json UDPPacketReceiverThreadHealthCheck::output_json()
{
    return  { {"valid", threadValid}, {"healthy", healthy}, {"threadNumber", threadNumber}, {"threadId", threadId},
             {"pktsIn", pktsIn}, {"bytesIn", bytesIn}, {"secsSinceLastPacket", timepointDeltaDouble(std::chrono::steady_clock::now(), lastPacket)} };
}

UDPPacketReceiverHealthCheck::UDPPacketReceiverHealthCheck(uint16_t portNumber, std::list<UDPPacketReceiverThreadHealthCheck> threadHealthChecks) :
        portNumber(portNumber), threadHealthChecks(std::move(threadHealthChecks))
{
}

std::string UDPPacketReceiverHealthCheck::output_str()
{
    std::string ret;

    ret += "UDP receiver threads for port number "s + std::to_string(portNumber) + ":\n";
    for(auto &t : threadHealthChecks)
        ret += t.output_str();

    ret += "\n";

    return ret;
}

json UDPPacketReceiverHealthCheck::output_json()
{
    json ret;

    ret["UDPPacketReceiver"] = { {"portNumber", portNumber}, {"threads", json::array()} };

    for(auto &t : threadHealthChecks)
    {
        auto js = t.output_json();
        if (js["valid"] == true)
            ret["UDPPacketReceiver"]["threads"].push_back(js);
    }

    return ret;
}