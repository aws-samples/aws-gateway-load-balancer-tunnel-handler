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
#include <algorithm>
#include <climits>
#include "UDPPacketReceiver.h"
#include <unistd.h>
#include <utility>
#include "utils.h"
#include "Logger.h"
#include "WorkerThread.h"

using namespace std::string_literals;

/**
 * Start the UDP threads GwlbtunConfig laid out (see resolveUdpPlan there).
 *
 * One set of threads per interface in the plan, or one set bound to all interfaces. Sockets bound to
 * different interfaces form separate SO_REUSEPORT groups, so each interface's packets are spread over its own
 * threads only. Whenever an interface has one thread per receive queue, thread i's socket also gets queue i's
 * CPU as its SO_INCOMING_CPU: in a reuseport group, Linux 6.2+ then hands a packet to the socket whose
 * incoming CPU received it from the NIC, instead of picking a socket by flow hash (older kernels ignore it).
 * With more threads than queues it stays off: the kernel scans the group for a matching socket on every
 * packet, which doesn't pay with several sockets per queue.
 *
 * If a thread can't be set up, the exception unwinds `threads`, which stops the ones already running.
 *
 * @param plan UDP threads per interface, from GwlbtunConfig.
 * @param portNumberParam UDP port number to listen to.
 * @param recvDispatcher Function to callback to on each packet received.
 * @param batchEnd Function to call after each recvmmsg() batch has been dispatched.
 * @param rcvBufSizeMB Socket receive buffer size in megabytes.
 * @param busyPollUsec SO_BUSY_POLL microseconds (0 = off).
 */
UDPPacketReceiver::UDPPacketReceiver(const std::vector<UdpInterfacePlan> &plan, uint16_t portNumberParam, const udpCallback &recvDispatcher, const udpBatchCallback &batchEnd,
                                     int rcvBufSizeMB, int busyPollUsec)
: portNumber(portNumberParam)
{
    LOG(LS_UDP, LL_DEBUG, "UDP receiver setting up on port "s + ts(portNumber) + " with "s + ts(rcvBufSizeMB) + "MB receive buffer"s);

    int tIndex = 0;
    for(const auto &p : plan)
    {
        const bool tie = p.tiedToQueues();
        for(size_t local = 0; local < p.cores.size(); local++)
        {
            threads.emplace_back(tIndex, p.cores[local], portNumber, recvDispatcher, batchEnd, rcvBufSizeMB, busyPollUsec, p.name,
                                 tie ? p.queueCpus[local] : -1);
            tIndex ++;
        }
    }
}

UDPPacketReceiver::~UDPPacketReceiver()
{
    for(auto &t : threads)
        t.wake();
}

/**
 * Check on the status of the UDP receiver thread.
 *
 * @return true if the thread is still alive, false otherwise.
 */
bool UDPPacketReceiver::healthCheck() const
{
    return std::all_of(threads.begin(), threads.end(), [](const auto &t) { return t.healthCheck(); });
}

/**
 * Human-readable status check of the module.
 *
 * @return A string containing thread status and packet counters.
 */
UDPPacketReceiverHealthCheck UDPPacketReceiver::status() const
{
    std::vector<UDPPacketReceiverThreadHealthCheck> thcs;
    thcs.reserve(threads.size());
    for(const auto &t : threads)
        thcs.push_back(t.status());
    return {portNumber, std::move(thcs)};
}

UDPPacketReceiverThread::UDPPacketReceiverThread(int threadNumberParam, int coreNumberParam, uint16_t portNumberParam,
                                                 udpCallback recvDispatcherParam, udpBatchCallback batchEndParam, int rcvBufSizeMB, int busyPollUsec,
                                                 const std::string &interfaceParam, int incomingCpu)
: threadNumber(threadNumberParam), coreNumber(coreNumberParam), portNumber(portNumberParam), interface(interfaceParam),
  recvDispatcher(std::move(recvDispatcherParam)), batchEnd(std::move(batchEndParam)),
  sock(openSocket(threadNumberParam, portNumberParam, rcvBufSizeMB, busyPollUsec, interfaceParam, incomingCpu)),
  lastPacket(std::chrono::steady_clock::now()),
  thread(std::async(std::launch::async, &UDPPacketReceiverThread::threadFunction, this))   // throws std::system_error if no thread can be started
{
}

/**
 * Make the thread stop: shutting the socket down (not closing it) wakes it out of a blocking recvmmsg(), which
 * returns at once with zero-length entries. close() from another thread would not wake it. On an unconnected
 * UDP socket shutdown() reports ENOTCONN but still does this, so its result is ignored.
 */
void UDPPacketReceiverThread::wake() noexcept
{
    stopping = true;
    ::shutdown(sock.get(), SHUT_RDWR);
}

// Stop and join the thread (see joinWorker: the wait is unbounded, but a stuck thread gets logged).
UDPPacketReceiverThread::~UDPPacketReceiverThread()
{
    wake();
    joinWorker(thread, LS_UDP, "UDP receiver thread "s + ts(threadNumber));
}

/**
 * Open, configure and bind one receiver thread's GENEVE socket. Throws std::system_error on failure.
 */
UniqueFd UDPPacketReceiverThread::openSocket(int threadNumber, uint16_t portNumber, int rcvBufSizeMB, int busyPollUsec,
                                             const std::string &interface, int incomingCpu)
{
    const int yes = 1;
    auto fail = [](const std::string &what) {
        const int err = errno;   // before building the message can change it
        throw std::system_error(err, std::generic_category(), what);
    };

    UniqueFd sockOwner(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    if(!sockOwner)
        fail("Socket creation failed");
    const int sock = sockOwner.get();

    // SO_REUSEPORT lets each receiver thread bind its own socket to the GENEVE port, with the
    // kernel spreading flows across them. It requires the same effective UID for every socket on
    // the port. SO_REUSEADDR is deliberately NOT set: for UDP it would let any other process bind
    // the port and take a share of the traffic. (The old code passed "SO_REUSEADDR | SO_REUSEPORT"
    // as one option name; that ORs the option numbers, which happens to equal SO_REUSEPORT.)
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)))
        fail("Socket setsockopt() for port reuse failed");

    // A large receive buffer absorbs traffic bursts. The kernel caps the request at net.core.rmem_max (and then
    // reports double the size it applied, for its bookkeeping), so check what it actually applied.
    const int rcvbuf = rcvBufSizeMB * 1024 * 1024;   // --rcvbuf is at most 2047 MB, which fits an int
    if(setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0)
    {
        const int err = errno;
        LOG(LS_UDP, LL_IMPORTANT, "Unable to set the GENEVE socket receive buffer to "s + ts(rcvBufSizeMB) + " MB: "s + errText(err) + "."s);
    }
    int applied = 0;
    socklen_t optlen = sizeof(applied);
    if(threadNumber == 0 && getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &applied, &optlen) == 0 && applied / 2 < rcvbuf)
        LOG(LS_UDP, LL_IMPORTANT, "GENEVE socket receive buffers are "s + ts(applied / 2 / (1024 * 1024)) + " MB, not the "s + ts(rcvBufSizeMB) +
            " MB requested (--rcvbuf): the kernel caps them at net.core.rmem_max. For the full size, set net.core.rmem_max to at least "s +
            ts(rcvbuf) + " (sysctl -w net.core.rmem_max="s + ts(rcvbuf) + ", and in /etc/sysctl.d/ to keep it)."s);

    // Optionally enable NIC busy polling (--busypoll USEC; 0 = disabled).
    // Trades CPU for lower receive latency; most beneficial at high packet rates.
    if(busyPollUsec > 0)
    {
        if(setsockopt(sock, SOL_SOCKET, SO_BUSY_POLL, &busyPollUsec, sizeof(busyPollUsec)) < 0)
        {
            const int err = errno;
            LOG(LS_UDP, LL_IMPORTANT, "Unable to enable busy polling (--busypoll): "s + errText(err) +
                " (raising it above net.core.busy_read needs CAP_NET_ADMIN)."s);
        }
        else if(threadNumber == 0)
            LOG(LS_UDP, LL_IMPORTANT, "Busy polling enabled ("s + ts(busyPollUsec) + "us per receive)."s);
    }

    // Set up to receive the packet info
    if(setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &yes, sizeof(yes)))
        fail("Socket setsockopt() for IP_PKTINFO failed");

    // Receive only on one interface (-I). Must be set before bind(): the reuseport group a socket
    // joins depends on the interface it's bound to.
    if(!interface.empty() && setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface.c_str(), (socklen_t)interface.size()) < 0)
        fail("Unable to bind UDP socket to interface "s + interface);

    struct sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(portNumber);
    if(bind(sock, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) < 0)
        fail("Port binding failed");

    if(incomingCpu >= 0 && setsockopt(sock, SOL_SOCKET, SO_INCOMING_CPU, &incomingCpu, sizeof(incomingCpu)) < 0)
    {
        const int err = errno;
        LOG(LS_UDP, LL_IMPORTANT, "Unable to set SO_INCOMING_CPU: "s + errText(err));
    }

    LOG(LS_UDP, LL_DEBUG, "UDP receiver thread "s + ts(threadNumber) + " configured with "s + ts(rcvBufSizeMB) + "MB receive buffer"s);

    return sockOwner;
}

/**
 * Thread for the UDP receiver. Waits for packets to come in, then calls our dispatcher.
 * Uses recvmmsg() for batch packet processing to achieve high throughput (50+ Gbps).
 *
 * @return Never returns, until told to shutdown.
 */
int UDPPacketReceiverThread::threadFunction()
{
    threadId = gettid();
    t_udpThreadIndex = threadNumber;
    startWorkerThread('U', threadNumber, coreNumber, LS_UDP, LL_IMPORTANT, "UDP receiver thread "s + ts(threadNumber));

    // Batch receive: up to BATCH_SIZE packets per recvmmsg(). Packet buffers are allocated one by one: buffers
    // laid out at an exact 64 KiB stride would put every packet's headers in the same CPU cache set. Each
    // packet's only control message is its IP_PKTINFO (with headroom; a truncated one just drops the packet).
    constexpr int BATCH_SIZE = 64;
    constexpr size_t PKTBUF_SIZE = 65536;
    constexpr size_t CONTROL_SIZE = CMSG_SPACE(sizeof(struct in_pktinfo)) + 32;
    struct mmsghdr msgs[BATCH_SIZE];
    struct iovec iovecs[BATCH_SIZE];
    struct sockaddr_in srcAddrs[BATCH_SIZE];   // the socket is AF_INET
    alignas(struct cmsghdr) unsigned char controls[BATCH_SIZE][CONTROL_SIZE];
    std::unique_ptr<unsigned char[]> pktbufs[BATCH_SIZE];
    for(int i = 0; i < BATCH_SIZE; i++)
    {
        pktbufs[i].reset(new unsigned char[PKTBUF_SIZE]);
        iovecs[i].iov_base = pktbufs[i].get();
        iovecs[i].iov_len = PKTBUF_SIZE;
        memset(&msgs[i], 0, sizeof(struct mmsghdr));
        msgs[i].msg_hdr.msg_name = &srcAddrs[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(srcAddrs[i]);
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_control = controls[i];
        msgs[i].msg_hdr.msg_controllen = CONTROL_SIZE;
    }

    LOG(LS_UDP, LL_DEBUG, "UDP receiver thread "s + ts(threadNumber) + " starting with batch size "s + ts(BATCH_SIZE));

    // Blocks until at least one packet arrives (MSG_WAITFORONE). No timeout: wake() shuts the socket down,
    // which makes the call return.
    while(!stopping)
    {
        int numPkts = recvmmsg(sock.get(), msgs, BATCH_SIZE, MSG_WAITFORONE, nullptr);
        if(numPkts < 0)
        {
            const int err = errno;
            if(stopping)
                break;
            if(err != EINTR)
            {
                LOG(LS_UDP, LL_IMPORTANT, "recvmmsg error: "s + errText(err));
                usleep(10000);   // don't spin on a persistent error
            }
            continue;
        }

        uint64_t batchPkts = 0, batchBytes = 0;
        for(int i = 0; i < numPkts; i++)
        {
            const ssize_t msgLen = msgs[i].msg_len;
            // Zero length is either our own shutdown() (end of file: no sender address, and srcAddrs[i]
            // still holds the previous packet's) or an empty datagram, which can't be GENEVE. Skip both.
            if(msgLen == 0 || msgs[i].msg_hdr.msg_namelen == 0)
                continue;

            for(struct cmsghdr *cmhdr = CMSG_FIRSTHDR(&msgs[i].msg_hdr); cmhdr; cmhdr = CMSG_NXTHDR(&msgs[i].msg_hdr, cmhdr))
            {
                if(cmhdr->cmsg_level != IPPROTO_IP || cmhdr->cmsg_type != IP_PKTINFO)
                    continue;
                auto ipi = (struct in_pktinfo *)CMSG_DATA(cmhdr);
                batchPkts++;
                batchBytes += (uint64_t)msgLen;
                try {
                    recvDispatcher(pktbufs[i].get(), msgLen, &srcAddrs[i].sin_addr, be16toh(srcAddrs[i].sin_port), &ipi->ipi_spec_dst,
                                   portNumber, ipi->ipi_ifindex);
                }
                catch (std::exception& e) {
                    LOG(LS_UDP, LL_IMPORTANT, "UDP packet dispatch function failed: "s + e.what());
                }
                break;
            }
        }
        // Counters are published once per batch: they're only read by health checks.
        if(batchPkts)
        {
            lastPacket.store(std::chrono::steady_clock::now(), std::memory_order_relaxed);
            pktsIn.fetch_add(batchPkts, std::memory_order_relaxed);
            bytesIn.fetch_add(batchBytes, std::memory_order_relaxed);
        }

        // recvmmsg() writes back the address and control lengths each entry used. Restore the full
        // buffer sizes before the next call, so a short value left behind can't truncate a later
        // packet's IP_PKTINFO, and a zero length above really means this call received no address.
        for(int i = 0; i < numPkts; i++)
        {
            msgs[i].msg_hdr.msg_namelen = sizeof(srcAddrs[i]);
            msgs[i].msg_hdr.msg_controllen = CONTROL_SIZE;
        }
        if(batchEnd)
            batchEnd();
    }

    LOG(LS_UDP, LL_DEBUG, "UDP receiver thread "s + ts(threadNumber) + " shutting down");
    return 0;
}

bool UDPPacketReceiverThread::healthCheck() const
{
    return workerRunning(thread);
}

UDPPacketReceiverThreadHealthCheck UDPPacketReceiverThread::status() const
{
    return {healthCheck(), threadNumber, threadId, interface, pktsIn, bytesIn, lastPacket};
}

UDPPacketReceiverThreadHealthCheck::UDPPacketReceiverThreadHealthCheck(bool healthy, int threadNumber, int threadId, std::string interface, uint64_t pktsIn, uint64_t bytesIn, std::chrono::steady_clock::time_point lastPacket) :
        healthy(healthy), threadNumber(threadNumber), threadId(threadId), interface(std::move(interface)), pktsIn(pktsIn), bytesIn(bytesIn), lastPacket(lastPacket)
{
}

std::string UDPPacketReceiverThreadHealthCheck::output_str() const
{
    std::string ret;

    ret += "UDP receiver thread "s + std::to_string(threadNumber) + " (ID "s + std::to_string(threadId) + ")"s;
    if(!interface.empty())
        ret += " on "s + interface;
    if(healthy)
        ret += ": Healthy, "s;
    else {
        ret += ": NOT healthy, "s;
    }
    ret += std::to_string(pktsIn) + " packets in, "s + std::to_string(bytesIn) + " bytes in, "s;
    ret += timepointDeltaString(std::chrono::steady_clock::now(), lastPacket) + " since last packet.\n"s;

    return ret;
}

json UDPPacketReceiverThreadHealthCheck::output_json() const
{
    // "valid" is always true; kept for tools that read it (it was false only for an unused thread slot).
    return  { {"valid", true}, {"healthy", healthy}, {"threadNumber", threadNumber}, {"threadId", threadId},
             {"interface", interface.empty() ? "any"s : interface}, {"pktsIn", pktsIn}, {"bytesIn", bytesIn}, {"secsSinceLastPacket", timepointDeltaDouble(std::chrono::steady_clock::now(), lastPacket)} };
}

UDPPacketReceiverHealthCheck::UDPPacketReceiverHealthCheck(uint16_t portNumber, std::vector<UDPPacketReceiverThreadHealthCheck> threadHealthChecks) :
        portNumber(portNumber), threadHealthChecks(std::move(threadHealthChecks))
{
}

std::string UDPPacketReceiverHealthCheck::output_str() const
{
    std::string ret;

    ret += "UDP receiver threads for port number "s + std::to_string(portNumber) + ":\n";
    for(auto &t : threadHealthChecks)
        ret += t.output_str();

    ret += "\n";

    return ret;
}

json UDPPacketReceiverHealthCheck::output_json() const
{
    json threads = json::array();
    for(const auto &t : threadHealthChecks)
        threads.push_back(t.output_json());
    return { {"UDPPacketReceiver", { {"portNumber", portNumber}, {"threads", threads} }} };
}
