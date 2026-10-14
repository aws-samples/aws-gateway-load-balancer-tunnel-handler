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
#include <sys/epoll.h>
#include <cerrno>
#include <cstring>
#include <sys/ioctl.h>
#include <unistd.h>
#include <algorithm>
#include <exception>
#include <utility>
#include "utils.h"
#include "Logger.h"
#include "WorkerThread.h"

using namespace std::string_literals;

/**
 * Constructor. Build a TUN interface and start listening for packets on it.
 *
 * @param devname The name of the TUN itnerface to build.
 * @param mtu MTU to set the interface to.
 * @param recvDispatcher Function the thread should callback to on packets received.
 * @param createsDevice True if this interface's first thread creates the device (exclusively), false if
 *                      the device already exists and the threads attach queues to it.
 */
TunInterface::TunInterface(std::string devnameParam, int mtu, const ThreadConfig &threadConfig, const tunCallback &recvDispatcherParam, bool createsDevice)
: devname(std::move(devnameParam))
{
    LOG(LS_TUNNEL, LL_DEBUG, "TunInterface creating for "s + devname);

    // Open each thread's queue and start it. If any of them fails, the exception unwinds `threads`, which
    // stops and joins the ones already running.
    int tIndex = 0;
    for(int core : threadConfig.cfg)
    {
        threads.emplace_back(tIndex, core, devname, recvDispatcherParam, stop, createsDevice && tIndex == 0);
        tIndex ++;
    }

    // Mark the tun device link up. We need a dummy socket to do this call.
    struct ifreq ifr;
    bzero(&ifr, sizeof(ifr));
    strncpy(ifr.ifr_name, devname.c_str(), IFNAMSIZ - 1);

    auto fail = [this](const std::string &what) {
        const int err = errno;   // before building the message can change it
        throw std::system_error(err, std::generic_category(), what + " "s + devname);
    };
    UniqueFd dummy(socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    if(!dummy)
        fail("Unable to create dummy socket to configure device");
    if(ioctl(dummy.get(), SIOCGIFFLAGS, (void *)&ifr) < 0)
        fail("Unable to get device flags for");

    ifr.ifr_flags |= IFF_UP;        // Set interface is up
    // These two lines have no effect on Linux, and we know it: IFF_RUNNING and IFF_POINTOPOINT are "volatile"
    // flags, owned by the driver. SIOCSIFFLAGS (__dev_change_flags() in net/core/dev.c) keeps the device's
    // current value of every volatile flag and ignores what we pass (include/uapi/linux/if.h lists them), and
    // the tun driver itself marks TUN devices point-to-point and running once a queue is attached. They stay
    // to record the intent: an interface that is running, with no point-to-point peer.
    ifr.ifr_flags |= IFF_RUNNING;
    ifr.ifr_flags &= ~IFF_POINTOPOINT;
    if(ioctl(dummy.get(), SIOCSIFFLAGS, (void *)&ifr) < 0)
        fail("Unable to set device flags for");

    // Set the MTU to the GWLB standard (8500)
    ifr.ifr_mtu = mtu;
    if(ioctl(dummy.get(), SIOCSIFMTU, (void *)&ifr) < 0)
        fail("Unable to set MTU on");
}

/**
 * Destructor. The members do the work: destroying `threads` stops and joins every reader thread (see
 * ~TunInterfaceThread), and closing their queues removes the device unless another fd still holds it.
 */
TunInterface::~TunInterface()
{
    LOG(LS_TUNNEL, LL_DEBUG, "TunInterface destroying for "s + devname);
}

/**
 * Check that all of this interface's started reader threads are still alive.
 *
 * @return true if every started thread is still running, false otherwise.
 */
bool TunInterface::healthCheck() const
{
    return std::all_of(threads.begin(), threads.end(), [](const auto &t) { return t.healthCheck(); });
}

/**
 * Human-readable status check of the module.
 *
 * @return A HealthCheck class
 */
TunInterfaceHealthCheck TunInterface::status() const
{
    std::vector<TunInterfaceThreadHealthCheck> thcs;
    thcs.reserve(threads.size());
    for(const auto &t : threads)
        thcs.push_back(t.status());
    return { devname, std::move(thcs) };
}

/**
 * Return the last time any of our threads saw a packet (each thread's time starts at its creation).
 * @return
 */
std::chrono::steady_clock::time_point TunInterface::lastPacketTime() const
{
    std::chrono::steady_clock::time_point ret{};
    for(const auto &t : threads)
        ret = std::max(ret, t.lastPacketTime());
    return ret;
}

/**
 * TunInterfaceThread class handles an individual thread assigned to processing packets coming in from the OS via the gwo interfaces.
 * Packets
 * - Launches a thread to service that interface
 * - Takes a callback function (recvDispatcher) which is called for each packet received by that interface.
 * - Provides a status() function that returns the packet counters and checks that the thread is still alive.
 */

/**
 * The epoll set a reader thread waits on: its tun queue (data 0) and the interface's stop event (data 1).
 * epoll rather than poll(): poll() adds the caller to, and removes it from, each fd's wait queue on every
 * call, and the stop event is one eventfd shared by all of an interface's readers, so with many readers that
 * wait queue's lock was the busiest lock in the process (measured: about a fifth of all CPU at 14M pps with
 * 128 tunnel threads on a c8in.96xlarge). An epoll set registers on each wait queue once, here.
 */
UniqueFd TunInterfaceThread::makeWaitSet(int tunFd, int stopFd)
{
    UniqueFd ep(epoll_create1(EPOLL_CLOEXEC));
    if(!ep)
        throw std::system_error(errno, std::generic_category(), "Unable to create an epoll set for a tunnel thread");
    struct epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.u32 = 0;
    if(epoll_ctl(ep.get(), EPOLL_CTL_ADD, tunFd, &ev) < 0)
        throw std::system_error(errno, std::generic_category(), "Unable to add a tun queue to a tunnel thread's epoll set");
    ev.data.u32 = 1;
    if(epoll_ctl(ep.get(), EPOLL_CTL_ADD, stopFd, &ev) < 0)
        throw std::system_error(errno, std::generic_category(), "Unable to add the stop event to a tunnel thread's epoll set");
    return ep;
}

TunInterfaceThread::TunInterfaceThread(int threadNumberParam, int coreNumberParam, const std::string &devname, tunCallback recvDispatcherParam,
                                       const EventFd &stopParam, bool createDevice)
: threadNumber(threadNumberParam), coreNumber(coreNumberParam), stop(stopParam), recvDispatcher(std::move(recvDispatcherParam)),
  tunSocket(devname, createDevice, true), waitSet(makeWaitSet(tunSocket.get(), stop.get())),
  lastPacket(std::chrono::steady_clock::now()),
  thread(std::async(std::launch::async, &TunInterfaceThread::threadFunction, this))   // throws std::system_error if no thread can be started
{
}

/**
 * Stop and join the thread. Signalling the interface's stop event wakes all of its readers at once, so when
 * an interface is destroyed only the first thread's destructor waits for anything; the rest have usually
 * exited by the time their turn comes.
 */
TunInterfaceThread::~TunInterfaceThread()
{
    stop.signal();
    joinWorker(thread, LS_TUNNEL, "Tunnel thread "s + ts(threadNumber));
}

/**
 * Thread for the tunnel handler. Waits for packets on its queue, then calls recvDispatch, until the
 * interface's stop event is signalled.
 *
 * @return 0 once stopped.
 */
int TunInterfaceThread::threadFunction()
{
    threadId = gettid();
    // Pin to the requested core, or (unpinned) undo the affinity inherited from the creating thread: endpoints
    // are created on UDP threads, which may be pinned to one CPU, and every tunnel thread would end up there.
    startWorkerThread('T', threadNumber, coreNumber, LS_TUNNEL, LL_INFO, "tunnel thread "s + ts(threadNumber));
    LOG(LS_TUNNEL, LL_DEBUG, "Thread starting");

#ifndef NO_RETURN_TRAFFIC
    // This thread's own raw socket for sending return traffic to GWLB (see utils.h); closed when the
    // thread exits. (Receive-only builds have no tunnel threads, and send nothing.)
    ThreadRawSendSocket rawSendSock;
#endif

    // Packet buffer: one packet per read() (a tun device returns exactly one), up to the largest IP packet.
    constexpr size_t PKTBUF_SIZE = 65535;
    auto pktbuf = std::make_unique<unsigned char[]>(PKTBUF_SIZE);

    // Wait on the queue and on the interface's stop event together (the epoll set, see makeWaitSet), with no
    // timeout: the stop event wakes the thread as soon as the interface is being destroyed, and stays readable
    // after that. The fd is non-blocking (see TunSocket) so that each wakeup drains the queue (up to a batch
    // limit) instead of returning to epoll_wait() per packet.
    const int fd = tunSocket.get();
    constexpr int DRAIN_BATCH = 64;
    for(;;)
    {
        struct epoll_event evs[2];
        const int nEvents = epoll_wait(waitSet.get(), evs, 2, -1);
        if(nEvents < 0)
        {
            const int err = errno;
            if(err != EINTR)
            {
                LOG(LS_TUNNEL, LL_DEBUG, "epoll_wait() for tun device "s + ts(fd) + " failed: "s + errText(err));
                if(stop.waitFor(100))   // back off briefly rather than spinning, still waking for a stop
                    break;
            }
            continue;
        }
        uint32_t tunEvents = 0;
        bool stopping = false;
        for(int i = 0; i < nEvents; i++)
        {
            if(evs[i].data.u32 == 1)
                stopping = true;
            else
                tunEvents = evs[i].events;
        }
        if(stopping)
            break;
        if(!(tunEvents & EPOLLIN))
        {
            // Error or hangup with nothing to read. Back off briefly rather than spinning on it.
            LOG(LS_TUNNEL, LL_DEBUG, "epoll_wait() for tun device "s + ts(fd) + " returned events 0x"s + stringFormat("%x", tunEvents));
            if(stop.waitFor(100))
                break;
            continue;
        }
        // The tun interface has received packets. Drain up to a batch, dispatching each; a stop is seen at
        // the next epoll_wait(). Counters are published once per drain: they're read by health checks and the idle
        // check, which works in seconds.
        uint64_t drained = 0, drainedBytes = 0;
        for(int n = 0; n < DRAIN_BATCH; n++)
        {
            const ssize_t msgLen = read(fd, pktbuf.get(), PKTBUF_SIZE);
            if(msgLen <= 0)
            {
                // Negative = read error (EAGAIN: queue drained); zero = spurious empty read. Nothing to
                // dispatch, and a negative length passed downstream would corrupt the byte counters.
                const int err = errno;
                if(msgLen < 0 && err != EAGAIN && err != EWOULDBLOCK && err != EINTR)
                    LOG(LS_TUNNEL, LL_DEBUG, "read() on tun device "s + ts(fd) + " failed: "s + errText(err));
                break;
            }
            try {
                recvDispatcher(pktbuf.get(), msgLen);
            }
            catch (std::exception& e) {
                LOG(LS_TUNNEL, LL_IMPORTANT, "Packet dispatch function failed: "s + e.what());
            }
            drained++;
            drainedBytes += (uint64_t)msgLen;
        }
        if(drained)
        {
            lastPacket.store(std::chrono::steady_clock::now(), std::memory_order_relaxed);
            pktsIn.fetch_add(drained, std::memory_order_relaxed);
            bytesIn.fetch_add(drainedBytes, std::memory_order_relaxed);
        }
    }
    LOG(LS_TUNNEL, LL_DEBUG, "Thread stopping by request");
    return 0;
}

bool TunInterfaceThread::healthCheck() const
{
    return workerRunning(thread);   // healthy while the thread is still running
}

TunInterfaceThreadHealthCheck TunInterfaceThread::status() const
{
    return { healthCheck(), threadNumber, threadId, pktsIn, bytesIn, lastPacket };
}

TunInterfaceThreadHealthCheck::TunInterfaceThreadHealthCheck(bool healthy, int threadNumber, int threadId, uint64_t pktsIn, uint64_t bytesIn,
                                                             std::chrono::steady_clock::time_point lastPacket) :
        healthy(healthy), threadNumber(threadNumber), threadId(threadId), pktsIn(pktsIn), bytesIn(bytesIn), lastPacket(lastPacket)
{
}

std::string TunInterfaceThreadHealthCheck::output_str() const
{
    return "Tunnel handler thread "s + std::to_string(threadNumber) + " (ID "s + std::to_string(threadId) + ")"s +
           (healthy ? ": Healthy, "s : ": NOT healthy, "s) +
           std::to_string(pktsIn) + " packets in from OS, "s + std::to_string(bytesIn) + " bytes in from OS, "s +
           timepointDeltaString(std::chrono::steady_clock::now(), lastPacket) + " since last packet.\n";
}

json TunInterfaceThreadHealthCheck::output_json() const
{
    // "valid" is always true; kept for tools that read it (it was false only for an unused thread slot).
    return { {"valid", true}, {"threadNumber", threadNumber}, {"threadId", threadId},
             {"healthy", healthy}, {"pktsIn", pktsIn}, {"bytesIn", bytesIn}, {"secsSinceLastPacket", timepointDeltaDouble(std::chrono::steady_clock::now(), lastPacket)} };
}

TunInterfaceHealthCheck::TunInterfaceHealthCheck(std::string devname, std::vector<TunInterfaceThreadHealthCheck> thcs) :
        devname(std::move(devname)), thcs(std::move(thcs))
{}

std::string TunInterfaceHealthCheck::output_str() const
{
    std::string ret = "Interface "s + devname + ":\n"s;
    for(const auto &t : thcs)
        ret += t.output_str();
    return ret + "\n"s;
}

json TunInterfaceHealthCheck::output_json() const
{
    json threads = json::array();
    for(const auto &t : thcs)
        threads.push_back(t.output_json());
    return { {"devname", devname}, {"threads", threads} };
}

/**
* TunSocket implementations - RAII wrapper for TUN file descriptors
*/


TunSocket::TunSocket(const std::string &devnameParam, bool exclusive, bool nonBlocking)
: devname(devnameParam), fd(open("/dev/net/tun", O_RDWR | O_CLOEXEC | (nonBlocking ? O_NONBLOCK : 0)))
{
    if(!fd)
        throw std::system_error(errno, std::generic_category(), "Unable to open /dev/net/tun");
    LOG(LS_OS, LL_DEBUG, "Opening TUN device for dev "s + devname + " and thread ID "s + ts(gettid()));

    // Set up a new multiqueue file handler to process our packets
    struct ifreq ifr;
    bzero(&ifr, sizeof(ifr));

    // Code adapted from Linux Documentation/networking/tuntap.txt to create the tun device.
    // IFF_TUN_EXCL makes the open that creates a device fail if one of that name already exists,
    // instead of silently adding a queue to it. Without it, a second gwlbtun (or anything else) using
    // the same name would share our device and steal packets from it. Only the first fd of each device
    // sets it; the rest of our own queues attach to the device that fd created.
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE | (exclusive ? IFF_TUN_EXCL : 0);
    strncpy(ifr.ifr_name, devname.c_str(), IFNAMSIZ - 1);

    if(ioctl(fd.get(), TUNSETIFF, (void *)&ifr) < 0)
    {
        const int err = errno;
        std::string msg = "Unable to create TUN device "s + devname;
        if(exclusive && err == EBUSY)
            msg += " (IFF_TUN_EXCL): a device with that name already exists - is this the only gwlbtun trying to use it?"s;
        else if(err == EPERM || err == EACCES)
            msg += " (does this process have the CAP_NET_ADMIN capability?)"s;
        throw std::system_error(err, std::generic_category(), msg);   // fd's destructor closes it
    }
}

TunSocket::~TunSocket()
{
    if(fd)
        LOG(LS_OS, LL_DEBUG, "Destroying TUN socket for devname "s + devname + " for thread ID "s + ts(gettid()));
}

bool TunSocket::detachQueue()
{
    struct ifreq ifr;
    bzero(&ifr, sizeof(ifr));
    ifr.ifr_flags = IFF_DETACH_QUEUE;
    if(ioctl(fd.get(), TUNSETQUEUE, (void *)&ifr) < 0)
    {
        const int err = errno;
        LOG(LS_OS, LL_IMPORTANT, "Unable to detach writer queue on "s + devname + ": "s + errText(err));
        return false;
    }
    return true;
}
