// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * Miscellaneous handy utilities.
 */

#include "utils.h"

#include <cstring>
#include <sched.h>
#include <pthread.h>
#include <cerrno>
#include <stdexcept>
#include <ctime>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string>
#include <algorithm>
#include <iostream>
#include <cstdlib>
#include <sstream>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <poll.h>
#include <system_error>
#include <unistd.h>
#include <cinttypes>
#include "Logger.h"

using namespace std::string_literals;

/**
 * Perform a printf-like function, but on a std::string and returning a std::string
 *
 * @param fmt_str printf-like formatting string
 * @param ... Parameters for the fmt_str
 * @return A std::string of the formatted output
 */
std::string stringFormat(const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    std::string ret = stringFormat(fmt, ap);
    va_end(ap);

    return ret;
}

std::string stringFormat(const char *fmt, va_list ap)
{
    // Measure with a copy of the va_list (it can only be walked once), then format straight into the string.
    va_list measure;
    va_copy(measure, ap);
    const int size = vsnprintf(nullptr, 0, fmt, measure);
    va_end(measure);
    if(size < 0)
        return std::string();
    std::string s((size_t)size + 1, '\0');
    vsnprintf(s.data(), s.size(), fmt, ap);
    s.resize((size_t)size);
    return s;
}

std::string flowL4Text(uint8_t prot, uint16_t srcpt, uint16_t dstpt)
{
    if(prot == IPPROTO_UDP || prot == IPPROTO_TCP)
        return stringFormat("  Prot %s, src pt %u, dst pt %u", prot == IPPROTO_UDP ? "UDP" : "TCP", srcpt, dstpt);
    return "  Prot #"s + std::to_string(prot);
}

/**
 * Send a UDP packet, with control over the source and destination. We have to use a RAW socket for specifying the
 * source port and it changing constantly.
 *
 * @param sock Existing socket(AF_INET,SOCK_RAW, IPPROTO_RAW) to use for sending
 * @param from IP address to send the packet from.
 * @param fport UDP source port to use
 * @param to IP address to send the packet to.
 * @param tport UDP destination port
 * @param hdr, hdrLen The GENEVE header
 * @param pkt, pktLen The packet it encapsulates
 * @param ifindex Interface to send out of (the flow's ingress interface); 0 = let routing choose.
 * @return true if packet was sent successfully, false otherwise.
 */
bool sendUdpSG(int sock, struct in_addr from, uint16_t fport, struct in_addr to, uint16_t tport,
               const void *hdr, size_t hdrLen, const void *pkt, size_t pktLen, int ifindex)
{
    struct {
        struct iphdr ip;
        struct udphdr udp;
    } __attribute__((packed)) headers;

    // The IP and UDP length fields are 16 bits. A packet this large couldn't leave the instance anyway (the
    // send would fail with EMSGSIZE), but don't let the lengths wrap.
    const size_t payload = hdrLen + pktLen;
    if(payload > 65535 - sizeof(headers))
        return false;

    headers.ip.version = 4;
    headers.ip.ihl = 5;
    headers.ip.tos = 0;
    headers.ip.tot_len = htons((uint16_t)(sizeof(headers) + payload));
    // Don't Fragment, which makes each packet an "atomic datagram" (RFC 6864): its ID field carries no
    // meaning, so the kernel leaves it 0. Without DF, Linux gives every raw IP_HDRINCL packet whose ID is 0 an ID
    // from a hash table keyed by source, destination and protocol, so all tunnel threads sending to the same
    // GWLB address update one shared counter per packet (measured: 3-13% of all CPU on a c8in.96xlarge at
    // 12-14M pps). These packets were never fragmented anyway: the kernel rejects raw IP_HDRINCL sends larger
    // than the interface MTU (EMSGSIZE) rather than fragmenting them.
    headers.ip.id = 0;
    headers.ip.frag_off = htons(IP_DF);
    headers.ip.ttl = 2;
    headers.ip.protocol = IPPROTO_UDP;
    headers.ip.check = 0;
    headers.ip.saddr = from.s_addr;
    headers.ip.daddr = to.s_addr;

    headers.udp.source = htons(fport);
    headers.udp.dest = htons(tport);
    headers.udp.len = htons((uint16_t)(sizeof(struct udphdr) + payload));
    headers.udp.check = 0;   // 0 = no UDP checksum (valid for IPv4). The kernel does not compute it for raw IP_HDRINCL sockets, so an unset field would ship stack garbage.

    struct iovec iov[3] = { { &headers, sizeof(headers) }, { const_cast<void *>(hdr), hdrLen }, { const_cast<void *>(pkt), pktLen } };

    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_addr = to;

    struct msghdr msg = {};
    msg.msg_name = &dest;
    msg.msg_namelen = sizeof(dest);
    msg.msg_iov = iov;
    msg.msg_iovlen = 3;

    // Send out of the interface the flow arrived on, from the address it arrived at. Without this the
    // kernel picks the output interface by destination alone, so on an instance with several ENIs a
    // reply could leave by a different ENI than the one whose address is in the IP header, and in our tests
    // such replies were dropped (source/destination checking on). IP_PKTINFO sets the route lookup's output interface and source
    // address (the latter also lets per-ENI source policy routing match).
    union {
        char buf[CMSG_SPACE(sizeof(struct in_pktinfo))];
        struct cmsghdr align;
    } control;
    if(ifindex > 0)
    {
        memset(&control, 0, sizeof(control));
        msg.msg_control = control.buf;
        msg.msg_controllen = sizeof(control.buf);
        struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
        cm->cmsg_level = IPPROTO_IP;
        cm->cmsg_type = IP_PKTINFO;
        cm->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
        auto pi = (struct in_pktinfo *)CMSG_DATA(cm);
        pi->ipi_ifindex = ifindex;
        pi->ipi_spec_dst = from;
    }

    if(sendmsg(sock, &msg, 0) < 0) {
        // Per packet on the return path, so a persistent failure (for example ENOBUFS) is logged on the first
        // occurrence and then every 4096th.
        const int err = errno;
        static std::atomic<uint64_t> failures{0};
        const uint64_t n = failures.fetch_add(1, std::memory_order_relaxed);
        if((n & 0xFFF) == 0)
            LOG(LS_UDP, LL_IMPORTANT, "Unable to send UDP packet to GWLB: "s + errText(err) + " (failures so far: "s + std::to_string(n + 1) +
                ", logging the first and every 4096th)."s);
        return false;
    }
    return true;
}

static constexpr char base60[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
/**
 * Convert a 64 bit number to base60 notation. Note: With a uint64_t, the maximum return from this is "uur953OEv0f".
 *
 * @param val The value to convert
 * @return The value represented as base60
 */
std::string toBase60(uint64_t val)
{
    std::string ret;
    while(val >= 60)
    {
        ret.insert(0, 1, base60[val % 60]);
        val = val / 60;
    }
    ret = base60[val] + ret;
    return ret;
}

/**
 * Convert the time between two time_points to a human-readable short form duration.
 *
 * @param t1 The earlier timepoint
 * @param t2 The later timepoint
 * @return Human-readable (hours, minutes, seconds, etc) duration between the two time_points.
 */
std::string timepointDeltaString(std::chrono::steady_clock::time_point t1, std::chrono::steady_clock::time_point t2)
{
    char tbuf[32];
    long delta = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t2).count();
    std::string ret;

    if (delta >= 86400000) { ret += std::to_string(delta / 86400000) + "d "s; delta = delta % 86400000; }
    if (delta >= 3600000) { ret += std::to_string(delta / 3600000) + "h"s; delta = delta % 3600000; }
    if (delta >= 60000) { ret += std::to_string(delta / 60000) + "m"s; delta = delta % 60000; }
    snprintf(tbuf, 31, "%.3f", float(delta / 1000.0));
    ret += tbuf + "s"s;

    return ret;
}

double timepointDeltaDouble(std::chrono::steady_clock::time_point t1, std::chrono::steady_clock::time_point t2)
{
    return (double)(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t2).count()) / 1000.0;
}

/**
 * Convert a sockaddr to a human-readable value. Supports both IPv4 and IPv6.
 *
 * @param sa The sockaddr structure to parse
 * @return The human-readable IP address the sockaddr represents.
 */
std::string sockaddrToName(struct sockaddr *sa)
{
    char tbuf[256];
    if(sa->sa_family == AF_INET)
        inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, tbuf, 256);
    else if(sa->sa_family == AF_INET6)
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr, tbuf, 256);
    else
        strcpy(tbuf, "Unknown address family");

    return std::string(tbuf);
}

/**
 * Convert a GWLB endpoint id to its hex string. Rendered as 17-char zero-padded
 * hex, matching the "vpce-" endpoint id as shown in the AWS console.
 * @param eni
 * @return
 */
std::string MakeGwlbeStr(gwlbeid_t eni)
{
    return stringFormat("%017" PRIx64, (uint64_t)eni);
}





static int g_rawSndBufBytes = DEFAULT_SNDBUF_MB * 1024 * 1024;

int setCurrentThreadAffinity(int core)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    if(core >= 0)
        CPU_SET(core, &set);
    else if(sched_getaffinity(getpid(), sizeof(set), &set) != 0)   // the main thread's mask; gwlbtun never pins it
        return errno;
    return pthread_setaffinity_np(pthread_self(), sizeof(set), &set);   // returns the error; doesn't set errno
}

void setRawSendBufferSize(int megabytes)
{
    g_rawSndBufBytes = megabytes * 1024 * 1024;
}

/**
 * Set a raw send socket's send buffer. A full buffer makes the sending tunnel thread wait, which on busy
 * hosts was the largest cost on the return path. SO_SNDBUFFORCE (gwlbtun has CAP_NET_ADMIN) isn't capped
 * by net.core.wmem_max; plain SO_SNDBUF is the fallback. The kernel doubles the value for its overhead.
 */
static void applyRawSendBuffer(int sock)
{
    const int sndbuf = g_rawSndBufBytes;
    if(sndbuf > 0 && setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf)) < 0)
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
}

// A raw send socket with the --sndbuf buffer, or an empty UniqueFd (errno set) if socket() fails.
static UniqueFd tryOpenRawSendSocket()
{
    UniqueFd sock(socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW));
    if(sock)
        applyRawSendBuffer(sock.get());
    return sock;
}

UniqueFd openRawSendSocket()
{
    UniqueFd sock = tryOpenRawSendSocket();
    if(!sock)
        throw std::system_error(errno, std::generic_category(), "Unable to open a raw socket for sending traffic to GWLB");
    return sock;
}

EventFd::EventFd() : fd(eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC))
{
    if(!fd)
        throw std::system_error(errno, std::generic_category(), "Unable to create an eventfd");
}

void EventFd::signal() const noexcept
{
    const int savedErrno = errno;   // may be called from a signal handler
    uint64_t one = 1;
    // Can only fail with EAGAIN if the counter would overflow (2^64 - 2 signals): it's readable either way.
    [[maybe_unused]] ssize_t r = ::write(fd.get(), &one, sizeof(one));
    errno = savedErrno;
}

bool EventFd::waitFor(int ms) const noexcept
{
    struct pollfd pfd{ fd.get(), POLLIN, 0 };
    int r;
    while((r = poll(&pfd, 1, ms)) < 0 && errno == EINTR)
        ;
    return r > 0;
}

ThreadRawSendSocket::ThreadRawSendSocket() : fd(tryOpenRawSendSocket())
{
    if(!fd)
    {
        const int err = errno;
        LOG(LS_TUNNEL, LL_IMPORTANT, "Unable to open a per-thread raw send socket ("s + errText(err) +
            "); this thread uses the endpoint's shared socket."s);
        return;
    }
    t_rawSendSock = fd.get();
}

ThreadRawSendSocket::~ThreadRawSendSocket()
{
    t_rawSendSock = -1;
}

// --- Coarse monotonic clock (see utils.h) -----------------------------------
std::atomic<uint32_t> g_coarseSec{0};
static struct timespec g_coarseStart;

// CLOCK_BOOTTIME keeps advancing while the system is suspended; fall back to
// CLOCK_MONOTONIC where it isn't available.
#ifdef CLOCK_BOOTTIME
static const clockid_t g_coarseClockId = CLOCK_BOOTTIME;
#else
static const clockid_t g_coarseClockId = CLOCK_MONOTONIC;
#endif

void initCoarseClock()
{
    clock_gettime(g_coarseClockId, &g_coarseStart);
    g_coarseSec.store(0, std::memory_order_relaxed);
}

void updateCoarseClock()
{
    struct timespec now;
    clock_gettime(g_coarseClockId, &now);
    g_coarseSec.store((uint32_t)(now.tv_sec - g_coarseStart.tv_sec), std::memory_order_relaxed);
}
