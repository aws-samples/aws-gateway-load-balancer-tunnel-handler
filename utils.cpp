// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * Miscellaneous handy utilities.
 */

#include "utils.h"

#include <cstring>
#include <ctime>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string>
#include <algorithm>
#include <iostream>
#include "Logger.h"

using namespace std::string_literals;

/**
 * Perform a printf-like function, but on a std::string and returning a std::string
 *
 * @param fmt_str printf-like formatting string
 * @param ... Parameters for the fmt_str
 * @return A std::string of the formatted output
 */
std::string stringFormat(const std::string& fmt_str, ...) {
    va_list ap;

    va_start(ap, &fmt_str);
    std::string ret = stringFormat(fmt_str, ap);
    va_end(ap);

    return ret;
}

std::string stringFormat(const std::string& fmt_str, va_list ap)
{
    // Make a copy of the va_list since we need to use it multiple times
    va_list ap_copy;
    va_copy(ap_copy, ap);

    // Calculate the size needed for the formatted string
    int size = vsnprintf(nullptr, 0, fmt_str.c_str(), ap_copy);
    va_end(ap_copy);

    // Allocate the exact buffer size needed
    std::unique_ptr<char[]> formatted(new char[size + 1]);

    // Use the original va_list for the actual formatting
    vsnprintf(formatted.get(), size + 1, fmt_str.c_str(), ap);

    return std::string(formatted.get());
}

/**
 * Send a UDP packet, with control over the source and destination. We have to use a RAW socket for specifying the
 * source port and it changing constantly.
 *
 * @param sock Existing socket(AF_INET,SOCK_RAW, IPPROTO_RAW) to use for sending
 * @param from_addr IP address to send the packet from.
 * @param from_port UDP source port to use
 * @param to_addr IP address to send the packet to.
 * @param to_port UDP destination port
 * @param payload_iov Scatter-gather array of payload buffers
 * @param payload_iovcnt Number of entries in payload_iov
 * @return true if packet was sent successfully, false otherwise.
 */
bool sendUdpSG(int sock, struct in_addr from_addr, uint16_t from_port,
               struct in_addr to_addr, uint16_t to_port,
               const struct iovec *payload_iov, int payload_iovcnt)
{
    // Build headers on stack
    struct {
        struct iphdr ip;
        struct udphdr udp;
    } __attribute__((packed)) headers;

    // Calculate total payload length
    size_t total_payload = 0;
    for(int i = 0; i < payload_iovcnt; i++) {
        total_payload += payload_iov[i].iov_len;
    }

    headers.ip.version = 4;
    headers.ip.ihl = 5;
    headers.ip.tos = 0;
    headers.ip.tot_len = htons(sizeof(headers) + total_payload);
    headers.ip.id = 0;
    headers.ip.frag_off = 0;
    headers.ip.ttl = 2;
    headers.ip.protocol = IPPROTO_UDP;
    headers.ip.check = 0;
    headers.ip.saddr = from_addr.s_addr;
    headers.ip.daddr = to_addr.s_addr;

    headers.udp.source = htons(from_port);
    headers.udp.dest = htons(to_port);
    headers.udp.len = htons(sizeof(struct udphdr) + total_payload);
    headers.udp.check = 0;   // 0 = no UDP checksum (valid for IPv4). The kernel does not compute it for raw IP_HDRINCL sockets, so an unset field would ship stack garbage.

    // Build iovec array: headers + payload segments
    struct iovec iov[payload_iovcnt + 1];
    iov[0].iov_base = &headers;
    iov[0].iov_len = sizeof(headers);

    // Copy payload iovec entries
    for(int i = 0; i < payload_iovcnt; i++) {
        iov[i + 1] = payload_iov[i];
    }

    struct sockaddr_in to_zero_port;
    to_zero_port.sin_family = AF_INET;
    to_zero_port.sin_port = 0;
    to_zero_port.sin_addr.s_addr = to_addr.s_addr;

    struct msghdr msg = {};
    msg.msg_name = &to_zero_port;
    msg.msg_namelen = sizeof(to_zero_port);
    msg.msg_iov = iov;
    msg.msg_iovlen = payload_iovcnt + 1;

    if(sendmsg(sock, &msg, 0) < 0) {
        LOG(LS_UDP, LL_IMPORTANT, "Unable to send UDP packet: %s", strerror(errno));
        return false;
    }
    return true;
}

/**
 * Build the GWLB return-path outer encap into 'out': outer IPv4 + UDP (same header
 * layout and field values as sendUdpSG, including the intentional ttl=2) followed by
 * the GENEVE header verbatim. The IP tot_len/checksum and UDP length are left zero —
 * the egress BPF program fills them from the real packet length at send time.
 * Returns the number of bytes written, or 0 if the output buffer is too small.
 */
size_t buildGwlbEncapBlob(uint8_t *out, size_t outcap, struct in_addr fromAddr, uint16_t fromPort,
                          struct in_addr toAddr, uint16_t toPort,
                          const unsigned char *geneve, size_t genevelen)
{
    const size_t hdrlen = sizeof(struct iphdr) + sizeof(struct udphdr);  // 20 + 8
    if(outcap < hdrlen + genevelen)
        return 0;

    struct iphdr ip;
    memset(&ip, 0, sizeof(ip));
    ip.version = 4;
    ip.ihl = 5;
    ip.tos = 0;
    ip.tot_len = 0;          // filled by the egress program (skb->len)
    ip.id = 0;
    ip.frag_off = 0;
    ip.ttl = 2;              // intentional GWLB value, matches sendUdpSG
    ip.protocol = IPPROTO_UDP;
    ip.check = 0;            // filled by the egress program
    ip.saddr = fromAddr.s_addr;
    ip.daddr = toAddr.s_addr;

    struct udphdr udp;
    memset(&udp, 0, sizeof(udp));
    udp.source = htons(fromPort);
    udp.dest = htons(toPort);
    udp.len = 0;             // filled by the egress program
    udp.check = 0;

    memcpy(out, &ip, sizeof(ip));
    memcpy(out + sizeof(ip), &udp, sizeof(udp));
    memcpy(out + hdrlen, geneve, genevelen);
    return hdrlen + genevelen;
}

const std::string base60 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
/**
 * Convert a 64 bit number to base60 notation. Note: With a uint64_t, the maximum return from this is "uur953OEv0f".
 *
 * @param val The value to convert
 * @return The value represented as base60
 */
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

    if (delta > 86400000) { ret += std::to_string((long)delta / 86400000) + "d "s; delta = delta % 86400000; }
    if (delta > 3600000) { ret += std::to_string((long)delta / 3600000) + "h"s; delta = delta % 3600000; }
    if (delta > 60000) { ret += std::to_string((long)delta / 60000) + "m"s; delta = delta % 60000; }
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
 * Parse input parameters of thread count and core configuration, and populate the ThreadConfig. A thread configuration
 * string is a comma-separated list of cores or ranges, i.e. 1,2,4-6,8.
 *
 * @param threadcount Number of threads requested on command line, if provided,  0 if not. Defaults to 1, if needed.
 * @param affinity The thread affinity string requested on command line.
 * @param dest
 * @return None, but raises exceptions on error (generally a threadcfg that doesn't make sense)
 */
void ParseThreadConfiguration(int threadcount, std::string& affinity, ThreadConfig *dest)
{
    // Handle case when the detailed thread configuration wasn't passed, and we just want some threads.
    if(affinity.empty())
    {
        if(threadcount == 0)
            dest->cfg.resize(1, -1);
        else
            dest->cfg.resize(threadcount, -1);
    } else {
        // Parse the threadcfg string.
        dest->cfg.resize(0);
        size_t pos = 0;
        while(pos < affinity.length())
        {
            // Find next comma if any, pull out substring.
            size_t comma_pos = affinity.find(",",pos);
            if(comma_pos == std::string::npos)
                comma_pos = affinity.length();
            std::string range = affinity.substr(pos, comma_pos - pos);
            // Is this a range?
            size_t dash_pos = range.find("-");
            if(dash_pos == std::string::npos)
            {
                // Nope, just a bare number.
                dest->cfg.push_back(std::stoi(range));
            } else {
                int start = std::stoi(range.substr(0, dash_pos));
                int end = std::stoi(range.substr(dash_pos + 1));
                for(int i = start ; i <= end ; i ++)
                {
                    dest->cfg.push_back(i);
                }
            }
            // Move up.
            pos = comma_pos + 1;
        }
    }
    // Do some checks.
    if(dest->cfg.size() > MAX_THREADS)
        throw std::length_error("The number of threads specified ("s + std::to_string(dest->cfg.size()) + ") exceeds the maximum allowed ("s + std::to_string(MAX_THREADS) + "). Recompile code and increase MAX_THREADS in utils.h if you need more."s);

    // We will check the ability to set affinity at set time.
}

/**
 * Convert a GWLB endpoint id to its hex string. Rendered as 17-char zero-padded
 * hex, matching the "vpce-" endpoint id as shown in the AWS console.
 * @param eni
 * @return
 */
std::string MakeGwlbeStr(gwlbeid_t eni)
{
    std::stringstream ss;

    ss << std::hex << std::setw(17) << std::setfill('0') << eni << std::dec;
    return ss.str();
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
