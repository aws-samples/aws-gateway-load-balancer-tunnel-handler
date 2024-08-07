// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * Miscellaneous handy utilities.
 */

#include "utils.h"

#include <cstring>
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
    int final_n, n = ((int)fmt_str.size()) * 2; /* Reserve two times as much as the length of the fmt_str */
    std::unique_ptr<char[]> formatted;
    while(true) {
        formatted.reset(new char[n]); /* Wrap the plain char array into the unique_ptr */
        strcpy(&formatted[0], fmt_str.c_str());
        final_n = vsnprintf(&formatted[0], n, fmt_str.c_str(), ap);
        if (final_n < 0 || final_n >= n)
            n += abs(final_n - n + 1);
        else
            break;
    }
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
 * @param pktBuf Payload buffer pointer
 * @param pktLen Payload buffer length
 * @return true if packet was sent successfully, false otherwise.
 */
bool sendUdp(int sock, struct in_addr from_addr, uint16_t from_port, struct in_addr to_addr, uint16_t to_port, unsigned char *pktBuf, ssize_t pktLen)
{
    // Build the IP header
    uint8_t packet_buffer[16000];
    struct iphdr *iph;
    struct udphdr *udph;
    iph = (struct iphdr *)&packet_buffer[0];
    udph = (struct udphdr *)&packet_buffer[sizeof(struct iphdr)];
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + pktLen);
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 2;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = from_addr.s_addr;
    iph->daddr = to_addr.s_addr;

    udph->source = htons(from_port);
    udph->dest = htons(to_port);
    udph->len = htons(sizeof(struct udphdr) + pktLen);

    memcpy(&packet_buffer[sizeof(struct iphdr) + sizeof(struct udphdr)], pktBuf, pktLen);

    // Linux will return an EINVAL if we have an addr with a non-zero sin_port.
    struct sockaddr_in to_zero_port;
    to_zero_port.sin_family = AF_INET;
    to_zero_port.sin_port = 0;
    to_zero_port.sin_addr.s_addr = to_addr.s_addr;

    if(sendto(sock, packet_buffer, sizeof(struct iphdr) + sizeof(struct udphdr) + pktLen, 0, (struct sockaddr *)&to_zero_port, sizeof(to_zero_port)) < 0)
    {
        LOG(LS_UDP, LL_IMPORTANT, "Unable to send UDP packet. Parameters were %d, %p, %d, %d, %d, %d", sock, packet_buffer, sizeof(struct iphdr) + sizeof(struct udphdr) + pktLen, 0, (struct sockaddr *)&to_addr, sizeof(to_addr));
        LOGHEXDUMP(LS_UDP, LL_IMPORTANT, "UDP packet buffer", packet_buffer, sizeof(struct iphdr) + sizeof(struct udphdr) + pktLen);
        return false;
    }

    return true;
}

const std::string base60 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
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
 * Convert an eniid_t to a hex string
 * @param eni
 * @return
 */
std::string MakeENIStr(eniid_t eni)
{
    std::stringstream ss;

    ss << std::hex << std::setw(17) << std::setfill('0') << eni << std::dec;
    return ss.str();
}

