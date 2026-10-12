// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * PacketHeaderV6 class serves to interpret and provide a hashing function for an IPv6 header, looking at the fields
 * that identify a flow (protocol, addresses and ports).
 */

#include "PacketHeaderV6.h"

#include <netinet/ip6.h>
#include <arpa/inet.h>

using namespace std::string_literals;

/**
 * Parse an IP packet header.
 *
 * @param pktbuf IP packet header to parse
 * @param pktlen Length of the packet.
 */
PacketHeaderV6::PacketHeaderV6(const unsigned char *pktbuf, ssize_t pktlen)
{
    const struct ip6_hdr *iph6 = (const struct ip6_hdr *)pktbuf;

    if(__builtin_expect(pktlen < (ssize_t)sizeof(struct ip6_hdr), 0))
        throw std::invalid_argument("PacketHeaderV6 provided a packet too small to be an IPv6 packet.");

    if(__builtin_expect((pktbuf[0] >> 4) != 6, 0))
        throw std::invalid_argument("PacketHeaderV6 provided a packet that isn't IPv6.");

    // The first 4 bits are version, next 8 are traffic class. The last 20 (0xFFFFF) are the flow label.
    flow = be32toh_unaligned(pktbuf) & 0xFFFFF;
    memcpy(&src, &iph6->ip6_src, sizeof(struct in6_addr));
    memcpy(&dst, &iph6->ip6_dst, sizeof(struct in6_addr));
    prot = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    ssize_t offset = sizeof(struct ip6_hdr);
    bool noPorts = false;      // set for later fragments and headers we can't walk

    // Skip IPv6 extension headers to reach the upper-layer protocol, so that (for example) TCP
    // with a hop-by-hop or destination options header is still treated as TCP. All lengths come
    // from the packet, so each step is bounds-checked, and the walk is capped. Anything we can't
    // walk (ESP, unknown types, truncated headers) stops with the current protocol and no ports.
    for(int hops = 0; hops < 8; hops++)
    {
        if(prot != IPPROTO_HOPOPTS && prot != IPPROTO_ROUTING && prot != IPPROTO_DSTOPTS &&
           prot != IPPROTO_FRAGMENT && prot != IPPROTO_AH)
            break;
        if(pktlen < offset + 8)
        {
            noPorts = true;          // Truncated: no readable L4 header.
            break;
        }
        const uint8_t next = pktbuf[offset];
        ssize_t extlen;
        if(prot == IPPROTO_FRAGMENT)
        {
            extlen = 8;
            // Fragment offset is the top 13 bits of bytes 2-3; non-zero means not the first fragment.
            if((be16toh_unaligned(pktbuf + offset + 2) & 0xFFF8) != 0)
                noPorts = true;
        }
        else if(prot == IPPROTO_AH)
            extlen = ((ssize_t)pktbuf[offset + 1] + 2) * 4;
        else
            extlen = ((ssize_t)pktbuf[offset + 1] + 1) * 8;
        prot = next;
        offset += extlen;
    }

    // Most traffic is TCP or UDP - optimize for that
    if(__builtin_expect((prot == IPPROTO_UDP || prot == IPPROTO_TCP) && !noPorts, 1))
    {
        if(__builtin_expect(pktlen < offset + 4, 0))
            throw std::invalid_argument("PacketHeaderV6 provided a packet with protocol=TCP/UDP, but too small to carry port information.");

        // Ports are at same offset for both TCP and UDP
        srcpt = be16toh_unaligned(pktbuf + offset);
        dstpt = be16toh_unaligned(pktbuf + offset + 2);
    }
    else
    {
        srcpt = 0;
        dstpt = 0;
    }
}

/**
 * Returns a string with the contents of the PacketHeaderV6 for human consumption.
 *
 * @return The string.
 */
std::string PacketHeaderV6::text() const
{
    char srcip[INET6_ADDRSTRLEN], dstip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &src, srcip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &dst, dstip, INET6_ADDRSTRLEN);
    return "PacketHeaderV6: "s + stringFormat("SrcIP: %s, DstIP: %s, Flow: %x", srcip, dstip, flow) + flowL4Text(prot, srcpt, dstpt);
}
