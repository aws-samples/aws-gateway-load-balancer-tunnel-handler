// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * PacketHeaderV4 class serves to interpret and provide a hashing function for an IPv4 header, looking at the fields
 * that identify a flow (protocol, addresses and ports).
 */

#include "PacketHeaderV4.h"

#include <netinet/ip.h>

using namespace std::string_literals;

/**
 * Parse an IP packet header.
 *
 * @param pktbuf IP packet header to parse
 * @param pktlen Length of the packet.
 */
PacketHeaderV4::PacketHeaderV4(const unsigned char *pktbuf, ssize_t pktlen)
{
    const struct ip *iph = (const struct ip *)pktbuf;

    if(__builtin_expect(pktlen < (ssize_t)sizeof(struct ip), 0))
        throw std::invalid_argument("PacketHeaderV4 provided a packet too small to be an IPv4 packet.");

    if(__builtin_expect(iph->ip_v != 4, 0))
        throw std::invalid_argument("PacketHeaderV4 provided a packet that isn't IPv4.");

    prot = iph->ip_p;
    src = be32toh_unaligned(&iph->ip_src);
    dst = be32toh_unaligned(&iph->ip_dst);

    // The header length comes from the packet, so check it before trusting it. Packets with IP
    // options have a header longer than 20 bytes, and the ports start after the options.
    const ssize_t hdrlen = (ssize_t)iph->ip_hl * 4;
    if(__builtin_expect(hdrlen < (ssize_t)sizeof(struct ip) || hdrlen > pktlen, 0))
        throw std::invalid_argument("PacketHeaderV4 provided a packet with an invalid header length.");

    // Only the first fragment of a fragmented packet carries the TCP/UDP header. Later fragments
    // start mid-payload, so they get ports 0 instead of whatever payload bytes sit at that offset.
    const bool laterFragment = (be16toh_unaligned(&iph->ip_off) & IP_OFFMASK) != 0;

    // Most traffic is TCP or UDP - optimize for that
    if(__builtin_expect((prot == IPPROTO_UDP || prot == IPPROTO_TCP) && !laterFragment, 1))
    {
        if(__builtin_expect(pktlen < hdrlen + 4, 0))
            throw std::invalid_argument("PacketHeaderV4 provided a packet with protocol=TCP/UDP, but too small to carry port information.");

        // Ports are at same offset for both TCP and UDP
        srcpt = be16toh_unaligned(pktbuf + hdrlen);
        dstpt = be16toh_unaligned(pktbuf + hdrlen + 2);
    }
    else
    {
        srcpt = 0;
        dstpt = 0;
    }
}

/**
 * Returns a string with the contents of the PacketHeaderV4 for human consumption.
 *
 * @return The string.
 */
std::string PacketHeaderV4::text() const
{
    return "PacketHeaderV4: "s +
           stringFormat("SrcIP: %u.%u.%u.%u, DstIP: %u.%u.%u.%u",
                        (src >> 24) & 0xFF, (src >> 16) & 0xFF, (src >> 8) & 0xFF, src & 0xFF,
                        (dst >> 24) & 0xFF, (dst >> 16) & 0xFF, (dst >> 8) & 0xFF, dst & 0xFF) +
           flowL4Text(prot, srcpt, dstpt);
}
