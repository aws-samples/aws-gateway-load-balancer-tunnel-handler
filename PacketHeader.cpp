// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * PacketHeader class serves to interpret and provide a hashing function for an IP header, looking at similiar fields
 * to what GWLB does when producing a flow cookie.
 */

#include "PacketHeader.h"

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "utils.h"

/**
 * Parse an IP packet header.
 *
 * @param pktbuf IP packet header to parse
 * @param pktlen Length of the packet.
 */
PacketHeader::PacketHeader(unsigned char *pktbuf, ssize_t pktlen)
{
    struct ip *iph = (struct ip *)pktbuf;

    if(pktlen < sizeof(struct ip))
        throw std::invalid_argument("PacketHeader provided a packet too small to be an IP packet.");
    prot = iph->ip_p;
    src = be32toh(*(uint32_t *)&iph->ip_src);
    dst = be32toh(*(uint32_t *)&iph->ip_dst);
    if(prot == 17)   // UDP
    {
        if(pktlen < sizeof(struct ip) + sizeof(struct udphdr))
            throw std::invalid_argument("PacketHeader provided a packet with protocol=UDP, but too small to carry UDP information.");
        struct udphdr *udp = (struct udphdr *)(pktbuf + sizeof(struct ip));
        srcpt = be16toh(udp->uh_sport);
        dstpt = be16toh(udp->uh_dport);
    }
    else if(prot == 6) // TCP
    {
        if(pktlen < sizeof(struct ip) + sizeof(struct tcphdr))
            throw std::invalid_argument("PacketHeader provided a packet with protocol=TCP, but too small to carry UDP information.");
        struct tcphdr *tcp = (struct tcphdr *)(pktbuf + sizeof(struct ip));
        srcpt = be16toh(tcp->th_sport);
        dstpt = be16toh(tcp->th_dport);
    }
    else
    {
        srcpt = 0;
        dstpt = 0;
    }
}

/**
 * Compare if the headers in one packet match another. Meant to be used for the various sort and search functions.
 *
 * @param ph PacketHeader to compare againgst.
 * @return true if PacketHeaders are the same, false otherwise.
 */
bool PacketHeader::operator==(const PacketHeader &ph) const
{
    // also allowing return traffic
    return prot == ph.prot &&
           ((src == ph.src && dst == ph.dst) || (src == ph.dst && dst == ph.src)) &&
           ((srcpt == ph.srcpt && dstpt == ph.dstpt) || (srcpt == ph.dstpt && dstpt == ph.srcpt));
}

/**
 * Returns a hash value based on the protocol data. Not a great hash at present, but works well enough.
 *
 * @return Hash value.
 */
std::size_t PacketHeader::hash() const
{
    return prot + src + dst + srcpt + dstpt;
}

/**
 * Returns a string with the contents of the PacketHeader for human consumption.
 *
 * @return The string.
 */
std::string PacketHeader::text() const
{
    std::string s = "PacketHeader: ";

    s = s + stringFormat("SrcIP: %d.%d.%d.%d, DstIP: %d.%d.%d.%d",
                         (src & 0xFF000000) >> 24, (src & 0xFF0000) >> 16, (src & 0xFF00) >> 8, src & 0xFF,
                         (dst & 0xFF000000) >> 24, (dst & 0xFF0000) >> 16, (dst & 0xFF00) >> 8, dst & 0xFF);

    if(prot == 17)
        s = s + stringFormat("  Prot UDP, src pt %d, dst pt %d", srcpt, dstpt);
    else if(prot == 6)
        s = s + stringFormat("  Prot TCP, src pt %d, dst pt %d", srcpt, dstpt);
    else
        s = s + " Prot #" + std::to_string(prot);

    s = s + stringFormat(", hash %x", hash());

    return s;
}

/**
 * Output the human-readable content to an output stream.
 * @param os Output stream to write to.
 * @param m The PacketHeader to output
 * @return The same output stream.
 */
std::ostream &operator<<(std::ostream &os, PacketHeader const &m)
{
    return os << m.text();
}

/**
 * Returns the hash of a PacketHeader.
 *
 * @param ph PacketHeader
 * @return Result of the PacketHeader::hash() function
 */
std::size_t PacketHeaderHash::operator()(const PacketHeader &ph) const
{
    return ph.hash();
}
