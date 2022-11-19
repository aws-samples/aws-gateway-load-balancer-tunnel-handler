// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * PacketHeaderV4 class serves to interpret and provide a hashing function for an IPv4 header, looking at similiar fields
 * to what GWLB does when producing a flow cookie.
 */

#include "PacketHeaderV4.h"

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <cstring>
#include <typeindex>

#include "utils.h"

/**
 * Parse an IP packet header.
 *
 * @param pktbuf IP packet header to parse
 * @param pktlen Length of the packet.
 */
PacketHeaderV4::PacketHeaderV4(unsigned char *pktbuf, ssize_t pktlen)
{
    struct ip *iph = (struct ip *)pktbuf;

    if(pktlen < sizeof(struct ip))
        throw std::invalid_argument("PacketHeaderV4 provided a packet too small to be an IPv4 packet.");

    if(iph->ip_v != 4)
        throw std::invalid_argument("PacketHeaderV4 provided a packet that isn't IPv4.");

    prot = iph->ip_p;
    src = be32toh(*(uint32_t *)&iph->ip_src);
    dst = be32toh(*(uint32_t *)&iph->ip_dst);
    switch(prot)
    {
        case IPPROTO_UDP:
        {
            if(pktlen < sizeof(struct ip) + sizeof(struct udphdr))
                throw std::invalid_argument("PacketHeaderV4 provided a packet with protocol=UDP, but too small to carry UDP information.");
            struct udphdr *udp = (struct udphdr *)(pktbuf + sizeof(struct ip));
            srcpt = be16toh(udp->uh_sport);
            dstpt = be16toh(udp->uh_dport);
            break;
        }
        case IPPROTO_TCP:
        {
            if(pktlen < sizeof(struct ip) + sizeof(struct tcphdr))
                throw std::invalid_argument("PacketHeaderV4 provided a packet with protocol=TCP, but too small to carry UDP information.");
            struct tcphdr *tcp = (struct tcphdr *)(pktbuf + sizeof(struct ip));
            srcpt = be16toh(tcp->th_sport);
            dstpt = be16toh(tcp->th_dport);
            break;
        }
        default:
        {
            srcpt = 0;
            dstpt = 0;
            break;
        }
    }
}

PacketHeaderV4::PacketHeaderV4(uint8_t prot, uint32_t src, uint32_t dst, uint16_t srcpt, uint16_t dstpt)
: src(src), dst(dst), srcpt(srcpt), dstpt(dstpt), prot(prot)
{
}

/***
 * Return a new packet header with the src/dst ips and ports swapped (i.e. this flow in the reverse direction)
 * @return A new PacketHeaderV4 object
 */
PacketHeaderV4 PacketHeaderV4::reverse() const
{
    return PacketHeaderV4(prot, dst, src, dstpt, srcpt);
}

/**
 * Compare if the headers in one packet match another. Meant to be used for the various sort and search functions.
 *
 * @param ph PacketHeaderV4 to compare againgst.
 * @return true if PacketHeaders are the same, false otherwise.
 */
bool PacketHeaderV4::operator==(const PacketHeaderV4 &ph) const
{
#ifdef HASH_IS_SYMMETRICAL
    return prot == ph.prot && ((src == ph.src && dst == ph.dst && srcpt == ph.srcpt && dstpt == ph.dstpt) ||
                               (src == ph.dst && dst == ph.src && srcpt == ph.dstpt && dstpt == ph.srcpt));
#else
    return prot == ph.prot && src == ph.src && dst == ph.dst && srcpt == ph.srcpt && dstpt == ph.dstpt;
#endif
}

/**
 * Returns a hash value based on the protocol data.
 *
 * @return Hash value.
 */
std::size_t PacketHeaderV4::hash() const
{
    return hashFunc(prot, (void *)&src, (void *)&dst, 4, srcpt, dstpt);
}

/**
 * Returns a string with the contents of the PacketHeaderV4 for human consumption.
 *
 * @return The string.
 */
std::string PacketHeaderV4::text() const
{
    std::string s = "PacketHeaderV4: ";

    s = s + stringFormat("SrcIP: %d.%d.%d.%d, DstIP: %d.%d.%d.%d",
                         (src & 0xFF000000) >> 24, (src & 0xFF0000) >> 16, (src & 0xFF00) >> 8, src & 0xFF,
                         (dst & 0xFF000000) >> 24, (dst & 0xFF0000) >> 16, (dst & 0xFF00) >> 8, dst & 0xFF);

    if(prot == IPPROTO_UDP)
        s = s + stringFormat("  Prot UDP, src pt %d, dst pt %d", srcpt, dstpt);
    else if(prot == IPPROTO_TCP)
        s = s + stringFormat("  Prot TCP, src pt %d, dst pt %d", srcpt, dstpt);
    else
        s = s + " Prot #" + std::to_string(prot);

    //s = s + stringFormat(", hash %x", hash());

    return s;
}

/**
 * Output the human-readable content to an output stream.
 * @param os Output stream to write to.
 * @param m The PacketHeaderV4 to output
 * @return The same output stream.
 */
std::ostream &operator<<(std::ostream &os, PacketHeaderV4 const &m)
{
    return os << m.text();
}

/**
 * Extend std::hash for PacketHeaderV4
 */
std::size_t std::hash<PacketHeaderV4>::operator()(const PacketHeaderV4& t) const
{
    return t.hash();
};
