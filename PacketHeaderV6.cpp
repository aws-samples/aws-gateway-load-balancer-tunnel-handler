// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * PacketHeaderV4 class serves to interpret and provide a hashing function for an IPv6 header, looking at similiar fields
 * to what GWLB does when producing a flow cookie.
 */

#include "PacketHeaderV6.h"

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <cstring>
#include <typeindex>

#include "utils.h"
using namespace std::string_literals;

/**
 * Parse an IP packet header.
 *
 * @param pktbuf IP packet header to parse
 * @param pktlen Length of the packet.
 */
PacketHeaderV6::PacketHeaderV6(unsigned char *pktbuf, ssize_t pktlen)
{
    struct ip6_hdr *iph6 = (struct ip6_hdr *)pktbuf;

    if(pktlen < sizeof(struct ip6_hdr))
        throw std::invalid_argument("PacketHeaderV6 provided a packet too small to be an IPv6 packet.");

    if( ((iph6->ip6_ctlun.ip6_un2_vfc & 0xF0) >> 4) != 6)

        throw std::invalid_argument("PacketHeaderV6 provided a packet that isn't IPv6 : "s + std::to_string(iph6->ip6_ctlun.ip6_un2_vfc) + " -- "s + std::to_string(iph6->ip6_ctlun.ip6_un2_vfc >> 4) + " at offset "s + std::to_string(
                offsetof(struct ip6_hdr, ip6_ctlun.ip6_un2_vfc)));

    // The first 4 bits are version, next 8 are traffic class. The last 20 (0xFFFFF) are the flow label.
    flow = be32toh(iph6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0xFFFFF;
    memcpy(&src, &iph6->ip6_src, sizeof(struct in6_addr));
    memcpy(&dst, &iph6->ip6_dst, sizeof(struct in6_addr));
    prot = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    switch(prot)
    {
        case IPPROTO_UDP:
        {
            if(pktlen < sizeof(struct ip6_hdr) + sizeof(struct udphdr))
                throw std::invalid_argument("PacketHeaderV6 provided a packet with protocol=UDP, but too small to carry UDP information.");
            struct udphdr *udp = (struct udphdr *)(pktbuf + sizeof(struct ip6_hdr));
            srcpt = be16toh(udp->uh_sport);
            dstpt = be16toh(udp->uh_dport);
            break;
        }
        case IPPROTO_TCP:
        {
            if(pktlen < sizeof(struct ip6_hdr) + sizeof(struct tcphdr))
                throw std::invalid_argument("PacketHeaderV6 provided a packet with protocol=TCP, but too small to carry UDP information.");
            struct tcphdr *tcp = (struct tcphdr *)(pktbuf + sizeof(struct ip6_hdr));
            srcpt = be16toh(tcp->th_sport);
            dstpt = be16toh(tcp->th_dport);
            break;
        }
        default:
            srcpt = 0;
            dstpt = 0;
            break;
    }
}

PacketHeaderV6::PacketHeaderV6(uint8_t prot, uint32_t flow, struct in6_addr src, struct in6_addr dst, uint16_t srcpt, uint16_t dstpt)
        : src(src), dst(dst), flow(flow), srcpt(srcpt), dstpt(dstpt), prot(prot)
{
}

/***
 * Return a new packet header with the src/dst ips and ports swapped (i.e. this flow in the reverse direction)
 * @return A new PacketHeaderV4 object
 */
PacketHeaderV6 PacketHeaderV6::reverse() const
{
    return PacketHeaderV6(prot, flow, dst, src, dstpt, srcpt);
}

/**
 * Compare if the headers in one packet match another. Meant to be used for the various sort and search functions.
 *
 * @param ph PacketHeaderV4 to compare againgst.
 * @return true if PacketHeaders are the same, false otherwise.
 */
bool PacketHeaderV6::operator==(const PacketHeaderV6 &ph) const
{
#ifdef HASH_IS_SYMMETRICAL
    return prot == ph.prot &&
           ((srcpt == ph.srcpt && dstpt == ph.dstpt && !memcmp(&src, &ph.src, sizeof(struct in6_addr)) && !memcmp(&dst, &ph.dst, sizeof(struct in6_addr))) ||
            (srcpt == ph.dstpt && dstpt == ph.srcpt && !memcmp(&src, &ph.dst, sizeof(struct in6_addr)) && !memcmp(&dst, &ph.src, sizeof(struct in6_addr))));
#else
    return prot == ph.prot &&  srcpt == ph.srcpt && dstpt == ph.dstpt &&
        !memcmp(&src, &ph.src, sizeof(struct in6_addr)) && !memcmp(&dst, &ph.dst, sizeof(struct in6_addr));
#endif
}

/**
 * Returns a hash value based on the protocol data.
 *
 * @return Hash value.
 */
std::size_t PacketHeaderV6::hash() const
{
    return hashFunc(prot, (void *)&src, (void *)&dst, 16, srcpt, dstpt);
}

/**
 * Returns a string with the contents of the PacketHeaderV4 for human consumption.
 *
 * @return The string.
 */
std::string PacketHeaderV6::text() const
{
    std::string s = "PacketHeaderV6: ";

    char srcip[INET6_ADDRSTRLEN], dstip[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &src, srcip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &dst, dstip, INET6_ADDRSTRLEN);

    s = s + stringFormat("SrcIP: %s, DstIP: %s, Flow: %x", srcip, dstip, flow);

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
std::ostream &operator<<(std::ostream &os, PacketHeaderV6 const &m)
{
    return os << m.text();
}

/**
 * Extend std::hash for PacketHeaderV6
 */
std::size_t std::hash<PacketHeaderV6>::operator()(const PacketHeaderV6& t) const
{
    return t.hash();
};
