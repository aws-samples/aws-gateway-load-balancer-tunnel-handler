/*
 * Copyright Amazon.com, Inc. or its affiliates. This material is AWS Content under the AWS Enterprise Agreement 
 * or AWS Customer Agreement (as applicable) and is provided under the AWS Intellectual Property License.
 */
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


/**
 * Parse an IP packet header.
 *
 * @param pktbuf IP packet header to parse
 * @param pktlen Length of the packet.
 */
PacketHeaderV4::PacketHeaderV4(unsigned char *pktbuf, ssize_t pktlen)
{
    struct ip *iph = (struct ip *)pktbuf;

    if(__builtin_expect(pktlen < (ssize_t)sizeof(struct ip), 0))
        throw std::invalid_argument("PacketHeaderV4 provided a packet too small to be an IPv4 packet.");

    if(__builtin_expect(iph->ip_v != 4, 0))
        throw std::invalid_argument("PacketHeaderV4 provided a packet that isn't IPv4.");

    prot = iph->ip_p;
    src = be32toh(*(uint32_t *)&iph->ip_src);
    dst = be32toh(*(uint32_t *)&iph->ip_dst);
    
    // Most traffic is TCP or UDP - optimize for that
    if(__builtin_expect(prot == IPPROTO_UDP || prot == IPPROTO_TCP, 1))
    {
        if(__builtin_expect(pktlen < (ssize_t)(sizeof(struct ip) + 4), 0))
            throw std::invalid_argument("PacketHeaderV4 provided a packet with protocol=TCP/UDP, but too small to carry port information.");
        
        // Ports are at same offset for both TCP and UDP
        uint16_t *ports = (uint16_t *)(pktbuf + sizeof(struct ip));
        srcpt = be16toh(ports[0]);
        dstpt = be16toh(ports[1]);
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
