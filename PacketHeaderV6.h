// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
//
// Quick class to generate hashes of IPv6 packets for use in std::unordered_map
//

#ifndef GWLBTUN_PACKETHEADERV6_H
#define GWLBTUN_PACKETHEADERV6_H

#include <cinttypes>
#include <iostream>
#include <stdexcept>
#include <netinet/ip6.h>

class PacketHeaderV6 {
public:
    PacketHeaderV6(unsigned char *pktbuf, ssize_t pktlen);   // pktbuf points to the start of the IP header.
    bool operator==(const PacketHeaderV6 &) const;
    std::string text() const;
    std::size_t hash() const;
    PacketHeaderV6 reverse() const;   // Return a PH for the reverse flow direction (src/dst ips and ports swapped)

private:
    struct in6_addr src;
    struct in6_addr dst;
    uint32_t  flow;
    uint16_t  srcpt;
    uint16_t  dstpt;
    uint8_t   prot;

    PacketHeaderV6(uint8_t prot, uint32_t flow, struct in6_addr src, struct in6_addr dst, uint16_t srcpt, uint16_t dstpt);
};

std::ostream &operator<<(std::ostream &os, PacketHeaderV6 const &m);
template<> struct std::hash<PacketHeaderV6>:unary_function<PacketHeaderV6, size_t> { std::size_t operator()(const PacketHeaderV6& t) const; };

#endif //GWLBTUN_PACKETHEADERV6_H
