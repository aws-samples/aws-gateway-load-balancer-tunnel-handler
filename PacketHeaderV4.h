// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
//
// Quick class to generate hashes of IPv4 packets for use in std::unordered_map
//

#ifndef GWLBTUN_PACKETHEADERV4_H
#define GWLBTUN_PACKETHEADERV4_H

#include <cinttypes>
#include <iostream>
#include <stdexcept>
#include <netinet/ip6.h>

class PacketHeaderV4 {
public:
    PacketHeaderV4(unsigned char *pktbuf, ssize_t pktlen);   // pktbuf points to the start of the IP header.
    bool operator==(const PacketHeaderV4 &) const;
    std::string text() const;
    std::size_t hash() const;
    PacketHeaderV4 reverse() const;   // Return a PH for the reverse flow direction (src/dst ips and ports swapped)

private:
    uint32_t  src;
    uint32_t  dst;
    uint16_t  srcpt;
    uint16_t  dstpt;
    uint8_t   prot;

    PacketHeaderV4(uint8_t prot, uint32_t src, uint32_t dst, uint16_t srcpt, uint16_t dstpt);
};

std::ostream &operator<<(std::ostream &os, PacketHeaderV4 const &m);
template<> struct std::hash<PacketHeaderV4>:unary_function<PacketHeaderV4, size_t> { std::size_t operator()(const PacketHeaderV4& t) const; };

#endif //GWLBTUN_PACKETHEADERV4_H
