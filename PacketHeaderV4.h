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
#include <typeindex>
#include "utils.h"

class PacketHeaderV4 {
public:
    PacketHeaderV4(unsigned char *pktbuf, ssize_t pktlen) __attribute__((hot));   // pktbuf points to the start of the IP header.
    std::string text() const;

    /**
    * Compare if the headers in one packet match another. Meant to be used for the various sort and search functions.
    *
    * @param ph PacketHeaderV4 to compare againgst.
    * @return true if PacketHeaders are the same, false otherwise.
    */
    bool operator==(const PacketHeaderV4 &ph) const
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
    std::size_t hash() const
    {
        return hashFunc(prot, (void *)&src, (void *)&dst, 4, srcpt, dstpt);
    }

private:
    uint32_t  src;
    uint32_t  dst;
    uint16_t  srcpt;
    uint16_t  dstpt;
    uint8_t   prot;
};

std::ostream &operator<<(std::ostream &os, PacketHeaderV4 const &m);

template<> struct std::hash<PacketHeaderV4> {
    std::size_t operator()(const PacketHeaderV4& t) const
    {
        return t.hash();
    };
};

/**
 * Extend std::hash for PacketHeaderV4
 */
inline std::size_t hash_value(const PacketHeaderV4& t)
{
    return t.hash();
}

#endif //GWLBTUN_PACKETHEADERV4_H
