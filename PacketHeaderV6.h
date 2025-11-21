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
#include "utils.h"

class PacketHeaderV6 {
public:
    PacketHeaderV6(unsigned char *pktbuf, ssize_t pktlen) __attribute__((hot));   // pktbuf points to the start of the IP header.
    
    bool operator==(const PacketHeaderV6 &ph) const
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
    std::size_t hash() const
    {
        return hashFunc(prot, (void *)&src, (void *)&dst, 16, srcpt, dstpt);
    }

    std::string text() const;

private:
    struct in6_addr src;
    struct in6_addr dst;
    uint32_t  flow;
    uint16_t  srcpt;
    uint16_t  dstpt;
    uint8_t   prot;
};

std::ostream &operator<<(std::ostream &os, PacketHeaderV6 const &m);

template<> struct std::hash<PacketHeaderV6>:unary_function<PacketHeaderV6, size_t> { 
    std::size_t operator()(const PacketHeaderV6& t) const
    {
        return t.hash();
    };
 };

inline std::size_t hash_value(const PacketHeaderV6& t) {
    return t.hash();
}

#endif //GWLBTUN_PACKETHEADERV6_H
