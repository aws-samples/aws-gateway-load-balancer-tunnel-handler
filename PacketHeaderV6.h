// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWLBTUN_PACKETHEADERV6_H
#define GWLBTUN_PACKETHEADERV6_H

#include <cinttypes>
#include <cstring>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <netinet/in.h>
#include "utils.h"

class PacketHeaderV6 {
public:
    // pktbuf points to the start of the IP header. Throws std::invalid_argument for a malformed header.
    PacketHeaderV6(const unsigned char *pktbuf, ssize_t pktlen) __attribute__((hot));
    std::string text() const;

    // Bidirectional: a flow and its reverse compare equal (depends on the symmetric hash invariant in utils.h).
    bool operator==(const PacketHeaderV6 &ph) const
    {
        return prot == ph.prot &&
            ((srcpt == ph.srcpt && dstpt == ph.dstpt && !memcmp(&src, &ph.src, sizeof(struct in6_addr)) && !memcmp(&dst, &ph.dst, sizeof(struct in6_addr))) ||
             (srcpt == ph.dstpt && dstpt == ph.srcpt && !memcmp(&src, &ph.dst, sizeof(struct in6_addr)) && !memcmp(&dst, &ph.src, sizeof(struct in6_addr))));
    }

    std::size_t hash() const { return hashFlow(prot, src, dst, srcpt, dstpt); }

    uint8_t   prot;    // Inner IP protocol number (after any extension headers; picks the flow cache)

private:
    struct in6_addr src;
    struct in6_addr dst;
    uint32_t  flow;    // Flow label: shown in text() only, not part of the flow's identity
    uint16_t  srcpt;
    uint16_t  dstpt;
};

// Hash for boost::hash (used by the flow cache's boost::concurrent_flat_map).
inline std::size_t hash_value(const PacketHeaderV6& t) { return t.hash(); }

#endif //GWLBTUN_PACKETHEADERV6_H
