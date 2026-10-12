// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWLBTUN_PACKETHEADERV4_H
#define GWLBTUN_PACKETHEADERV4_H

#include <cinttypes>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include "utils.h"

class PacketHeaderV4 {
public:
    // pktbuf points to the start of the IP header. Throws std::invalid_argument for a malformed header.
    PacketHeaderV4(const unsigned char *pktbuf, ssize_t pktlen) __attribute__((hot));
    std::string text() const;

    // Bidirectional: a flow and its reverse compare equal (depends on the symmetric hash invariant in utils.h).
    bool operator==(const PacketHeaderV4 &ph) const
    {
        return prot == ph.prot && ((src == ph.src && dst == ph.dst && srcpt == ph.srcpt && dstpt == ph.dstpt) ||
                                   (src == ph.dst && dst == ph.src && srcpt == ph.dstpt && dstpt == ph.srcpt));
    }

    std::size_t hash() const { return hashFlow(prot, src, dst, srcpt, dstpt); }

    uint8_t   prot;    // Inner IP protocol number (picks the flow cache)

private:
    uint32_t  src;
    uint32_t  dst;
    uint16_t  srcpt;
    uint16_t  dstpt;
};

// Hash for boost::hash (used by the flow cache's boost::concurrent_flat_map).
inline std::size_t hash_value(const PacketHeaderV4& t) { return t.hash(); }

#endif //GWLBTUN_PACKETHEADERV4_H
