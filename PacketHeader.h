// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
//
// Quick class to generate hashes of packets for use in std::unordered_map
//

#ifndef GWLBTUN_PACKETHEADER_H
#define GWLBTUN_PACKETHEADER_H

#include <cinttypes>
#include <iostream>
#include <stdexcept>

class PacketHeaderHash;

class PacketHeader {
public:
    PacketHeader(unsigned char *pktbuf, ssize_t pktlen);   // pktbuf points to the start of the IP header.
    bool operator==(const PacketHeader &) const;
    std::string text() const;
    std::size_t hash() const;

private:
    uint8_t   prot;
    uint32_t  src;
    uint32_t  dst;
    uint16_t  srcpt;
    uint16_t  dstpt;

    friend PacketHeaderHash;
};

std::ostream &operator<<(std::ostream &os, PacketHeader const &m);

class PacketHeaderHash {
public:
    std::size_t operator()(const PacketHeader &) const;
};

#endif //GWLBTUN_PACKETHEADER_H
