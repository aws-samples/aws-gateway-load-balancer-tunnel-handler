// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWAPPLIANCE_GENEVEPACKET_H
#define GWAPPLIANCE_GENEVEPACKET_H

#include <inttypes.h>
#include <vector>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <iostream>

// Storage for options seen in a Geneve header.
struct GeneveOption {
    uint16_t optClass;           // Option class, converted to host format
    uint8_t optType;             // Type, converted to host format
    unsigned char r : 3;         // R bits
    uint8_t optLen;              // Option length, in bytes (converted from on-wire 4-byte multiples value)
    unsigned char *optData;      // Pointer to the option data.  May be nullptr, if optLen is 0.
};

class GenevePacket {
public:
    GenevePacket(unsigned char *pktBuf, ssize_t pktLen);   // pktBuf points to the start of the Geneve header (i.e. after the outer UDP header)

    int status;
    int headerLen;               // Total length of the Geneve header parsed.
    std::vector<struct GeneveOption> geneveOptions;   // Parsed options from the Geneve header.
    uint32_t geneveVni;          // The outer VNI identifier from the Geneve header.
    bool gwlbeEniIdValid, attachmentIdValid, flowCookieValid;   // False if the options weren't found (and the below values MUST NOT be used), or true if they were.
    uint64_t gwlbeEniId;         // The GWLBE ENI ID option, if it was found (check via the valid boolean)
    uint64_t attachmentId;       // The attachment ID option, if it was found
    uint32_t flowCookie;         // The flow cookie, if it was found
    std::vector<unsigned char>header;   // Copy of the Geneve header to put back on packets
    friend auto operator<<(std::ostream& os, GenevePacket const& m) -> std::ostream&;
};

// GenevePacket status codes
enum {
    GP_STATUS_EMPTY = 0,                // Nothing done yet
    GP_STATUS_OK,                       // Everything looks good, packet is valid.
    GP_STATUS_TOO_SHORT,                // Packet is too short to carry a Geneve header
    GP_STATUS_BAD_VER,                  // Version wasn't 0
    GP_STATUS_BAD_OPTLEN,               // Options length exceeded packet size
    GP_STATUS_BAD_ETHERTYPE,            // Geneve Ethertype wasn't 0x8000 (L3 IPv4)
    GP_STATUS_MISSING_GWLB_OPTIONS,     // Required options for GWLB are missing.
};

#endif //GWAPPLIANCE_GENEVEPACKET_H
