// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWAPPLIANCE_GENEVEPACKET_H
#define GWAPPLIANCE_GENEVEPACKET_H

#include <cinttypes>
#include <string>
#include <sys/types.h>
#include <boost/container/small_vector.hpp>

typedef uint64_t gwlbeid_t;

// A copy of a GENEVE header: the 8-byte base header plus GWLB's options (32 bytes) fit inline; a longer
// header still works, but moves to the heap.
typedef boost::container::small_vector<unsigned char, 40> GeneveHeader;

class GenevePacket {
public:
    GenevePacket(const unsigned char *pktBuf, ssize_t pktLen) __attribute__((hot));   // pktBuf points to the start of the Geneve header (i.e. after the outer UDP header)
    
    gwlbeid_t gwlbeEndpointId = 0;   // The GWLB endpoint (VPC endpoint, "vpce-") ID option, if found (check via the valid boolean). This is the endpoint identifier, NOT the ENI of that endpoint.
    uint64_t attachmentId = 0;       // The attachment ID option, if it was found
    int status = 0;                  // GP_STATUS_ code
    uint32_t flowCookie = 0;         // The flow cookie, if it was found
    uint32_t headerLen = 0;          // Length of the Geneve header
    bool gwlbeEndpointIdValid = false, attachmentIdValid = false, flowCookieValid = false;   // False if the options weren't found (and the values above MUST NOT be used), or true if they were.

    std::string text() const;
};

// GenevePacket status codes
enum {
    GP_STATUS_EMPTY = 0,                // Nothing done yet
    GP_STATUS_OK,                       // Everything looks good, packet is valid.
    GP_STATUS_TOO_SHORT,                // Packet is too short to carry a Geneve header
    GP_STATUS_BAD_VER,                  // Version wasn't 0
    GP_STATUS_BAD_OPTLEN,               // Options length exceeded packet size
    GP_STATUS_BAD_ETHERTYPE,            // Geneve protocol type was neither 0x0800 (IPv4) nor 0x86DD (IPv6)
    GP_STATUS_MISSING_GWLB_OPTIONS,     // Required options for GWLB are missing.
};

#endif //GWAPPLIANCE_GENEVEPACKET_H
