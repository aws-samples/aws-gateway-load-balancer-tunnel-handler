// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * GenevePacket class takes in a raw packet buffer and attempts to interpret it as a Geneve-encapsulated packet.
 * The status member variable will be GP_STATUS_OK if this is successful and everything passes sanity checks,
 * otherwise will be one of the other codes defined in GenevePacket.h.
 *
 * This code is based on the version of Geneve as defined in RFC 8926.
 */

#include "GenevePacket.h"
#include <netinet/if_ether.h>
#include "utils.h"

using namespace std::string_literals;

/**
 * Interpret the packet as a GENEVE packet. Does sanity checks to ensure the packet is correct. Callers should
 * verify the class's status member is GP_STATUS_OK before using - otherwise handle the error code provided in
 * that variable.
 *
 * @param pktBuf Pointer to the UDP packet payload received.
 * @param pktLen Length of pktBuf
 */
GenevePacket::GenevePacket(const unsigned char *pktBuf, ssize_t pktLen)
{
    if(__builtin_expect(pktLen < 8, 0))
    {
        status = GP_STATUS_TOO_SHORT;
        return;
    }

    // Version check (bits 0-1 must be 0)
    if(__builtin_expect((pktBuf[0] & 0xc0) != 0, 0))
    {
        status = GP_STATUS_BAD_VER;
        return;
    }

    const uint16_t ethertype = be16toh_unaligned(&pktBuf[2]);
    if(__builtin_expect(ethertype != ETH_P_IP && ethertype != ETH_P_IPV6, 0))
    {
        status = GP_STATUS_BAD_ETHERTYPE;
        return;
    }

    // Geneve options processing. The options length is expressed in 4-byte multiples (RFC 8926 section 3.4).
    const size_t optLen = (size_t)(pktBuf[0] & 0x3f) * 4;
    if(__builtin_expect(optLen > (size_t)pktLen - 8, 0))
    {
        status = GP_STATUS_BAD_OPTLEN;
        return;
    }

    // Work through the options one by one, by offset (never forming a pointer past the buffer). Each needs a
    // 4-byte option header, and its declared data length must fit in what's left of the option region, or a
    // malformed packet could read past it. See RFC 8926 section 3.5.
    const size_t end = 8 + optLen;
    for(size_t off = 8; end - off >= 4; )
    {
        const uint16_t optClass = be16toh_unaligned(&pktBuf[off]);
        const uint8_t optType = pktBuf[off + 2];
        const size_t optDataLen = (size_t)(pktBuf[off + 3] & 0x1f) * 4;
        if(end - off - 4 < optDataLen)
            break;
        const unsigned char *optData = &pktBuf[off + 4];

        // Check for AWS specific options for GWLB (class 0x108)
        if(__builtin_expect(optClass == 0x108, 1))
        {
            if(optType == 1 && optDataLen == 8)
            {
                // Class 0x0108, type 1: the GWLB endpoint (VPC endpoint, "vpce-")
                // identifier the flow arrived through -- NOT the ENI of that endpoint.
                // Carried as a 64-bit value; rendered as hex (see MakeGwlbeStr).
                gwlbeEndpointIdValid = true;
                gwlbeEndpointId = be64toh_unaligned(optData);
            }
            else if(optType == 2 && optDataLen == 8)
            {
                attachmentIdValid = true;
                attachmentId = be64toh_unaligned(optData);
            }
            else if(optType == 3 && optDataLen == 4)
            {
                flowCookieValid = true;
                flowCookie = be32toh_unaligned(optData);
            }
        }
        off += 4 + optDataLen;
    }

    headerLen = (uint32_t)end;

    // gwlbtun requires all three GWLB options (endpoint ID, attachment ID, flow cookie), which GWLB sent on every
    // packet in our tests; without them the packet is rejected.
    if(__builtin_expect(!gwlbeEndpointIdValid || !attachmentIdValid || !flowCookieValid, 0))
        status = GP_STATUS_MISSING_GWLB_OPTIONS;
    else
        status = GP_STATUS_OK;
}

/**
 * The GWLB options, for logs: " GWLBe endpoint: vpce-<id> Attachment ID: 0x<id> Flow Cookie: 0x<cookie>", with
 * " (status N)" added when the header didn't parse cleanly. Options that weren't found show as 0.
 */
std::string GenevePacket::text() const
{
    return stringFormat(" GWLBe endpoint: vpce-%s Attachment ID: 0x%" PRIx64 " Flow Cookie: 0x%08" PRIx32 "%s",
                        MakeGwlbeStr(gwlbeEndpointIdValid ? gwlbeEndpointId : 0).c_str(), attachmentIdValid ? attachmentId : 0,
                        flowCookieValid ? flowCookie : 0, status == GP_STATUS_OK ? "" : (" (status "s + std::to_string(status) + ")"s).c_str());
}
