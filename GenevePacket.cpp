// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * GenevePacket class takes in a raw packet buffer and attempts to interpret it as a Geneve-encapsulated packet.
 * The status member variable will be GP_STATUS_OK if this is successful and everything passes sanity checks,
 * otherwise will be one of the other codes defined in GeneveHeader.h.
 *
 * This code is based on the version of Geneve as defined in RFC 8926.
 */

#include "GenevePacket.h"
#include <cstring>
#include "utils.h"

/**
 * Empty initializer
 */
GenevePacket::GenevePacket() : status(GP_STATUS_EMPTY) { }

/**
 * Interpret the packet as a GENEVE packet. Does sanity checks to ensure the packet is correct. Callers should
 * verify the class's status member is GP_STATUS_OK before using - otherwise handle the error code provided in
 * that variable.
 *
 * @param pktBuf Pointer to the UDP packet payload received.
 * @param pktLen Length of pktBuf
 */
GenevePacket::GenevePacket(unsigned char *pktBuf, ssize_t pktLen)
        : status(GP_STATUS_EMPTY), gwlbeEndpointIdValid(false), attachmentIdValid(false), flowCookieValid(false)
{
    // Fast path checks with branch prediction hints
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

    // Ethertype check - load as uint16_t directly
    uint16_t ethertype = be16toh_unaligned(&pktBuf[2]);
    if(__builtin_expect(ethertype != ETH_P_IP && ethertype != ETH_P_IPV6, 0))
    {
        status = GP_STATUS_BAD_ETHERTYPE;
        return;
    }
    
    // Extract VNI (24 bits at offset 4) - avoid memcpy
    geneveVni = (pktBuf[4] << 16) | (pktBuf[5] << 8) | pktBuf[6];

    // Geneve options processing. The options length is expressed in 4-byte multiples (RFC 8926 section 3.4).
    int optLen = (pktBuf[0] & 0x3f) * 4;
    if(__builtin_expect(optLen > pktLen - 8, 0))
    {
        status = GP_STATUS_BAD_OPTLEN;
        return;
    }

    // Work through the packet buffer, option-by-option
    unsigned char *pktPtr = &pktBuf[8];
    unsigned char *pktEnd = &pktBuf[8 + optLen];
    
    while(pktPtr < pktEnd)
    {
        // Need at least 4 bytes left for the option header itself. See RFC 8926 section 3.5.
        if(pktPtr + 4 > pktEnd)
            break;
        uint16_t optClass = be16toh_unaligned(&pktPtr[0]);
        uint8_t optType = pktPtr[2];
        uint8_t optLen = (pktPtr[3] & 0x1f) * 4;
        // The option's declared data length must also fit within the remaining option region,
        // otherwise a malformed/truncated packet could read past it into stale buffer bytes.
        if(pktPtr + 4 + optLen > pktEnd)
            break;
        unsigned char *optData = &pktPtr[4];

        // Check for AWS specific options for GWLB (class 0x108)
        if(__builtin_expect(optClass == 0x108, 1))
        {
            if(optType == 1 && optLen == 8)
            {
                // Class 0x0108, type 1: the GWLB endpoint (VPC endpoint, "vpce-")
                // identifier the flow arrived through -- NOT the ENI of that endpoint.
                // Carried as a 64-bit value; rendered as hex (see MakeGwlbeStr).
                gwlbeEndpointIdValid = true;
                gwlbeEndpointId = be64toh_unaligned(optData);
            }
            else if(optType == 2 && optLen == 8)
            {
                attachmentIdValid = true;
                attachmentId = be64toh_unaligned(optData);
            }
            else if(optType == 3 && optLen == 4)
            {
                flowCookieValid = true;
                flowCookie = be32toh_unaligned(optData);
            }
        }
        pktPtr += 4 + optLen;
    }

    headerLen = 8 + optLen;

    // If the three mandatory options for GWLB weren't seen, this can't be a valid packet from it.
    if(__builtin_expect(!gwlbeEndpointIdValid || !attachmentIdValid || !flowCookieValid, 0))
        status = GP_STATUS_MISSING_GWLB_OPTIONS;
    else
        status = GP_STATUS_OK;
}

std::string GenevePacket::text()
{
    std::ostringstream ss;
    ss << " Status: " << (status) << std::hex << " GWLBe endpoint: vpce-" << (MakeGwlbeStr(gwlbeEndpointIdValid?gwlbeEndpointId:0)) << " Attachment ID: " << (attachmentIdValid?attachmentId:0) << " Flow Cookie: " << (flowCookieValid?flowCookie:0) << std::dec;
    return ss.str();
}

/**
 * Output a human-readable string of the contents of this GenevePacket.
 *
 * @param os Output stream to write to.
 * @param m The GenevePacket to write.
 * @return The same output stream, with the text added.
 */
auto operator<<(std::ostream& os, GenevePacket const& m) -> std::ostream&
{
    return os << " Status: " << (m.status) << std::hex << " GWLBe endpoint: vpce-" << (MakeGwlbeStr(m.gwlbeEndpointIdValid?m.gwlbeEndpointId:0)) << " Attachment ID: " << (m.attachmentIdValid?m.attachmentId:0) << " Flow Cookie: " << (m.flowCookieValid?m.flowCookie:0) << std::dec;
}

