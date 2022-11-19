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

/**
 * Interpret the packet as a GENEVE packet. Does sanity checks to ensure the packet is correct. Callers should
 * verify the class's status member is GP_STATUS_OK before using - otherwise handle the error code provided in
 * that variable.
 *
 * @param pktBuf Pointer to the UDP packet payload received.
 * @param pktLen Length of pktBuf
 */
GenevePacket::GenevePacket(unsigned char *pktBuf, ssize_t pktLen)
        : status(GP_STATUS_EMPTY)
{
    // 1) Process the Geneve Header in the passed in raw packet buffer.  Since we're receiving via a UDP socket,
    // the outer IPv4 header has been removed for us by the OS, so our first byte is the outer Geneve Reader.
    // Geneve Header:
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |        Virtual Network Identifier (VNI)       |    Reserved   |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // ~                    Variable-Length Options                    ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    unsigned char workBuf[8];
    unsigned char *pktPtr;          // Pointer to where the packet is being processed.

    if(pktLen < 8)
    {
        status = GP_STATUS_TOO_SHORT;
        return;
    }
    // Version check. This must be 0, by the current RFC.
    if( (pktBuf[0] & 0xc0) != 0)
    {
        status = GP_STATUS_BAD_VER;
        return;
    }

    // This application has no use for the O or C bits.  Reserved must be ignored.

    // GWLB uses L3 IPv4 encapsulation - ethertype 0x0800, or L3 IPv6 encapsulation - 0x86dd. Make sure that's what is here.
    if( (be16toh(*(uint16_t *)&pktBuf[2]) != ETH_P_IP) && (be16toh(*(uint16_t *)&pktBuf[2]) != ETH_P_IPV6))
    {
        status = GP_STATUS_BAD_ETHERTYPE;
        return;
    }
    bzero(workBuf, 8);
    // This next copy is deliberately dest off by 1 to allow using be32toh which expects 32 bits. The off-by-one
    // and the bzero just before ensure the first 8 bits are 0.
    memcpy(&workBuf[1], &pktBuf[4], 3);
    geneveVni = be32toh(*(uint32_t *)&workBuf);

    // Geneve options processing. The options length is expressed in 4-byte multiples (RFC 8926 section 3.4).
    int optLen = (pktBuf[0] & 0x3f) * 4;
    if( optLen > pktLen - 8)
    {
        status = GP_STATUS_BAD_OPTLEN;
        return;
    }

    // Work through the packet buffer, option-by-option, moving pktPtr as needed. We're expecting 3, so reserve that.
    geneveOptions.reserve(3);
    pktPtr = &pktBuf[8];
    struct GeneveOption go;
    while(pktPtr < &pktBuf[8 + optLen])
    {
        // Convert option to host format and in the struct. See RFC 8926 section 3.5.
        bzero(&go, sizeof(go));
        go.optClass = be16toh(*(uint16_t *)&pktPtr[0]);
        go.optType = (uint8_t)pktPtr[2];
        go.r = (unsigned char)(pktPtr[3] & 0xe0 >> 5);
        go.optLen = (pktPtr[3] & 0x1f) * 4;
        if(go.optLen > 0) go.optData = &pktPtr[4];
        geneveOptions.push_back(go);

        // check for AWS specific options for GWLB.
        if(go.optClass == 0x108 && go.optType == 1 && go.optLen == 8)
        {
            gwlbeEniIdValid = true;
            gwlbeEniId = be64toh(*(uint64_t *)go.optData);
        }
        else if(go.optClass == 0x108 && go.optType == 2 && go.optLen == 8)
        {
            attachmentIdValid = true;
            attachmentId = be64toh(*(uint64_t *)go.optData);
        }
        else if(go.optClass == 0x108 && go.optType == 3 && go.optLen == 4)
        {
            flowCookieValid = true;
            flowCookie = be32toh(*(uint32_t *)go.optData);
        }
        pktPtr += 4 + go.optLen;
    }

    header = std::vector<unsigned char>(pktBuf, pktBuf + 8 + optLen);
    headerLen = 8 + optLen;

    // If the three mandatory options for GWLB weren't seen, this can't be a valid packet from it.
    if(!gwlbeEniIdValid || !attachmentIdValid || !flowCookieValid)
        status = GP_STATUS_MISSING_GWLB_OPTIONS;
    else
        status = GP_STATUS_OK;
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
    return os << " Status: " << (m.status) << std::hex << " GWLBe ENI ID: " << (m.gwlbeEniIdValid?m.gwlbeEniId:0) << " Attachment ID: " << (m.attachmentIdValid?m.attachmentId:0) << " Flow Cookie: " << (m.flowCookieValid?m.flowCookie:0) << std::dec;
}

