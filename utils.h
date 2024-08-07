// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWLBTUN_UTILS_H
#define GWLBTUN_UTILS_H

#include <iostream>
#include <iomanip>
#include <cctype>
#include <string>
#include <memory>
#include <stdexcept>
#include <cstdarg>  // For va_start, etc.
#include <chrono>
#include <vector>
#include <algorithm>
#include "GenevePacket.h"   // For eniid_t

using namespace std::string_literals;

#define VERSION_MAJOR 2
#define VERSION_MINOR 5

// If only decapsulation is required, i.e. you will never send traffic back to GWLB via the local interfaces,
// you can define the following symbol to improve performance (GWLBTun no longer needs to track flow cookies, etc.)
//#define NO_RETURN_TRAFFIC

// Thread configuration parser and data struct
#define MAX_THREADS    128
typedef struct ThreadConfigStruct {
    std::vector<int> cfg;
} ThreadConfig;

std::string stringFormat(const std::string& fmt_str, ...);
std::string stringFormat(const std::string& fmt_str, va_list ap);
bool sendUdp(int sock, struct in_addr from_addr, uint16_t from_port, struct in_addr to_addr, uint16_t to_port, unsigned char *pktBuf, ssize_t pktLen);
std::string toBase60(uint64_t val);
std::string timepointDeltaString(std::chrono::steady_clock::time_point t1, std::chrono::steady_clock::time_point t2);
double timepointDeltaDouble(std::chrono::steady_clock::time_point t1, std::chrono::steady_clock::time_point t2);
std::string sockaddrToName(struct sockaddr *sa);
void ParseThreadConfiguration(int threadcount, std::string& affinity, ThreadConfig *dest);
std::string MakeENIStr(eniid_t eni);
int FindIndexOf(std::vector<std::string> vector, std::string search);

// If hashFunc is a function that does not result in the same hash for both flow directions,
// #undef the next line so that GeneveHandler and PacketHeader changes their logic appropriately.
#define HASH_IS_SYMMETRICAL
/**
 * Simple, basic, but very fast hash function.  Returns same hash in both directions, so leave HASH_IS_SYMMETRICAL
 * defined.
 * @param prot    Protocol number
 * @param srcip   Pointer to source IP data
 * @param dstip   Pointer to destination IP data
 * @param ipsize  Size of IP data (4 for IPv4, 16 for IPv6)
 * @param srcpt   Source Port Number
 * @param dstpt   Destination Port NUmber
 * @return
 */
inline size_t hashFunc(uint8_t prot, void *srcip, void *dstip, int ipsize, uint16_t srcpt, uint16_t dstpt)
{
    uint32_t *srciplongs = (uint32_t *)srcip;
    uint32_t *dstiplongs = (uint32_t *)dstip;
    if(ipsize == 4)
    {
        return prot + srciplongs[0] + dstiplongs[0] + srcpt + dstpt;
    } else {
        return prot + srciplongs[0] + srciplongs[1] + srciplongs[2] + srciplongs[3] +
               dstiplongs[0] + dstiplongs[1] + dstiplongs[2] + dstiplongs[3] + srcpt + dstpt;
    }
}

/**
 * Case-insensitive iterable thing search
 *
 * @param iter     Iterable to search through
 * @param search   Search string
 * @return Index in vector of string case-insensitive, or -1 if not found.
 */
template <class X> int FindIndexOf(X iter, std::string search)
{
    int ret = 0;

    std::string searchLower = search;
    std::transform(searchLower.begin(), searchLower.end(), searchLower.begin(), [](unsigned char c){return std::tolower(c); });

    for(auto it = iter.begin(); it != iter.end(); it++, ret++)
        if(*it == searchLower)
            return ret;

    return -1;
}

#endif //GWLBTUN_UTILS_H
