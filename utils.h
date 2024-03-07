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
#include <unistd.h>
#include <sys/syscall.h>

#ifndef SYS_gettid
#error "SYS_gettid unavailable on this system"
#endif

#define gettid() ((pid_t)syscall(SYS_gettid))

using namespace std::string_literals;

extern std::ofstream dev_null;
extern std::ostream *debugout;
extern std::ostream *hexout;
extern int debug;

#define DEBUG_ON       1
#define DEBUG_VERBOSE  2

// If only decapsulation is required, i.e. you will never send traffic back to GWLB via the local interfaces,
// you can define the following symbol to improve performance (GWLBTun no longer needs to track flow cookies, etc.)
//#define NO_RETURN_TRAFFIC

// Thread configuration parser and data struct
#define MAX_THREADS    128
typedef struct ThreadConfigStruct {
    std::vector<int> cfg;
} ThreadConfig;

std::ostream& hexDump(std::ostream& os, const void *buffer,
                      std::size_t bufsize, bool showPrintableChars = true, const std::string& prefix = ""s);
std::string stringFormat(const std::string& fmt_str, ...);
bool sendUdp(int sock, struct in_addr from_addr, uint16_t from_port, struct in_addr to_addr, uint16_t to_port, unsigned char *pktBuf, ssize_t pktLen);
std::string toBase60(uint64_t val);
std::string timepointDelta(std::chrono::steady_clock::time_point t1, std::chrono::steady_clock::time_point t2);
std::string currentTime();
std::string sockaddrToName(struct sockaddr *sa);
void ParseThreadConfiguration(int threadcount, std::string& affinity, ThreadConfig *dest);

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

#endif //GWLBTUN_UTILS_H
