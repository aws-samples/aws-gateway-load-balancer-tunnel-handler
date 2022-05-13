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

using namespace std::string_literals;

extern std::ofstream dev_null;
extern std::ostream *debugout;
extern std::ostream *hexout;
extern int debug;

#define DEBUG_ON       1
#define DEBUG_VERBOSE  2

std::ostream& hexDump(std::ostream& os, const void *buffer,
                      std::size_t bufsize, bool showPrintableChars = true, std::string prefix = ""s);
std::string stringFormat(std::string fmt_str, ...);
bool sendUdp(struct in_addr from_addr, uint16_t from_port, struct in_addr to_addr, uint16_t to_port, unsigned char *pktBuf, ssize_t pktLen);
std::string toBase60(uint64_t val);
std::string timepointDelta(std::chrono::steady_clock::time_point t1, std::chrono::steady_clock::time_point t2);
std::string currentTime();
std::string sockaddrToName(struct sockaddr *sa);

#endif //GWLBTUN_UTILS_H
