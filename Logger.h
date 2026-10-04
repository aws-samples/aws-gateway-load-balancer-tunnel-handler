// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWLBTUN_LOGGER_H
#define GWLBTUN_LOGGER_H

#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <initializer_list>
#include <string>
#include <sstream>
#include <iostream>
#include "utils.h"

// Log Section (LS_) defines
typedef enum {
    LS_CORE,         // Core messaging, startup, etc.
    LS_UDP,          // UDP receiver
    LS_GENEVE,       // GENEVE packet details
    LS_TUNNEL,       // Tunnel processing
    LS_HEALTHCHECK,  // Health check reporting
    LS_OS,           // Operating system function calls
    LS_COUNT
} LogSection;

// Log level (LL_) defines
typedef enum {
    LL_CRITICAL,        // Critical alerts
    LL_IMPORTANT,       // Important messages
    LL_INFO,            // Informational messages
    LL_DEBUG,           // Debug messages
    LL_DEBUGDETAIL,     // Debug detail
    LL_COUNT
} LogLevel;

struct LoggingConfiguration {
    LogLevel ll[LS_COUNT];
};

struct LoggingMessage {
    LogSection ls;
    LogLevel ll;
    std::string msg;
    std::chrono::system_clock::time_point ts;
    char thread[16];
};

extern class Logger *logger;

#define LOG(s,l,msg,...) do { if(logger->cfg.ll[s] >= l) logger->Log(s, l, msg, ##__VA_ARGS__); } while(0)
#define LOGHEXDUMP(s,l,hdr,buf,buflen) do { if(logger->cfg.ll[s] >= l) logger->LogHexDump(s, l, buf, buflen); } while(0)
#define IS_LOGGING(s,l) (logger->cfg.ll[s] <= l)
#define ts(s)  std::to_string(s)

class Logger {
public:
    Logger(std::string loggingOptions);
    ~Logger();
    std::string help();    // Return help text for configuring the logger.
    const LoggingConfiguration cfg;
    void Log(LogSection ls, LogLevel ll, const std::string& fmt_str, ...);
    void LogHexDump(LogSection ls, LogLevel ll, const void *buf, std::size_t bufLen);

private:
    bool shouldTerminate;

    LoggingConfiguration optionsParse(std::string loggingOptions);
    void threadFunc();

    // Logging queue
    std::mutex queue_mutex;
    std::condition_variable queue_condvar;
    std::queue<struct LoggingMessage> queue;
    
    // Thread startup synchronization
    std::mutex startup_mutex;
    std::condition_variable startup_condvar;
    bool thread_ready;

    // Declared LAST so the thread is constructed -- and threadFunc() starts running --
    // only AFTER every member it touches (queue_mutex/condvar, queue, startup_*,
    // thread_ready) is constructed. Members init in declaration order, so starting the
    // thread earlier raced with their construction (TSan-confirmed; this is also the
    // historical v2.5 "crash on startup if the logger thread didn't initialize quick
    // enough" footgun).
    std::thread thread;
};

#endif //GWLBTUN_LOGGER_H
