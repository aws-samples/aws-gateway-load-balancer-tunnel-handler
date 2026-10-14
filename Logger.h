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
#include <future>
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

// LOG(section, level, msg) logs msg exactly as given; a std::string message is never used as a
// printf format, so text that came from packets, interface names or exceptions can't inject
// format directives. LOG(section, level, "fmt %d", args...) formats with printf rules, and the
// compiler checks the format against the arguments. A bare const char * (such as e.what()) picks the
// printf overload, so wrap text that isn't a format in std::string.
#define LOG(s,l,msg,...) do { if(logger->cfg.ll[s] >= l) logger->Log(s, l, msg, ##__VA_ARGS__); } while(0)
#define LOGHEXDUMP(s,l,hdr,buf,buflen) do { if(logger->cfg.ll[s] >= l) logger->LogHexDump(s, l, hdr, buf, buflen); } while(0)
#define IS_LOGGING(s,l) (logger->cfg.ll[s] >= l)
// Shorthand for std::to_string in log messages.
template<class T> inline std::string ts(T v) { return std::to_string(v); }

class Logger {
public:
    explicit Logger(const std::string &loggingOptions);
    Logger(const Logger &) = delete;
    Logger &operator=(const Logger &) = delete;
    ~Logger();
    static std::string help();    // Return help text for configuring the logger.
    const LoggingConfiguration cfg;
    void Log(LogSection ls, LogLevel ll, const std::string& msg);                                 // Logged as-is
    void Log(LogSection ls, LogLevel ll, const char *fmt, ...) __attribute__((format(printf, 4, 5))); // printf-style
    void LogHexDump(LogSection ls, LogLevel ll, const std::string &title, const void *buf, std::size_t bufLen);

private:
    bool shouldTerminate = false;     // Guarded by queue_mutex

    void enqueue(LogSection ls, LogLevel ll, std::string msg);

    static LoggingConfiguration optionsParse(const std::string &loggingOptions);
    void threadFunc();

    // Logging queue
    std::mutex queue_mutex;
    std::condition_variable queue_condvar;
    std::queue<struct LoggingMessage> queue;
    
    std::promise<void> ready;   // set by threadFunc once it's running; the constructor waits for it

    // ORDER MATTERS: LAST. threadFunc uses every member above, so the thread starts only once they all exist.
    std::thread thread;
};

#endif //GWLBTUN_LOGGER_H
