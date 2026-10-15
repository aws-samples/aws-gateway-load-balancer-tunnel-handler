// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#include "Logger.h"
#include <string>
#include <sstream>
#include <vector>
#include <array>
#include <cstring>
#include <algorithm>
#include <cctype>

using namespace std::string_literals;

static const std::array<std::string, LS_COUNT + 1> loggingSections = {
        "core"s, "udp"s, "geneve"s, "tunnel"s, "healthcheck"s, "os"s, "ebpf"s, "all"s
};

static const std::array<std::string, LL_COUNT> loggingLevels = {
        "critical"s, "important"s, "info"s, "debug"s, "debugdetail"s
};

Logger::Logger(const std::string &loggingOptions) :
    cfg(optionsParse(loggingOptions)), thread(&Logger::threadFunc, this)
{
    // Return only once the logging thread is running, so a message logged straight after construction (or a
    // quick destruction) can't race with the thread's start-up.
    ready.get_future().wait();
}

Logger::~Logger()
{
    // Join the logging thread before our queue/mutex/condvar members are
    // destroyed. threadFunc() touches all three every iteration, so returning
    // without a join would (a) let it run on with freed state and (b) destroy a
    // still-joinable std::thread, which calls std::terminate(). Set the flag
    // under queue_mutex so the notify can't be lost against threadFunc's wait().
    {
        std::lock_guard<std::mutex> lk(queue_mutex);
        shouldTerminate = true;
    }
    queue_condvar.notify_one();
    thread.join();
}

std::string Logger::help()
{
    std::stringstream ss;

    ss << "The logging configuration can be set by passing a string to the --logging option. That string is a series of <section>=<level>, comma separated and case insensitive." << std::endl << "The available sections are: ";
    for(auto& it : loggingSections) ss << it << " ";
    ss << std::endl;
    ss << "The logging levels available for each are: ";
    for(auto& it : loggingLevels) ss << it << " ";
    ss << std::endl;
    ss << "The default level for all sections is 'info'.";
    ss << std::endl;

    return ss.str();
}

/**
 * Case-insensitive iterable thing search
 *
 * @param iter     Iterable to search through
 * @param search   Search string
 * @return Index in vector of string case-insensitive, or -1 if not found.
 */
template <class X> static int FindIndexOf(const X &iter, const std::string &search)
{
    int ret = 0;

    std::string searchLower = search;
    std::transform(searchLower.begin(), searchLower.end(), searchLower.begin(), [](unsigned char c){return std::tolower(c); });

    for(auto it = iter.begin(); it != iter.end(); it++, ret++)
        if(*it == searchLower)
            return ret;

    return -1;
}

LoggingConfiguration Logger::optionsParse(const std::string &loggingOptions)
{
    LoggingConfiguration lc;
    LogSection i;

    // Set default levels
    for(i = LS_CORE; i < LS_COUNT; i = LogSection(i+1))
        lc.ll[i] = LL_INFO;

    // Parse string
    std::istringstream ss(loggingOptions);
    std::string token;
    while(std::getline(ss, token, ','))
    {
        size_t pos = token.find('=');
        if(pos != std::string::npos)
        {
            std::string key = token.substr(0, pos);
            std::string value = token.substr(pos + 1);

            int valN = FindIndexOf(loggingLevels, value);
            if(valN == -1)
            {
                fprintf(stderr, "Unrecognized logging level '%s' caused %s to be ignored.\n", value.c_str(), token.c_str());
            } else {
                int keyN = FindIndexOf(loggingSections, key);
                if(keyN == -1)
                {
                   fprintf(stderr, "Unrecognized logging section '%s' caused %s to be ignored.\n", key.c_str(), token.c_str());
                } else if(keyN == LS_COUNT) {   // aka 'all'
                    for(i = LS_CORE; i < LS_COUNT; i = LogSection(i+1))
                        lc.ll[i] = (LogLevel)valN;
                } else {
                    lc.ll[(LogSection)keyN] = (LogLevel)valN;
                }
            }
        }
    }
    return lc;
}

/**
 * Logging thread. Receives messages from the Log function, and prints them out, splitting lines on newlines
 * as needed.
 */
void Logger::threadFunc()
{
    struct tm localtm;
    struct LoggingMessage lm;

    pthread_setname_np(pthread_self(), "gwlbtun Logger");
    
    std::stringstream ss;
    ss << "Logging thread started. Configuration:";
    for(auto i = LS_CORE; i < LS_COUNT; i = LogSection(i+1))
        ss << loggingSections[i] << "=" << loggingLevels[cfg.ll[i]].c_str() << "  ";

    // Use direct call instead of LOG macro here since during initialization the global it points is not valid yet.
    this->Log(LS_CORE, LL_IMPORTANT, ss.str());

    ready.set_value();   // the constructor returns

    // Wait for messages (or the shutdown request) under queue_mutex, then print each one with the
    // lock released so callers don't wait on console output. Exit only after the queue is empty,
    // so messages logged just before shutdown (e.g. "Shutdown complete.") are not lost.
    std::unique_lock<std::mutex> lk(queue_mutex);
    for(;;)
    {
        queue_condvar.wait(lk, [this]{ return shouldTerminate || !queue.empty(); });

        while(!queue.empty())
        {
            std::stringstream header;
            lm = std::move(queue.front());
            queue.pop();
            lk.unlock();
            auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(lm.ts.time_since_epoch()).count() % 1000;
            std::time_t cur_time = std::chrono::system_clock::to_time_t(lm.ts);
            localtime_r(&cur_time, &localtm);
            header << std::put_time(&localtm, "%F %T") << "."s << std::setw(3) << std::setfill('0') << millis << ": " << lm.thread << "(" << loggingSections[lm.ls] << "," << loggingLevels[lm.ll] << "): ";
            std::string line;
            std::stringstream is(lm.msg);
            while(std::getline(is, line))
                std::cout << header.str() << line << '\n';
            lk.lock();
        }

        // Flush once the queue is drained: once per batch rather than once per line.
        std::cout.flush();
        if(shouldTerminate)
            break;
    }
}

/**
 * Log a message as-is. Sends the message to the logging thread, which will split lines if needed.
 * The message is never interpreted as a printf format.
 *
 * @param ls        Logging section (LS_ defines)
 * @param ll        Logging level (LL_ defines)
 * @param msg       The message
 */
void Logger::Log(LogSection ls, LogLevel ll, const std::string& msg)
{
    // The LOG() macro checks the level too; this is for direct callers.
    if(cfg.ll[ls] >= ll)
        enqueue(ls, ll, msg);
}

/**
 * Log a printf-style formatted message. Sends the message to the logging thread, which will split
 * lines if needed.
 *
 * @param ls        Logging section (LS_ defines)
 * @param ll        Logging level (LL_ defines)
 * @param fmt       printf-style format string
 * @param ...       Arguments for the formatting in fmt
 */
void Logger::Log(LogSection ls, LogLevel ll, const char *fmt, ...)
{
    // The LOG() macro checks the level too; this is for direct callers.
    if(cfg.ll[ls] >= ll)
    {
        va_list ap;
        va_start(ap, fmt);
        std::string msg = stringFormat(fmt, ap);
        va_end(ap);
        enqueue(ls, ll, std::move(msg));
    }
}

/**
 * Queue a finished message for the logging thread.
 */
void Logger::enqueue(LogSection ls, LogLevel ll, std::string msg)
{
    LoggingMessage lm{ ls, ll, std::move(msg), std::chrono::system_clock::now(), "" };
    pthread_getname_np(pthread_self(), lm.thread, 16);
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        queue.emplace(std::move(lm));
    }
    queue_condvar.notify_one();
}

/**
 * Log a hex dump. Formats the incoming buffer into multiple lines, then sends to the logging thread.
 * The thread will split the lines for us, ensuring they all output at the same time.
 *
 * @param ls        Logging section (LS_ defines)
 * @param ll        Logging level (LL_ defines)
 * @param title     What's being dumped; logged as the first line
 * @param buffer    Buffer the hex dump
 * @param bufsize   Length of buffer
 */
void Logger::LogHexDump(LogSection ls, LogLevel ll, const std::string &title, const void *buffer, std::size_t bufsize)
{
    if(cfg.ll[ls] >= ll)
    {
        std::stringstream ss;
        ss << title << " (" << bufsize << " bytes):" << std::endl;
        char hexBuf[140];
        char printBuf[36];
        unsigned char *cBuffer = (unsigned char *)buffer;
        std::size_t offset;

        for(offset = 0; offset < bufsize; offset ++)
        {
            if(offset % 32 == 0)
            {
                if(offset > 0) ss << hexBuf << printBuf << std::endl;
                bzero(hexBuf, 140);
                bzero(printBuf, 36);
                strcpy(printBuf, " | ");
                snprintf(hexBuf, 7, "%04zx: ", offset & 0xFFFF);
            }
            snprintf(&hexBuf[5+((offset % 32)*3)], 4, " %02x", cBuffer[offset]);
            printBuf[3 + (offset % 32)] = (isprint(cBuffer[offset]))?cBuffer[offset]:'.';
        }
        // Emit the last line, padded so the printable column lines up. (This used to pad from
        // offset % 32, which for a buffer that's a whole number of lines blanked the last line's
        // bytes, and it printed the uninitialised buffers for an empty dump.)
        if(bufsize > 0)
        {
            const std::size_t used = (bufsize % 32 == 0) ? 32 : bufsize % 32;
            for(std::size_t p = 5 + used * 3; p < 101; p++) hexBuf[p] = ' ';
            ss << hexBuf << printBuf << std::endl;
        }

        this->Log(ls, ll, ss.str());
    }
}
