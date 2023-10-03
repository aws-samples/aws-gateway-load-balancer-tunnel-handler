// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#include "Logger.h"
#include <string>
#include <sstream>
#include <vector>
#include <cstring>

using namespace std::string_literals;

const std::vector<std::string> loggingSections = {
        "core"s, "udp"s, "geneve"s, "tunnel"s, "healthcheck"s, "all"s
};

const std::vector<std::string> loggingLevels = {
        "critical"s, "important"s, "info"s, "debug"s, "debugdetail"s
};

Logger::Logger(std::string loggingOptions) :
    cfg(optionsParse(loggingOptions)), thread(&Logger::threadFunc, this), shouldTerminate(false)
{

}

Logger::~Logger()
{
    shouldTerminate = true;
    queue_condvar.notify_one();
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
    ss << "The default level for all secions is 'important'.";
    ss << std::endl;

    return ss.str();
}

LoggingConfiguration Logger::optionsParse(std::string loggingOptions)
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

            int valN = VectorIndexI(loggingLevels, value);
            if(valN == -1)
            {
                fprintf(stderr, "Unrecognized logging level '%s' caused %s to be ignored.", value.c_str(), token.c_str());
            } else {
                int keyN = VectorIndexI(loggingSections, key);
                if(keyN == -1)
                {
                   fprintf(stderr, "Unrecognized logging section '%s' caused %s to be ignored.", key.c_str(), token.c_str());
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

    LOG(LS_CORE, LL_IMPORTANT, ss.str());

    while(!shouldTerminate)
    {
        std::unique_lock<std::mutex> lk(queue_mutex);

        while(!queue.empty())
        {
            std::stringstream header;
            lm = queue.front();
            queue.pop();
            auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(lm.ts.time_since_epoch()).count() % 1000;
            std::time_t cur_time = std::chrono::system_clock::to_time_t(lm.ts);
            localtime_r(&cur_time, &localtm);
            header << std::put_time(&localtm, "%F %T") << "."s << std::setw(3) << std::setfill('0') << millis << ": " << lm.thread << "(" << loggingSections[lm.ls] << "," << loggingLevels[lm.ll] << ") : ";
            std::string line;
            std::stringstream is(lm.msg);
            while(std::getline(is, line))
            {
                std::cout <<  header.str() << ": " << line << std::endl;
            }
        }

        queue_condvar.wait(lk);
    }
}

/**
 * Log a message. Sends the message to the logging thread, which will split lines if needed.
 *
 * @param ls        Logging section (LS_ defines)
 * @param ll        Logging level (LL_ defines)
 * @param fmt_str   String, possibly including printf-type formatting arguments
 * @param ...       Arguments for the formatting in fmt_str
 */
void Logger::Log(LogSection ls, LogLevel ll, const std::string& fmt_str, ...)
{
    va_list ap;

    // This check also occurs the LOG() macro, but let's verify
    if(cfg.ll[ls] >= ll)
    {
        struct LoggingMessage lm;
        va_start(ap, &fmt_str);
        lm = (struct LoggingMessage){.ls = ls, .ll = ll, .msg = stringFormat(fmt_str, ap), .ts = std::chrono::system_clock::now(), .thread = "" };
        va_end(ap);
        pthread_getname_np(pthread_self(), lm.thread, 16);
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            queue.emplace(std::move(lm));
        }
        queue_condvar.notify_one();
    }
}

/**
 * Log a hex dump. Formats the incoming buffer into multiple lines, then sends to the logging thread.
 * The thread will split the lines for us, ensuring they all output at the same time.
 *
 * @param ls        Logging section (LS_ defines)
 * @param ll        Logging level (LL_ defines)
 * @param buffer    Buffer the hex dump
 * @param bufsize   Length of buffer
 */
void Logger::LogHexDump(LogSection ls, LogLevel ll, const void *buffer, std::size_t bufsize)
{
    if(cfg.ll[ls] >= ll)
    {
        std::stringstream ss;
        char hexBuf[140];
        char printBuf[36];
        unsigned char *cBuffer = (unsigned char *)buffer;
        std::size_t offset;
        const bool showPrintableChars = true;

        for(offset = 0; offset < bufsize; offset ++)
        {
            if(offset % 32 == 0)
            {
                if(offset > 0) ss << hexBuf << printBuf << std::endl;
                bzero(hexBuf, 140);
                bzero(printBuf, 36);
                if(showPrintableChars) strcpy(printBuf, " | ");
                snprintf(hexBuf, 7, "%04zx: ", offset);
            }
            snprintf(&hexBuf[5+((offset % 32)*3)], 4, " %02x", cBuffer[offset]);
            if(showPrintableChars)
                printBuf[3 + (offset % 32)] = (isprint(cBuffer[offset]))?cBuffer[offset]:'.';
        }
        // Add in enough padding to make sure our lines line up.
        for(offset = 5+((offset % 32) * 3); offset < 101; offset ++) hexBuf[offset] = ' ';
        if(offset > 0) ss << hexBuf << printBuf << std::endl;

        this->Log(ls, ll, ss.str());
    }
}
