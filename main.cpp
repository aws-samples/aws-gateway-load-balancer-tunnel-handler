// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// GWLB Tunnel Handling user-space program. See the README.md for details on usage.

#include <iostream>
#include <unistd.h>
#include <getopt.h>
#include "GeneveHandler.h"
#include <cstdlib>
#include <sstream>
#include <fstream>
#include "utils.h"
#include <csignal>
#include <cstring>
#include "Logger.h"

using namespace std::string_literals;

std::string newCmd = "";
std::string delCmd = "";
volatile sig_atomic_t keepRunning = 1;

/**
 * Callback function for when a new GWLB endpoint has been detected by GeneveHandler. Prints a message and calls the create script.
 *
 * @param ingressInt New ingress interface.
 * @param egressInt New egress interface.
 * @param eniId ENI ID of the new endpoint.
 */
void newInterfaceCallback(std::string ingressInt, const std::string egressInt, eniid_t eniId)
{
    LOG(LS_CORE, LL_IMPORTANT, "New interface "s + ingressInt + " and "s + egressInt + " for ENI ID "s  + MakeENIStr(eniId) +  " created."s);
    if(newCmd.length() > 0)
    {
        std::stringstream ss;
        ss << newCmd << " CREATE " << ingressInt << " " << egressInt << " " << MakeENIStr(eniId);
        system(ss.str().c_str());
    }
}

/**
 * Callback function for when GeneveHandler deems an endpoint has disappeared. Prints a message and calls the delete script.
 * @param ingressInt Old ingress interface.
 * @param egressInt Old egress interface.
 * @param eniId Old ENI ID.
 */
void deleteInterfaceCallback(std::string ingressInt, const std::string egressInt, eniid_t eniId)
{
    LOG(LS_CORE, LL_IMPORTANT, "Removing interface "s + ingressInt + " and "s + egressInt + " for ENI ID "s + MakeENIStr(eniId) + "."s);
    if(delCmd.length() > 0)
    {
        std::stringstream ss;
        ss << delCmd << " DESTROY " << ingressInt << " " << egressInt << " " << MakeENIStr(eniId);
        system(ss.str().c_str());
    }
}

/**
 * Performs a health check of the GeneveHandler and sends an HTTP/1.1 string conveying that status. The HTTP header
 * has a 200 code if everything is well, a 503 if not.
 *
 * @param details true to return packet counters, false to just return the status code.
 * @param gh The GeneveHandler to return the status for.
 * @param s The socket to send the health check to
 * @param json Whether to output as human text (false) or json (true)
 */
void performHealthCheck(bool details, GeneveHandler *gh, int s, bool json)
{
    GeneveHandlerHealthCheck ghhc = gh->check();

    std::stringstream responseStream;

    responseStream << "HTTP/1.1 " << (gh->healthy ? "200 OK" : "503 Service Unavailable") << "\r\n"
                   << "Cache-Control: max-age=0, no-cache\r\n"
                   << "Connection: close\r\n"
                   << "Content-Type: " << (json ? "application/json" : "text/html") << "\r\n";

    if (details) {
        std::string body = json ? ghhc.output_json().dump() :
            "<!DOCTYPE html>\n<html lang=\"en-us\">\n<head><title>Health check</title></head><body>" + ghhc.output_str() + "\n</body></html>";

        responseStream << "Content-Length: " << body.length() << "\r\n\r\n" << body;
    } else {
        responseStream << "Content-Length: 0\r\n\r\n";
    }

    std::string response = responseStream.str();

    // Send all data
    size_t total_sent = 0;
    while(total_sent < response.length()) {
        ssize_t sent = send(s, response.c_str() + total_sent, response.length() - total_sent, 0);
        if(sent < 0) {
            if(errno == EINTR) continue;
            LOG(LS_HEALTHCHECK, LL_IMPORTANT, "Send failed: " + std::string(strerror(errno)));
            break;
        }
        total_sent += sent;
    }

    // Make sure we've discarded any data coming in
    char buffer[128];
    ssize_t bytes_read;
    while ((bytes_read = recv(s, buffer, sizeof(buffer), 0)) > 0) {
        // Process received data if necessary
    }

    // Graceful shutdown: send FIN
    shutdown(s, SHUT_WR);
}

/**
 * Returns the number of cores available to this process.
 * @return Integer core count.
 */
int numCores()
{
    cpu_set_t cpuset;
    sched_getaffinity(0, sizeof(cpuset), &cpuset);
    return CPU_COUNT(&cpuset);
}

/**
 * Prints command help.
 *
 * @param progname
 */
void printHelp(char *progname)
{
    fprintf(stderr,
            "AWS Gateway Load Balancer Tunnel Handler v%d.%d (%s)\n"
            "Built: %s\n"
            "Usage: %s [options]\n"
            "Example: %s\n"
            "\n"
            "  -h         Print this help\n"
            "  -c FILE    Command to execute when a new tunnel has been built. See below for arguments passed.\n"
            "  -r FILE    Command to execute when a tunnel times out and is about to be destroyed. See below for arguments passed.\n"
            "  -t TIME    Minimum time in seconds between last packet seen and to consider the tunnel timed out. Set to 0 (the default) to never time out tunnels.\n"
            "             Note the actual time between last packet and the destroy call may be longer than this time.\n"
#ifndef NO_RETURN_TRAFFIC
            "  -i TIME    Idle timeout to use for the flow caches. Set this to match what GWLB is configured for. Defaults to 350 seconds.\n"
#endif
            "  -p PORT    Listen to TCP port PORT and provide a health status report on it.\n"
            "  -j         For health check detailed statistics, output as JSON instead of text.\n"
            "  -s         Only return simple health check status (only the HTTP response code), instead of detailed statistics.\n"
            "  -d         Enable debugging output. Short version of --logging all=debug.\n"
            "\n"
            "Threading options:\n"
            "  --udpthreads NUM         Generate NUM threads for the UDP receiver.\n"
            "  --udpaffinity AFFIN      Generate threads for the UDP receiver, pinned to the cores listed. Takes precedence over udptreads.\n"
#ifndef NO_RETURN_TRAFFIC
            "  --tunthreads NUM         Generate NUM threads for each tunnel processor.\n"
            "  --tunaffinity AFFIN      Generate threads for each tunnel processor, pinned to the cores listed. Takes precedence over tunthreads.\n"
#endif
            "\n"
            "AFFIN arguments take a comma separated list of cores or range of cores, e.g. 1-2,4,7-8.\n"
            "It is recommended to have the same number of UDP threads as tunnel processor threads, in one-arm operation.\n"
            "If unspecified, the thread argument(s) will assume %d as a default, based on the number of cores present.\n"
            "\n"
            "Logging options:\n"
            "  --logging CONFIG         Set the logging configuration, as described below.\n"
#ifdef NO_RETURN_TRAFFIC
            "\nThis version of GWLBTun has been compiled with NO_RETURN_TRAFFIC defined.\n"
#endif
            "---------------------------------------------------------------------------------------------------------\n"
            "Hook scripts arguments:\n"
            "These arguments are provided when gwlbtun calls the hook scripts (the -c <FILE> and/or -r <FILE> command options).\n"
            "On gwlbtun startup, it will automatically create gwi-<X> and gwo-<X> interfaces upon seeing the first packet from a specific GWLBE, and the hook scripts are invoked when interfaces are created or destroyed. You should at least disable rpf_filter for the gwi-<X> tunnel interface with the hook scripts.\n"
            "The hook scripts will be called with the following arguments:\n"
            "1: The string 'CREATE' or 'DESTROY', depending on which operation is occurring.\n"
            "2: The interface name of the ingress interface (gwi-<X>).\n"
            "3: The interface name of the egress interface (gwo-<X>).  Packets can be sent out via in the ingress\n"
            "   as well, but having two different interfaces makes routing and iptables easier.\n"
            "4: The GWLBE ENI ID in base 16 (e.g. '2b8ee1d4db0c51c4') associated with this tunnel.\n"
            "\n"
            "The <X> in the interface name is replaced with the base 60 encoded ENI ID (to fit inside the 15 character\n"
            "device name limit).\n"
            "---------------------------------------------------------------------------------------------------------\n"
            , VERSION_MAJOR, VERSION_MINOR, GIT_DESCRIBE, BUILD_TIMESTAMP, progname, progname, numCores());
    fputs(logger->help().c_str(), stderr);
}

/**
 * Handler for when Ctrl-C is received. Sets a global flag so everything can start shutting down.
 *
 * @param sig
 */
void shutdownHandler(int)
{
    keepRunning = 0;
}

class Logger *logger;

int main(int argc, char *argv[])
{
    int c;
    int healthCheck = 0, healthSocket;
    int tunnelTimeout = 0, cacheTimeout = 350;
    int udpthreads = numCores();
#ifndef NO_RETURN_TRAFFIC
    int tunthreads = numCores();
#endif
    std::string udpaffinity, tunaffinity, logoptions;
    bool detailedHealth = true, printHelpFlag = false, jsonHealth = false;

    static struct option long_options[] = {
            {"cmdnew", required_argument, NULL, 'c'},
            {"cmddel", required_argument, NULL, 'r'},
            {"timeout", required_argument, NULL, 't'},
            {"port", required_argument, NULL, 'p'},
            {"debug", no_argument, NULL, 'd'},
            {"help", no_argument, NULL, 'h'},
            {"help", no_argument, NULL, '?'},
            {"udpthreads", required_argument, NULL, 0},    // optind 7
            {"udpaffinity", required_argument, NULL, 0},   // optind 8
            {"logging", required_argument, NULL, 0},       // optind 9
            {"json", no_argument, NULL, 'j'},              // optind 10
            {"idle", required_argument, NULL, 'i'},        // optind 11
#ifndef NO_RETURN_TRAFFIC
            {"tunthreads", required_argument, NULL, 0},    // optind 12
            {"tunaffinity", required_argument, NULL, 0},   // optind 13
#endif
            {0, 0, 0, 0}
    };

    // Argument parsing
    int optind;
    while ((c = getopt_long (argc, argv, "h?djxc:r:t:p:si:", long_options, &optind)) != -1)
    {
        switch(c)
        {
            case 0:
                // Long option
                switch(optind) {
                    case 7:
                        udpthreads = atoi(optarg);
                        break;
                    case 8:
                        udpaffinity = std::string(optarg);
                        break;
                    case 9:
                        logoptions = std::string(optarg);
                        break;
#ifndef NO_RETURN_TRAFFIC
                    case 12:
                        tunthreads = atoi(optarg);
                        break;
                    case 13:
                        tunaffinity = std::string(optarg);
                        break;
#endif
                }
                break;
            case 'c':
                newCmd = std::string(optarg);
                break;
            case 'r':
                delCmd = std::string(optarg);
                break;
            case 't':
                tunnelTimeout = atoi(optarg);
                break;
            case 'p':
                healthCheck = atoi(optarg);
                break;
            case 's':
                detailedHealth = false;
                break;
            case 'd':
                logoptions = "all=debug";
                break;
            case 'j':
                jsonHealth = true;
                break;
            case 'i':
                cacheTimeout = atoi(optarg);
                break;
            case '?':
            case 'h':
            default:
                printHelpFlag = true;
                break;
        }
    }

    if(printHelpFlag)
    {
        printHelp(argv[0]);
        exit(EXIT_FAILURE);
    }

    logger = new Logger(logoptions);

    // Set up for health check reporting, if requested. We listen on both IPv4 and IPv6 for completeness, although
    // GWLB only supports IPv4.
    if(healthCheck > 0)
    {
        if((healthSocket = socket(AF_INET6, SOCK_STREAM, 0)) == 0)
        {
            LOG(LS_CORE, LL_CRITICAL, "Creating health check socket failed: "s + std::strerror(errno));
            exit(EXIT_FAILURE);
        }

        struct sockaddr_in6 addr;
        bzero(&addr, sizeof(addr));

        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(healthCheck);
        addr.sin6_addr = in6addr_any;
        if(bind(healthSocket, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
            LOG(LS_CORE, LL_CRITICAL, "Unable to listen to health status port: "s + std::strerror(errno));
            exit(EXIT_FAILURE);
        }
        listen(healthSocket, 3);
    }

    signal(SIGINT, shutdownHandler);

    ThreadConfig udp;
    ParseThreadConfiguration(udpthreads, udpaffinity, &udp);

#ifndef NO_RETURN_TRAFFIC
    ThreadConfig tun;
    ParseThreadConfiguration(tunthreads, tunaffinity, &tun);
#else
    // In NO_RETURN_TRAFFIC mode, we only write to the TUN (via this class) and never read from it, so we need no reader threads.
    ThreadConfig tun;
    tun.cfg.resize(0);
#endif

    auto gh = new GeneveHandler(&newInterfaceCallback, &deleteInterfaceCallback, tunnelTimeout, cacheTimeout, udp, tun);
    struct timespec timeout;
    timeout.tv_sec = 1; timeout.tv_nsec = 0;
    fd_set fds;
    int ready;
    int ticksSinceCheck = 60;
    LOG(LS_CORE, LL_IMPORTANT, "AWS Gateway Load Balancer Tunnel Handler v%d.%d (%s) built %s", VERSION_MAJOR, VERSION_MINOR, GIT_DESCRIBE, BUILD_TIMESTAMP);
    while(keepRunning)
    {
        FD_ZERO(&fds);
        if(healthCheck > 0)
        {
            FD_SET(healthSocket, &fds);
        }

        ready = pselect(healthSocket + 1, &fds, nullptr, nullptr, &timeout, nullptr);
        if(ready > 0 && healthCheck > 0 && FD_ISSET(healthSocket, &fds))
        {
            // Process a health check client
            int hsClient;
            struct sockaddr_in6 from;
            socklen_t fromlen = sizeof(from);
            hsClient = accept(healthSocket, (struct sockaddr *)&from, &fromlen);
            LOG(LS_HEALTHCHECK, LL_DEBUG, "Processing a health check client for " + sockaddrToName((struct sockaddr *)&from));
            try {
                performHealthCheck(detailedHealth, gh, hsClient, jsonHealth);
                close(hsClient);
            } catch(...) {
                close(hsClient);
                throw;
            }
            ticksSinceCheck = 60;
        }

        ticksSinceCheck --;
        if(ticksSinceCheck < 0)
        {
            GeneveHandlerHealthCheck ghhc = gh->check();
            LOG(LS_HEALTHCHECK, LL_DEBUG, ghhc.output_str());
            ticksSinceCheck = 60;
        }
    }

    // The loop was interrupted (most likely by Ctrl-C or likewise).  Clean up a few things.
    LOG(LS_CORE, LL_IMPORTANT, "Shutting down.");
    delete(gh);
    if(healthCheck > 0) close(healthSocket);
    LOG(LS_CORE, LL_IMPORTANT, "Shutdown complete.");

    return 0;
}
