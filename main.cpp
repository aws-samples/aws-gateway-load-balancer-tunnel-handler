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

using namespace std::string_literals;

// Default debug output to /dev/null - if the -d flag gets passed, this pointer is changed to stderr.
std::ofstream dev_null("/dev/null");
std::ostream *debugout = &dev_null;
std::ostream *hexout = &dev_null;
std::string newCmd = "";
std::string delCmd = "";
int debug = 0;
volatile sig_atomic_t keepRunning = 1;

/**
 * Callback function for when a new GWLB endpoint has been detected by GeneveHandler. Prints a message and calls the create script.
 *
 * @param ingressInt New ingress interface.
 * @param egressInt New egress interface.
 * @param eniId ENI ID of the new endpoint.
 */
void newInterfaceCallback(std::string ingressInt, const std::string egressInt, uint64_t eniId)
{
    std::cout << "New interface " << ingressInt << " and " << egressInt << " for ENI ID " << std::hex << std::setw(17) << std::setfill('0') << eniId << std::dec << " created." << std::endl;
    if(newCmd.length() > 0)
    {
        std::stringstream ss;
        ss << newCmd << " CREATE " << ingressInt << " " << egressInt << " " << std::hex << std::setw(17) << std::setfill('0') << eniId << std::dec;
        system(ss.str().c_str());
    }
}

/**
 * Callback function for when GeneveHandler deems an endpoint has disappeared. Prints a message and calls the delete script.
 * @param ingressInt Old ingress interface.
 * @param egressInt Old egress interface.
 * @param eniId Old ENI ID.
 */
void deleteInterfaceCallback(std::string ingressInt, const std::string egressInt, uint64_t eniId)
{
    std::cout << "Removing interface " << ingressInt << " and " << egressInt << " for ENI ID " << std::hex << std::setw(17) << std::setfill('0') << eniId << std::dec << "." << std::endl;
    if(delCmd.length() > 0)
    {
        std::stringstream ss;
        ss << delCmd << " DESTROY " << ingressInt << " " << egressInt << " " << std::hex << std::setw(17) << std::setfill('0') << eniId << std::dec;
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
 */
void performHealthCheck(bool details, GeneveHandler *gh, int s)
{
    std::string status = gh->check();
    std::string response = "HTTP/1.1 "s + (gh->healthy ? "200 OK"s: "503 Failed"s) + "\n"s +
            "Cache-Control: max-age=0, no-cache\n\n<!DOCTYPE html>\n<html lang=\"en-us\">\n<head><title>Health check</title></head><body>"s;
    if(details) response += status;
    response += "\n</body></html>";

    send(s, response.c_str(), response.length(), 0);
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
            "AWS Gateway Load Balancer Tunnel Handler\n"
            "Usage: %s [options]\n"
            "Example: %s\n"
            "\n"
            "  -h         Print this help\n"
            "  -c FILE    Command to execute when a new tunnel has been built. See below for arguments passed.\n"
            "  -r FILE    Command to execute when a tunnel times out and is about to be destroyed. See below for arguments passed.\n"
            "  -t TIME    Minimum time in seconds between last packet seen and to consider the tunnel timed out. Set to 0 (the default) to never time out tunnels.\n"
            "             Note the actual time between last packet and the destroy call may be longer than this time.\n"
            "  -p PORT    Listen to TCP port PORT and provide a health status report on it.\n"
            "  -s         Only return simple health check status (only the HTTP response code), instead of detailed statistics.\n"
            "  -d         Enable debugging output.\n"
            "  -x         Enable dumping the hex payload of packets being processed.\n"
            "\n"
            "Threading options:\n"
            "  --udpthreads NUM         Generate NUM threads for the UDP receiver.\n"
            "  --udpaffinity AFFIN      Generate threads for the UDP receiver, pinned to the cores listed. Takes precedence over udptreads.\n"
            "  --tunthreads NUM         Generate NUM threads for each tunnel processor.\n"
            "  --tunaffinity AFFIN      Generate threads for each tunnel processor, pinned to the cores listed. Takes precedence over tunthreads.\n"
            "\n"
            "AFFIN arguments take a comma separated list of cores or range of cores, e.g. 1-2,4,7-8.\n"
            "It is recommended to have the same number of UDP threads as tunnel processor threads, in one-arm operation.\n"
            "If unspecified, --udpthreads %d and --tunthreads %d will be assumed as a default, based on the number of cores present.\n"
            "\n"
#ifdef NO_RETURN_TRAFFIC
            "This version of GWLBTun has been compiled with NO_RETURN_TRAFFIC defined.\n"
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
            , progname, progname, numCores(), numCores());
}

/**
 * Handler for when Ctrl-C is received. Sets a global flag so everything can start shutting down.
 *
 * @param sig
 */
void shutdownHandler(int sig)
{
    keepRunning = 0;
}

int main(int argc, char *argv[])
{
    int c;
    int healthCheck = 0, healthSocket;
    int tunnelTimeout = 0;
    int udpthreads = numCores(), tunthreads = numCores();
    std::string udpaffinity, tunaffinity;
    bool detailedHealth = true;

    static struct option long_options[] = {
            {"cmdnew", required_argument, NULL, 'c'},
            {"cmddel", required_argument, NULL, 'r'},
            {"timeout", required_argument, NULL, 't'},
            {"port", required_argument, NULL, 'p'},
            {"debug", no_argument, NULL, 'd'},
            {"hex", no_argument, NULL, 'x'},
            {"help", no_argument, NULL, 'h'},
            {"help", no_argument, NULL, '?'},
            {"udpthreads", required_argument, NULL, 0},    // optind 8
            {"udpaffinity", required_argument, NULL, 0},   // optind 9
            {"tunthreads", required_argument, NULL, 0},    // optind 10
            {"tunaffinity", required_argument, NULL, 0},   // optind 11
            {0, 0, 0, 0}
    };

    // Argument parsing
    int optind;
    while ((c = getopt_long (argc, argv, "h?dxc:r:t:p:s", long_options, &optind)) != -1)
    {
        switch(c)
        {
            case 0:
                // Long option
                switch(optind) {
                    case 8:
                        udpthreads = atoi(optarg);
                        break;
                    case 9:
                        udpaffinity = std::string(optarg);
                        break;
                    case 10:
                        tunthreads = atoi(optarg);
                        break;
                    case 11:
                        tunaffinity = std::string(optarg);
                        break;
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
                debugout = &std::clog;
                if(debug < DEBUG_ON) debug = DEBUG_ON;
                break;
            case 'x':
                hexout = &std::clog;
                if(debug < DEBUG_VERBOSE) debug = DEBUG_VERBOSE;
                break;
            case '?':
            case 'h':
            default:
                printHelp(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // Set up for health check reporting, if requested. We listen on both IPv4 and IPv6 for completeness, although
    // GWLB only supports IPv4.
    if(healthCheck > 0)
    {
        if((healthSocket = socket(AF_INET6, SOCK_STREAM, 0)) == 0)
        {
            perror("Creating health check socket failed");
            exit(EXIT_FAILURE);
        }

        struct sockaddr_in6 addr;
        bzero(&addr, sizeof(addr));

        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(healthCheck);
        addr.sin6_addr = in6addr_any;
        if(bind(healthSocket, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
            perror("Unable to listen to health status port");
            exit(EXIT_FAILURE);
        }
        listen(healthSocket, 3);
    }

    signal(SIGINT, shutdownHandler);

    ThreadConfig udp, tun;
    ParseThreadConfiguration(udpthreads, udpaffinity, &udp);
    ParseThreadConfiguration(tunthreads, tunaffinity, &tun);

    auto gh = new GeneveHandler(&newInterfaceCallback, &deleteInterfaceCallback, tunnelTimeout, udp, tun);
    struct timespec timeout;
    timeout.tv_sec = 1; timeout.tv_nsec = 0;
    fd_set fds;
    int ready;
    int ticksSinceCheck = 60;
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
            *debugout << currentTime() << ": Processing a health check client for " << sockaddrToName((struct sockaddr *)&from) << std::endl;
            performHealthCheck(detailedHealth, gh, hsClient);
            close(hsClient);
            ticksSinceCheck = 60;
        }

        ticksSinceCheck --;
        if(ticksSinceCheck < 0)
        {
            std::string hcText = currentTime() + ": "s + gh->check();
            *debugout << hcText;
            ticksSinceCheck = 60;
        }
    }

    // The loop was interrupted (most likely by Ctrl-C or likewise).  Clean up a few things.
    printf("Shutting down...\n");
    delete(gh);
    if(healthCheck > 0) close(healthSocket);
    printf("Shutdown complete.\n");

    return 0;
}
