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
    std::cout << "New interface " << ingressInt << " and " << egressInt << " for ENI ID " << std::hex << eniId << std::dec << " created." << std::endl;
    if(newCmd.length() > 0)
    {
        std::stringstream ss;
        ss << newCmd << " CREATE " << ingressInt << " " << egressInt << " " << std::hex << eniId << std::dec;
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
    std::cout << "Removing interface " << ingressInt << " and " << egressInt << " for ENI ID " << std::hex << eniId << std::dec << "." << std::endl;
    if(delCmd.length() > 0)
    {
        std::stringstream ss;
        ss << delCmd << " DESTROY " << ingressInt << " " << egressInt << " " << std::hex << eniId << std::dec;
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
            "---------------------------------------------------------------------------------------------------------\n"
            "Tunnel command arguments:\n"
            "The commands will be called with the following arguments:\n"
            "1: The string 'CREATE' or 'DESTROY', depending on which operation is occurring.\n"
            "2: The interface name of the ingress interface (gwi-<X>).\n"
            "3: The interface name of the egress interface (gwo-<X>).  Packets can be sent out via in the ingress\n"
            "   as well, but having two different interfaces makes routing and iptables easier.\n"
            "4: The GWLBE ENI ID in base 16 (e.g. '2b8ee1d4db0c51c4') associated with this tunnel.\n"
            "\n"
            "The <X> in the interface name is replaced with the base 60 encoded ENI ID (to fit inside the 15 character\n"
            "device name limit).\n"
            , progname, progname);
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
    bool detailedHealth = true;

    // Argument parsing
    while ((c = getopt (argc, argv, "hdxc:r:t:p:s")) != -1)
    {
        switch(c)
        {
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
                debugout = &std::cerr;
                if(debug < DEBUG_ON) debug = DEBUG_ON;
                break;
            case 'x':
                hexout = &std::cerr;
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
            perror("Creating health check socket filaed");
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

    auto gh = new GeneveHandler(&newInterfaceCallback, &deleteInterfaceCallback, tunnelTimeout);
    struct timespec timeout;
    timeout.tv_sec = 1; timeout.tv_nsec = 0;
    fd_set fds;
    int ready;
    int ticksSinceCheck = 60;
    while(keepRunning)
    {
        FD_ZERO(&fds);
        FD_SET(healthSocket, &fds);

        ready = pselect(healthSocket + 1, &fds, nullptr, nullptr, &timeout, nullptr);
        if(ready > 0 && FD_ISSET(healthSocket, &fds))
        {
            // Process a health check client
            int hsClient;
            struct sockaddr_in6 from;
            socklen_t fromlen = sizeof(from);
            hsClient = accept(healthSocket, (struct sockaddr *)&from, &fromlen);
            *debugout << "Processing a health check client for " << sockaddrToName((struct sockaddr *)&from) << std::endl;
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
    close(healthSocket);
    printf("Shutdown complete.\n");

    return 0;
}
