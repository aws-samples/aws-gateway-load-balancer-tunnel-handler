// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * TunInterface handles creating and processing traffic received on TUN interfaces. This class:
 * - Creates the requested Tun interface
 * - Launches a thread to service that interface
 * - Takes a callback function (recvDispatcher) which is called for each packet received by that interface.
 * - Provides a status() function that returns the packet counters and checks that the thread is still alive.
 */

#include "TunInterface.h"

#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include <sys/ioctl.h>
#include <unistd.h>
#include <exception>
#include <iostream>
#include "utils.h"

using namespace std::string_literals;

/**
 * Constructor. Build a TUN interface and start listening for packets on it.
 *
 * @param devname The name of the TUN itnerface to build.
 * @param mtu MTU to set the interface to.
 * @param recvDispatcher Function the thread should callback to on packets received.
 */
TunInterface::TunInterface(std::string devname, int mtu, tunCallback recvDispatcher)
: lastPacket(std::chrono::steady_clock::now()),pktsIn(0),pktsOut(0),bytesIn(0),bytesOut(0), shutdownRequested(false), recvDispatcher(std::move(recvDispatcher))
{
    struct ifreq ifr;

    // Code adapted from Linux Documentation/networking/tuntap.txt to create the tun device.
    if((fd = open("/dev/net/tun", O_RDWR)) < 0)
        throw std::system_error(errno, std::generic_category(), "Unable to open /dev/net/tun");

    bzero(&ifr, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, devname.c_str(), IFNAMSIZ);
    this->devname = devname;

    if(ioctl(fd, TUNSETIFF, (void *)&ifr) < 0)
        throw std::system_error(errno, std::generic_category(), "Unable to create TUN device (does this process have CAP_NET_ADMIN capability?)");

    // Mark the tun device link up. We need a dummy socket to do this call.
    int dummy = socket(PF_INET, SOCK_DGRAM, 0);
    if(ioctl(dummy, SIOCGIFFLAGS, (void *)&ifr) < 0)
        throw std::system_error(errno, std::generic_category(), "Unable to get device flags");

    ifr.ifr_flags |= IFF_UP;        // Set interface is up
    ifr.ifr_flags |= IFF_RUNNING;   // Interface is running
    ifr.ifr_flags &= ~IFF_POINTOPOINT;
    if(ioctl(dummy, SIOCSIFFLAGS, (void *)&ifr) < 0)
        throw std::system_error(errno, std::generic_category(), "Unable to set device flags");

    // Set the MTU to the GWLB standard (8500)
    ifr.ifr_mtu = mtu;
    if(ioctl(dummy, SIOCSIFMTU, (void *)&ifr) < 0)
        throw std::system_error(errno, std::generic_category(), "Unable to set MTU");
    close(dummy);

    // Launch receiving thread
    recvThread = std::async(&TunInterface::recvThreadFunction, this);
}

/**
 * Thread for the tunnel handler. Waits for packets to come in, then calls recvDispatch.
 *
 * @return Never returns until termination signal is sent.
 */
int TunInterface::recvThreadFunction()
{
    unsigned char *pktbuf;

    pthread_setname_np(pthread_self(), "gwlbtun (Tun)");

    // Static packet processing buffer.
    pktbuf = new unsigned char[65535];

    // Receive packets and dispatch them. Additionally, ensure a check at least every second to make sure a
    // shutdown hasn't been requested.
    ssize_t msgLen;
    struct timeval tv;
    fd_set readfds;
    while(!shutdownRequested)
    {
        tv.tv_sec = 1; tv.tv_usec = 0;
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        select(fd + 1, &readfds, nullptr, nullptr, &tv);
        if(FD_ISSET(fd, &readfds))
        {
            // The tun interface has received packets. Drain all, dispatching each.
            msgLen = read(fd, pktbuf, 65534);   // Remember: TUN devices always return 1 and only 1 packet on read()
            lastPacket = std::chrono::steady_clock::now();
            try {
                recvDispatcher(pktbuf, msgLen);
            }
            catch (std::exception& e) {
                std::cerr << currentTime() << "Tunnel interface " << devname << " packet dispatch function failed: " << e.what() << std::endl;
            }
            pktsIn ++; bytesIn += msgLen;
        }
    }
    delete [] pktbuf;
    return(0);
}

/**
 * Destructor. Signals the thread to stop, waits for it to shut down, destroys the TUN interface, and returns.
 */
TunInterface::~TunInterface() {
    shutdownRequested = true;
    // The std::async threads will see that boolean change within 1 second, then exit, which allows the
    // async object to finish its destruction.
    auto status = recvThread.wait_for(std::chrono::seconds(2));
    while(status == std::future_status::timeout)
    {
        std::cerr << currentTime() << ": Tunnel thread has not yet shutdown - waiting more." << std::endl;
        status = recvThread.wait_for(std::chrono::seconds(2));
    }
    close(fd);
}

/**
 * Send a packet out the TUN interface. Updates internal counters as well.
 *
 * @param pkt Buffer pointing to the packet to send
 * @param pktlen Packet length
 */
void TunInterface::writePacket(unsigned char *pkt, ssize_t pktlen)
{
    lastPacket = std::chrono::steady_clock::now();
    pktsOut ++; bytesOut += pktlen;
    write(fd, (void *)pkt, pktlen);
}

/**
 * Check on the status of the TUN receiver thread.
 *
 * @return true if the thread is still alive, false otherwise.
 */
bool TunInterface::healthCheck() {
    auto status = recvThread.wait_for(std::chrono::seconds(0));
    if(status != std::future_status::timeout)
    {
        return false;
    }
    return true;
}

/**
 * Human-readable status check of the module.
 *
 * @return A string containing thread status and packet counters.
 */
std::string TunInterface::status() {
    std::string ret;

    ret += "Interface "s + devname;
    if(healthCheck())
        ret += ": Healthy, "s;
    else {
        ret += ": NOT healthy, "s;
    }
    ret += std::to_string(pktsIn) + " packets in from OS, "s + std::to_string(bytesIn) + " bytes in from OS, "s +
           std::to_string(pktsOut) + " packets out to OS, "s + std::to_string(bytesOut) + " bytes out to OS, "s;
    ret += timepointDelta(std::chrono::steady_clock::now(), lastPacket) + " since last packet.\n";

    return ret;
}
