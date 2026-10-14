// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// GWLB Tunnel Handling user-space program. See the README.md for details on usage.
//
// Everything main() starts is an object whose constructor starts it and whose destructor stops it, declared
// in run() in the order they depend on each other; returning from run() (normally, or by an exception) takes
// them down in reverse. See run() for the order.

#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/resource.h>
#include <poll.h>
#include <memory>
#include <mutex>
#include <net/if.h>
#include <arpa/inet.h>
#include "GeneveHandler.h"
#include "GwlbtunConfig.h"
#include "HookScripts.h"
#include <thread>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include "utils.h"
#include <csignal>
#include <atomic>
#include <cstring>
#include <cerrno>
#include <climits>
#include <algorithm>
#include <exception>
#include <system_error>
#include <type_traits>
#include "Logger.h"

using namespace std::string_literals;

class Logger *logger;

// A startup failure whose message has been written for the user: logged as-is, then gwlbtun exits.
class StartupError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/**
 * The process's Logger, for the life of main(): sets the global `logger` that LOG() uses. On destruction it
 * clears the global first, then the Logger prints everything still queued.
 */
class ProcessLogger {
public:
    explicit ProcessLogger(const std::string &options) : instance(options) { logger = &instance; }
    ~ProcessLogger() { logger = nullptr; }
    ProcessLogger(const ProcessLogger &) = delete;
    ProcessLogger &operator=(const ProcessLogger &) = delete;

private:
    Logger instance;
};

/**
 * Last words when the process ends through std::terminate() (an exception nothing caught, or one thrown out
 * of a noexcept function): say why on stderr and in the log, give the logging thread a moment to print what
 * it has queued, then abort.
 */
[[noreturn]] static void terminateHandler() noexcept
{
    try {
        std::string why = "std::terminate() called"s;
        if(auto ep = std::current_exception())
        {
            try { std::rethrow_exception(ep); }
            catch(const std::exception &e) { why = "uncaught exception: "s + e.what(); }
            catch(...) { why = "uncaught exception of unknown type"s; }
        }
        fprintf(stderr, "gwlbtun: terminating: %s\n", why.c_str());
        if(logger)
        {
            LOG(LS_CORE, LL_CRITICAL, "Terminating: "s + why);
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
    } catch(...) {
    }
    std::abort();
}

/**
 * The process-wide shutdown request. SIGINT and SIGTERM signal its EventFd (async-signal-safe), which the main
 * loop polls; everything else is stopped by destruction when run() returns. The default handlers are put back
 * on destruction.
 */
class ShutdownSignal {
public:
    ShutdownSignal()
    {
        active = &requested;
        struct sigaction sa{};
        sa.sa_handler = &ShutdownSignal::handler;
        sa.sa_flags = SA_RESTART;   // as signal() did: other threads' blocking calls (sendmsg, accept4) carry on
        sigemptyset(&sa.sa_mask);
        sigaction(SIGINT, &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);
    }
    ~ShutdownSignal()
    {
        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        active = nullptr;
    }
    ShutdownSignal(const ShutdownSignal &) = delete;
    ShutdownSignal &operator=(const ShutdownSignal &) = delete;

    // The request's EventFd: poll its fd, or waitFor() it.
    const EventFd &event() const { return requested; }

private:
    static void handler(int)
    {
        if(auto e = active.load())
            e->signal();
    }
    static inline std::atomic<const EventFd *> active{nullptr};
    EventFd requested;
};

/**
 * A background thread that runs until this object is destroyed. The function is given the thread's own stop
 * event and must return once it's signalled; the destructor signals it and joins. Stopping depends on nothing
 * else having happened first, so however run() is left (a return or an exception), the thread stops.
 */
class BackgroundThread {
public:
    template<class F, class = std::enable_if_t<!std::is_same_v<std::decay_t<F>, BackgroundThread>>>
    explicit BackgroundThread(F &&f) : thread([this, fn = std::forward<F>(f)]() { fn(stop); }) {}
    ~BackgroundThread() { stop.signal(); thread.join(); }
    BackgroundThread(const BackgroundThread &) = delete;
    BackgroundThread &operator=(const BackgroundThread &) = delete;

private:
    EventFd stop;          // ORDER MATTERS: before `thread`, which uses it
    std::thread thread;
};

/**
 * The coarse clock (see utils.h). Constructing it starts a thread that records the start time and then refreshes
 * the clock twice a second; destroying it stops that thread. It gets its own thread so nothing else can stall it:
 * the main loop is busy with health check clients, and the reaper with sweeps. A frozen clock would stop flows
 * from expiring, then expire everything at once when it moved. Nothing reads it before the GeneveHandler
 * exists, and until the first update it reads 0, the start.
 */
class CoarseClock {
    BackgroundThread updater{[](const EventFd &stop) {
        pthread_setname_np(pthread_self(), "gwlbtun Clock");
        initCoarseClock();   // only this thread reads the start time
        do {
            updateCoarseClock();
        } while(!stop.waitFor(500));
    }};
};

/**
 * Lets the detached health-client threads log without outliving the logger. run() opens it after the logger
 * exists and its destructor closes it, waiting for any log call in progress, so no health thread can reach
 * the logger once it may be destroyed. (The threads are not waited for at exit; they hold only their socket
 * and a copy of the response.)
 */
class HealthLogGate {
public:
    HealthLogGate() { std::lock_guard<std::mutex> lk(m); open = true; }
    ~HealthLogGate() { std::lock_guard<std::mutex> lk(m); open = false; }
    HealthLogGate(const HealthLogGate &) = delete;
    HealthLogGate &operator=(const HealthLogGate &) = delete;

    static void log(LogLevel ll, const std::string &msg)
    {
        std::lock_guard<std::mutex> lk(m);
        if(open)
            LOG(LS_HEALTHCHECK, ll, msg);
    }

private:
    static inline std::mutex m;
    static inline bool open = false;
};

/**
 * Build the HTTP/1.1 health response for the GeneveHandler's current state: 200 if everything is well, 503 if not.
 * check() is safe alongside the packet and reaper threads.
 *
 * @param gh The GeneveHandler to report on.
 * @param cfg For -s (status code only) and -j (JSON rather than text).
 */
static std::string buildHealthResponse(const GeneveHandler &gh, const GwlbtunConfig &cfg)
{
    const bool details = cfg.detailedHealth, asJson = cfg.jsonHealth;
    const GeneveHandlerHealthCheck ghhc = gh.check();

    std::stringstream responseStream;
    responseStream << "HTTP/1.1 " << (ghhc.isHealthy() ? "200 OK" : "503 Service Unavailable") << "\r\n"
                   << "Cache-Control: max-age=0, no-cache\r\n"
                   << "Connection: close\r\n"
                   << "Content-Type: " << (asJson ? "application/json" : "text/html") << "\r\n";
    if (details) {
        // Invalid UTF-8 (an interface name can contain any bytes) is replaced rather than thrown on.
        std::string body = asJson ? ghhc.output_json().dump(-1, ' ', false, json::error_handler_t::replace) :
            "<!DOCTYPE html>\n<html lang=\"en-us\">\n<head><title>Health check</title></head><body>" + ghhc.output_str() + "\n</body></html>";
        responseStream << "Content-Length: " << body.length() << "\r\n\r\n" << body;
    } else {
        responseStream << "Content-Length: 0\r\n\r\n";
    }
    return responseStream.str();
}

/**
 * Make sure gwlbtun instances in this network namespace don't share the GENEVE port.
 *
 * The GENEVE sockets use SO_REUSEPORT (one per receiver thread), so a second gwlbtun receiving on the
 * same interfaces would bind the port too and the kernel would split GWLB traffic between the two,
 * each building its own tunnel interfaces. Each instance therefore binds a Linux abstract Unix socket
 * per interface it serves: "gwlbtun:any:6081" with no -I, or "gwlbtun:if:<name>:6081" for each -I
 * interface. Binding one that's taken fails. An all-interfaces instance and an interface-specific one
 * would overlap too, so after binding, each checks /proc/net/unix for the other kind and gives up if it
 * finds one; two that start at the same moment can both give up, which is the safe outcome.
 *
 * Abstract socket names (and /proc/net/unix) are per network namespace, so separate namespaces
 * (containers, `ip netns`) can each run their own gwlbtun. The kernel releases the names when the
 * process exits for any reason, so there is no lock file to go stale.
 *
 * Holding an InstanceLock holds the names; run() keeps it until everything else has been taken down.
 * The constructor throws StartupError if another instance overlaps this one.
 */
class InstanceLock {
public:
    explicit InstanceLock(const std::vector<std::string> &interfaces);
private:
    std::vector<UniqueFd> sockets;
};

InstanceLock::InstanceLock(const std::vector<std::string> &interfaces)
{
    const std::string port = std::to_string(GENEVE_PORT);
    std::vector<std::pair<std::string, std::string>> names;   // (lock name, what it covers)
    if(interfaces.empty())
        names.emplace_back("gwlbtun:any:"s + port, "all interfaces"s);
    for(const auto &i : interfaces)
        names.emplace_back("gwlbtun:if:"s + i + ":"s + port, "interface "s + i);

    for(const auto &[name, what] : names)
    {
        UniqueFd sock(socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0));   // CLOEXEC: hook scripts must not inherit it
        if(!sock)
        {
            const int err = errno;
            throw StartupError("Unable to create the single-instance lock socket: "s + errText(err));
        }
        struct sockaddr_un addr;
        bzero(&addr, sizeof(addr));
        addr.sun_family = AF_UNIX;
        const size_t n = std::min(name.size(), sizeof(addr.sun_path) - 1);
        memcpy(addr.sun_path + 1, name.c_str(), n);   // sun_path[0] == '\0' selects the abstract namespace
        const socklen_t len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n);
        if(bind(sock.get(), (struct sockaddr *)&addr, len) < 0)
        {
            const int err = errno;
            if(err == EADDRINUSE)
                throw StartupError("Another gwlbtun is already serving UDP port "s + port + " on "s + what +
                                   " in this network namespace. Each interface can be served by only one gwlbtun."s);
            throw StartupError("Unable to claim the single-instance lock: "s + errText(err));
        }
        sockets.push_back(std::move(sock));
    }

    // An all-interfaces instance conflicts with every interface-specific one, and vice versa.
    std::ifstream unixSockets("/proc/net/unix");
    std::string line;
    const std::string anyName = "@gwlbtun:any:"s + port;
    const std::string ifPrefix = "@gwlbtun:if:"s;
    const std::string portSuffix = ":"s + port;
    while(std::getline(unixSockets, line))
    {
        auto pos = line.rfind(' ');
        std::string path = (pos == std::string::npos) ? line : line.substr(pos + 1);
        bool otherIsAny = path == anyName;
        bool otherIsIf = path.compare(0, ifPrefix.size(), ifPrefix) == 0 && path.size() > portSuffix.size() &&
                         path.compare(path.size() - portSuffix.size(), portSuffix.size(), portSuffix) == 0;
        if((interfaces.empty() && otherIsIf) || (!interfaces.empty() && otherIsAny))
        {
            throw StartupError("Another gwlbtun is already serving UDP port "s + port + " in this network namespace "s +
                (otherIsAny ? "on all interfaces"s : "on interface "s + path.substr(ifPrefix.size(), path.size() - ifPrefix.size() - portSuffix.size())) +
                ". An instance for all interfaces (no -I) can't run alongside instances for specific interfaces (-I)."s);
        }
    }
}

// Health clients being served. Each runs on its own short-lived thread, so a slow or idle client delays
// only itself; the cap bounds the threads (and fds) a burst of connections can tie up.
static std::atomic<int> healthClientsInFlight{0};
static constexpr int HEALTH_MAX_IN_FLIGHT = 16;
static constexpr int HEALTH_CLIENT_TIMEOUT_MS = 2000;   // whole exchange, per client

// One of the HEALTH_MAX_IN_FLIGHT slots, held while a client is served; `held` is false if all were taken.
class HealthClientSlot {
public:
    HealthClientSlot() : held(healthClientsInFlight.fetch_add(1) < HEALTH_MAX_IN_FLIGHT) { if(!held) healthClientsInFlight--; }
    ~HealthClientSlot() { if(held) healthClientsInFlight--; }
    HealthClientSlot(const HealthClientSlot &) = delete;
    HealthClientSlot &operator=(const HealthClientSlot &) = delete;
    const bool held;
};

// A health client being served: its connection (closed with it), the response to send, and its slot.
struct HealthClient {
    HealthClient(UniqueFd s, std::string a) : sock(std::move(s)), address(std::move(a)) {}
    UniqueFd sock;
    std::shared_ptr<const std::string> response;
    std::string address;   // for the log
    HealthClientSlot slot;
};

/**
 * Serve one health client: read its request up to the end of the headers, send the prepared response, close.
 * Reading the request before closing means close() doesn't find unread data and reset the connection, and
 * closing right after the response (it says "Connection: close") means no client has to time out waiting.
 * Runs on its own detached thread and touches nothing but the socket, the response and HealthLogGate, so it
 * never needs the main thread's objects; at exit it is simply ended with the process.
 *
 * @param client The client; its connection is closed, and its slot released, when the caller destroys it.
 */
static void serveHealthClient(const HealthClient &client)
{
    const int s = client.sock.get();
    const std::string &response = *client.response;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(HEALTH_CLIENT_TIMEOUT_MS);
    auto msLeft = [&deadline]() {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        return (int)std::max<long long>(0, ms);
    };
    const char *timedOutWhile = nullptr;   // set if the deadline passed

    // The request itself is ignored (every path gets the health report); only read to the end of the headers.
    // That's a blank line, which sloppy clients (e.g. printf ... | nc) often end with bare "\n"s rather than
    // "\r\n"s; accept any mix ("\n\r\n" also matches "\r\n\r\n"), so they don't sit out the whole timeout.
    std::string request;
    char buf[1024];
    while(request.find("\n\r\n") == std::string::npos && request.find("\n\n") == std::string::npos && request.size() < 8192)
    {
        struct pollfd pfd{ s, POLLIN, 0 };
        int r = poll(&pfd, 1, msLeft());
        if(r < 0 && errno == EINTR) continue;
        if(r == 0) timedOutWhile = "reading its request";
        if(r <= 0) break;   // timed out, or error
        ssize_t n = recv(s, buf, sizeof(buf), 0);
        if(n < 0 && errno == EINTR) continue;
        if(n <= 0) break;   // client closed, or error
        request.append(buf, (size_t)n);
    }

    size_t sent = 0;
    while(sent < response.size())
    {
        struct pollfd pfd{ s, POLLOUT, 0 };
        int r = poll(&pfd, 1, msLeft());
        if(r < 0 && errno == EINTR) continue;
        if(r == 0) timedOutWhile = "sending the response";
        if(r <= 0) break;
        ssize_t n = send(s, response.data() + sent, response.size() - sent, MSG_NOSIGNAL | MSG_DONTWAIT);
        if(n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if(n <= 0) break;
        sent += (size_t)n;
    }
    if(timedOutWhile)
        HealthLogGate::log(LL_IMPORTANT, "Health check client "s + client.address + " did not finish within "s + std::to_string(HEALTH_CLIENT_TIMEOUT_MS / 1000) +
                           " seconds (timed out "s + timedOutWhile + (sent == response.size() ? "; the response was sent"s : ""s) +
                           "); closed the connection."s);
}

/**
 * The health check listening socket (-p), if one was asked for; none if the port is 0. We listen on both IPv4
 * and IPv6 for completeness, although GWLB reaches its targets over IPv4. Throws StartupError if it can't be set up.
 */
class HealthListener {
public:
    explicit HealthListener(const GwlbtunConfig &cfg);
    int get() const { return sock.get(); }
    explicit operator bool() const { return bool(sock); }

private:
    UniqueFd sock;
};

HealthListener::HealthListener(const GwlbtunConfig &cfg)
{
    const int healthCheck = cfg.healthPort;
    const std::string &healthAddress = cfg.healthAddress, &healthInterface = cfg.healthInterface;
    if(healthCheck <= 0)
        return;

    sock.reset(socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if(!sock)
    {
        const int err = errno;
        throw StartupError("Creating health check socket failed: "s + errText(err));
    }
    const int healthSocket = sock.get();

    // Disable IPV6_V6ONLY to allow IPv4 connections on the IPv6 socket (dual-stack)
    // This is required on RHEL 10+ where IPV6_V6ONLY defaults to 1
    int v6only = 0;
    if(setsockopt(healthSocket, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) < 0)
    {
        const int err = errno;
        LOG(LS_CORE, LL_IMPORTANT, "Warning: Could not disable IPV6_V6ONLY, IPv4 health checks may not work: "s + errText(err));
    }

    // SO_REUSEADDR lets a restarted gwlbtun bind the health port while connections from the
    // previous run are still in TIME_WAIT (GWLB health-checks targets continually),
    // instead of failing with "Address already in use" for up to a minute. On Linux it does
    // NOT allow binding while another socket is listening on the port, so a second gwlbtun
    // using the same health port still fails to start.
    int reuse = 1;
    if(setsockopt(healthSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    {
        const int err = errno;
        LOG(LS_CORE, LL_IMPORTANT, "Warning: Could not set SO_REUSEADDR on the health check socket: "s + errText(err));
    }

    struct sockaddr_in6 addr;
    bzero(&addr, sizeof(addr));

    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(healthCheck);
    addr.sin6_addr = in6addr_any;
    std::string where = "all addresses"s;
    if(!healthAddress.empty())
    {
        // The socket is dual-stack, so an IPv4 address binds as its v4-mapped form (::ffff:a.b.c.d).
        struct in_addr a4;
        if(inet_pton(AF_INET, healthAddress.c_str(), &a4) == 1)
        {
            addr.sin6_addr.s6_addr[10] = 0xff;
            addr.sin6_addr.s6_addr[11] = 0xff;
            memcpy(&addr.sin6_addr.s6_addr[12], &a4, 4);
        }
        else
            inet_pton(AF_INET6, healthAddress.c_str(), &addr.sin6_addr);   // validated by parseHealthListen
        where = healthAddress;
    }
    else if(!healthInterface.empty())
    {
        if(setsockopt(healthSocket, SOL_SOCKET, SO_BINDTODEVICE, healthInterface.c_str(), (socklen_t)healthInterface.size()) < 0)
        {
            const int err = errno;
            throw StartupError("Unable to bind the health check socket to interface "s + healthInterface + ": "s + errText(err));
        }
        where = "interface "s + healthInterface;
    }
    if(bind(healthSocket, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        const int err = errno;
        throw StartupError("Unable to listen to health status port "s + std::to_string(healthCheck) + " on "s + where + ": "s + errText(err));
    }
    if(listen(healthSocket, 16) < 0)
    {
        const int err = errno;
        throw StartupError("Unable to listen on health status port: "s + errText(err));
    }
    LOG(LS_CORE, LL_IMPORTANT, "Health check listening on port %d on %s", healthCheck, where.c_str());
}

/**
 * The health report sent to clients: rebuilt at most once a second, by the main loop (the only caller), so a burst
 * of clients doesn't rebuild it for each one. If building it fails, a bare 503 is sent instead.
 */
class HealthReport {
public:
    std::shared_ptr<const std::string> get(const GeneveHandler &gh, const GwlbtunConfig &cfg)
    {
        const auto now = std::chrono::steady_clock::now();
        if(!response || now - builtAt >= std::chrono::seconds(1))
        {
            try {
                response = std::make_shared<const std::string>(buildHealthResponse(gh, cfg));
            } catch(const std::exception &e) {
                LOG(LS_HEALTHCHECK, LL_CRITICAL, "Unable to build the health check report: "s + e.what());
                response = std::make_shared<const std::string>("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
            }
            builtAt = now;
        }
        return response;
    }

private:
    std::shared_ptr<const std::string> response;
    std::chrono::steady_clock::time_point builtAt;
};

/**
 * Accept one health check client and start a thread to serve it.
 *
 * @return false if accept() failed (for example out of file descriptors), so the caller can back off.
 */
static bool acceptHealthClient(const HealthListener &health, HealthReport &report, const GeneveHandler &gh, const GwlbtunConfig &cfg)
{
    struct sockaddr_in6 from;
    socklen_t fromlen = sizeof(from);
    UniqueFd sock(accept4(health.get(), (struct sockaddr *)&from, &fromlen, SOCK_CLOEXEC));
    if(!sock)
    {
        const int err = errno;
        LOG(LS_HEALTHCHECK, LL_IMPORTANT, "Unable to accept health check client: "s + errText(err));
        return false;
    }
    auto client = std::make_unique<HealthClient>(std::move(sock), sockaddrToName((struct sockaddr *)&from));
    if(!client->slot.held)
    {
        LOG(LS_HEALTHCHECK, LL_IMPORTANT, "Too many health check clients in progress ("s + std::to_string(HEALTH_MAX_IN_FLIGHT) +
            "); closing the connection from "s + client->address + "."s);
        return true;   // destroying `client` closes the connection
    }
    LOG(LS_HEALTHCHECK, LL_DEBUG, "Processing a health check client for " + client->address);
    client->response = report.get(gh, cfg);
    // The thread owns the client from here: its connection is closed and its slot released when it ends. If
    // the thread can't be started, the client is destroyed with the callable, which does the same.
    try {
        std::thread([c = std::move(client)]() { serveHealthClient(*c); }).detach();
    } catch(const std::system_error& e) {
        LOG(LS_HEALTHCHECK, LL_IMPORTANT, "Unable to start a thread for a health check client: "s + e.what());
    }
    return true;
}

/**
 * Raise the open-file soft limit to the hard limit, and log roughly how many endpoints fit. Each endpoint holds
 * several fds per tunnel thread (see below), so a many-core host can run out at the second or third endpoint
 * under the usual 1024 soft limit when gwlbtun isn't started by the systemd unit (which sets LimitNOFILE).
 *
 * @return The soft limit gwlbtun started with, which hook scripts get back (see HookScripts).
 */
static rlim_t raiseOpenFileLimit(const GwlbtunConfig &cfg)
{
    struct rlimit rl;
    if(getrlimit(RLIMIT_NOFILE, &rl) != 0)
        return RLIM_INFINITY;
    const rlim_t original = rl.rlim_cur;
    if(rl.rlim_cur < rl.rlim_max)
    {
        struct rlimit raised = rl;
        raised.rlim_cur = rl.rlim_max;
        if(setrlimit(RLIMIT_NOFILE, &raised) == 0)
            rl = raised;
        else
        {
            const int err = errno;
            LOG(LS_CORE, LL_IMPORTANT, "Unable to raise the open file limit from "s + std::to_string(rl.rlim_cur) + " to "s +
                std::to_string(rl.rlim_max) + ": "s + errText(err));
        }
    }

    const size_t perEndpoint = GeneveHandlerENI::fdsPerEndpoint(cfg);
    const size_t base = cfg.udpThreadCount() + 32;   // GENEVE sockets, and the logger, health, lock and std fds with room to spare
    const size_t limit = rl.rlim_cur == RLIM_INFINITY ? SIZE_MAX : (size_t)rl.rlim_cur;
    const size_t fits = limit > base ? (limit - base) / perEndpoint : 0;
    const LogLevel level = fits < 4 ? LL_IMPORTANT : LL_INFO;
    LOG(LS_CORE, level, "Open file limit "s + std::to_string(limit) + "; each GWLB endpoint uses about "s +
        std::to_string(perEndpoint) + " file descriptors, so about "s + std::to_string(fits) + " endpoints fit."s +
        (fits < 4 ? " Raise the hard limit (ulimit -Hn, or LimitNOFILE= in a systemd unit) or use fewer tunnel threads."s : ""s));
    return original;
}

/**
 * Run gwlbtun until a shutdown is requested. The objects below start everything, in the order declared, and
 * are destroyed in reverse when this returns or throws; their comments say why each is where it is. There is
 * no separate stop step: the ShutdownSignal ends the main loop, and leaving this function does the rest.
 * Health client threads are not waited for.
 *
 * @return The process exit status.
 */
static int run(const GwlbtunConfig &cfg)
{
    // First, so a signal during startup still shuts down cleanly.
    ShutdownSignal shutdown;

    // Refuse to start if another gwlbtun already serves the GENEVE port on the same interfaces in this
    // network namespace. Held until everything else, GENEVE sockets included, is gone.
    InstanceLock instanceLock(cfg.interfaces);

    // Used by every endpoint, so it outlives the GeneveHandler. Built after raising the open-file limit, so it
    // knows the limit to give scripts back.
    HookScripts hookScripts(cfg.createHook, cfg.destroyHook, raiseOpenFileLimit(cfg));
    HealthListener health(cfg);
    HealthLogGate healthLogGate;   // for the health client threads

    // The flow caches read the coarse clock from the first packet on.
    CoarseClock coarseClock;

    auto logReserve = [](const std::string &which, const std::array<std::size_t, 6> &r) {
        LOG(LS_CORE, LL_IMPORTANT, "Flow-cache reserve (%s): v4[tcp=%zu udp=%zu other=%zu] v6[tcp=%zu udp=%zu other=%zu]",
            which.c_str(), r[0], r[1], r[2], r[3], r[4], r[5]);
    };
    logReserve("default, entries", cfg.defaultReserve);
    for(const auto& kv : cfg.perEndpointReserve)
        logReserve("vpce-"s + MakeGwlbeStr(kv.first), kv.second);

    // The UDP threads, then endpoints as traffic arrives. Destroying it stops the UDP threads, then destroys
    // every endpoint (running its DESTROY hook).
    GeneveHandler gh(cfg, hookScripts);

    // Flow-cache expiry and idle-endpoint teardown, every 60 seconds, on their own thread so the O(N) scans
    // never stall the main loop's health checks. It uses the GeneveHandler, so it's stopped and joined first.
    BackgroundThread reaper([&gh](const EventFd &stop) {
        pthread_setname_np(pthread_self(), "gwlbtun Reaper");
        while(!stop.waitFor(60 * 1000))
            try {
                gh.sweep();
            } catch(const std::exception &e) {
                LOG(LS_CORE, LL_CRITICAL, "Flow-cache and idle endpoint sweep failed: "s + e.what() + ". Trying again at the next sweep."s);
            }
    });

    // Wait for a shutdown request, serving health check clients meanwhile. Without a listener its fd is -1,
    // which poll() ignores.
    HealthReport healthReport;
    struct pollfd pfds[2] = { { shutdown.event().get(), POLLIN, 0 }, { health.get(), POLLIN, 0 } };
    for(;;)
    {
        if(poll(pfds, 2, -1) < 0)
        {
            const int err = errno;
            if(err != EINTR)
            {
                LOG(LS_CORE, LL_IMPORTANT, "poll() in the main loop failed: "s + errText(err));
                shutdown.event().waitFor(100);
            }
            continue;
        }
        if(pfds[0].revents)
            break;
        if((pfds[1].revents & POLLIN) && !acceptHealthClient(health, healthReport, gh, cfg))
            shutdown.event().waitFor(100);   // e.g. out of file descriptors: the listener stays readable, so don't spin
    }

    // Interrupted (most likely by Ctrl-C or likewise). Leaving this function shuts everything down.
    LOG(LS_CORE, LL_IMPORTANT, "Shutting down.");
    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
    GwlbtunConfig cfg;
    try {
        cfg = GwlbtunConfig::fromCommandLine(argc, argv);
    } catch(const ConfigError &e) {
        fprintf(stderr, "%s\n", e.what());
        return EXIT_FAILURE;
    }
    if(cfg.helpRequested)
    {
        fputs(GwlbtunConfig::helpText(argv[0]).c_str(), stderr);
        return EXIT_FAILURE;
    }
    if(cfg.showConfigRequested)
    {
        fputs(cfg.toYaml().c_str(), stdout);
        return EXIT_SUCCESS;
    }

    std::set_terminate(terminateHandler);

    // The logger outlives everything else, so whatever stops gwlbtun is logged; its destructor prints
    // anything still queued before returning.
    ProcessLogger processLogger(cfg.logging);
    LOG(LS_CORE, LL_IMPORTANT, "AWS Gateway Load Balancer Tunnel Handler v%d.%d (%s) built %s", VERSION_MAJOR, VERSION_MINOR, GIT_DESCRIBE, BUILD_TIMESTAMP);
    cfg.logResults();
    if(!cfg.configFile.empty())
        LOG(LS_CORE, LL_IMPORTANT, "Configuration read from "s + cfg.configFile + " (command-line options override it)."s);

    try {
        int status = run(cfg);
        if(status == EXIT_SUCCESS)
            LOG(LS_CORE, LL_IMPORTANT, "Shutdown complete.");
        return status;
    } catch(const StartupError &e) {
        LOG(LS_CORE, LL_CRITICAL, std::string(e.what()));   // std::string: never a printf format
    } catch(const std::exception &e) {
        LOG(LS_CORE, LL_CRITICAL, "Fatal error: "s + e.what());
    }
    return EXIT_FAILURE;
}
