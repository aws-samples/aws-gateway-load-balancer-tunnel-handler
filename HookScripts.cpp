// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * Runs the user's CREATE/DESTROY scripts for each GWLB endpoint. See HookScripts.h.
 */

#include "HookScripts.h"

#include <cerrno>
#include <cstring>
#include <exception>
#include <pthread.h>
#include <sched.h>
#include <spawn.h>
#include <sys/wait.h>
#include <utility>
#include "utils.h"
#include "Logger.h"

using namespace std::string_literals;

extern char **environ;

HookScripts::HookScripts(std::string createCmdParam, std::string destroyCmdParam, rlim_t childFileLimitParam)
: createCmd(std::move(createCmdParam)), destroyCmd(std::move(destroyCmdParam)), childFileLimit(childFileLimitParam)
{
}

namespace {
// Widens the calling thread's CPU mask to every CPU the process may use, and puts the original back when
// destroyed. A new process inherits its creator's mask.
class ProcessWideAffinity {
public:
    ProcessWideAffinity() : saved(pthread_getaffinity_np(pthread_self(), sizeof(mask), &mask) == 0) { setCurrentThreadAffinity(-1); }
    ~ProcessWideAffinity() { if(saved) pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask); }
    ProcessWideAffinity(const ProcessWideAffinity &) = delete;
    ProcessWideAffinity &operator=(const ProcessWideAffinity &) = delete;
private:
    cpu_set_t mask;
    const bool saved;
};
} // namespace

HookScripts::Endpoint::Endpoint(const HookScripts &hooksParam, std::string ingressIntParam, std::string egressIntParam, gwlbeid_t eniParam)
: hooks(hooksParam), ingressInt(std::move(ingressIntParam)), egressInt(std::move(egressIntParam)), eni(eniParam)
{
    LOG(LS_CORE, LL_IMPORTANT, "New interface "s + ingressInt + " and "s + egressInt + " for GWLB endpoint vpce-"s + MakeGwlbeStr(eni) + " created."s);
    hooks.run(hooks.createCmd, "CREATE", ingressInt, egressInt, eni);
}

HookScripts::Endpoint::~Endpoint()
{
    try {
        LOG(LS_CORE, LL_IMPORTANT, "Removing interface "s + ingressInt + " and "s + egressInt + " for GWLB endpoint vpce-"s + MakeGwlbeStr(eni) + "."s);
    } catch(...) {
        // Only possible if building the message runs out of memory. Run DESTROY regardless.
    }
    hooks.run(hooks.destroyCmd, "DESTROY", ingressInt, egressInt, eni);
}

/**
 * Run a create/destroy hook and wait for it to finish.
 *
 * The user's command string is still interpreted by /bin/sh (so a -c/-r value may include its own
 * arguments), but the values gwlbtun supplies -- mode, interface names and endpoint ID -- are
 * passed as separate positional arguments ("$@") and are never parsed by the shell.
 *
 * What the script inherits:
 *  - CPU affinity: a new process inherits its creator's, and CREATE runs on whichever UDP receiver thread
 *    saw the endpoint's first packet, which may be pinned to one CPU. The calling thread's mask is widened
 *    to the process's while the script is started, so the script (and anything it starts) isn't confined
 *    to that CPU.
 *  - File descriptors: only stdin, stdout and stderr. Every fd gwlbtun opens is close-on-exec. Otherwise a
 *    script that leaves a process running would hold gwlbtun's tun queues (keeping gwi-/gwo- alive, so
 *    re-creating them fails), GENEVE sockets (taking a share of port 6081's traffic after gwlbtun exits)
 *    and health port.
 *  - Open-file limit: the soft limit gwlbtun started with, not the raised one (programs using select()
 *    expect at most 1024).
 *
 * @param cmd The -c or -r command string; nothing is run if it's empty.
 * @param mode "CREATE" or "DESTROY".
 * @param ingressInt Ingress (gwi-) interface name.
 * @param egressInt Egress (gwo-) interface name.
 * @param eni GWLB endpoint ID.
 */
void HookScripts::run(const std::string &cmd, const char *mode, const std::string &ingressInt, const std::string &egressInt, gwlbeid_t eni) const noexcept
{
    if(cmd.empty())
        return;
    try {
        const std::string eniStr = MakeGwlbeStr(eni);
        const std::string script = (childFileLimit == RLIM_INFINITY ? ""s : "ulimit -S -n "s + std::to_string(childFileLimit) + " 2>/dev/null; "s) +
                                   cmd + " \"$@\"";
        const char *argv[] = { "/bin/sh", "-c", script.c_str(), "sh", mode, ingressInt.c_str(), egressInt.c_str(), eniStr.c_str(), nullptr };

        pid_t pid;
        int rc;
        {
            ProcessWideAffinity affinity;
            rc = posix_spawn(&pid, "/bin/sh", nullptr, nullptr, const_cast<char * const *>(argv), environ);
        }
        if(rc != 0)
        {
            LOG(LS_CORE, LL_CRITICAL, "Unable to run "s + mode + " hook '"s + cmd + "': "s + errText(rc));
            return;
        }

        int status = 0;
        while(waitpid(pid, &status, 0) < 0)
        {
            const int err = errno;
            if(err != EINTR)
            {
                LOG(LS_CORE, LL_IMPORTANT, "Unable to wait for "s + mode + " hook '"s + cmd + "': "s + errText(err));
                return;
            }
        }
        if(WIFEXITED(status) && WEXITSTATUS(status) != 0)
            LOG(LS_CORE, LL_IMPORTANT, mode + " hook '"s + cmd + "' exited with status "s + std::to_string(WEXITSTATUS(status)) + "."s);
        else if(WIFSIGNALED(status))
            LOG(LS_CORE, LL_IMPORTANT, mode + " hook '"s + cmd + "' was killed by signal "s + std::to_string(WTERMSIG(status)) + "."s);
    } catch(...) {
        // Only possible if building a message runs out of memory; this must not throw.
        try { LOG(LS_CORE, LL_CRITICAL, "Unable to run "s + mode + " hook '"s + cmd + "'."s); } catch(...) {}
    }
}
