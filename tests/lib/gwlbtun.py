# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Run gwlbtun under test: the binary (Build), one running process (Gwlbtun), and a recording hook script
(HookRecorder)."""

import json
import os
import re
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request

from .geneve import GENEVE_PORT
from .netutil import udp_sockets, wait_for

SANITIZER_RE = re.compile(r"AddressSanitizer|LeakSanitizer|ThreadSanitizer|runtime error:")


class Build:
    """The gwlbtun binary under test and what it was built with."""

    def __init__(self, path):
        self.path = os.path.abspath(path)
        # NO_RETURN_TRAFFIC builds have no tunnel threads (and no flow cache or gwo- device).
        self.return_traffic = self.run("--tunthreads", "1", "--show-config").returncode == 0

    def run(self, *args, timeout=10, wrapper=()):
        """Run to completion (configuration, help); stdout and stderr together in .out."""
        p = subprocess.run(list(wrapper) + [self.path] + [str(a) for a in args], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, universal_newlines=True, timeout=timeout)
        p.out = p.stdout
        return p

    def show_config(self, *args):
        p = self.run(*args, "--show-config")
        return p.out

    def threads(self, udp=2, tun=2):
        """Arguments for a small, fixed thread layout (tests shouldn't depend on the host's CPU count)."""
        a = ["--udpthreads", str(udp)]
        if self.return_traffic:
            a += ["--tunthreads", str(tun)]
        return a


def _health_target(args):
    """(host, port) gwlbtun's -p/--port argument listens on, or None."""
    for i, a in enumerate(args):
        if a in ("-p", "--port") and i + 1 < len(args):
            v = args[i + 1]
            host, _, port = v.rpartition(":")
            if not port.isdigit() or int(port) == 0:
                return None
            if host.startswith("["):
                return host.strip("[]"), int(port)
            try:
                socket.inet_aton(host)
                return host, int(port)
            except OSError:
                return "127.0.0.1", int(port)
    return None


class Gwlbtun:
    """One gwlbtun process. Output goes to `log_path`. The constructor starts it and, with wait=True, waits
    until it has bound its GENEVE sockets (and answers health checks, with -p or health_port)."""

    def __init__(self, build, args, log_path, wrapper=(), wait=True, ready_timeout=15, min_udp_sockets=1, health_port=None,
                 sanitizer_ignore=None):
        self.build, self.args, self.log_path = build, [str(a) for a in args], str(log_path)
        self.sanitizer_ignore = re.compile(sanitizer_ignore) if sanitizer_ignore else None
        # health_port: where the health check listens when -p isn't on the command line (set in a -f file).
        self.health_target = ("127.0.0.1", health_port) if health_port else _health_target(self.args)
        self._logf = open(self.log_path, "w")
        self.proc = subprocess.Popen(list(wrapper) + [build.path] + self.args, stdout=self._logf,
                                     stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
        if wait:
            self.wait_ready(ready_timeout, min_udp_sockets)

    @property
    def pid(self):
        return self.proc.pid

    def alive(self):
        return self.proc.poll() is None

    def log(self):
        with open(self.log_path, errors="replace") as fh:
            return fh.read()

    def wait_ready(self, timeout=15, min_udp_sockets=1):
        def ready():
            if not self.alive():
                raise AssertionError("gwlbtun exited (%s) during startup:\n%s" % (self.proc.returncode, self.log()[-2000:]))
            if udp_sockets(GENEVE_PORT) < min_udp_sockets:
                return False
            return self.health_target is None or self.health_status() is not None
        wait_for(ready, timeout, what="gwlbtun to start")

    def wait_log(self, pattern, timeout=5.0, count=1):
        """Wait until `pattern` (a regex) has matched at least `count` log lines; return the matches."""
        rx = re.compile(pattern)

        def found():
            m = [line for line in self.log().splitlines() if rx.search(line)]
            return m if len(m) >= count else None
        return wait_for(found, timeout, what="log line /%s/ x%d" % (pattern, count))

    def log_lines(self, pattern):
        rx = re.compile(pattern)
        return [line for line in self.log().splitlines() if rx.search(line)]

    def _url(self, path, host=None):
        h, port = self.health_target
        h = host or h
        return "http://%s:%d%s" % ("[%s]" % h if ":" in h else h, port, path)

    def health_status(self, host=None, timeout=1.0):
        """The health check's HTTP status code, or None if it doesn't answer."""
        try:
            with urllib.request.urlopen(self._url("/", host), timeout=timeout) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except (OSError, ValueError):
            return None

    def health_text(self, host=None, timeout=3.0):
        try:
            with urllib.request.urlopen(self._url("/", host), timeout=timeout) as r:
                return r.read().decode()
        except urllib.error.HTTPError as e:
            return e.read().decode()

    def health(self, host=None, timeout=3.0):
        """The health check's JSON (gwlbtun must run with -j)."""
        return json.loads(self.health_text(host, timeout))

    def counters(self):
        s = self.health()["summary"]
        return s["totalPktsIn"], s["totalPktsOut"], s["totalPktsDropped"]

    def stop(self, sig=signal.SIGTERM, timeout=30.0):
        """Signal and wait; returns seconds taken. Kills it (and fails) if it doesn't stop in time."""
        if not self.alive():
            self._logf.close()
            return 0.0
        t = time.monotonic()
        self.proc.send_signal(sig)
        try:
            self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
            raise AssertionError("gwlbtun did not stop within %.0fs:\n%s" % (timeout, self.log()[-2000:]))
        finally:
            self._logf.close()
        return time.monotonic() - t

    def sanitizer_findings(self):
        return [line for line in self.log().splitlines() if SANITIZER_RE.search(line)
                and not (self.sanitizer_ignore and self.sanitizer_ignore.search(line))]


class HookRecorder:
    """A -c/-r hook script that appends one line per call to a file:
    mode, ingress and egress names, whether each exists right now, endpoint ID, soft open-file limit and the
    file descriptors it inherited. Optionally sleeps in CREATE for one endpoint (slow_create)."""

    def __init__(self, directory, slow_create=None, slow_secs=3):
        self.path = os.path.join(str(directory), "hook.sh")
        self.out = os.path.join(str(directory), "hook.out")
        slow = ""
        if slow_create:
            slow = '[ "$1" = CREATE ] && [ "$4" = %s ] && sleep %d\n' % (slow_create, slow_secs)
        with open(self.path, "w") as fh:
            fh.write("#!/bin/bash\n"
                     "start=$(date +%%s.%%N)\n"
                     "a=no; b=no\n"
                     'ip link show dev "$2" >/dev/null 2>&1 && a=yes\n'
                     'ip link show dev "$3" >/dev/null 2>&1 && b=yes\n'
                     "fds=$(ls /proc/$$/fd | grep -vxE '[012]|255' | tr '\\n' ',')\n"
                     "%s"
                     'echo "$1 $2 $a $3 $b $4 $(ulimit -Sn) $fds $start $(date +%%s.%%N)" >> %s\n' % (slow, self.out))
        os.chmod(self.path, 0o755)

    def args(self):
        return ["-c", self.path, "-r", self.path]

    def records(self):
        """One dict per hook call, in order."""
        try:
            with open(self.out) as fh:
                lines = fh.read().splitlines()
        except FileNotFoundError:
            return []
        out = []
        for line in lines:
            f = line.split(" ")
            out.append({"mode": f[0], "ingress": f[1], "ingress_exists": f[2] == "yes", "egress": f[3],
                        "egress_exists": f[4] == "yes", "endpoint": f[5], "nofile": int(f[6]),
                        "fds": [x for x in f[7].split(",") if x], "start": float(f[8]), "end": float(f[9])})
        return out

    def calls(self, mode):
        return [r for r in self.records() if r["mode"] == mode]
