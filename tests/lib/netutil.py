# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Small helpers for the host's (or the test network namespace's) network state."""

import contextlib
import ctypes
import os
import shutil
import subprocess
import time


def wait_for(pred, timeout=5.0, interval=0.05, what="condition"):
    """Poll pred() until it returns something truthy; return that. AssertionError on timeout."""
    end = time.monotonic() + timeout
    while True:
        v = pred()
        if v:
            return v
        if time.monotonic() >= end:
            raise AssertionError("timed out after %.1fs waiting for %s" % (timeout, what))
        time.sleep(interval)


def sh(*cmd, check=True):
    return subprocess.run(cmd, check=check, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True).stdout


def _devices():
    # /proc/net/dev is per network namespace; /sys/class/net shows the namespace sysfs was mounted in.
    with open("/proc/net/dev") as fh:
        return [line.split(":", 1)[0].strip() for line in fh.readlines()[2:]]


def gw_devices():
    """gwi-/gwo- devices present now."""
    return sorted(d for d in _devices() if d.startswith(("gwi-", "gwo-")))


def device_exists(name):
    return name in _devices()


def udp_sockets(port):
    """Number of UDP sockets (IPv4 and IPv6) bound to `port` in this network namespace."""
    n = 0
    for f in ("/proc/net/udp", "/proc/net/udp6"):
        try:
            with open(f) as fh:
                next(fh)
                n += sum(1 for line in fh if line.split()[1].endswith(":%04X" % port))
        except FileNotFoundError:
            pass
    return n


def udp_noports():
    """The Udp NoPorts counter: datagrams that found no socket."""
    with open("/proc/net/snmp") as fh:
        rows = [line.split() for line in fh if line.startswith("Udp:")]
    return int(rows[1][rows[0].index("NoPorts")])


def default_route_interface():
    with open("/proc/net/route") as fh:
        next(fh)
        for line in fh:
            f = line.split()
            if f[1] == "00000000":
                return f[0]
    return None


def rx_queue_count(ifname):
    """Receive queues of an ENA-style interface, from its '<ifname>-Tx-Rx-<n>' IRQs (0 if none)."""
    with open("/proc/interrupts") as fh:
        return sum(1 for line in fh if (ifname + "-Tx-Rx-") in line)


def raw_sockets(pid):
    """Raw sockets open in the process's network namespace."""
    with open("/proc/%d/net/raw" % pid) as fh:
        return max(0, len(fh.readlines()) - 1)


@contextlib.contextmanager
def dummy_interface(name, address):
    """A dummy interface with an IPv4 address, removed afterwards: a second "network" to bind to with -I/-p."""
    sh("ip", "link", "add", name, "type", "dummy")
    try:
        sh("ip", "addr", "add", address + "/24", "dev", name)
        sh("ip", "link", "set", name, "up")
        yield name
    finally:
        sh("ip", "link", "del", name, check=False)


@contextlib.contextmanager
def tun_device(name):
    """A pre-existing multi-queue tun device, removed afterwards."""
    sh("ip", "tuntap", "add", "dev", name, "mode", "tun", "multi_queue")
    try:
        yield name
    finally:
        sh("ip", "tuntap", "del", "dev", name, "mode", "tun", "multi_queue", check=False)


def have(tool):
    return shutil.which(tool) is not None


_CLONE_NEWNET = 0x40000000


def _setns(fd):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.setns(fd, _CLONE_NEWNET) != 0:
        e = ctypes.get_errno()
        raise OSError(e, "setns: " + os.strerror(e))


class PeerNamespace:
    """A second network namespace joined to this one by a veth pair, to play GWLB from a separate host:
    `local_addr` on `local_dev` here, `peer_addr` over there. Sockets created inside `with peer.inside():`
    belong to the peer namespace (setns() on this thread; pytest runs tests on one thread)."""

    def __init__(self, name="gt-gwlb", local_dev="gt-v0", local_addr="10.253.0.1", peer_addr="10.253.0.2"):
        self.name = "%s-%d" % (name, os.getpid())
        self.local_dev, self.local_addr, self.peer_addr = local_dev, local_addr, peer_addr

    def __enter__(self):
        sh("ip", "netns", "add", self.name)
        try:
            sh("ip", "link", "add", self.local_dev, "type", "veth", "peer", "name", "gt-v1", "netns", self.name)
            sh("ip", "addr", "add", self.local_addr + "/24", "dev", self.local_dev)
            sh("ip", "link", "set", self.local_dev, "up")
            for cmd in (["addr", "add", self.peer_addr + "/24", "dev", "gt-v1"], ["link", "set", "gt-v1", "up"],
                        ["link", "set", "lo", "up"]):
                sh("ip", "-n", self.name, *cmd)
        except Exception:
            self.__exit__()
            raise
        return self

    def __exit__(self, *exc):
        sh("ip", "netns", "del", self.name, check=False)    # takes the veth pair with it

    @contextlib.contextmanager
    def inside(self):
        here = os.open("/proc/thread-self/ns/net", os.O_RDONLY)
        there = os.open("/run/netns/" + self.name, os.O_RDONLY)
        try:
            _setns(there)
            try:
                yield
            finally:
                _setns(here)
        finally:
            os.close(here)
            os.close(there)
