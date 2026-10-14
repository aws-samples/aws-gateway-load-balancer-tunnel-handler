# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Endpoint lifecycle: hook scripts and their order against the interfaces, shutdown, idle teardown (-t),
setup failures (fd and thread limits, a device that already exists), the one-instance guard and device naming."""

import os
import re
import time

import pytest

from lib.geneve import Sender
from lib.gwlbtun import HookRecorder
from lib.netutil import dummy_interface, gw_devices, have, tun_device, wait_for

pytestmark = pytest.mark.root

PORT = 18500


def endpoint(n):
    return 0xA11E000000000000 + n


def endpoint_str(n):
    return "%017x" % endpoint(n)


def expected_devices(build, endpoints):
    return endpoints * (2 if build.return_traffic else 1)


def test_hooks_see_both_interfaces(gw, build, hook):
    """CREATE runs once both interfaces exist; DESTROY runs (at shutdown) while both still exist."""
    g = gw(*hook.args(), "-p", PORT, "-j", *build.threads(2, 4))
    with Sender() as s:
        s.flows(endpoint(1), 3, 5)
    wait_for(lambda: len(hook.calls("CREATE")) == 3, what="3 CREATE hooks")
    secs = g.stop()
    assert "Shutdown complete." in g.log()
    assert len(hook.calls("DESTROY")) == 3
    for r in hook.records():
        assert r["ingress_exists"], r
        if build.return_traffic:
            assert r["egress_exists"], r
    assert not gw_devices()
    assert secs < 10


@pytest.mark.parametrize("tunthreads", [4, 32])
def test_shutdown_with_20_endpoints(gw, build, hook, tunthreads):
    g = gw("-r", hook.path, "-p", 0, *build.threads(2, tunthreads))
    with Sender() as s:
        s.flows(endpoint(0x100), 20, 3)
    wait_for(lambda: len(gw_devices()) == expected_devices(build, 20), 15, what="40 devices")
    secs = g.stop()
    assert len(hook.calls("DESTROY")) == 20 and not gw_devices()
    assert secs < 10, "shutdown took %.1fs" % secs


def test_setup_failure_fd_limit(gw, build, hook, return_traffic):
    """An endpoint that can't get its file descriptors: logged, no hooks, no devices, process carries on.
    (A NO_RETURN_TRAFFIC endpoint needs only two, so the limit can't be placed between startup and it.)"""
    # UBSan's vptr check needs a file descriptor of its own (compiler-rt's IsAccessibleMemoryRange opens a pipe),
    # so with none left it reports every polymorphic object it checks as having an invalid vptr.
    g = gw(*hook.args(), "-p", PORT, "-j", *build.threads(1, 8), wrapper=["prlimit", "--nofile=24:24", "--"],
           sanitizer_ignore=r"runtime error: member (access within|call on) address \S+ which does not point to an object of type")
    with Sender() as s:
        s.flows(endpoint(0x200), 1, 5)
    g.wait_log("Unable to set up GWLB endpoint vpce-%s" % endpoint_str(0x200))
    assert not hook.records() and not gw_devices()
    assert g.health_status() == 200
    g.stop()
    assert "Shutdown complete." in g.log()


@pytest.mark.skipif(not (have("setpriv") and have("prlimit")), reason="needs setpriv and prlimit (util-linux)")
def test_setup_failure_thread_limit(gw, build, hook, return_traffic):
    """Thread creation failing part-way through an endpoint (an unprivileged user with a process limit).
    NO_RETURN_TRAFFIC endpoints start no threads."""
    wrapper = ["prlimit", "--nproc=10:10", "setpriv", "--reuid=nobody", "--regid=nobody", "--clear-groups",
               "--inh-caps=+net_admin,+net_raw", "--ambient-caps=+net_admin,+net_raw"]
    g = gw(*hook.args(), "-p", PORT, "-j", *build.threads(1, 8), wrapper=wrapper)
    with Sender() as s:
        s.flows(endpoint(0x300), 1, 5)
    g.wait_log("Unable to set up GWLB endpoint vpce-%s" % endpoint_str(0x300))
    assert not hook.records() and not gw_devices()
    g.stop()
    assert "Shutdown complete." in g.log()


@pytest.mark.slow
def test_idle_teardown_and_recreate(gw, build, hook):
    """-t 5: the reaper (every 60 s) removes idle endpoints; traffic sets them up again."""
    # New tun devices send IPv6 router solicitations, which count as tunnel traffic; keep IPv6 off on them.
    with open("/proc/sys/net/ipv6/conf/default/disable_ipv6") as fh:
        saved = fh.read().strip()
    with open("/proc/sys/net/ipv6/conf/default/disable_ipv6", "w") as fh:
        fh.write("1")
    try:
        g = gw(*hook.args(), "-p", 0, "-t", 5, *build.threads(2, 4))
        with Sender() as s:
            s.flows(endpoint(0x400), 2, 5)
            wait_for(lambda: len(hook.calls("CREATE")) == 2, what="2 CREATE hooks")
            wait_for(lambda: len(hook.calls("DESTROY")) == 2, 75, interval=1, what="the reaper to remove both endpoints")
            assert all(r["ingress_exists"] for r in hook.calls("DESTROY"))
            # The DESTROY hook runs while the endpoint's interfaces still exist; they go just after it.
            wait_for(lambda: not gw_devices(), 10, interval=0.05, what="the endpoints' interfaces to be removed")
            s.flows(endpoint(0x400), 1, 5)
            wait_for(lambda: len(hook.calls("CREATE")) == 3, what="re-creation")
        g.stop()
        assert len(hook.calls("DESTROY")) == 3
    finally:
        with open("/proc/sys/net/ipv6/conf/default/disable_ipv6", "w") as fh:
            fh.write(saved)


def test_setup_runs_outside_the_lifecycle_lock(gw, build, tmp_path):
    """While one endpoint's CREATE hook runs (3 s), another endpoint is set up and health checks answer."""
    hook = HookRecorder(tmp_path, slow_create=endpoint_str(0x700))
    g = gw("-c", hook.path, "-p", PORT, "-j", *build.threads(8, 2), min_udp_sockets=8)
    with Sender() as a:
        a.flows(endpoint(0x700), 1, 3)
    wait_for(lambda: g.log_lines("New interface"), what="the slow endpoint's interfaces")
    for _ in range(6):                       # new source ports, so some land on other UDP threads
        with Sender() as b:
            b.flows(endpoint(0x701), 1, 2)
    assert g.health_status(timeout=1.0) == 200, "health check blocked during a CREATE hook"
    wait_for(lambda: len(hook.calls("CREATE")) == 2, 6, what="both CREATE hooks")
    slow, = [r for r in hook.calls("CREATE") if r["endpoint"] == endpoint_str(0x700)]
    fast, = [r for r in hook.calls("CREATE") if r["endpoint"] == endpoint_str(0x701)]
    assert fast["end"] < slow["end"], "the second endpoint waited for the first one's hook"


def test_hooks_get_no_fds_and_the_original_limit(gw, build, hook):
    g = gw(*hook.args(), "-p", PORT, "-j", *build.threads(2, 4), wrapper=["prlimit", "--nofile=1024:65536", "--"])
    with Sender() as s:
        s.flows(endpoint(0x800), 1, 3)
    wait_for(lambda: hook.calls("CREATE"), what="CREATE hook")
    limits = open("/proc/%d/limits" % g.pid).read()
    assert re.search(r"Max open files\s+65536", limits), "soft open-file limit not raised"
    g.wait_log("Open file limit 65536; each GWLB endpoint uses about")
    g.stop()
    for r in hook.records():
        assert len(r["fds"]) <= 1, "hook inherited gwlbtun fds: %s" % r       # 1: the shell's own pipe
        assert r["nofile"] == 1024, r


def test_deprecated_x_and_oversubscribed_threads(gw, build):
    n = 2 * os.cpu_count()
    g = gw("-x", "-p", PORT, "-j", *build.threads(n, n), min_udp_sockets=n)
    g.wait_log(r"important.*-x is no longer used and is ignored")
    g.wait_log(r"important.*%d UDP threads requested, more than the \d+ CPUs available: this is untested" % n)
    if build.return_traffic:
        g.wait_log(r"important.*%d tunnel threads per interface requested, more than the \d+ CPUs available" % n)
    with Sender() as s:
        s.flows(endpoint(0x900), 1, 3)
    g.wait_log("New interface")


def test_runs_from_config_file(gw, build, tmp_path):
    cfg = tmp_path / "run.yaml"
    cfg.write_text("port: %d\njson: true\nudpthreads: 2\n%scmdnew: /bin/true\ncmddel: /bin/true\n"
                   % (PORT, "tunthreads: 1\n" if build.return_traffic else ""))
    g = gw("-f", cfg, health_port=PORT)
    assert len(g.health()["udp"]["UDPPacketReceiver"]["threads"]) == 2
    g.wait_log("Configuration read from %s" % cfg)


# --- One instance per receive scope -------------------------------------------------------------------------

def refused(g, text):
    wait_for(lambda: not g.alive(), what="the second instance to exit")
    assert text in g.log()


def test_instance_guard(gw, build):
    with dummy_interface("gt-d2", "10.252.0.1"):
        a = gw("-p", 0, *build.threads(1, 1))
        refused(gw("-p", 0, wait=False), "already serving UDP port 6081 on all interfaces")
        refused(gw("-I", "lo", "-p", 0, wait=False), "on all interfaces. An instance for all interfaces")
        a.stop()
        b = gw("-I", "lo", "-p", 0, *build.threads(1, 1))
        refused(gw("-p", 0, wait=False), "on interface lo. An instance for all interfaces")
        refused(gw("-I", "lo", "-p", 0, wait=False), "already serving UDP port 6081 on interface lo")
        c = gw("-I", "gt-d2", "-p", 0, *build.threads(1, 1), min_udp_sockets=2)
        assert b.alive() and c.alive()
        c.stop()
        b.stop()


# --- Device names --------------------------------------------------------------------------------------------

def device_for(gw, build, *args):
    g = gw("-p", 0, *build.threads(1, 1), *args)
    with Sender() as s:
        s.flows(endpoint(0x504), 1, 5)
    name = re.search(r"New interface (gwi-\S+)", g.wait_log("New interface")[0]).group(1)
    g.stop()
    return name


def test_interface_list_changes_device_name(gw, build):
    plain = device_for(gw, build)
    with_i = device_for(gw, build, "-I", "lo")
    assert plain != with_i and len(with_i) <= 15


def test_existing_device_refused_then_recovers(gw, build, hook):
    """IFF_TUN_EXCL: a device that already exists isn't shared. The error is logged once, the endpoint retries
    every 5 s, and is set up once the device is gone."""
    name = device_for(gw, build)
    with tun_device(name):
        g = gw(*hook.args(), "-p", 0, *build.threads(1, 1))
        with Sender() as s:
            for _ in range(5):                   # 2.5 s of traffic, inside the 5 s retry back-off
                s.flows(endpoint(0x504), 1, 5)
                time.sleep(0.5)
        g.wait_log(r"Unable to set up GWLB endpoint vpce-%s: Unable to create TUN device %s \(IFF_TUN_EXCL\): "
                   r"a device with that name already exists - is this the only gwlbtun trying to use it\?"
                   % (endpoint_str(0x504), re.escape(name)))
        assert len(g.log_lines("IFF_TUN_EXCL")) == 1, "logged on every retry"
        assert not hook.calls("CREATE")
    time.sleep(5)
    with Sender() as s:
        s.flows(endpoint(0x504), 1, 5)
    g.wait_log("New interface %s" % re.escape(name))
