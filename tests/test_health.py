# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The health check listener (-p): binding, slow and idle clients (#43), the cached report, output formats,
and failure handling."""

import socket
import subprocess
import time
import urllib.request

import pytest

from lib.geneve import Sender, gwlb_packet, ipv4, udp
from lib.netutil import dummy_interface, sh, wait_for

pytestmark = pytest.mark.root

PORT = 18400


def timed_get(url, timeout=3.0):
    t = time.monotonic()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, time.monotonic() - t
    except OSError:
        return None, time.monotonic() - t


def answers(url, timeout=1.0):
    return timed_get(url, timeout)[0] == 200


@pytest.fixture
def hc(gw, build):
    return gw("-p", PORT, "-j", *build.threads())


URL = "http://127.0.0.1:%d/" % PORT


def test_idle_client_does_not_delay_others(hc):
    with socket.create_connection(("127.0.0.1", PORT)):
        time.sleep(0.2)
        status, secs = timed_get(URL)
    assert status == 200 and secs < 1.0


def test_server_closes_after_response(hc):
    """The #43 reporter's client: sends a request, reads the response, waits for the server to close."""
    with socket.create_connection(("127.0.0.1", PORT), timeout=5) as s:
        s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\nAccept: */*\r\n\r\n")
        t, data = time.monotonic(), b""
        while True:
            d = s.recv(65536)
            if not d:
                break
            data += d
    assert data.startswith(b"HTTP/1.1 200") and time.monotonic() - t < 2.5


def test_idle_flood_recovers(hc):
    """Twenty idle clients: those past the in-flight cap are closed, and checks work again once the idle ones
    time out (2 s)."""
    idles = [socket.create_connection(("127.0.0.1", PORT)) for _ in range(20)]
    try:
        time.sleep(0.3)
        timed_get(URL)                            # may or may not get a slot
        time.sleep(2.5)
        status, secs = timed_get(URL)
        assert status == 200 and secs < 1.0
    finally:
        for c in idles:
            c.close()


def test_report_cached_within_a_second(hc):
    b1 = urllib.request.urlopen(URL, timeout=3).read()
    b2 = urllib.request.urlopen(URL, timeout=3).read()
    assert b1 and b1 == b2
    time.sleep(1.2)
    assert urllib.request.urlopen(URL, timeout=3).read().startswith(b"{")


def test_text_and_simple_output(gw, build):
    g = gw("-p", PORT, *build.threads())
    with Sender() as s:
        s.send(gwlb_packet(0xF17E000000000401, ipv4(udp(40000, 53))), 3)
    body = wait_for(lambda: "packets out to OS" in g.health_text() and g.health_text(), what="an endpoint in the text report")
    assert "3 packets out to OS" in body and "packets dropped," in body and "dropped on write" not in body
    g.stop()
    g2 = gw("-p", PORT, "-s", *build.threads())
    assert g2.health_status() == 200


def test_shutdown_with_idle_client_is_prompt(gw, build):
    g = gw("-p", PORT, *build.threads())
    with socket.create_connection(("127.0.0.1", PORT)):
        time.sleep(0.5)
        secs = g.stop()
    assert secs < 4 and "Shutdown complete." in g.log()


# --- Binding -----------------------------------------------------------------------------------------------

def listeners(port):
    return [l for l in sh("ss", "-ltnH").splitlines() if l.split()[3].endswith(":%d" % port)]


def test_bind_address(gw, build):
    with dummy_interface("gt-d1", "10.251.0.1"):
        gw("-p", "127.0.0.1:%d" % PORT, "-j", *build.threads())
        (l,) = listeners(PORT)
        assert l.split()[3] in ("127.0.0.1:%d" % PORT, "[::ffff:127.0.0.1]:%d" % PORT)
        assert answers(URL) and not answers("http://10.251.0.1:%d/" % PORT)


def test_bind_interface(gw, build):
    with dummy_interface("gt-d1", "10.251.0.1"):
        g = gw("-p", "lo:%d" % PORT, "-j", *build.threads())
        assert answers(URL) and not answers("http://10.251.0.1:%d/" % PORT)
        g.wait_log("Health check listening on port %d on interface lo" % PORT)
        g.stop()


def test_bind_ipv6(gw, build):
    try:
        socket.socket(socket.AF_INET6).bind(("::1", 0))
    except OSError:
        pytest.skip("no IPv6 loopback")
    gw("-p", "[::1]:%d" % PORT, "-j", *build.threads())
    assert answers("http://[::1]:%d/" % PORT)


def test_port_in_use_exits_1(build, tmp_path):
    with socket.socket(socket.AF_INET6) as busy:
        busy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        busy.bind(("::", PORT))
        busy.listen()
        p = build.run("-p", PORT, *build.threads(), timeout=10)
    assert p.returncode == 1 and "Unable to listen to health status port %d" % PORT in p.out


def test_out_of_fds_accept_backs_off(gw, build):
    """With the fd limit exhausted the listener stays readable; gwlbtun must not spin on accept()."""
    g = gw("-p", PORT, "-j", *build.threads(1, 1), wrapper=["prlimit", "--nofile=16:16", "--"])
    clients = []
    for _ in range(40):
        try:
            clients.append(socket.create_connection(("127.0.0.1", PORT), timeout=1))
        except OSError:
            pass
    try:
        time.sleep(1)
        hz = int(subprocess.check_output(["getconf", "CLK_TCK"]))

        def cpu():
            f = open("/proc/%d/stat" % g.pid).read().rsplit(")", 1)[1].split()
            return int(f[11]) + int(f[12])
        c0 = cpu()
        time.sleep(3)
        ticks = cpu() - c0
        assert g.log_lines("Unable to accept health check client"), "no accept failure logged"
        assert ticks < hz / 2, "%d ticks of CPU in 3 s while out of fds" % ticks
    finally:
        for c in clients:
            c.close()
