# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The eBPF datapath (-e): flows gwlbtun has learned are carried between the GWLB-facing interface and gwi-/gwo-
in the kernel, and everything the programs can't handle exactly as userspace would still works through
userspace. "GWLB" is a socket in a second network namespace across a veth pair (see test_datapath's
test_round_trip), with a hook looping gwi- back into gwo- as a one-arm appliance would.

Needs a build with eBPF support (clang and libbpf-devel) and Linux 6.6 or later."""

import os
import platform
import re
import signal
import struct
import time

import pytest

from lib.geneve import Sender, gwlb_packet, ipv4, ipv6, parse_geneve, tcp, udp
from lib.netutil import PeerNamespace, gw_devices, have, sh, wait_for

PORT = 18400
EP = 0xF17E000000000E01          # vpce-0f17e000000000e01


def _kernel_has_tcx():
    m = re.match(r"(\d+)\.(\d+)", platform.release())
    return bool(m) and (int(m.group(1)), int(m.group(2))) >= (6, 6)


pytestmark = [
    pytest.mark.root,
    pytest.mark.skipif(not _kernel_has_tcx(), reason="the eBPF datapath needs Linux 6.6 or later (tcx)"),
    pytest.mark.skipif(not have("tc"), reason="needs tc (iproute-tc)"),
]


@pytest.fixture
def ebpf(build):
    if not build.ebpf_object:
        pytest.skip("gwlbtun was built without eBPF support")
    return build.ebpf_object


@pytest.fixture
def peer():
    with PeerNamespace(name="gt-ebpf", local_dev="gt-e0", local_addr="10.252.0.1", peer_addr="10.252.0.2") as p:
        yield p


@pytest.fixture
def loop_hook(tmp_path):
    """A CREATE hook sending everything that arrives on gwi- straight out of gwo-."""
    hook = tmp_path / "loop.sh"
    hook.write_text("#!/bin/bash\n"
                    '[ "$1" = CREATE ] || exit 0\n'
                    'tc qdisc add dev "$2" ingress\n'
                    'tc filter add dev "$2" parent ffff: protocol all prio 2 u32 match u32 0 0 flowid 1:1 '
                    'action mirred egress redirect dev "$3"\n')
    os.chmod(str(hook), 0o755)
    return str(hook)


def start(gw, build, ebpf, peer, *extra, hook=None):
    args = ["-e", ebpf, "-I", peer.local_dev, "-p", PORT, "-j"] + build.threads()
    if hook:
        args += ["-c", hook]
    g = gw(*args, *extra)
    g.wait_log("eBPF datapath loaded")
    return g


def gwlb(peer):
    """The "GWLB" socket, in the peer namespace, on port 6081 so it receives gwlbtun's replies."""
    with peer.inside():
        return Sender(target=peer.local_addr, sport=6081, bind_addr=peer.peer_addr)


def fresh(g):
    """The health report, rebuilt after everything sent so far (gwlbtun rebuilds it at most once a second)."""
    time.sleep(1.1)
    return g.health()


def ebpf_health(g):
    return fresh(g)["ebpf"]


def exchange(s, inner, cookie, count=1, attachment=0):
    """Send `count` packets of a flow and return the GENEVE replies that carry it."""
    replies = []
    for _ in range(count):
        s.send(gwlb_packet(EP, inner, cookie=cookie, attachment=attachment))
        for _ in range(5):                 # skip anything still in flight from earlier packets
            r = s.recv(3)
            if r is None:
                break
            if parse_geneve(r)[2] == inner:
                replies.append(r)
                break
    return replies


def check_reply(reply, inner, cookie, attachment=0):
    opts, ethertype, back = parse_geneve(reply)
    assert back == inner
    assert struct.unpack("!Q", opts[1])[0] == EP
    assert struct.unpack("!Q", opts[2])[0] == attachment
    assert struct.unpack("!I", opts[3])[0] == cookie
    assert ethertype == (0x86DD if inner[0] >> 4 == 6 else 0x0800)


def setup_endpoint(g, s):
    s.send(gwlb_packet(EP, ipv4(udp(39999, 53))))
    g.wait_log("New interface")
    wait_for(lambda: g.health()["summary"]["eniCount"] == 1, what="the endpoint")


@pytest.mark.parametrize("inner", [
    pytest.param(ipv4(udp(40001, 53, b"hello")), id="ipv4-udp"),
    pytest.param(ipv4(tcp(40002, 443), proto=6), id="ipv4-tcp"),
    pytest.param(ipv4(udp(40003, 53), ip_options=b"\x01" * 8), id="ipv4-with-ip-options"),
    pytest.param(ipv6(tcp(40004, 443), nh=6), id="ipv6-tcp"),
])
def test_flow_is_carried_in_the_kernel(gw, build, return_traffic, ebpf, peer, loop_hook, inner):
    """After a flow's first packet, its packets go both ways without gwlbtun copying them, and come back to
    GWLB exactly as userspace would have sent them."""
    g = start(gw, build, ebpf, peer, hook=loop_hook)
    with gwlb(peer) as s:
        setup_endpoint(g, s)
        cookie = 0xA1A2A3A4
        first = exchange(s, inner, cookie, attachment=0x55)
        assert len(first) == 1, "no reply to the flow's first packet"
        check_reply(first[0], inner, cookie, 0x55)
        before = fresh(g)
        replies = exchange(s, inner, cookie, 20, attachment=0x55)
        assert len(replies) == 20
        for r in replies:
            check_reply(r, inner, cookie, 0x55)
        after = fresh(g)
    gained = lambda h0, h1, d, k: h1["ebpf"][d][k] - h0["ebpf"][d][k]
    assert gained(before, after, "ingress", "accelerated") >= 18, after["ebpf"]
    assert gained(before, after, "egress", "accelerated") >= 18, after["ebpf"]
    # gwlbtun itself wrote (almost) none of them to gwi-.
    assert after["enis"][0]["pktsOut"] - before["enis"][0]["pktsOut"] <= 2
    assert after["enis"][0]["ebpf"]["lateRepunts"] == 0


@pytest.mark.parametrize("inner", [
    pytest.param(ipv6(udp(40010, 53), ext_headers=[(0, b"\x01\x04\0\0\0\0")]), id="ipv6-extension-header"),
    pytest.param(ipv4(b"\0" * 16, proto=17, frag=0x0010), id="ipv4-later-udp-fragment"),
])
def test_unkeyable_flows_stay_in_userspace(gw, build, return_traffic, ebpf, peer, loop_hook, inner):
    """Packets the programs can't key the way the flow cache does are left to userspace, which handles them."""
    g = start(gw, build, ebpf, peer, hook=loop_hook)
    with gwlb(peer) as s:
        setup_endpoint(g, s)
        before = fresh(g)
        replies = exchange(s, inner, 0xC0C0C0C0, 5)
        assert len(replies) == 5
        after = fresh(g)
    assert after["enis"][0]["pktsOut"] - before["enis"][0]["pktsOut"] == 5
    assert after["ebpf"]["ingress"]["accelerated"] == before["ebpf"]["ingress"]["accelerated"]


def test_shared_cookie(gw, build, return_traffic, ebpf, peer, loop_hook):
    """Two inner flows with the same cookie: the first is carried in the kernel; the second never takes the
    first's path, and still works, through userspace."""
    g = start(gw, build, ebpf, peer, hook=loop_hook)
    a, b = ipv4(udp(40020, 53, b"first")), ipv4(udp(40021, 53, b"second"))
    with gwlb(peer) as s:
        setup_endpoint(g, s)
        assert len(exchange(s, a, 0x5EED, 3)) == 3
        rb = exchange(s, b, 0x5EED, 5)
        assert len(rb) == 5
        for r in rb:
            check_reply(r, b, 0x5EED)
        ra = exchange(s, a, 0x5EED, 5)
        assert len(ra) == 5
    assert ebpf_health(g)["ingress"]["flowMismatch"] >= 4


def test_cookie_change_relearns(gw, build, return_traffic, ebpf, peer, loop_hook):
    """A flow coming back with a new cookie (as after GWLB's idle timeout) is learned again: its replies carry
    the new cookie, from the kernel as well."""
    g = start(gw, build, ebpf, peer, hook=loop_hook)
    inner = ipv4(tcp(40030, 443), proto=6)
    with gwlb(peer) as s:
        setup_endpoint(g, s)
        assert len(exchange(s, inner, 0x11111111, 5)) == 5
        before = ebpf_health(g)
        replies = exchange(s, inner, 0x22222222, 10)
        assert len(replies) == 10
        for r in replies:
            check_reply(r, inner, 0x22222222)
        after = ebpf_health(g)
    assert after["egress"]["accelerated"] - before["egress"]["accelerated"] >= 8
    g.wait_log("GWLB data changed for an established flow")


def test_full_maps_fall_back_to_userspace(gw, build, return_traffic, ebpf, peer, loop_hook):
    """With room for one IPv4 flow, others still work, through userspace, and are counted."""
    g = start(gw, build, ebpf, peer, "--ebpf-reserve", "1,1", hook=loop_hook)
    with gwlb(peer) as s:
        setup_endpoint(g, s)     # this flow takes the room
        for port in (40040, 40041, 40042):
            inner = ipv4(udp(port, 53))
            assert len(exchange(s, inner, port, 3)) == 3
    h = ebpf_health(g)
    assert h["mapSizes"]["ingress"] == 2 and h["mapSizes"]["egressV4"] == 2
    assert h["mapFull"]["egress"] >= 3
    g.wait_log("eBPF IPv4 egress map is full")


def test_receive_only_delivers_in_the_kernel(gw, build, ebpf, peer, tmp_path):
    """Without a hook to return anything (and in NO_RETURN_TRAFFIC builds), learned flows still reach gwi- in
    the kernel. A tc filter on gwi- counts what arrives there (tun's own counters only see gwlbtun's writes)."""
    hook = tmp_path / "count.sh"
    hook.write_text("#!/bin/bash\n"
                    '[ "$1" = CREATE ] || exit 0\n'
                    'tc qdisc add dev "$2" ingress\n'
                    'tc filter add dev "$2" parent ffff: protocol all prio 2 u32 match u32 0 0 flowid 1:1 action ok\n')
    os.chmod(str(hook), 0o755)
    g = start(gw, build, ebpf, peer, hook=str(hook))
    with gwlb(peer) as s:
        setup_endpoint(g, s)
        inner = ipv4(udp(40050, 53))
        s.send(gwlb_packet(EP, inner, cookie=0x50), 1)
        wait_for(lambda: g.health()["enis"][0]["pktsOut"] == 2, what="the flow's first packet through userspace")
        s.send(gwlb_packet(EP, inner, cookie=0x50), 30)
        wait_for(lambda: ebpf_health(g)["ingress"]["accelerated"] >= 28, what="packets delivered in the kernel")
    gwi = [d for d in gw_devices() if d.startswith("gwi-")][0]
    seen = re.findall(r"Sent \d+ bytes (\d+) pkt", sh("tc", "-s", "filter", "show", "dev", gwi, "parent", "ffff:"))
    assert seen and int(seen[0]) >= 32, "packets arriving on gwi-: %s" % seen
    assert fresh(g)["enis"][0]["pktsOut"] <= 3


def test_restart_after_sigkill(gw, build, return_traffic, ebpf, peer, loop_hook):
    """gwlbtun killed outright leaves nothing behind (the ingress program is a link owned by the process), so
    the next one attaches and carries traffic."""
    inner = ipv4(udp(40060, 53))
    for attempt in range(2):
        g = start(gw, build, ebpf, peer, hook=loop_hook)
        with gwlb(peer) as s:
            setup_endpoint(g, s)
            assert len(exchange(s, inner, 0x60, 10)) == 10, "attempt %d" % attempt
            assert ebpf_health(g)["ingress"]["accelerated"] >= 8
        if attempt == 0:
            g.proc.send_signal(signal.SIGKILL)
            g.proc.wait(10)
            wait_for(lambda: not gw_devices(), 10, what="the killed gwlbtun's devices to go")
    assert not [f for f in os.listdir("/sys/fs/bpf") if f.startswith("gwlbtun-")], "egress pins left in bpffs"


@pytest.mark.slow
def test_idle_teardown_removes_flows(gw, build, return_traffic, ebpf, peer, loop_hook):
    """An endpoint torn down for being idle (-t) takes its flows out of the maps: when its traffic comes back,
    a new endpoint is set up and the flow works (and is carried in the kernel) again, rather than being sent to
    interfaces that no longer exist."""
    # New tun devices send IPv6 router solicitations, which count as tunnel traffic; keep IPv6 off on them.
    knob = "/proc/sys/net/ipv6/conf/default/disable_ipv6"
    with open(knob) as fh:
        saved = fh.read().strip()
    with open(knob, "w") as fh:
        fh.write("1")
    try:
        _idle_teardown(gw, build, ebpf, peer, loop_hook)
    finally:
        with open(knob, "w") as fh:
            fh.write(saved)


def _idle_teardown(gw, build, ebpf, peer, loop_hook):
    g = start(gw, build, ebpf, peer, "-t", "5", hook=loop_hook)
    inner = ipv4(udp(40070, 53))
    with gwlb(peer) as s:
        setup_endpoint(g, s)
        assert len(exchange(s, inner, 0x70, 5)) == 5
        g.wait_log(r"Removed GWLB endpoint vpce-0f17e000000000e01's \d+ flows from the eBPF maps", timeout=75)
        wait_for(lambda: not gw_devices(), 10, what="the idle endpoint's devices to go")

        def recreated():
            # Packets that arrive while the old endpoint is still being torn down are dropped, so keep sending.
            s.send(gwlb_packet(EP, ipv4(udp(39999, 53))))
            return len(g.log_lines("New interface")) == 2
        wait_for(recreated, 10, interval=0.2, what="the endpoint to be set up again")
        before = ebpf_health(g)["ingress"]["accelerated"]
        assert len(exchange(s, inner, 0x70, 10)) == 10
        assert ebpf_health(g)["ingress"]["accelerated"] - before >= 8
