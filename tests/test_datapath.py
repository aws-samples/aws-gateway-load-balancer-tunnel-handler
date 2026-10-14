# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""GENEVE in, inner packets out: endpoint creation, what's forwarded and what's dropped, the flow cache, the
return path back to "GWLB", and malformed input. Packets are sent to gwlbtun on loopback."""

import os
import random
import struct

import pytest

from lib.geneve import Sender, geneve_header, geneve_option, gwlb_packet, ipv4, ipv6, parse_geneve, tcp, udp
from lib.netutil import PeerNamespace, dummy_interface, gw_devices, have, raw_sockets, udp_noports, wait_for

pytestmark = pytest.mark.root

PORT = 18300
EP = 0xF17E000000000901          # a GWLB endpoint ID (vpce-0f17e000000000901)
UDP_FLOW = ipv4(udp(40000, 53))


def eni(g, index=0):
    return g.health()["enis"][index]


def wait_counters(g, out=None, dropped=None, timeout=5.0):
    """Wait until the summary's totalPktsOut / totalPktsDropped reach the given values."""
    def ok():
        _, o, d = g.counters()
        return (out is None or o == out) and (dropped is None or d == dropped)
    wait_for(ok, timeout, what="pktsOut=%s pktsDropped=%s (now %s)" % (out, dropped, g.counters()))


@pytest.fixture
def started(gw, build):
    """gwlbtun with JSON health, and one endpoint already set up by a first packet."""
    g = gw("-p", PORT, "-j", *build.threads())
    s = Sender()
    s.send(gwlb_packet(EP, UDP_FLOW))
    wait_counters(g, out=1)
    yield g, s
    s.close()


def test_first_packet_creates_endpoint(gw, build):
    g = gw("-p", PORT, "-j", *build.threads())
    with Sender() as s:
        s.send(gwlb_packet(EP, UDP_FLOW), 5)
        wait_counters(g, out=5)
    h = g.health()
    assert h["summary"]["eniCount"] == 1
    e = h["enis"][0]
    assert e["gwlbEndpointId"] == "vpce-0f17e000000000901" and e["pktsOut"] == 5 and e["pktsDropped"] == 0
    devs = gw_devices()
    assert len(devs) == (2 if build.return_traffic else 1)
    g.wait_log(r"New interface gwi-\S+ and \S+ for GWLB endpoint vpce-0f17e000000000901 created")


@pytest.mark.parametrize("inner,forwarded", [
    pytest.param(UDP_FLOW, True, id="ipv4-udp"),
    pytest.param(ipv4(tcp(40000, 443), proto=6), True, id="ipv4-tcp"),
    pytest.param(ipv4(b"", proto=253), True, id="ipv4-header-only-20-bytes"),
    pytest.param(ipv4(udp(40000, 53), ip_options=b"\x01" * 8), True, id="ipv4-with-ip-options"),
    pytest.param(ipv4(udp(40000, 53), frag=0x2000), True, id="ipv4-first-fragment"),
    pytest.param(ipv6(udp(40000, 53)), True, id="ipv6-udp"),
    pytest.param(ipv6(udp(40000, 53), ext_headers=[(0, b"\x01\x04\0\0\0\0"), (60, b"\x01\x04\0\0\0\0")]), True,
                 id="ipv6-extension-headers"),
    pytest.param(ipv4(udp(40000, 53), version=7), False, id="ip-version-7"),
    pytest.param(ipv4(udp(40000, 53))[:12], False, id="shorter-than-ipv4-header"),
])
def test_inner_packets(started, inner, forwarded):
    g, s = started
    _, out0, drop0 = g.counters()
    s.send(gwlb_packet(EP, inner))
    if forwarded:
        wait_counters(g, out=out0 + 1, dropped=drop0)
    else:
        wait_counters(g, out=out0, dropped=drop0 + 1)
        assert eni(g)["pktsDropped"] == drop0 + 1


def test_empty_datagram_not_counted(started):
    g, s = started
    in0 = g.counters()[0]
    s.send(b"", 3)
    s.send(gwlb_packet(EP, UDP_FLOW))     # a marker: once it's counted, the empty ones have been seen
    wait_counters(g, out=2)
    assert g.counters()[0] == in0 + 1


def test_malformed_geneve_survives(started):
    """Truncated headers, lying length fields and random bytes: nothing crashes, nothing is created, and
    traffic still flows afterwards."""
    g, s = started
    rnd = random.Random(8926)
    good = gwlb_packet(EP + 1, UDP_FLOW)
    bad = [good[:n] for n in range(40)]                                   # every truncation of the header
    bad += [bytes([0x3F]) + good[1:]]                                     # options length past the packet
    bad += [bytes([0x48]) + good[1:]]                                     # version 1
    bad += [good[:2] + b"\x12\x34" + good[4:]]                            # unknown ethertype
    bad += [geneve_header(0, options=geneve_option(1, b"\0" * 8)) + UDP_FLOW]     # GWLB options missing
    bad += [geneve_header(0, options=struct.pack("!HBB", 0x108, 1, 0x1F) + b"\0" * 8) + UDP_FLOW]  # option overruns
    bad += [bytes(rnd.getrandbits(8) for _ in range(rnd.randrange(1, 200))) for _ in range(300)]
    for p in bad:
        s.send(p)
    s.send(gwlb_packet(EP, UDP_FLOW))
    wait_counters(g, out=2)
    assert g.alive()
    assert g.health()["summary"]["eniCount"] == 1, "a malformed packet created an endpoint"
    s.send(good)
    wait_for(lambda: g.health()["summary"]["eniCount"] == 2, what="a well-formed packet to set up a new endpoint")


# --- Flow cache (return-traffic builds) ------------------------------------------------------------------

@pytest.mark.parametrize("inner", [
    pytest.param(ipv4(udp(40000, 53)), id="ipv4"),
    pytest.param(ipv4(udp(40000, 53), ip_options=b"\x01" * 8), id="ipv4-with-ip-options"),
    pytest.param(ipv6(udp(40000, 53), ext_headers=[(0, b"\x01\x04\0\0\0\0")]), id="ipv6-extension-header"),
])
def test_flow_data_change_logged(gw, build, return_traffic, inner):
    """The same inner flow with a new cookie: one 'GWLB data changed' line, naming the flow's ports (read past
    any IP options or extension headers) and the old and new GENEVE options."""
    g = gw("-p", PORT, "-j", *build.threads())
    with Sender() as s:
        s.send(gwlb_packet(EP, inner, cookie=0x11111111), 2)
        wait_counters(g, out=2)
        assert not g.log_lines("GWLB data changed")
        s.send(gwlb_packet(EP, inner, cookie=0x22222222))
        wait_counters(g, out=3)
    lines = g.wait_log("GWLB data changed for an established flow")
    assert len(lines) == 1
    line = lines[0]
    assert "Prot UDP, src pt 40000, dst pt 53" in line
    assert "Flow Cookie: 0x11111111; now" in line and "Flow Cookie: 0x22222222." in line
    assert "Status:" not in line and "Attachment ID: 0x0 " in line
    cache = "v6FlowCacheUdp" if inner[0] >> 4 == 6 else "v4FlowCacheUdp"
    assert eni(g)[cache]["size"] == 1


@pytest.mark.skipif(not have("tc"), reason="needs tc (iproute-tc)")
def test_round_trip(gw, build, return_traffic, tmp_path):
    """A hook loops gwi- back into gwo- (tc mirred), as a one-arm appliance would, so each packet comes back to
    "GWLB" as GENEVE with the GWLB options it arrived with and the inner packet unchanged.

    gwlbtun answers GWLB with the addresses swapped and the ports kept, so the reply goes to port 6081 on the
    sender's address: "GWLB" is a socket on port 6081 in a second network namespace, across a veth pair, so
    the reply also has to leave by the interface the traffic arrived on."""
    hook = tmp_path / "loop.sh"
    hook.write_text("#!/bin/bash\n"
                    '[ "$1" = CREATE ] || exit 0\n'
                    'tc qdisc add dev "$2" ingress\n'
                    'tc filter add dev "$2" parent ffff: protocol all prio 2 u32 match u32 0 0 flowid 1:1 '
                    'action mirred egress redirect dev "$3"\n')
    os.chmod(str(hook), 0o755)
    with PeerNamespace() as peer:
        g = gw("-p", PORT, "-j", "-c", hook, *build.threads())
        with peer.inside():
            s = Sender(target=peer.local_addr, sport=6081, bind_addr=peer.peer_addr)
        with s:
            s.send(gwlb_packet(EP, UDP_FLOW))      # sets up the endpoint (and the hook)
            g.wait_log("New interface")
            for inner, cookie in ((ipv4(udp(40001, 53, b"hello")), 0xA1A2A3A4), (ipv6(tcp(40002, 443), nh=6), 0xB1B2B3B4)):
                s.send(gwlb_packet(EP, inner, cookie=cookie, attachment=0x55))
                reply = None
                for _ in range(5):                 # skip anything still in flight from the first packet
                    reply = s.recv(3)
                    if reply is None or parse_geneve(reply)[2] == inner:
                        break
                assert reply is not None, "no GENEVE reply"
                opts, ethertype, back = parse_geneve(reply)
                assert back == inner
                assert struct.unpack("!Q", opts[1])[0] == EP
                assert struct.unpack("!Q", opts[2])[0] == 0x55
                assert struct.unpack("!I", opts[3])[0] == cookie
                assert ethertype == (0x86DD if inner[0] >> 4 == 6 else 0x0800)
        g.stop()


def test_writers_and_raw_sockets(gw, return_traffic):
    """17 UDP threads share 3 detached gwi- writers; each tunnel thread has its own raw socket back to GWLB."""
    g = gw("-p", PORT, "-j", "--udpthreads", "17", "--tunthreads", "3", "--sndbuf", "8", "--logging", "tunnel=debug",
           min_udp_sockets=17)
    with Sender() as s:
        s.send(gwlb_packet(EP, UDP_FLOW), 5)
        wait_counters(g, out=5)
    g.wait_log(r"3 gwi writer\(s\), 3 detached")
    assert raw_sockets(g.pid) >= 2 * 3 + 1      # gwi- and gwo- x 3 tunnel threads, plus the shared one


# --- Receive interfaces (-I) -----------------------------------------------------------------------------

def test_interface_filter_ignores_other_interfaces(gw, build):
    with dummy_interface("gt-d0", "10.250.0.1"):
        g = gw("-I", "gt-d0", "-p", PORT, "-j", *build.threads())
        n0 = udp_noports()
        with Sender() as s:
            s.send(gwlb_packet(EP, UDP_FLOW), 20)
        wait_for(lambda: udp_noports() - n0 >= 20, what="lo packets to find no socket")
        h = g.health()
        assert h["summary"]["totalPktsIn"] == 0
        assert {t["interface"] for t in h["udp"]["UDPPacketReceiver"]["threads"]} == {"gt-d0"}
        g.stop()


def test_interface_list_threads_per_interface(gw, build):
    with dummy_interface("gt-d0", "10.250.0.1"):
        g = gw("-I", "lo,gt-d0", "-p", PORT, "-j", *build.threads(), min_udp_sockets=4)
        threads = g.health()["udp"]["UDPPacketReceiver"]["threads"]
        assert sorted(t["interface"] for t in threads) == ["gt-d0", "gt-d0", "lo", "lo"]
        with Sender() as s:
            s.send(gwlb_packet(EP, UDP_FLOW), 20)
        wait_counters(g, out=20)
        g.stop()
