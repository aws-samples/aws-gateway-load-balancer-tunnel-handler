# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""UDP thread layout against the host's real network interface and its receive queues (ENA's
'<ifname>-Tx-Rx-<n>' IRQs). Needs the host's network namespace: tests/run.sh --host on an EC2 instance."""

import os

import pytest

from lib.netutil import default_route_interface, rx_queue_count

pytestmark = [pytest.mark.root, pytest.mark.host_nic]


@pytest.fixture
def nic():
    iface = default_route_interface()
    return iface, rx_queue_count(iface)


def receiving(g):
    return g.wait_log("Receiving GENEVE on")


def tun1(build):
    return build.threads(1, 1)[2:]


def test_default_one_thread_per_queue(gw, build, nic):
    iface, nq = nic
    g = gw("-p", 0, *tun1(build), min_udp_sockets=nq)
    assert any("on all interfaces with %d UDP threads, one per receive queue of %s" % (nq, iface) in l for l in receiving(g))


def test_explicit_thread_count_matching_queues_is_tied(gw, build, nic):
    iface, nq = nic
    g = gw("-p", 0, "--udpthreads", nq, *tun1(build), min_udp_sockets=nq)
    assert any("one per receive queue of %s" % iface in l for l in receiving(g))


def test_more_threads_than_queues_not_tied(gw, build, nic):
    iface, nq = nic
    g = gw("-p", 0, "--udpthreads", 2 * nq, *tun1(build), min_udp_sockets=2 * nq)
    assert any("with %d UDP threads; %s has %d receive queues" % (2 * nq, iface, nq) in l for l in receiving(g))


def test_pinned_one_per_queue_sets_incoming_cpu(gw, build, nic):
    iface, nq = nic
    g = gw("-p", 0, "--udpaffinity", "0-%d" % (nq - 1), *tun1(build), min_udp_sockets=nq)
    assert any("one per receive queue of %s" % iface in l for l in receiving(g))
    assert not g.log_lines("Unable to set SO_INCOMING_CPU")


def test_one_pinned_thread_not_tied(gw, build, nic):
    iface, nq = nic
    if nq < 2:
        pytest.skip("one receive queue")
    g = gw("-p", 0, "--udpaffinity", "0", *tun1(build))
    assert not any("one per receive queue" in l for l in receiving(g))


def test_interface_list_ties_only_the_nic(gw, build, nic):
    iface, nq = nic
    g = gw("-p", 0, "-I", "lo," + iface, *tun1(build), min_udp_sockets=nq + 1)
    lines = receiving(g)
    assert any("interface %s with %d UDP threads, one per receive queue" % (iface, nq) in l for l in lines)
    assert any("interface lo with %d UDP threads (no receive queues found for lo)" % len(os.sched_getaffinity(0)) in l for l in lines)
