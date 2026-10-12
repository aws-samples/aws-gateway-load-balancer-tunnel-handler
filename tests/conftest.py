# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""pytest setup for gwlbtun's local test suite. See tests/README.md."""

import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from lib.gwlbtun import Build, Gwlbtun, HookRecorder  # noqa: E402
from lib.netutil import default_route_interface, gw_devices, rx_queue_count, wait_for  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def pytest_addoption(parser):
    parser.addoption("--gwlbtun", default=os.environ.get("GWLBTUN"),
                     help="gwlbtun binary to test (default: $GWLBTUN, else build/gwlbtun)")


def _isolated():
    """run.sh runs the suite in its own network namespace and says so here."""
    return os.environ.get("GWLBTUN_TEST_NETNS") == "1"


def pytest_collection_modifyitems(config, items):
    root = os.geteuid() == 0
    others = subprocess.run(["pgrep", "-x", "gwlbtun"], stdout=subprocess.DEVNULL).returncode == 0
    iface = default_route_interface()
    nic = bool(iface) and rx_queue_count(iface) > 0
    for item in items:
        if "root" in item.keywords and not root:
            item.add_marker(pytest.mark.skip(reason="needs root (run tests/run.sh)"))
        elif "root" in item.keywords and others and not _isolated():
            item.add_marker(pytest.mark.skip(reason="another gwlbtun is running in this network namespace"))
        if "host_nic" in item.keywords and not nic:
            item.add_marker(pytest.mark.skip(reason="needs a default-route interface with ENA-style receive queue IRQs "
                                                    "(run tests/run.sh --host on an EC2 instance)"))


@pytest.fixture(scope="session")
def build(request):
    path = request.config.getoption("--gwlbtun") or os.path.join(REPO, "build", "gwlbtun")
    if not os.access(path, os.X_OK):
        pytest.exit("No gwlbtun binary at %s: build it, or pass --gwlbtun PATH" % path, returncode=2)
    return Build(path)


@pytest.fixture
def return_traffic(build):
    if not build.return_traffic:
        pytest.skip("NO_RETURN_TRAFFIC build: no tunnel threads or flow cache")


@pytest.fixture
def gw(build, tmp_path):
    """Start gwlbtun processes: gw(*args, wrapper=(), wait=True) -> Gwlbtun. All are stopped afterwards, and the
    test fails if one left gwi-/gwo- devices behind or its log has sanitizer findings."""
    started = []

    def start(*args, wrapper=(), wait=True, **kw):
        g = Gwlbtun(build, args, tmp_path / ("gwlbtun-%d.log" % len(started)), wrapper=wrapper, wait=wait, **kw)
        started.append(g)
        return g

    yield start
    for g in reversed(started):
        g.stop()
    findings = [f for g in started for f in g.sanitizer_findings()]
    assert not findings, "sanitizer findings:\n" + "\n".join(findings[:20])
    wait_for(lambda: not gw_devices(), 10, what="gwi-/gwo- devices to go: %s" % gw_devices())


@pytest.fixture
def hook(tmp_path):
    return HookRecorder(tmp_path)
