#!/bin/bash
# Run the local test suite (tests/) inside an Amazon Linux 2023 container. The container must be privileged:
# the tests create tun devices, network namespaces and raw sockets.
#
# Intended invocation (from the CI workflow), run from the repo root:
#   docker run --rm --privileged -v "$PWD":/src -w /src amazonlinux:2023 bash .github/scripts/test-al2023.sh
set -euo pipefail

dnf -y install gcc gcc-c++ cmake make git python3-pytest iproute iproute-tc util-linux procps-ng
git config --global --add safe.directory /src

# The slow test waits for the 60-second reaper; it runs in release testing, not on every push.
tests/run.sh --quick
