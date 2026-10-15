#!/bin/bash
# Run the local test suite (tests/) inside an Amazon Linux 2023 container. The container must be privileged:
# the tests create tun devices, network namespaces and raw sockets, and load gwlbtun's eBPF programs.
#
# Intended invocation (from the CI workflow), run from the repo root:
#   docker run --rm --privileged -v "$PWD":/src -w /src amazonlinux:2023 bash .github/scripts/test-al2023.sh
set -euo pipefail

# clang and libbpf-devel build the eBPF datapath, so its tests (tests/test_ebpf.py) run too. They need Linux 6.6
# or later on the host, and skip otherwise.
dnf -y install gcc gcc-c++ cmake make git python3-pytest iproute iproute-tc util-linux procps-ng clang libbpf-devel
git config --global --add safe.directory /src
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

# The slow test waits for the 60-second reaper; it runs in release testing, not on every push.
tests/run.sh --quick
