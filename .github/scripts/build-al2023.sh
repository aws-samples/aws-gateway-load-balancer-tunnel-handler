#!/bin/bash
# Build gwlbtun inside an Amazon Linux 2023 container so the resulting binary links the same
# glibc as the AL2023 hosts it is deployed on (a binary built on a newer-glibc runner can fail
# to run on AL2023). Boost and nlohmann/json are VENDORED in third_party/, so there is no
# external Boost download, no boost-devel package, and no -DBOOST_ROOT -- just a toolchain.
#
# Intended invocation (from the CI workflow), run from the repo root:
#   docker run --rm -v "$PWD":/src -w /src amazonlinux:2023 bash .github/scripts/build-al2023.sh
set -euo pipefail

# git is needed so CMake's `git describe --tags` can stamp the version banner (otherwise it
# falls back to "unknown"). The repo is bind-mounted from the runner and owned by a different
# uid than this container's root, so mark it safe or git refuses on "dubious ownership".
# clang + libbpf-devel enable the eBPF variant: CMake auto-detects them and compiles the
# in-kernel datapath object (gwlbtun-ebpf.o). Without them the build silently falls back to
# the userspace-only path, which is NOT what we want to ship from the v4.0 line.
dnf -y install gcc gcc-c++ cmake make git clang libbpf-devel
git config --global --add safe.directory /src

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"

# The eBPF object must actually build. If clang/libbpf detection ever regresses, CMake quietly
# disables eBPF and the binary falls back to userspace; fail the build loudly instead of
# shipping a mislabeled "v4.0" artifact that has no in-kernel datapath.
if [ ! -f build/gwlbtun-ebpf.o ]; then
  echo "eBPF build FAILED: build/gwlbtun-ebpf.o was not produced (clang/libbpf-devel detection?)" >&2
  exit 1
fi
echo "eBPF object built: $(ls -l build/gwlbtun-ebpf.o)"

# Smoke-check: the freshly built binary runs and prints its version banner.
# Note: gwlbtun's help output exits non-zero, and this script runs under
# `set -euo pipefail`, so capture the banner defensively (|| true) and then
# assert on its content rather than letting the help exit code abort the build.
banner="$(./build/gwlbtun -h 2>&1 | head -1 || true)"
echo "smoke-check banner: ${banner}"
case "${banner}" in
  *"Gateway Load Balancer Tunnel Handler"*) echo "smoke-check OK" ;;
  *) echo "smoke-check FAILED: unexpected or empty banner"; exit 1 ;;
esac
