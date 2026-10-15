#!/bin/bash
# Build gwlbtun inside an Amazon Linux 2023 container so the resulting binary links the same
# glibc as the AL2023 hosts it is deployed on (a binary built on a newer-glibc runner can fail
# to run on AL2023). Boost and nlohmann/json are VENDORED in third_party/, so there is no
# external Boost download, no boost-devel package, and no -DBOOST_ROOT -- just a toolchain.
#
# Two builds:
#   build/gwlbtun                       without eBPF support (no libbpf dependency)
#   build-ebpf/gwlbtun, gwlbtun-ebpf.o  with the eBPF datapath (-e; needs libbpf at run time)
#
# Intended invocation (from the CI workflow), run from the repo root:
#   docker run --rm -v "$PWD":/src -w /src amazonlinux:2023 bash .github/scripts/build-al2023.sh
set -euo pipefail

# git is needed so CMake's `git describe --tags` can stamp the version banner (otherwise it
# falls back to "unknown"). The repo is bind-mounted from the runner and owned by a different
# uid than this container's root, so mark it safe or git refuses on "dubious ownership".
# clang and libbpf-devel are for the eBPF build.
dnf -y install gcc gcc-c++ cmake make git clang libbpf-devel
git config --global --add safe.directory /src

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DGWLBTUN_EBPF=OFF
cmake --build build -j"$(nproc)"
cmake -S . -B build-ebpf -DCMAKE_BUILD_TYPE=Release -DGWLBTUN_EBPF=ON
cmake --build build-ebpf -j"$(nproc)"

# Smoke-check: the freshly built binaries run and print their version banner.
# Note: gwlbtun's help output exits non-zero, and this script runs under
# `set -euo pipefail`, so capture the banner defensively (|| true) and then
# assert on its content rather than letting the help exit code abort the build.
for b in build/gwlbtun build-ebpf/gwlbtun; do
  banner="$(./$b -h 2>&1 | head -1 || true)"
  echo "smoke-check $b banner: ${banner}"
  case "${banner}" in
    *"Gateway Load Balancer Tunnel Handler"*) echo "smoke-check OK" ;;
    *) echo "smoke-check FAILED: unexpected or empty banner"; exit 1 ;;
  esac
done
if ldd build/gwlbtun | grep -q libbpf; then
  echo "build/gwlbtun links libbpf, but was built without eBPF support" >&2
  exit 1
fi
test -s build-ebpf/gwlbtun-ebpf.o
