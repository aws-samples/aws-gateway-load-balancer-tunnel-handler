#!/usr/bin/env bash
# Build gwlbtun (AWS Gateway Load Balancer Tunnel Handler) inside an
# Amazon Linux 2023 environment.
#
# Designed to run inside an `amazonlinux:2023` container so the linked glibc
# matches the AL2/AL2023 hosts this handler is deployed on. Produces:
#   ${WORKSPACE}/build/gwlbtun
#
# Inputs (env vars):
#   BOOST_VERSION   Boost release version (headers only). Default: 1.83.0
#   WORKSPACE       Repo root (mounted into the container). Default: /workspace
#   TARGET_ARCH     Informational label for the build. Default: $(uname -m)
#
# The repository source is expected to already be present at ${WORKSPACE}
# (this project builds itself, unlike downstream consumers that clone it).

set -euo pipefail

BOOST_VERSION="${BOOST_VERSION:-1.83.0}"
WORKSPACE="${WORKSPACE:-/workspace}"
TARGET_ARCH="${TARGET_ARCH:-$(uname -m)}"

echo "=== gwlbtun build configuration ==="
echo "  BOOST_VERSION = ${BOOST_VERSION}"
echo "  WORKSPACE     = ${WORKSPACE}"
echo "  TARGET_ARCH   = ${TARGET_ARCH}"
echo

#-------------------------------------------------------------------------------
# Install build dependencies (we're in an AL2023 container)
#-------------------------------------------------------------------------------
echo "=== Installing build dependencies ==="
# Note: amazonlinux:2023 ships curl-minimal (which provides the `curl` command);
# installing the full `curl` package conflicts with it, so we don't request it.
dnf install -y \
    cmake \
    gcc gcc-c++ \
    make \
    tar \
    gzip \
    findutils

#-------------------------------------------------------------------------------
# Stage Boost (headers only — no Boost compilation required)
#-------------------------------------------------------------------------------
BOOST_DIR=/tmp/srcs/boost
if [ ! -d "${BOOST_DIR}" ]; then
    echo "=== Downloading Boost ${BOOST_VERSION} ==="
    mkdir -p /tmp/srcs && cd /tmp/srcs
    BOOST_UNDERSCORE="${BOOST_VERSION//./_}"
    curl -fsSL -o boost.tar.gz \
        "https://archives.boost.io/release/${BOOST_VERSION}/source/boost_${BOOST_UNDERSCORE}.tar.gz"
    tar xzf boost.tar.gz
    mv "boost_${BOOST_UNDERSCORE}" boost
    rm -f boost.tar.gz
fi

#-------------------------------------------------------------------------------
# Compile (out-of-tree, pointing CMake at our staged Boost headers)
#-------------------------------------------------------------------------------
echo "=== Compiling gwlbtun ==="
BUILD_DIR=/tmp/build
rm -rf "${BUILD_DIR}"
cmake -S "${WORKSPACE}" -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBoost_INCLUDE_DIR="${BOOST_DIR}"
cmake --build "${BUILD_DIR}" -j"$(nproc)"

if [ ! -x "${BUILD_DIR}/gwlbtun" ]; then
    echo "ERROR: build did not produce ${BUILD_DIR}/gwlbtun" >&2
    exit 1
fi

#-------------------------------------------------------------------------------
# Collect the binary
#-------------------------------------------------------------------------------
mkdir -p "${WORKSPACE}/build"
install -m 0755 "${BUILD_DIR}/gwlbtun" "${WORKSPACE}/build/gwlbtun"

echo
echo "=== Done. Built: ${WORKSPACE}/build/gwlbtun (${TARGET_ARCH}) ==="
ls -lh "${WORKSPACE}/build/gwlbtun"
file "${WORKSPACE}/build/gwlbtun" 2>/dev/null || true
