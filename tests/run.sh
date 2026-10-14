#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Build gwlbtun (standard and NO_RETURN_TRAFFIC) and run the local test suite against each build, as root,
# in a private network namespace so it can't disturb (or be disturbed by) anything else on the host.
#
# Usage: tests/run.sh [options] [-- pytest arguments]
#   --binary PATH   test this binary only, instead of building (repeatable)
#   --asan          build with AddressSanitizer + UndefinedBehaviorSanitizer (Debug)
#   --host          run in the host's network namespace instead: adds the receive-queue layout tests, which
#                   need the real network interface. Stop any other gwlbtun on the host first.
#   --quick         skip tests marked slow (the idle-teardown test waits for the 60 s reaper)
# Examples:
#   tests/run.sh
#   tests/run.sh --binary build/gwlbtun -- -k datapath -x
set -euo pipefail
cd "$(dirname "$0")/.."
REPO=$PWD

BINARIES=(); ASAN=0; HOST=0; PYARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BINARIES+=("$(realpath "$2")"); shift 2 ;;
    --asan)   ASAN=1; shift ;;
    --host)   HOST=1; shift ;;
    --quick)  PYARGS+=(-m "not slow"); shift ;;
    --)       shift; PYARGS+=("$@"); break ;;
    -h|--help) sed -n '5,16p' "$0"; exit 0 ;;
    *) echo "unknown option $1 (see --help)" >&2; exit 2 ;;
  esac
done

python3 -c 'import pytest' 2>/dev/null || { echo "pytest is needed: dnf install python3-pytest (or pip install pytest)" >&2; exit 2; }

if [ ${#BINARIES[@]} -eq 0 ]; then
  CMAKE=$(command -v cmake3 || command -v cmake)
  mkdir -p build-tests
  for V in std nr; do
    D=build-tests/$V; [ $ASAN = 1 ] && D=build-tests/$V-asan
    CXX=""; [ $V = nr ] && CXX="-DNO_RETURN_TRAFFIC"
    TYPE=Release
    if [ $ASAN = 1 ]; then CXX="$CXX -fsanitize=address,undefined -fno-omit-frame-pointer -g"; TYPE=Debug; fi
    echo "== building $V in $D"
    "$CMAKE" -S . -B "$D" -DCMAKE_BUILD_TYPE=$TYPE ${CXX:+"-DCMAKE_CXX_FLAGS=$CXX"} > "$D.cmake.log" 2>&1 || { cat "$D.cmake.log"; exit 1; }
    make -C "$D" -j"$(nproc)" > "$D.make.log" 2>&1 || { tail -40 "$D.make.log"; exit 1; }
    BINARIES+=("$REPO/$D/gwlbtun")
  done
fi

SUDO=(); [ "$(id -u)" = 0 ] || SUDO=(sudo)
# No root-owned __pycache__ in the checkout.
TEST_ENV="PYTHONDONTWRITEBYTECODE=1 ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1"
rc=0
for B in "${BINARIES[@]}"; do
  echo "== testing $B"
  if [ $HOST = 1 ]; then
    "${SUDO[@]}" env $TEST_ENV GWLBTUN="$B" python3 -m pytest tests "${PYARGS[@]}" || rc=1
  else
    # A fresh network namespace has only lo, and it starts down.
    "${SUDO[@]}" env $TEST_ENV GWLBTUN="$B" GWLBTUN_TEST_NETNS=1 unshare --net -- \
      bash -c 'ip link set lo up && exec python3 -m pytest tests "$@"' pytest "${PYARGS[@]}" || rc=1
  fi
done
exit $rc
