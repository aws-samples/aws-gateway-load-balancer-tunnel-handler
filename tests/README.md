# gwlbtun local tests

These tests run gwlbtun on one Linux host, with no AWS account and no Gateway Load Balancer. A small GENEVE
sender (`lib/geneve.py`) plays GWLB over loopback, and each test checks gwlbtun's health output, logs, hook
script calls and network devices. They cover configuration parsing, the data path (what is forwarded, what
is dropped, the flow cache, the return path), the health check listener, and the endpoint lifecycle (hooks,
shutdown, idle teardown, setup failures, the one-instance guard).

Forwarding through a real GWLB, performance and multi-host setups need an AWS environment; see
[Testing in AWS](#testing-in-aws).

## Running

```
tests/run.sh
```

This builds gwlbtun twice, standard and `NO_RETURN_TRAFFIC`, into `build-tests/`, then runs the suite against
each build as root in a private network namespace. The namespace has only `lo` (and whatever devices the
tests create), so the tests don't touch the host's interfaces or conflict with another gwlbtun.

| Option | |
|---|---|
| `--binary PATH` | test an existing binary instead of building (repeatable) |
| `--quick` | skip the slow tests (idle teardown waits for the 60-second reaper) |
| `--asan` | build with AddressSanitizer and UndefinedBehaviorSanitizer; any finding in a gwlbtun log fails the test |
| `--host` | run in the host's network namespace, which adds the receive-queue layout tests (`test_host_layout.py`). Needs an EC2 instance with an ENA interface, and no other gwlbtun running |
| `-- ARGS` | passed to pytest, e.g. `-- -k datapath -x` |

Requirements: Linux with tun support, root (via sudo), Python 3.9+, pytest, iproute2, and for some tests
`tc` (iproute-tc), `prlimit` and `setpriv` (util-linux). On Amazon Linux 2023:

```
sudo dnf install -y gcc-c++ cmake make python3-pytest iproute-tc
```

The configuration tests (`test_config.py`) need no root, so they also run directly:
`python3 -m pytest tests/test_config.py --gwlbtun build/gwlbtun`.

## Layout

| File | Covers |
|---|---|
| `test_config.py` | command-line options, `-f` configuration files, `--show-config`, error messages, help text |
| `test_datapath.py` | endpoint creation, forwarded and dropped inner packets, the flow cache, a GENEVE round trip, malformed input, `-I` |
| `test_health.py` | the health check listener: slow and idle clients, caching, output formats, `-p` binding, failures |
| `test_lifecycle.py` | hook scripts, shutdown, idle teardown (`-t`), setup failures, the one-instance guard, device names |
| `test_host_layout.py` | UDP threads against the host's receive queues (`--host` only) |
| `lib/geneve.py` | GENEVE/GWLB packet builder and sender |
| `lib/gwlbtun.py` | the gwlbtun process under test, and a recording hook script |
| `lib/netutil.py` | waiting, devices, sockets, dummy interfaces, a peer network namespace |

Tests that need return traffic (tunnel threads, the flow cache) skip themselves on a `NO_RETURN_TRAFFIC` build.

## Writing a test

Start gwlbtun with the `gw` fixture and send it packets with `Sender`:

```python
from lib.geneve import Sender, gwlb_packet, ipv4, udp
from lib.netutil import wait_for

def test_example(gw, build):
    g = gw("-p", 18300, "-j", *build.threads())         # waits until it's receiving and answering health checks
    with Sender() as s:
        s.send(gwlb_packet(0xF17E000000000901, ipv4(udp(40000, 53))), 3)
    wait_for(lambda: g.health()["summary"]["totalPktsOut"] == 3)
```

The fixture stops every gwlbtun it started, and fails the test if gwi-/gwo- devices are left behind or a
log contains sanitizer findings. Prefer checking the health JSON over log text, and poll with `wait_for`
rather than sleeping a fixed time.

## Testing in AWS

The tests above stay on one host: their GENEVE sender uses loopback and network namespaces, and nothing
leaves the machine. Forwarding through a real Gateway Load Balancer, performance tests and multi-host setups
run on EC2 instances behind a GWLB, with traffic generators (TRex, iperf3, ethr and others) sending to
gwlbtun appliances.

Those tests cost real money. Instances, the load balancer and its endpoints, data processing and data
transfer are all billed to the AWS account you run them in, and the large instances some tests use add up
quickly. Tear the test environment down when you're done.

They also generate high volumes of traffic. Before running them, review:

- [AWS penetration testing and simulated events](https://aws.amazon.com/security/penetration-testing/),
  which lists the kinds of testing that need a request to AWS in advance.
- The [Amazon EC2 Testing Policy](https://aws.amazon.com/ec2/testing/), which covers network stress tests
  from EC2.
