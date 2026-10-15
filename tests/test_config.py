# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Command line, configuration file (-f) and --show-config. Nothing here starts gwlbtun: no root needed."""

import pytest

A_YAML = """\
# comment
cmdnew: /bin/true
timeout: 30
port: "127.0.0.1:18100"
interface: [lo]
json: true
udpthreads: 3
reserve:
  - 100,100,10,10,10,10
  - vpce-0123456789abcdef0:5,5,5,5,5,5
logging: core=debug
"""


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_bytes(text if isinstance(text, bytes) else text.encode())
    return str(p)


@pytest.fixture
def a_yaml(tmp_path):
    return write(tmp_path, "a.yaml", A_YAML)


def without_banner(text):
    return "\n".join(l for l in text.splitlines() if not l.startswith("# gwlbtun configuration"))


# --- Configuration files -------------------------------------------------------------------------------

def test_file_values_applied(build, a_yaml):
    o = build.show_config("-f", a_yaml)
    for want in ['timeout: 30', 'port: "127.0.0.1:18100"', 'interface: ["lo"]', 'json: true', 'udpthreads: 3',
                 '"vpce-0123456789abcdef0:5,5,5,5,5,5"', 'logging: "core=debug"']:
        assert want in o


def test_show_config_round_trip(build, a_yaml, tmp_path):
    first = without_banner(build.show_config("-f", a_yaml))
    again = without_banner(build.show_config("-f", write(tmp_path, "b.yaml", first)))
    assert first == again


def test_command_line_overrides_file(build, a_yaml):
    o = build.show_config("-f", a_yaml, "--udpthreads", "5", "-t", "0", "-p", "18101")
    assert 'udpthreads: 5' in o and 'timeout: 0' in o and 'port: "18101"' in o


def test_udpthreads_replaces_files_udpaffinity(build, tmp_path):
    o = build.show_config("-f", write(tmp_path, "c.yaml", 'udpaffinity: "0"\n'), "--udpthreads", "2")
    assert 'udpthreads: 2' in o and 'udpaffinity' not in o.replace("# udpaffinity", "")


def test_cli_interface_replaces_files_list(build, a_yaml):
    assert 'interface: ["lo"]' in build.show_config("-f", a_yaml, "-I", "lo")


def test_cli_reserve_replaces_files_list(build, a_yaml):
    o = build.show_config("-f", a_yaml, "--reserve", "1,2,3,4,5,6")
    assert '"1,2,3,4,5,6"' in o and "vpce-0123456789abcdef0" not in o


def test_debug_replaces_files_logging(build, a_yaml):
    assert 'logging: "all=debug"' in build.show_config("-f", a_yaml, "-d")


@pytest.mark.parametrize("name,text,expect", [
    ("e1", "timeout: 5\nbogus: 1\n", "Unknown option 'bogus' in {path}:2"),
    ("e2", "udpthreads: lots\n", "udpthreads 'lots'"),
    ("e3", "timeout: [1\n", "Invalid YAML in {path}"),
    ("e4", "timeout: [1, 2]\n", "takes a single value"),
    ("e5", "json: maybe\n", "expected true or false"),
    ("e6", "show-config: true\n", "Option 'show-config' is not allowed in a configuration file"),
    ("e7", "config: other.yaml\n", "Option 'config' is not allowed in a configuration file"),
    ("e8", "interface: nosuchif0\n", "no network interface named 'nosuchif0'"),
    ("e9", "timeout: 1\n\n\nbogus2: 2\n", "{path}:4"),
    ("n1", "timeout:\n", "timeout: needs a value"),
    ("n3", "port:\n  a: 1\n", "expected a value, not a mapping"),
])
def test_file_errors(build, tmp_path, name, text, expect):
    path = write(tmp_path, name + ".yaml", text)
    p = build.run("-f", path)
    assert p.returncode != 0
    assert expect.format(path=path) in p.out


def test_missing_file(build, tmp_path):
    path = str(tmp_path / "missing.yaml")
    assert "Unable to read configuration file " + path in build.run("-f", path).out


@pytest.mark.parametrize("name,text,expect", [
    ("empty", "", "timeout: 0"),
    ("doc", "---\ntimeout: 7\n", "timeout: 7"),
    ("n2", 'logging: ""\n', "# logging: (default)"),
    ("n4", "interface:\n  - lo\n", 'interface: ["lo"]'),
    ("n5", 'cmdnew: "/opt/my hooks/create.sh"\nlogging: core=debug, udp=info\n', 'cmdnew: "/opt/my hooks/create.sh"'),
    ("n5b", 'logging: core=debug, udp=info\n', 'logging: "core=debug, udp=info"'),
    ("bom", b"\xef\xbb\xbftimeout: 9\n", "timeout: 9"),
])
def test_file_forms_accepted(build, tmp_path, name, text, expect):
    assert expect in build.show_config("-f", write(tmp_path, name + ".yaml", text))


# --- Command line --------------------------------------------------------------------------------------

def test_stray_argument_rejected(build):
    assert "Unexpected argument 'stray'" in build.run("stray").out


def test_unknown_option_prints_help(build):
    assert "Usage:" in build.run("--nosuch").out


@pytest.mark.parametrize("args,expect", [
    (["-I", "nosuchif0"], "no network interface named 'nosuchif0'"),
    (["-p", "bogus:80"], "Invalid -p"),
    (["-p", "70000"], "Invalid -p"),
    (["--rcvbuf", "2048"], "1 to 2047"),
    (["--udpincomingcpu", "auto"], "unrecognized option"),   # removed during 3.3 development
])
def test_invalid_options(build, args, expect):
    p = build.run(*args, "--show-config")
    assert p.returncode != 0 and expect in p.out


@pytest.mark.parametrize("value", ["abc,1,2,3,4,5", "-1,1,2,3,4,5", "100000001,1,2,3,4,5", "1,2,3,4,5",
                                   "1,2,3,4,5,6,7", "1,,3,4,5,6", " 1,2,3,4,5,6", "+1,2,3,4,5,6",
                                   "vpce-xyz:1,2,3,4,5,6", "vpce-:1,2,3,4,5,6"])
def test_reserve_rejected(build, value):
    assert "Invalid --reserve" in build.run("--reserve", value, "--show-config").out


def test_reserve_cap_and_override_accepted(build):
    o = build.show_config("--reserve", "100000000,0,0,0,0,0", "--reserve", "vpce-0123456789abcdef0:1,2,3,4,5,6")
    assert '"100000000,0,0,0,0,0"' in o and "vpce-0123456789abcdef0:1,2,3,4,5,6" in o


@pytest.mark.parametrize("args", [["-t", "5x"], ["-t", "+5"], ["-t", "-1"], ["-p", "80x"], ["-p", "65536"],
                                  ["--rcvbuf", "0"], ["--busypoll", "1e3"], ["--udpthreads", "2000000000"],
                                  ["--udpthreads", "0"]])
def test_numbers_strict(build, args):
    p = build.run(*args, "--show-config", timeout=5)
    assert p.returncode != 0 and "Invalid" in p.out


def test_tunthreads_range(build, return_traffic):
    p = build.run("--tunthreads", "2000000000", "--show-config", timeout=5)
    assert "expected a whole number of threads, 1 to 255" in p.out
    assert "tunthreads: 255" in build.show_config("--tunthreads", "255")


@pytest.mark.parametrize("value", ["0", "2000"])
def test_sndbuf_range(build, return_traffic, value):
    assert "Invalid --sndbuf" in build.run("--sndbuf", value, "--show-config").out


def test_tunnel_options_absent_without_return_traffic(build):
    if build.return_traffic:
        pytest.skip("return-traffic build")
    for opt in ("--tunthreads", "--tunaffinity", "--sndbuf"):
        assert build.run(opt, "1", "--show-config").returncode != 0
    assert "--tunthreads" not in build.run("-h").out


# --- Help and --show-config text -----------------------------------------------------------------------

def test_help(build):
    h = build.run("-h").out
    assert "-f FILE" in h
    assert "Takes precedence over udpthreads." in h and "udptreads" not in h
    assert "at most 100000000 each). Default 16384,16384,1024,1024,1024,1024." in h
    assert "--udpincomingcpu" not in h


def test_show_config_reserve_default(build):
    assert "# reserve: (default) 16384,16384,1024,1024,1024,1024" in build.show_config()


# --- eBPF options (-e, --ebpf-reserve) -----------------------------------------------------------------

def test_ebpf_reserve_default_follows_reserve(build):
    assert "# ebpf-reserve: (default, from reserve) 33792,3072" in build.show_config()
    assert "# ebpf-reserve: (default, from reserve) 6,15" in build.show_config("--reserve", "1,2,3,4,5,6")


def test_ebpf_reserve_round_trip(build, tmp_path):
    o = build.show_config("--ebpf-reserve", "1000000,20000")
    assert 'ebpf-reserve: "1000000,20000"' in o
    assert 'ebpf-reserve: "1000000,20000"' in build.show_config("-f", write(tmp_path, "e.yaml", without_banner(o)))


@pytest.mark.parametrize("value", ["5", "1,2,3", "a,1", "1,-1", "100000001,1", "1, 2"])
def test_ebpf_reserve_rejected(build, value):
    assert "Invalid --ebpf-reserve" in build.run("--ebpf-reserve", value, "--show-config").out


def test_ebpf_object(build, tmp_path):
    if not build.ebpf_object:
        o = build.run("-e", "/nonexistent", "--show-config").out
        assert "built without eBPF support" in o and "eBPF options" in build.run("-h").out
        return
    assert "Invalid -e/--ebpf '/nonexistent'" in build.run("-e", "/nonexistent", "--show-config").out
    assert 'ebpf: "%s"' % build.ebpf_object in build.show_config("-e", build.ebpf_object)
    assert 'ebpf: "%s"' % build.ebpf_object in build.show_config("-f", write(tmp_path, "o.yaml", "ebpf: %s\n" % build.ebpf_object))
