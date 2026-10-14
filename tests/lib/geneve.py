# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Build GENEVE packets the way Gateway Load Balancer sends them (RFC 8926, with GWLB's three options in
class 0x0108: endpoint ID, attachment ID, flow cookie) around inner IPv4/IPv6 packets, and send them to
gwlbtun over UDP. Standard library only."""

import socket
import struct

GENEVE_PORT = 6081
ETH_P_IP, ETH_P_IPV6 = 0x0800, 0x86DD
GWLB_CLASS = 0x0108


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def geneve_option(opt_type, data, opt_class=GWLB_CLASS):
    assert len(data) % 4 == 0
    return struct.pack("!HBB", opt_class, opt_type, len(data) // 4) + data


def geneve_header(endpoint_id, cookie=0x12345678, attachment=0, ethertype=ETH_P_IP, options=None):
    """The GENEVE base header plus GWLB's options. `options` replaces the three GWLB options."""
    if options is None:
        options = (geneve_option(1, struct.pack("!Q", endpoint_id)) +
                   geneve_option(2, struct.pack("!Q", attachment)) +
                   geneve_option(3, struct.pack("!I", cookie)))
    assert len(options) % 4 == 0 and len(options) // 4 < 64
    return struct.pack("!BBHI", len(options) // 4, 0, ethertype, 0) + options


def udp(sport, dport, payload=b"abcd"):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, flags=0x02, seq=1):
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 65535, 0, 0)


def ipv4(payload, proto=17, src="10.9.8.7", dst="192.0.2.1", ttl=64, ip_options=b"", version=4, ident=1, frag=0):
    """An IPv4 packet; `ip_options` (a multiple of 4 bytes) lengthens the header."""
    assert len(ip_options) % 4 == 0
    ihl = 5 + len(ip_options) // 4
    hdr = struct.pack("!BBHHHBBH4s4s", (version << 4) | ihl, 0, ihl * 4 + len(payload), ident, frag, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst)) + ip_options
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    return hdr + payload


def ipv6(payload, nh=17, src="2001:db8::7", dst="2001:db8:1::1", hop_limit=64, ext_headers=()):
    """An IPv6 packet. ext_headers: (type, body) pairs, outermost first, using the generic
    next-header/length layout (hop-by-hop 0, routing 43, destination options 60). Bodies are padded
    to the 8-byte multiple the format needs."""
    chain = b""
    next_types = [t for t, _ in ext_headers] + [nh]
    for i, (_, body) in enumerate(ext_headers):
        body = body + b"\0" * ((-(len(body) + 2)) % 8)
        chain += struct.pack("!BB", next_types[i + 1], (len(body) + 2) // 8 - 1) + body
    first = next_types[0]
    return struct.pack("!IHBB16s16s", 6 << 28, len(chain) + len(payload), first, hop_limit,
                       socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst)) + chain + payload


def gwlb_packet(endpoint_id, inner, cookie=0x12345678, attachment=0):
    """GENEVE with GWLB options around `inner`; the ethertype follows the inner IP version."""
    ethertype = ETH_P_IPV6 if inner and inner[0] >> 4 == 6 else ETH_P_IP
    return geneve_header(endpoint_id, cookie, attachment, ethertype) + inner


def parse_geneve(data):
    """(options dict {type: bytes}, ethertype, inner) for a GENEVE payload with GWLB options."""
    optlen = (data[0] & 0x3F) * 4
    ethertype = struct.unpack("!H", data[2:4])[0]
    opts, off = {}, 8
    while off + 4 <= 8 + optlen:
        cls, typ, ln = struct.unpack("!HBB", data[off:off + 4])
        ln = (ln & 0x1F) * 4
        if cls == GWLB_CLASS:
            opts[typ] = data[off + 4:off + 4 + ln]
        off += 4 + ln
    return opts, ethertype, data[8 + optlen:]


class Sender:
    """A UDP socket that plays GWLB. Bound to a fixed source port, so every packet carries the same outer
    5-tuple (a new port would itself count as a change of GWLB data for a flow).

    gwlbtun replies to GWLB with the outer addresses swapped and the ports kept, so replies go to port 6081 on
    the sender's address. To receive them, bind to port 6081 (sport=6081) in another network namespace (see
    netutil.PeerNamespace); in gwlbtun's own namespace gwlbtun would receive its replies itself."""

    def __init__(self, target="127.0.0.1", port=GENEVE_PORT, sport=0, family=socket.AF_INET, bind_addr=None):
        self.target, self.port = target, port
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind_addr or ("127.0.0.1" if family == socket.AF_INET else "::1"), sport))
        self.sport = self.sock.getsockname()[1]

    def send(self, packet, count=1):
        for _ in range(count):
            self.sock.sendto(packet, (self.target, self.port))

    def recv(self, timeout=2.0):
        """The next datagram sent back to this socket (gwlbtun's return traffic), or None."""
        self.sock.settimeout(timeout)
        try:
            return self.sock.recvfrom(65535)[0]
        except socket.timeout:
            return None

    def flows(self, first_endpoint, endpoints, per_endpoint=1, inner=None):
        """Send `per_endpoint` packets for each of `endpoints` consecutive endpoint IDs."""
        inner = inner if inner is not None else ipv4(udp(40000, 8080, b"\0" * 16), src="10.0.0.1", dst="10.0.0.2")
        for i in range(endpoints):
            self.send(gwlb_packet(first_endpoint + i, inner), per_endpoint)

    def close(self):
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
