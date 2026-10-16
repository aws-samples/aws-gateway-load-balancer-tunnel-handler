// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * The contract between gwlbtun's eBPF programs (EbpfHelpers.c, compiled with clang -target bpf) and gwlbtun
 * itself (EbpfLoader, GeneveHandler): map key and value layouts, counter codes, and the inner-flow digest both
 * sides compute. Plain C, included by both. Every struct here is read and written as raw map bytes by both
 * sides, so each has a fixed size with explicit padding, and is zeroed before it's filled in.
 */

#ifndef GWLBTUN_EBPFHELPERS_H
#define GWLBTUN_EBPFHELPERS_H

#include <linux/types.h>

#ifdef __bpf__
#define GWLBTUN_INLINE static __always_inline
#else
#define GWLBTUN_INLINE static inline
#endif

// The GENEVE encapsulation GWLB sends: outer IPv4 + UDP to port 6081 + GENEVE (version 0, VNI 0, options length
// 8 words) with three class 0x0108 options: endpoint ID (12 bytes), attachment ID (12) and flow cookie (8). See
// "What is the packet format that the GWLB and appliance exchange?" in the AWS blog post "Integrate your custom
// logic or appliance with AWS Gateway Load Balancer"; the outer header is IPv4 for IPv6 payloads too ("New –
// Gateway Load Balancer support for IPv6"). We have only observed outer IPv4 headers without options. The
// programs only handle packets with exactly this layout; anything else is left to gwlbtun's userspace path.
#define GWLB_GENEVE_LEN      40
#define GWLB_ENCAP_LEN       (20 + 8 + GWLB_GENEVE_LEN)   // 68
#define GWLB_RETURN_ETH_LEN  14
#define GWLB_EGRESS_ROOM     (GWLB_RETURN_ETH_LEN + GWLB_ENCAP_LEN)   // 82: what the egress program prepends
// Bytes the ingress program wants in the skb's linear area: outer Ethernet + encap, then an inner IPv6 header
// (or IPv4 without options) and the four bytes of ports.
#define GWLB_INGRESS_PULL_LEN (GWLB_RETURN_ETH_LEN + GWLB_ENCAP_LEN + 40 + 4)

#define GWLBTUN_GENEVE_PORT  6081

// The tcx return codes (linux/bpf.h from Linux 6.6). Defined here so the object also builds against older
// kernel headers; tcx itself needs Linux 6.6 at run time.
#define GWLBTUN_TCX_NEXT     (-1)   // not ours: let the next program (or the stack) have it
#define GWLBTUN_TCX_REDIRECT 7

// ---- Ingress: the tcx program on each GWLB-facing interface -------------------------------------------------

// ingress_map key: one GWLB flow, as GWLB identifies it.
struct EbpfIngressKey {
    __u64 gwlbeId;      // GWLB endpoint ID (GENEVE option type 1)
    __u32 flowCookie;   // GWLB flow cookie (GENEVE option type 3)
    __u32 pad;
};

// Reserved for dispositions other than delivering to gwi- (dropping or returning a flow in the kernel). Only
// DISP_REDIRECT is implemented; the programs leave anything else to userspace.
enum ebpf_disposition {
    DISP_REDIRECT = 0,
};

struct EbpfIngressValue {
    __u64 flowDigest;     // gwlbtun_flow_digest() of the inner flow this cookie was learned for
    __u64 lastSeenNs;     // bpf_ktime_get_coarse_ns() of the last packet the program delivered
    __u32 gwiIfindex;     // the endpoint's gwi- interface
    __u32 disposition;    // enum ebpf_disposition
    __u8  returnEthSet;   // set once this flow has recorded its interface's return Ethernet header
    __u8  pad[7];
};

// ---- Egress: the tc action on each gwo- interface ------------------------------------------------------------

// egress_v4_map / egress_v6_map keys: the inner flow, in network byte order, as it leaves gwo-. gwoIfindex keeps
// endpoints apart (their inner address ranges may overlap). Both directions of a flow are stored.
struct EbpfEgressKeyV4 {
    __u32 gwoIfindex;
    __u32 src;
    __u32 dst;
    __u16 srcPort;
    __u16 dstPort;
    __u8  prot;
    __u8  pad[3];
};

struct EbpfEgressKeyV6 {
    __u32 gwoIfindex;
    __u32 src[4];
    __u32 dst[4];
    __u16 srcPort;
    __u16 dstPort;
    __u8  prot;
    __u8  pad[3];
};

// The outer headers for a flow's return traffic, as gwlbtun's userspace path would build them (sendUdpSG):
// IPv4 from the address the flow arrived at to GWLB (addresses swapped), UDP with the flow's ports kept as they
// were, then its GENEVE header unchanged; what the "Integrate your custom logic or appliance with AWS Gateway
// Load Balancer" blog post asks of an appliance. The program fills in the lengths and the IP checksum.
struct EbpfEgressValue {
    __u8  encap[GWLB_ENCAP_LEN];
    __u16 encapLen;       // always GWLB_ENCAP_LEN; checked by the program
    __u16 pad1;
    __u32 nicIfindex;     // the interface the flow arrived on, which its replies must leave by
    __u32 pad2;
    __u64 lastSentNs;     // bpf_ktime_get_coarse_ns() of the last packet the program sent
};

// egress_config_map (one entry): the interface the egress action's mirred sends to. Flows that arrived on
// another interface are left to userspace, which sends them out of the right one.
struct EbpfEgressConfig {
    __u32 mirredIfindex;
};

// return_eth_map value, keyed by interface index: the Ethernet header for packets back to GWLB from that
// interface, recorded from GWLB's packets with the addresses swapped. Laid out as struct ethhdr.
struct EbpfReturnEth {
    __u8  dest[6];
    __u8  source[6];
    __u16 proto;          // network order
};

// ---- Counters (per-CPU arrays, summed by gwlbtun) ---------------------------------------------------------

enum ebpf_ingress_code {
    ING_ACCELERATED = 0,   // delivered to gwi- in the kernel
    ING_NO_ETHER_HDR,
    ING_WRONG_ETHER_PROT,
    ING_NO_IP_HDR,
    ING_NOT_UDP,
    ING_NO_UDP_HDR,
    ING_WRONG_UDP_PORT,    // the four above and this one: not GENEVE traffic
    ING_NO_GENEVE_HDR,
    ING_BAD_GENEVE_VER,
    ING_BAD_GENEVE_VNI,
    ING_BAD_GENEVE_OPTS,   // the four above: GENEVE, but malformed or not from GWLB
    ING_UNSUPPORTED,       // outer IP options or fragment, a GENEVE layout other than GWLB's, or an inner packet the
                           // program can't key (a later TCP/UDP fragment, IPv6 extension headers)
    ING_UNKNOWN_FLOW,      // no map entry for the endpoint and cookie: a new flow, for userspace to learn
    ING_FLOW_MISMATCH,     // the cookie is known, but for a different inner flow
    ING_DECAP_FAILED,
    ING_CODES_COUNT
};

enum ebpf_egress_code {
    EGR_REENCAP = 0,       // sent back to GWLB in the kernel
    EGR_NOT_IP,
    EGR_UNSUPPORTED,       // a later TCP/UDP fragment or IPv6 extension headers
    EGR_UNKNOWN_FLOW,      // no map entry
    EGR_OTHER_NIC,         // the flow arrived on an interface other than the mirred target
    EGR_NO_L2,             // no return Ethernet header recorded for the flow's interface yet
    EGR_ENCAP_FAILED,
    EGR_CODES_COUNT
};

// ---- The inner-flow digest --------------------------------------------------------------------------------

// A 64-bit digest of an inner flow that is the same for both directions. The ingress program checks it so a
// cookie learned for one flow is never used to deliver another (see gwlbtun_flow_digest's callers).
GWLBTUN_INLINE __u64 gwlbtun_mix64(__u64 x)
{
    // The MurmurHash3 finalizer.
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

// One end of a flow: its address folded to 64 bits (an IPv4 address as is; an IPv6 address as
// gwlbtun_fold_v6), and its port as read from the packet (network order).
GWLBTUN_INLINE __u64 gwlbtun_flow_end(__u64 addrFold, __u16 port)
{
    return gwlbtun_mix64(addrFold ^ ((__u64)port << 48));
}

GWLBTUN_INLINE __u64 gwlbtun_fold_v6(const __u32 a[4])
{
    return gwlbtun_mix64(((__u64)a[0] << 32) | a[1]) ^ (((__u64)a[2] << 32) | a[3]);
}

// ipVersion 4 or 6; prot the inner protocol; the ends in either order.
GWLBTUN_INLINE __u64 gwlbtun_flow_digest(__u8 ipVersion, __u8 prot, __u64 endA, __u64 endB)
{
    const __u64 lo = endA < endB ? endA : endB;
    const __u64 hi = endA < endB ? endB : endA;
    return gwlbtun_mix64(lo ^ gwlbtun_mix64(hi ^ ((__u64)ipVersion << 8 | prot)));
}

#endif //GWLBTUN_EBPFHELPERS_H
