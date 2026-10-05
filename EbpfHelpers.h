// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#ifndef GWLBTUN_EBPFHELPERS_H
#define GWLBTUN_EBPFHELPERS_H

#include <linux/types.h>
#include "GeneveStructs.h"

// IPv4 header fields to match on
// Egress flow key. Shared across all gwo programs, so it includes the gwo ifindex
// (from skb->ifindex) to scope entries per-ENI and avoid collisions between ENIs
// with overlapping inner CIDRs. Zero the whole struct (incl. padding) before use.
struct EbpfEgressMapKeyV4 {
    uint32_t  ifindex;
    uint32_t  src;
    uint32_t  dst;
    uint16_t  srcpt;
    uint16_t  dstpt;
    uint8_t   prot;
};

struct EbpfEgressMapKeyV6 {
    uint32_t  ifindex;
    uint32_t  src[4];
    uint32_t  dst[4];
    uint16_t  srcpt;
    uint16_t  dstpt;
    uint8_t   prot;
};

// Max bytes of the prepend-ready encap template (outer IPv4 + UDP + GENEVE+TLVs).
// 20 + 8 + ~48 of GENEVE options fits comfortably.
#define EBPF_ENCAP_MAX 128

// GWLB's outer encap is a fixed length: outer IPv4 (20) + UDP (8) + GENEVE base (8)
// + the three fixed GWLB TLVs (GWLBE-ID 12, attachment 12, flow-cookie 8) = 68.
// Confirmed on the wire (gwlb-geneve.pcap: GENEVE opt_len=8 -> 32B options + 8B base).
// The attachment TLV (type 2) is always present (8B, zero today, value populated by
// AWS later for TGW/VPN/DX attachments) -- a value change, not a length change, so 68
// stays fixed. The egress program copies this many bytes with a compile-time constant
// (the verifier accepts a constant-length copy out of a map value, not a variable one)
// and guards val->encap_len == GWLB_ENCAP_LEN, falling back to userspace otherwise.
#define GWLB_ENCAP_LEN 68

// Bytes the tc ingress program needs linear (via bpf_skb_pull_data) to parse the
// outer headers down through the GENEVE options before the map lookup:
// outer eth (14) + outer IP (20) + outer UDP (8) + GENEVE base+options (40) = 82.
#define GWLB_INGRESS_PARSE_LEN 82

// The egress program prepends a cached return Ethernet header (14 B) in front of the
// outer IP+UDP+GENEVE encap, building a complete frame, then returns TC_ACT_PIPE so the
// chained act_mirred transmits it natively out the physical NIC (no per-packet
// FIB/neighbor lookup, and no bpf_redirect -- which drops a hand-built L2 frame on an
// L3 tun skb). GWLB_EGRESS_ROOM is the total room the egress program makes at the MAC
// layer: eth(14) + GWLB_ENCAP_LEN(68) = 82.
#define GWLB_RETURN_ETH_LEN 14
#define GWLB_EGRESS_ROOM    (GWLB_RETURN_ETH_LEN + GWLB_ENCAP_LEN)

// Cached return L2 header. The ingress program records the incoming GWLB frame's
// Ethernet header with src/dst swapped (dst = the GWLB-side next hop, src = our NIC),
// keyed by GWLBe ENI id -- one entry per GWLB, since the L2 next hop may differ when
// multiple GWLBs target the same appliance. The egress program prepends it. Layout
// matches struct ethhdr.
struct EbpfReturnEth {
    uint8_t   h_dest[6];
    uint8_t   h_source[6];
    uint16_t  h_proto;      // network order; ETH_P_IP
};

// Egress flow value: the prepend-ready outer encap (IP + UDP + GENEVE TLVs), built
// once by userspace from the ingress GwlbData (outer src=appliance, dst=GWLB, ports
// preserved, TLVs intact). No ethernet header in the blob -- the egress program
// prepends the cached return L2 (return_eth_map, keyed by gwlbeEniId below), builds the
// full frame, and returns TC_ACT_PIPE so the chained act_mirred transmits it out the
// physical NIC. Direction-independent, so both tuple directions share one value.
// last_sent_ns is stamped by the egress program for the GC sweep. encap[] is first
// (offset 0) so the constant-length copy out of it is at a zero offset, which the
// verifier accepts more readily.
struct EbpfEgressMapValue {
    uint8_t   encap[EBPF_ENCAP_MAX];
    uint16_t  encap_len;
    uint64_t  last_sent_ns;
    uint64_t  gwlbeEniId;    // set by userspace on learn; egress uses it to key return_eth_map
};

struct EbpfIngressRTKey {
    uint64_t  gwlbeEniId;
    uint32_t  flowCookie;
};

// Per-flow disposition for the ingress fast path. Today userspace only ever sets
// DISP_REDIRECT; FORWARD and DROP are reserved for a future "offload this flow"
// control interface (the appliance telling gwlbtun to handle a flow itself):
//   DISP_FORWARD -> re-encapsulate and XDP_TX straight back to GWLB (no gwi/stack)
//   DISP_DROP    -> XDP_DROP at the NIC
enum ingress_disposition {
    DISP_REDIRECT = 0,   // decap + redirect to gwi (appliance inspects) — current behavior
    DISP_FORWARD  = 1,   // reserved: re-encap + XDP_TX bounce to GWLB
    DISP_DROP     = 2,   // reserved: XDP_DROP
};

// Value for ingress_rt_map. disposition selects what the XDP program does with a
// known flow; ifindex is the gwi interface to redirect to for DISP_REDIRECT (per-ENI,
// so identical for every flow of a given ENI). last_seen_ns is stamped by the ingress
// program (per-CPU, via bpf_ktime_get_coarse_ns) on each hit so userspace can age the
// entry during its GC sweep. return_eth_set is a per-flow latch: 0 until the flow has
// ensured this ENI's return-L2 is cached in return_eth_map, then 1 so later packets
// skip that second hash lookup (the next-hop MAC is stable).
struct EbpfIngressRTValue {
    uint32_t  disposition;   // enum ingress_disposition
    uint32_t  ifindex;
    uint64_t  last_seen_ns;
    uint8_t   return_eth_set;
};

#define EBPF_MAX_IPV4_ENTRIES  2048
#define EBPF_MAX_IPV6_ENTRIES  512
#define EBPF_MAX_ENIS          128

// Status counters
typedef uint32_t rcv_counters_key;

enum recv_codes {
    RCV_VALID_GENEVE = 0,
    RCV_NO_ETHER_HDR,
    RCV_WRONG_ETHER_PROT,
    RCV_NO_IP_HDR,
    RCV_NOT_UDP,
    RCV_NO_UDP_HDR,
    RCV_WRONG_UDP_PORT,
    RCV_NO_GENEVE_HDR,
    RCV_BAD_GENEVE_VER,
    RCV_BAD_GENEVE_VNI,
    RCV_BAD_GENEVE_OPTS,
    RCV_UNKNOWN_FLOW,

    // This must be the last entry.
    RCV_CODES_COUNT
};

// Egress (gwo tc) disposition counters.
enum egr_codes {
    EGR_REENCAP = 0,     // re-encapsulated and redirected to GWLB in-kernel
    EGR_UNKNOWN_FLOW,    // no egress map entry -> left for the userspace fallback
    EGR_NOT_IP,          // not IPv4/IPv6 -> passed through untouched
    EGR_TOO_BIG,         // encap wouldn't fit / adjust_room failed -> left for userspace
    EGR_NO_L2,           // flow matched but no cached return L2 yet -> userspace fallback

    // This must be the last entry.
    EGR_CODES_COUNT
};

char const* const rcv_codes_str[] = {
        "Processed GENEVE packets",
        "No Ethernet header",
        "Wrong Ethernet protocol",
        "No IP header",
        "Not a UDP packet",
        "No UDP header",
        "Wrong UDP port",
        "No GENEVE header",
        "GENEVE version not 0",
        "GENEVE VNI not 0",
        "GENEVE options invalid",
        "Unknown flow - punting to user space",
        "End of codes"
};

#if __BIG_ENDIAN__
# define __bpf_htonll(x) (x)
# define __bpf_ntohll(x) (x)
#else
# define __bpf_htonll(x) (((uint64_t)__bpf_htonl((x) & 0xFFFFFFFF) << 32) | __bpf_htonl((x) >> 32))
# define __bpf_ntohll(x) (((uint64_t)__bpf_ntohl((x) & 0xFFFFFFFF) << 32) | __bpf_ntohl((x) >> 32))
#endif


#endif //GWLBTUN_EBPFHELPERS_H
