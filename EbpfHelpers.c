/*

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0

Compile this like:
clang -O2 -g -Wall -target bpf -c EbpfHelpers.cpp -o EbpfHelpers.o
*/
#include <stdint.h>                // Provides uint8_t, etc.
#include <linux/bpf.h>             // Provides the xdp_md definition
#include <bpf/bpf_endian.h>        // Contains the bpf_ntohs and bpf_ntohl macros
#include <bpf/bpf_helpers.h>       // Contains the SEC macro
#include <linux/if_ether.h>        // Contains the ethhdr definition
#include <linux/in.h>              // Contains the IPPROTO defines.
#include <linux/ip.h>              // Contains the iphdr definition
#include <linux/ipv6.h>            // Contains the ipv6hdr definition
#include <linux/udp.h>             // Contains the udphdr definition
#include <linux/pkt_cls.h>         // Contains TC_ACT_* return codes
#include <linux/types.h>           // Provides u8, u16, u32, and u64 defs
#include "EbpfHelpers.h"

// This next part requires Linux kernel 5.2 or newer,
#undef bpf_printk
#define bpf_printk(fmt, ...)                            \
({                                                      \
        static const char ____fmt[] = fmt;              \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

// Define our storage
#ifdef NO_RETURN_TRAFFIC
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, uint64_t);
    __type(value, u32);
    __uint(max_entries, EBPF_MAX_ENIS);
} ingress_nrt_map SEC(".maps");
#else
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct EbpfIngressRTKey);
    __type(value, struct EbpfIngressRTValue);
    __uint(max_entries, EBPF_MAX_ENIS * (EBPF_MAX_IPV4_ENTRIES + EBPF_MAX_IPV6_ENTRIES));
    //__uint(max_entries, 5);
} ingress_rt_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct EbpfEgressMapKeyV4 );
    __type(value, struct EbpfEgressMapValue );
    __uint(max_entries, EBPF_MAX_IPV4_ENTRIES);
} ipv4_flows_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct EbpfEgressMapKeyV6 );
    __type(value, struct EbpfEgressMapValue );
    __uint(max_entries, EBPF_MAX_IPV6_ENTRIES);
} ipv6_flows_map SEC(".maps");
#endif

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, rcv_counters_key);
    __type(value, uint64_t);
    __uint(max_entries, RCV_CODES_COUNT);
} counters_map SEC(".maps");

void __always_inline add_rcv_count(rcv_counters_key index)
{
    uint64_t* value = bpf_map_lookup_elem(&counters_map, &index);
    if(value) *value += 1;
}

#ifndef NO_RETURN_TRAFFIC
// Egress (gwo tc) disposition counters.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, rcv_counters_key);
    __type(value, uint64_t);
    __uint(max_entries, EGR_CODES_COUNT);
} egress_counters_map SEC(".maps");

void __always_inline add_egr_count(rcv_counters_key index)
{
    uint64_t* value = bpf_map_lookup_elem(&egress_counters_map, &index);
    if(value) *value += 1;
}

// Cached return L2 headers, keyed by GWLBe ENI id. The ingress program records the
// incoming frame's Ethernet header with src/dst swapped; the egress program prepends
// it, builds the full return frame, and returns TC_ACT_PIPE so the chained
// act_mirred transmits it natively out the physical NIC -- no per-packet FIB +
// neighbor lookup, and no bpf_redirect (see the egress program block for why). One
// entry per GWLB (the L2 next hop can differ when multiple GWLBs target the same
// appliance).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint64_t);                 // gwlbeEniId
    __type(value, struct EbpfReturnEth);
    __uint(max_entries, EBPF_MAX_ENIS);
} return_eth_map SEC(".maps");
#endif

/**
 * Parse a GENEVE header option field, and fill in EbpfIngressRTKey with the
 * gwlbeEniId or the flowCookie if we are at either of those options
 * @param data_cur  Pointer to the current byte being processed in the header
 * @param data_end  Pointer to the end of the current option being processed
 * @param rtk       The EbpfIngressRTKey to populate if possible.
 * @return  What data_cur should be advanced to after this call.
 */
void __always_inline *parse_geneve_option(void *data_cur, void *data_end, struct EbpfIngressRTKey *rtk)
{
    void* retptr;

    if(data_cur + sizeof(struct geneve_opt) > data_end)
    {
        add_rcv_count(RCV_BAD_GENEVE_OPTS);
        return NULL;
    }
    struct geneve_opt *opt;
    opt = (struct geneve_opt *)data_cur;

    if(opt->opt_class == __bpf_constant_htons(GENEVE_CLASS_AWS) && opt->type == GENEVE_TYPE_GWLBE_ID && opt->length == 2)
    {
        if( data_cur + sizeof(struct geneve_opt) + 8 > data_end)
        {
            add_rcv_count(RCV_BAD_GENEVE_OPTS);
            return NULL;
        }
        rtk->gwlbeEniId = __bpf_ntohll(*(uint64_t *)opt->opt_data);
    }
    else if(opt->opt_class == __bpf_constant_htons(GENEVE_CLASS_AWS) && opt->type == GENEVE_TYPE_FLOW_COOKIE && opt->length == 1)
    {
        if( data_cur + sizeof(struct geneve_opt) + 4 > data_end)
        {
            add_rcv_count(RCV_BAD_GENEVE_OPTS);
            return NULL;
        }
        rtk->flowCookie = __bpf_ntohl(*(uint32_t *)opt->opt_data);
    }

    // Note: Moving this check before the above checks would seem to allow removing the inner packet size checks,
    // however the validator can't handle this type of math so won't accept it.
    retptr = data_cur + sizeof(struct geneve_opt) + opt->length * 4;
    if( retptr > data_end)
    {
        add_rcv_count(RCV_BAD_GENEVE_OPTS);
        return NULL;
    }

    return retptr;
}

/*
 * ============================================================================
 *  INGRESS FAST PATH IS tc (clsact ingress), NOT XDP -- and here is why.
 * ============================================================================
 * This program was originally written as XDP. Live testing on a real GWLB
 * appliance (ENA NIC, Amazon Linux 2023) proved XDP cannot work here, for two
 * independent reasons. Both are fundamental, not tuning issues:
 *
 *  (1) XDP cannot deliver the decapped packet into gwi.
 *      Decap has to hand the inner packet to the gwi TUN as if it were RECEIVED
 *      there -- exactly what a userspace write() to the tun fd does -- so the
 *      host stack then routes it on toward gwo. That is an ingress redirect
 *      (BPF_F_INGRESS). XDP's bpf_redirect() accepts NO flags at all and only
 *      ever redirects to a device's EGRESS; passing BPF_F_INGRESS from XDP makes
 *      the redirect fail and the packet is silently dropped. A clean build and a
 *      clean verifier load hide this completely -- it only shows up on the wire
 *      (observed ~96% loss, while the "accelerated" counter happily counted the
 *      drops as successes). Redirecting to gwi's EGRESS instead does not help:
 *      for a TUN, the egress/ndo_xdp_xmit path goes to the fd read() side, not
 *      the host receive stack. Injecting into another device's RX via
 *      bpf_redirect(ifindex, BPF_F_INGRESS) is only available in skb context,
 *      i.e. tc / clsact. (See docs.ebpf.io bpf_redirect: "Currently, XDP only
 *      supports redirection to the egress interface, and accepts no flag at all.")
 *
 *  (2) Native XDP is unavailable at the MTU GWLB requires.
 *      GWLB inner payloads run up to 8500 bytes, so the data NIC uses a jumbo
 *      MTU (9001). ENA refuses to attach NATIVE XDP above its native-XDP MTU
 *      cap, so XDP could only load in SKB/generic mode -- which runs after the
 *      skb is already allocated, discarding the entire performance premise of
 *      XDP on this NIC. At that point tc clsact (also skb-based, same place in
 *      the stack) is equivalent in cost and strictly more capable, because it
 *      can do the ingress redirect that (1) needs and XDP cannot.
 *
 * Net: ingress is a tc clsact-INGRESS classifier on the physical NIC, mirroring
 * the clsact-EGRESS program on each gwo. The only thing XDP offered that tc does
 * not -- XDP_TX / XDP_DROP for a future "offload this flow entirely in-kernel"
 * mode -- is blocked by (2) on ENA regardless, so nothing is lost today. If that
 * offload is ever built it needs a NIC/MTU that supports native XDP.
 *
 * Decap is the exact inverse of the egress encap: strip the fixed 68-byte outer
 * IP+UDP+GENEVE (GWLB_ENCAP_LEN) right after the MAC header with
 * bpf_skb_adjust_room(-68, BPF_ADJ_ROOM_MAC); the outer Ethernet is then removed
 * for free by the L3-TUN redirect path (the kernel's __bpf_redirect_no_mac strips
 * the skb down to its network header for an ARPHRD_NONE device like gwi). Finally
 * bpf_redirect(gwi, BPF_F_INGRESS) returns TC_ACT_REDIRECT.
 * ============================================================================
 */
SEC("tc")
int gwlbtun_ingress_prog(struct __sk_buff *skb)
{
    // Make sure the outer headers through the GENEVE options are in the linear
    // area so the direct packet access below can read them (GRO / jumbo frames
    // may otherwise leave the tail in fragments). Best-effort: a packet shorter
    // than the header block is not GWLB traffic and the bounds checks below will
    // punt it to the stack with TC_ACT_OK anyway.
    bpf_skb_pull_data(skb, GWLB_INGRESS_PARSE_LEN);

    // Calculate where data starts and ends so later checks can ensure we don't go off the end of the data.
    void *data_end = (void *)(long)skb->data_end;
    void *data_start = (void *)(long)skb->data;
    void *data_cur = data_start;

    /*
     * Process the Ethernet header. At the tc clsact-ingress hook skb->data points
     * at the outer MAC header, the same layout XDP saw, so the parse is unchanged.
     */
    // Make sure we have enough bytes for an Ethernet header, then get a pointer to it.
    if (data_cur + sizeof(struct ethhdr) > data_end)
    {
        add_rcv_count(RCV_NO_ETHER_HDR);
        return TC_ACT_OK;
    }
    struct ethhdr *eth = data_cur; data_cur += sizeof(struct ethhdr);
    // Ensure outer Ethertype is an IPv4 packet
    if(eth->h_proto != __bpf_constant_htons(ETH_P_IP))
    {
        add_rcv_count(RCV_WRONG_ETHER_PROT);
        return TC_ACT_OK;
    }

    /*
     * Process the IP header.
     */
    // Make sure we have enough bytes for the IP header, then get a pointer to it.
    if (data_cur + sizeof(struct iphdr) > data_end)
    {
        add_rcv_count(RCV_NO_IP_HDR);
        return TC_ACT_OK;
    }
    struct iphdr *iphdr = data_cur; data_cur += iphdr->ihl * 4;  // The IP Header Length (ihl) field gives the header length in 32 bit (4 byte) increments.
    // Verify it's UDP
    if(iphdr->protocol != IPPROTO_UDP)
    {
        add_rcv_count(RCV_NOT_UDP);
        return TC_ACT_OK;
    }

    /*
     * Process the UDP header.
     */
    // Make sure we have enough bytes for the UDP header, then get a pointer to it.
    if (data_cur + sizeof(struct udphdr) > data_end)
    {
        add_rcv_count(RCV_NO_UDP_HDR);
        return TC_ACT_OK;
    }
    struct udphdr *udphdr = data_cur; data_cur += sizeof(struct udphdr);
    // Targeting Geneve port?
    if(udphdr->dest != __bpf_constant_htons(GENEVE_UDP_PORT))
    {
        add_rcv_count(RCV_WRONG_UDP_PORT);
        return TC_ACT_OK;
    }

    /*
     * Process the GENEVE header.
     */
    // Make sure we have enough bytes for the GENEVE header, then get a pointer to it.
    if (data_cur + sizeof(struct genevehdr) > data_end)
    {
        add_rcv_count(RCV_NO_GENEVE_HDR);
        return TC_ACT_OK;
    }
    struct genevehdr *genevehdr = data_cur; data_cur += sizeof(struct genevehdr);
    if (data_cur > data_end)
    {
        add_rcv_count(RCV_BAD_GENEVE_OPTS);
        return TC_ACT_OK;
    }

    // Test a couple fields to try and make sure this is actually GENEVE encap'ed and is what we want.
    // GENEVE version should always be 0 for GWLB.
    if(genevehdr->ver != 0)
    {
        add_rcv_count(RCV_BAD_GENEVE_VER);
        return TC_ACT_OK;
    }
    // The Virtual Network Identifier (VNI) is 24 bits (3 bytes), and GWLB always uses VNI ID = 0.
    if(genevehdr->vni[0] != 0 || genevehdr->vni[1] != 0 || genevehdr->vni[2] != 0)
    {
        add_rcv_count(RCV_BAD_GENEVE_VNI);
        return TC_ACT_OK;   // GWLB always uses VNI ID = 0.
    }

    // Process the 3 GENEVE options we're expecting. memset (not { 0 }) so the
    // trailing struct padding is zeroed too, otherwise the hash lookup can miss.
    struct EbpfIngressRTKey rtk;
    __builtin_memset(&rtk, 0, sizeof(rtk));
    data_cur = parse_geneve_option(data_cur, data_end, &rtk);
    if(!data_cur) return TC_ACT_OK;
    data_cur = parse_geneve_option(data_cur, data_end, &rtk);
    if(!data_cur) return TC_ACT_OK;
    data_cur = parse_geneve_option(data_cur, data_end, &rtk);
    if(!data_cur) return TC_ACT_OK;

    // Do we have a flow cache entry for this? If not, leave the packet unchanged and let it go through
    // to the userspace application for mapping to the ingress and egress structs.
    struct EbpfIngressRTValue* val = bpf_map_lookup_elem(&ingress_rt_map, &rtk);
    if(!val) {
        add_rcv_count(RCV_UNKNOWN_FLOW);
        return TC_ACT_OK;
    }
    // Stamp liveness on this CPU's copy of the value (per-CPU map, so no atomics
    // needed). Userspace reads the max across CPUs when aging the flow. Coarse clock
    // (CLOCK_MONOTONIC_COARSE, ~1 tick granularity) avoids a per-packet TSC read; GC
    // timeouts are hundreds of seconds, so tick-level precision is irrelevant.
    val->last_seen_ns = bpf_ktime_get_coarse_ns();

    // Flow disposition. Today userspace only sets DISP_REDIRECT. DISP_FORWARD and
    // DISP_DROP are reserved for the future offload control interface (and would
    // need native XDP, see the header block); until their handling lands, punt
    // them to userspace so behaviour stays correct.
    if(val->disposition != DISP_REDIRECT)
    {
        add_rcv_count(RCV_UNKNOWN_FLOW);
        return TC_ACT_OK;
    }

    add_rcv_count(RCV_VALID_GENEVE);

#ifndef NO_RETURN_TRAFFIC
    // Cache this GWLBe ENI's return L2 header so the egress program can prepend it and
    // skip a per-packet FIB/neighbor lookup. Swap the incoming frame's addresses: our
    // return dst = the GWLB-side next hop (incoming src), our src = our NIC (incoming
    // dst). Only touch return_eth_map until this flow has confirmed it is populated
    // (return_eth_set) -- otherwise this is a second hash lookup on every packet. After
    // the first packet of the flow (per CPU) we know the entry exists (we found or wrote
    // it) and skip the lookup entirely. eth is still valid here (decap hasn't run yet).
    if(!val->return_eth_set)
    {
        if(!bpf_map_lookup_elem(&return_eth_map, &rtk.gwlbeEniId))
        {
            struct EbpfReturnEth reth;
            __builtin_memcpy(reth.h_dest, eth->h_source, 6);
            __builtin_memcpy(reth.h_source, eth->h_dest, 6);
            reth.h_proto = bpf_htons(ETH_P_IP);
            bpf_map_update_elem(&return_eth_map, &rtk.gwlbeEniId, &reth, BPF_ANY);
        }
        val->return_eth_set = 1;
    }
#endif

    // Strip the fixed outer encap (IP+UDP+GENEVE = GWLB_ENCAP_LEN) from just after
    // the MAC header, leaving [outer eth][inner IP ...]. This is the exact inverse
    // of the egress program's bpf_skb_adjust_room(+GWLB_ENCAP_LEN, BPF_ADJ_ROOM_MAC).
    // The outer eth is dropped for free by the L3-TUN redirect path below.
    // NOTE (validate on the rig): the adjust_room removal offset, inner-checksum
    // handling, and redirect-into-an-L3-TUN delivery are only provable on the wire.
    if(bpf_skb_adjust_room(skb, -GWLB_ENCAP_LEN, BPF_ADJ_ROOM_MAC,
                           BPF_F_ADJ_ROOM_FIXED_GSO) < 0)
    {
        // Couldn't decap in-kernel; fall back to userspace rather than drop.
        add_rcv_count(RCV_BAD_GENEVE_OPTS);
        return TC_ACT_OK;
    }

    // Deliver the inner packet into gwi's RECEIVE path -- the kernel equivalent of
    // gwlbtun writing the decapped packet to the gwi tun fd. bpf_redirect() returns
    // TC_ACT_REDIRECT; the actual redirect happens after we return. BPF_F_INGRESS
    // is valid here precisely because this is a tc/skb program (not XDP).
    return bpf_redirect(val->ifindex, BPF_F_INGRESS);
}

#ifndef NO_RETURN_TRAFFIC
// Fold a 32-bit ones-complement sum down to a 16-bit checksum.
static __always_inline __u16 csum_fold_helper(__u32 csum)
{
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

/*
 * Egress fast path: attached to each gwo interface as a tc clsact-egress ACTION
 * chain -- `action bpf <this program> action mirred egress redirect dev <phys NIC>`.
 * gwo is an L3 TUN device, so the skb starts at the bare inner IP packet (no eth).
 *
 * For a flow we know, prepend the cached return L2 header plus the outer
 * IP+UDP+GENEVE encap stored at learn time, building a complete Ethernet frame, and
 * return TC_ACT_PIPE. The chained act_mirred then carries the frame to the physical
 * NIC's egress and transmits it natively toward GWLB. Unknown flows (and flows whose
 * return L2 is not learned yet) are left for the userspace fallback with TC_ACT_OK --
 * the packet continues out gwo unchanged and gwlbtun's userspace egress path handles it.
 *
 * WHY act_mirred AND NOT bpf_redirect:
 *   This frame is a hand-built L2 frame prepended onto an L3 (ARPHRD_NONE) tun skb.
 *   bpf_redirect() routes through __bpf_redirect(), which for a non-L3 target enters
 *   __bpf_redirect_common() and asserts mac_header < network_header. On a tun skb the
 *   outer mac_header is never set and there is no tc-BPF helper to set it, so the
 *   assertion fails and the kernel silently drops the frame (observed as 100% loss,
 *   stack-trace confirmed). act_mirred instead reaches the NIC via dev_queue_xmit()
 *   with no such guard, so a program that merely builds the bytes and returns
 *   TC_ACT_PIPE transmits correctly. This is why the program is SEC("action")
 *   (SCHED_ACT): tc's act_bpf requires a SCHED_ACT program, and object-pinned attach
 *   of a SCHED_CLS program is rejected by the kernel.
 *
 * Follows the kernel's test_tc_tunnel encap pattern (adjust_room MAC + write the outer
 * headers). The adjust_room offsets and outer checksum handling are dev-box validated
 * (frame transmitted and captured on the peer); GWLB wire-correctness of the 68-byte
 * encap is validated on the TRex rig.
 */
SEC("action")
int gwlbtun_egress_prog(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if(data + sizeof(struct iphdr) > data_end)
    {
        add_egr_count(EGR_NOT_IP);
        return TC_ACT_OK;
    }
    struct iphdr *iph = data;
    uint8_t ipver = iph->version;

    struct EbpfEgressMapValue *val = 0;

    if(ipver == 4)
    {
        struct EbpfEgressMapKeyV4 key;
        __builtin_memset(&key, 0, sizeof(key));
        key.ifindex = skb->ifindex;
        key.src = iph->saddr;      // network order, matched by userspace on insert
        key.dst = iph->daddr;
        key.prot = iph->protocol;
        if(iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
        {
            void *l4 = data + iph->ihl * 4;
            if(l4 + 4 > data_end) { add_egr_count(EGR_NOT_IP); return TC_ACT_OK; }
            uint16_t *ports = l4;
            key.srcpt = ports[0];
            key.dstpt = ports[1];
        }
        val = bpf_map_lookup_elem(&ipv4_flows_map, &key);
    }
    else if(ipver == 6)
    {
        if(data + sizeof(struct ipv6hdr) > data_end) { add_egr_count(EGR_NOT_IP); return TC_ACT_OK; }
        struct ipv6hdr *ip6 = data;
        struct EbpfEgressMapKeyV6 key;
        __builtin_memset(&key, 0, sizeof(key));
        key.ifindex = skb->ifindex;
        __builtin_memcpy(key.src, &ip6->saddr, sizeof(key.src));
        __builtin_memcpy(key.dst, &ip6->daddr, sizeof(key.dst));
        key.prot = ip6->nexthdr;
        if(ip6->nexthdr == IPPROTO_TCP || ip6->nexthdr == IPPROTO_UDP)
        {
            void *l4 = data + sizeof(struct ipv6hdr);
            if(l4 + 4 > data_end) { add_egr_count(EGR_NOT_IP); return TC_ACT_OK; }
            uint16_t *ports = l4;
            key.srcpt = ports[0];
            key.dstpt = ports[1];
        }
        val = bpf_map_lookup_elem(&ipv6_flows_map, &key);
    }
    else
    {
        add_egr_count(EGR_NOT_IP);
        return TC_ACT_OK;
    }

    if(!val)
    {
        add_egr_count(EGR_UNKNOWN_FLOW);
        return TC_ACT_OK;   // leave it for the userspace egress path
    }

    val->last_sent_ns = bpf_ktime_get_coarse_ns();   // coarse clock: no per-packet TSC read (GC-only timestamp)

    // GWLB's outer encap is a fixed length. Guard that userspace stored exactly that
    // much so a format change degrades to the userspace fallback, not a malformed frame.
    if(val->encap_len != GWLB_ENCAP_LEN)
    {
        add_egr_count(EGR_TOO_BIG);
        return TC_ACT_OK;
    }

    // We build the full return frame in place and let the chained act_mirred transmit
    // it, so we need this ENI's cached return L2 header. If it isn't learned yet, leave
    // the packet for the userspace path rather than emit something undeliverable.
    // (Copy it out before adjust_room touches the skb.)
    struct EbpfReturnEth *reth = bpf_map_lookup_elem(&return_eth_map, &val->gwlbeEniId);
    if(!reth)
    {
        add_egr_count(EGR_NO_L2);   // return L2 not learned yet -> userspace fallback
        return TC_ACT_OK;
    }
    struct EbpfReturnEth reth_copy = *reth;

    // Make room at the MAC layer for the full return frame -- Ethernet + outer
    // IP+UDP+GENEVE -- then write the cached L2 header and the encap template. No
    // ENCAP_L3/L4 flags: those describe an IP/UDP *tunnel* encap for GSO bookkeeping,
    // but we're prepending a complete L2 frame and transmitting it as-is.
    if(bpf_skb_adjust_room(skb, GWLB_EGRESS_ROOM, BPF_ADJ_ROOM_MAC,
                           BPF_F_ADJ_ROOM_FIXED_GSO) < 0)
    {
        add_egr_count(EGR_TOO_BIG);
        return TC_ACT_OK;
    }
    if(bpf_skb_store_bytes(skb, 0, &reth_copy, GWLB_RETURN_ETH_LEN, 0) < 0)
        return TC_ACT_SHOT;
    if(bpf_skb_store_bytes(skb, GWLB_RETURN_ETH_LEN, val->encap, GWLB_ENCAP_LEN, 0) < 0)
        return TC_ACT_SHOT;

    // Fix the outer IPv4 total length + checksum and the UDP length. The outer IP now
    // sits after the 14-byte Ethernet header, so its length excludes that eth.
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    if(data + GWLB_RETURN_ETH_LEN + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
        return TC_ACT_SHOT;
    struct iphdr *oip = data + GWLB_RETURN_ETH_LEN;
    oip->tot_len = bpf_htons(skb->len - GWLB_RETURN_ETH_LEN);
    oip->check = 0;
    __u32 csum = bpf_csum_diff(0, 0, (__be32 *)oip, sizeof(struct iphdr), 0);
    oip->check = csum_fold_helper(csum);

    // Fix the outer UDP length (checksum optional for IPv4, left 0).
    struct udphdr *oudp = data + GWLB_RETURN_ETH_LEN + sizeof(struct iphdr);
    oudp->len = bpf_htons(skb->len - GWLB_RETURN_ETH_LEN - sizeof(struct iphdr));
    oudp->check = 0;

    add_egr_count(EGR_REENCAP);

    // The complete L2 frame is built in place. Return TC_ACT_PIPE so the next action
    // in the chain -- act_mirred (egress redirect dev <phys NIC>) -- transmits it
    // natively toward GWLB. We deliberately do NOT bpf_redirect here: that path's
    // mac_header<network_header guard drops a hand-built L2 frame on an L3 tun skb
    // (see the program's header block).
    return TC_ACT_PIPE;
}
#endif

char _license[] SEC("license") = "GPL";