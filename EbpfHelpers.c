// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * gwlbtun's in-kernel datapath (-e), built into gwlbtun-ebpf.o. gwlbtun loads it, fills the maps as it learns
 * flows, and ages them out; see EbpfLoader and GeneveHandler. Two programs:
 *
 *  - gwlbtun_ingress (tcx ingress on each interface gwlbtun receives GENEVE on): for a GWLB flow gwlbtun has
 *    learned, strip the outer headers and deliver the inner packet into the endpoint's gwi- interface, as if
 *    gwlbtun had written it there. Everything else carries on to gwlbtun's UDP sockets unchanged.
 *  - gwlbtun_egress (a tc action on each gwo- interface, followed by mirred to the GWLB-facing interface): for a
 *    learned flow, prepend the Ethernet and outer headers gwlbtun would have sent it with, and hand it to
 *    mirred. Everything else carries on out of gwo- to gwlbtun's tunnel threads unchanged.
 *
 * Neither program decides what happens to a packet: that's still whatever the operator has attached to gwi-
 * and gwo-. They only skip gwlbtun's userspace copies for flows it already knows. Every packet they can't handle
 * exactly as userspace would is left to userspace.
 *
 * Why tc and not XDP: XDP can't deliver into another device's receive path (its bpf_redirect takes no flags and
 * only transmits), which is what handing a packet to gwi- needs, and ENA supports native XDP only below the
 * jumbo MTU GWLB traffic needs.
 *
 * Why the egress uses mirred and not bpf_redirect: gwo- is an L3 device, so its packets have no MAC header,
 * and bpf_redirect to an Ethernet device drops a packet whose MAC header offset isn't before its network
 * header. Building the frame here and letting act_mirred transmit it avoids that check.
 */

#include <stdint.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "EbpfHelpers.h"

// The IPv4 fragment bits (frag_off), host order.
#define IP_MF_BIT      0x2000
#define IP_OFFSET_MASK 0x1FFF

// Map sizes here are placeholders: gwlbtun sizes the flow maps from --reserve / --ebpf-reserve before loading.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct EbpfIngressKey);
    __type(value, struct EbpfIngressValue);
    __uint(max_entries, 1024);
} ingress_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct EbpfEgressKeyV4);
    __type(value, struct EbpfEgressValue);
    __uint(max_entries, 1024);
} egress_v4_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct EbpfEgressKeyV6);
    __type(value, struct EbpfEgressValue);
    __uint(max_entries, 1024);
} egress_v6_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);                      // interface index
    __type(value, struct EbpfReturnEth);
    __uint(max_entries, 256);
} return_eth_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct EbpfEgressConfig);
    __uint(max_entries, 1);
} egress_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, ING_CODES_COUNT);
} ingress_counters_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, EGR_CODES_COUNT);
} egress_counters_map SEC(".maps");

static __always_inline void count_ingress(__u32 code)
{
    __u64 *v = bpf_map_lookup_elem(&ingress_counters_map, &code);
    if(v) *v += 1;
}

static __always_inline void count_egress(__u32 code)
{
    __u64 *v = bpf_map_lookup_elem(&egress_counters_map, &code);
    if(v) *v += 1;
}

// Store a coarse timestamp only when it has changed (the coarse clock moves every few milliseconds), so a busy
// flow doesn't write its map entry's cache line on every packet.
static __always_inline void stamp(__u64 *slot)
{
    const __u64 now = bpf_ktime_get_coarse_ns();
    if(*slot != now)
        *slot = now;
}

/**
 * Read the GENEVE option at offset *off into the options (which start at opts and must take
 * GWLB_GENEVE_LEN - 8 bytes in all; end bounds the packet) and advance *off past it, picking up the GWLB endpoint
 * ID and flow cookie. Offsets rather than a moving pointer keep every packet access at a bounded offset from
 * opts, which the verifier can follow. Returns 0, or -1 if the option doesn't fit.
 */
static __always_inline int parse_geneve_option(__u8 *opts, void *end, __u32 *off, struct EbpfIngressKey *key, int *found)
{
    const __u32 o = *off;
    if(o > GWLB_GENEVE_LEN - 8 - 4)
        return -1;
    __u8 *opt = opts + o;
    if((void *)(opt + 4) > end)
        return -1;
    const __u16 optClass = ((__u16)opt[0] << 8) | opt[1];
    const __u8 type = opt[2];
    const __u32 words = opt[3] & 0x1F;   // option data length, in 4-byte words
    if(optClass == 0x0108 && type == 1 && words == 2)
    {
        if((void *)(opt + 12) > end)
            return -1;
        __u64 v;
        __builtin_memcpy(&v, opt + 4, sizeof(v));
        key->gwlbeId = bpf_be64_to_cpu(v);
        *found |= 1;
    }
    else if(optClass == 0x0108 && type == 3 && words == 1)
    {
        if((void *)(opt + 8) > end)
            return -1;
        __u32 v;
        __builtin_memcpy(&v, opt + 4, sizeof(v));
        key->flowCookie = bpf_ntohl(v);
        *found |= 2;
    }
    *off = o + 4 + words * 4;
    return 0;
}

/**
 * The inner flow of a packet starting at ip (bounded by end), as its digest. This must match how gwlbtun keys
 * the flow (PacketHeaderV4/V6, and ebpfFlowOf in GeneveHandler.cpp): the ports follow any IPv4 options; a later
 * fragment of a TCP or UDP packet, and an IPv6 packet with extension headers, can't be keyed here (return -1).
 * Other protocols have ports 0.
 */
static __always_inline int inner_flow_digest(void *ip, void *end, __u64 *digest)
{
    __u8 *p = ip;
    if((void *)(p + 1) > end)
        return -1;
    const __u8 version = p[0] >> 4;
    if(version == 4)
    {
        if((void *)(p + 20) > end)
            return -1;
        const __u32 ihl = p[0] & 0x0F;
        if(ihl < 5)
            return -1;
        const __u8 prot = p[9];
        const __u16 frag = ((__u16)p[6] << 8) | p[7];
        __u32 src, dst;
        __builtin_memcpy(&src, p + 12, 4);
        __builtin_memcpy(&dst, p + 16, 4);
        __u16 sp = 0, dp = 0;
        if(prot == IPPROTO_TCP || prot == IPPROTO_UDP)
        {
            if(frag & IP_OFFSET_MASK)
                return -1;
            __u8 *l4 = p + ihl * 4;
            if((void *)(l4 + 4) > end)
                return -1;
            __builtin_memcpy(&sp, l4, 2);
            __builtin_memcpy(&dp, l4 + 2, 2);
        }
        *digest = gwlbtun_flow_digest(4, prot, gwlbtun_flow_end(src, sp), gwlbtun_flow_end(dst, dp));
        return 0;
    }
    if(version == 6)
    {
        if((void *)(p + 40) > end)
            return -1;
        const __u8 prot = p[6];
        if(prot == 0 || prot == 43 || prot == 44 || prot == 60 || prot == 51)   // hop-by-hop, routing, fragment, dest opts, AH
            return -1;
        __u32 src[4], dst[4];
        __builtin_memcpy(src, p + 8, 16);
        __builtin_memcpy(dst, p + 24, 16);
        __u16 sp = 0, dp = 0;
        if(prot == IPPROTO_TCP || prot == IPPROTO_UDP)
        {
            if((void *)(p + 44) > end)
                return -1;
            __builtin_memcpy(&sp, p + 40, 2);
            __builtin_memcpy(&dp, p + 42, 2);
        }
        *digest = gwlbtun_flow_digest(6, prot, gwlbtun_flow_end(gwlbtun_fold_v6(src), sp), gwlbtun_flow_end(gwlbtun_fold_v6(dst), dp));
        return 0;
    }
    return -1;
}

SEC("tcx/ingress")
int gwlbtun_ingress(struct __sk_buff *skb)
{
    // Make sure the headers are in the linear area (GRO can leave them in fragments). Only when they aren't
    // already: pulling can copy the head of a cloned skb (when a packet capture is running).
    const __u32 want = skb->len < GWLB_INGRESS_PULL_LEN ? skb->len : GWLB_INGRESS_PULL_LEN;
    if((__u32)(skb->data_end - skb->data) < want)
        bpf_skb_pull_data(skb, want);

    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;

    // Outer Ethernet, IPv4 (no options, not a fragment), UDP to the GENEVE port.
    if(data + GWLB_RETURN_ETH_LEN > end) { count_ingress(ING_NO_ETHER_HDR); return GWLBTUN_TCX_NEXT; }
    struct ethhdr *eth = data;
    if(eth->h_proto != bpf_htons(ETH_P_IP)) { count_ingress(ING_WRONG_ETHER_PROT); return GWLBTUN_TCX_NEXT; }
    __u8 *ip = data + GWLB_RETURN_ETH_LEN;
    if((void *)(ip + 20) > end) { count_ingress(ING_NO_IP_HDR); return GWLBTUN_TCX_NEXT; }
    if(ip[9] != IPPROTO_UDP) { count_ingress(ING_NOT_UDP); return GWLBTUN_TCX_NEXT; }
    if((ip[0] & 0x0F) != 5 || ((((__u16)ip[6] << 8) | ip[7]) & (IP_MF_BIT | IP_OFFSET_MASK)))
    {
        count_ingress(ING_UNSUPPORTED);
        return GWLBTUN_TCX_NEXT;
    }
    __u8 *udp = ip + 20;
    if((void *)(udp + 8) > end) { count_ingress(ING_NO_UDP_HDR); return GWLBTUN_TCX_NEXT; }
    if((((__u16)udp[2] << 8) | udp[3]) != GWLBTUN_GENEVE_PORT) { count_ingress(ING_WRONG_UDP_PORT); return GWLBTUN_TCX_NEXT; }

    // GENEVE: version 0, VNI 0 (as GWLB always sends), and exactly GWLB's three options.
    __u8 *gen = udp + 8;
    if((void *)(gen + 8) > end) { count_ingress(ING_NO_GENEVE_HDR); return GWLBTUN_TCX_NEXT; }
    if((gen[0] >> 6) != 0) { count_ingress(ING_BAD_GENEVE_VER); return GWLBTUN_TCX_NEXT; }
    if(gen[4] || gen[5] || gen[6]) { count_ingress(ING_BAD_GENEVE_VNI); return GWLBTUN_TCX_NEXT; }
    if((gen[0] & 0x3F) * 4 != GWLB_GENEVE_LEN - 8) { count_ingress(ING_UNSUPPORTED); return GWLBTUN_TCX_NEXT; }

    struct EbpfIngressKey key;
    __builtin_memset(&key, 0, sizeof(key));
    int found = 0;
    __u32 off = 0;
    __u8 *opts = gen + 8;
    if(parse_geneve_option(opts, end, &off, &key, &found) < 0 || parse_geneve_option(opts, end, &off, &key, &found) < 0 ||
       parse_geneve_option(opts, end, &off, &key, &found) < 0)
    {
        count_ingress(ING_BAD_GENEVE_OPTS);
        return GWLBTUN_TCX_NEXT;
    }
    // The decapsulation below strips exactly GWLB_ENCAP_LEN bytes, so the three options must fill the options
    // area exactly, and include the endpoint ID and the cookie.
    if(found != 3 || off != GWLB_GENEVE_LEN - 8)
    {
        count_ingress(ING_UNSUPPORTED);
        return GWLBTUN_TCX_NEXT;
    }

    struct EbpfIngressValue *val = bpf_map_lookup_elem(&ingress_map, &key);
    if(!val) { count_ingress(ING_UNKNOWN_FLOW); return GWLBTUN_TCX_NEXT; }
    if(val->disposition != DISP_REDIRECT) { count_ingress(ING_UNKNOWN_FLOW); return GWLBTUN_TCX_NEXT; }

    // The cookie was learned for one inner flow; only deliver that flow. Anything else (a cookie GWLB has
    // given to another flow too, or a packet we can't key) goes to userspace, which handles it correctly.
    __u64 digest;
    if(inner_flow_digest(data + GWLB_RETURN_ETH_LEN + GWLB_ENCAP_LEN, end, &digest) < 0)
    {
        count_ingress(ING_UNSUPPORTED);
        return GWLBTUN_TCX_NEXT;
    }
    if(digest != val->flowDigest) { count_ingress(ING_FLOW_MISMATCH); return GWLBTUN_TCX_NEXT; }

    stamp(&val->lastSeenNs);

    // Record this interface's return Ethernet header (GWLB's side as destination, ours as source) for the egress
    // program, once per flow, so a changed next-hop address is picked up by the next new flow.
    if(!val->returnEthSet)
    {
        struct EbpfReturnEth reth;
        __builtin_memcpy(reth.dest, eth->h_source, 6);
        __builtin_memcpy(reth.source, eth->h_dest, 6);
        reth.proto = bpf_htons(ETH_P_IP);
        __u32 ifindex = skb->ifindex;
        if(bpf_map_update_elem(&return_eth_map, &ifindex, &reth, BPF_ANY) == 0)
            val->returnEthSet = 1;
    }

    // Strip the outer IPv4, UDP and GENEVE headers after the MAC header. The redirect into the L3 gwi- device
    // removes the outer Ethernet header.
    const __u32 gwi = val->gwiIfindex;
    if(bpf_skb_adjust_room(skb, -GWLB_ENCAP_LEN, BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_FIXED_GSO) < 0)
    {
        count_ingress(ING_DECAP_FAILED);
        return GWLBTUN_TCX_NEXT;
    }
    count_ingress(ING_ACCELERATED);
    return bpf_redirect(gwi, BPF_F_INGRESS);   // into gwi-'s receive path, like a write to its tun fd
}

// Fold a 32-bit ones-complement sum to a 16-bit checksum.
static __always_inline __u16 csum_fold(__u32 csum)
{
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    return (__u16)~csum;
}

/**
 * On each gwo- interface: `action bpf <this> action mirred egress redirect dev <GWLB-facing interface>`. gwo-
 * is an L3 tun device, so the packet starts at the inner IP header. TC_ACT_PIPE passes the finished frame to
 * mirred; TC_ACT_OK lets the packet carry on out of gwo- to gwlbtun's tunnel threads.
 */
SEC("action")
int gwlbtun_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;
    __u8 *p = data;
    struct EbpfEgressValue *val = 0;

    if((void *)(p + 20) > end) { count_egress(EGR_NOT_IP); return TC_ACT_OK; }
    const __u8 version = p[0] >> 4;
    if(version == 4)
    {
        const __u32 ihl = p[0] & 0x0F;
        if(ihl < 5) { count_egress(EGR_NOT_IP); return TC_ACT_OK; }
        struct EbpfEgressKeyV4 key;
        __builtin_memset(&key, 0, sizeof(key));
        key.gwoIfindex = skb->ifindex;
        __builtin_memcpy(&key.src, p + 12, 4);
        __builtin_memcpy(&key.dst, p + 16, 4);
        key.prot = p[9];
        if(key.prot == IPPROTO_TCP || key.prot == IPPROTO_UDP)
        {
            if(((((__u16)p[6] << 8) | p[7]) & IP_OFFSET_MASK)) { count_egress(EGR_UNSUPPORTED); return TC_ACT_OK; }
            __u8 *l4 = p + ihl * 4;
            if((void *)(l4 + 4) > end) { count_egress(EGR_NOT_IP); return TC_ACT_OK; }
            __builtin_memcpy(&key.srcPort, l4, 2);
            __builtin_memcpy(&key.dstPort, l4 + 2, 2);
        }
        val = bpf_map_lookup_elem(&egress_v4_map, &key);
    }
    else if(version == 6)
    {
        if((void *)(p + 40) > end) { count_egress(EGR_NOT_IP); return TC_ACT_OK; }
        struct EbpfEgressKeyV6 key;
        __builtin_memset(&key, 0, sizeof(key));
        key.gwoIfindex = skb->ifindex;
        __builtin_memcpy(key.src, p + 8, 16);
        __builtin_memcpy(key.dst, p + 24, 16);
        key.prot = p[6];
        if(key.prot == 0 || key.prot == 43 || key.prot == 44 || key.prot == 60 || key.prot == 51)
        {
            count_egress(EGR_UNSUPPORTED);
            return TC_ACT_OK;
        }
        if(key.prot == IPPROTO_TCP || key.prot == IPPROTO_UDP)
        {
            if((void *)(p + 44) > end) { count_egress(EGR_NOT_IP); return TC_ACT_OK; }
            __builtin_memcpy(&key.srcPort, p + 40, 2);
            __builtin_memcpy(&key.dstPort, p + 42, 2);
        }
        val = bpf_map_lookup_elem(&egress_v6_map, &key);
    }
    else
    {
        count_egress(EGR_NOT_IP);
        return TC_ACT_OK;
    }

    if(!val) { count_egress(EGR_UNKNOWN_FLOW); return TC_ACT_OK; }
    stamp(&val->lastSentNs);
    if(val->encapLen != GWLB_ENCAP_LEN) { count_egress(EGR_ENCAP_FAILED); return TC_ACT_OK; }

    // mirred sends to one interface; a flow that arrived on another must leave by that one (source/destination
    // checking drops it otherwise), which userspace does.
    __u32 zero = 0;
    struct EbpfEgressConfig *cfg = bpf_map_lookup_elem(&egress_config_map, &zero);
    if(!cfg || cfg->mirredIfindex != val->nicIfindex) { count_egress(EGR_OTHER_NIC); return TC_ACT_OK; }
    __u32 nic = val->nicIfindex;
    struct EbpfReturnEth *reth = bpf_map_lookup_elem(&return_eth_map, &nic);
    if(!reth) { count_egress(EGR_NO_L2); return TC_ACT_OK; }
    struct EbpfReturnEth ethCopy = *reth;   // copied before adjust_room changes the packet

    // Room for Ethernet and the outer headers in front of the inner packet, then write them.
    if(bpf_skb_adjust_room(skb, GWLB_EGRESS_ROOM, BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_FIXED_GSO) < 0)
    {
        count_egress(EGR_ENCAP_FAILED);
        return TC_ACT_OK;
    }
    if(bpf_skb_store_bytes(skb, 0, &ethCopy, GWLB_RETURN_ETH_LEN, 0) < 0 ||
       bpf_skb_store_bytes(skb, GWLB_RETURN_ETH_LEN, val->encap, GWLB_ENCAP_LEN, 0) < 0)
    {
        count_egress(EGR_ENCAP_FAILED);
        return TC_ACT_SHOT;   // the packet is half rewritten; it can't go anywhere now
    }

    // Outer IPv4 total length and checksum, and UDP length (UDP checksum 0, as userspace sends).
    data = (void *)(long)skb->data;
    end = (void *)(long)skb->data_end;
    if(data + GWLB_RETURN_ETH_LEN + 28 > end)
    {
        count_egress(EGR_ENCAP_FAILED);
        return TC_ACT_SHOT;
    }
    __u8 *oip = data + GWLB_RETURN_ETH_LEN;
    const __u16 ipLen = bpf_htons(skb->len - GWLB_RETURN_ETH_LEN);
    const __u16 udpLen = bpf_htons(skb->len - GWLB_RETURN_ETH_LEN - 20);
    __builtin_memcpy(oip + 2, &ipLen, 2);
    oip[10] = 0;
    oip[11] = 0;
    const __u16 check = csum_fold(bpf_csum_diff(0, 0, (__be32 *)oip, 20, 0));
    __builtin_memcpy(oip + 10, &check, 2);
    __builtin_memcpy(oip + 24, &udpLen, 2);
    oip[26] = 0;
    oip[27] = 0;

    count_egress(EGR_REENCAP);
    return TC_ACT_PIPE;
}

char _license[] SEC("license") = "GPL";
