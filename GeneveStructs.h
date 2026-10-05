// Code borrowed from Linux's source tree include/net/geneve.h.

#ifndef GWLBTUN_GENEVESTRUCTS_H
#define GWLBTUN_GENEVESTRUCTS_H

#define GENEVE_UDP_PORT		6081

/* Geneve Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Virtual Network Identifier (VNI)       |    Reserved   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Variable Length Options                    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Option Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Option Class         |      Type     |R|R|R| Length  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                      Variable Option Data                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef uint8_t u8;

struct geneve_opt {
    __be16	opt_class;
    u8	type;
#ifdef __LITTLE_ENDIAN_BITFIELD
    u8	length:5;
	u8	r3:1;
	u8	r2:1;
	u8	r1:1;
#else
    u8	r1:1;
    u8	r2:1;
    u8	r3:1;
    u8	length:5;
#endif
    u8	opt_data[];
};

#define GENEVE_CRIT_OPT_TYPE (1 << 7)

struct genevehdr {
#ifdef __LITTLE_ENDIAN_BITFIELD
    u8 opt_len:6;
	u8 ver:2;
	u8 rsvd1:6;
	u8 critical:1;
	u8 oam:1;
#else
    u8 ver:2;
    u8 opt_len:6;
    u8 oam:1;
    u8 critical:1;
    u8 rsvd1:6;
#endif
    __be16 proto_type;
    u8 vni[3];
    u8 rsvd2;
    u8 options[];
};

#define GENEVE_CLASS_AWS                0x108
#define GENEVE_TYPE_GWLBE_ID            0x1
#define GENEVE_TYPE_ATTACHMENT_ID       0x2
#define GENEVE_TYPE_FLOW_COOKIE         0x3

#endif //GWLBTUN_GENEVESTRUCTS_H
