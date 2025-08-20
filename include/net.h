#pragma once
#include "types.h"

#define IP(a, b, c, d) ((a << 24) | (b << 16) | (c << 8) | d)

#define IPv6(a, b, c, d, e, f, g, h)                                           \
	({                                                                         \
		struct                                                                 \
		{                                                                      \
			unsigned short d[8];                                               \
		} ipv6;                                                                \
		ipv6.d[7] = (unsigned short)a;                                         \
		ipv6.d[6] = (unsigned short)b;                                         \
		ipv6.d[5] = (unsigned short)c;                                         \
		ipv6.d[4] = (unsigned short)d;                                         \
		ipv6.d[3] = (unsigned short)e;                                         \
		ipv6.d[2] = (unsigned short)f;                                         \
		ipv6.d[1] = (unsigned short)g;                                         \
		ipv6.d[0] = (unsigned short)h;                                         \
		ipv6;                                                                  \
	})

#define SLICE_IP(x)                                                            \
	((x >> 24) & 0xff), ((x >> 16) & 0xff), ((x >> 8) & 0xff), ((x) & 0xff)

#define SLICE_IPv6(x)                                                          \
	((u16 *)&x)[7], ((u16 *)&x)[6], ((u16 *)&x)[5], ((u16 *)&x)[4],            \
		((u16 *)&x)[3], ((u16 *)&x)[2], ((u16 *)&x)[1], ((u16 *)&x)[0]

#define inet_daddr sk.__sk_common.skc_daddr
#define inet_rcv_saddr sk.__sk_common.skc_rcv_saddr
#define inet_dport sk.__sk_common.skc_dport
#define inet_num sk.__sk_common.skc_num
#define sk_node __sk_common.skc_node
#define sk_nulls_node __sk_common.skc_nulls_node
#define sk_refcnt __sk_common.skc_refcnt
#define sk_tx_queue_mapping __sk_common.skc_tx_queue_mapping
#define sk_rx_queue_mapping __sk_common.skc_rx_queue_mapping
#define sk_dontcopy_begin __sk_common.skc_dontcopy_begin
#define sk_dontcopy_end __sk_common.skc_dontcopy_end
#define sk_hash __sk_common.skc_hash
#define sk_portpair __sk_common.skc_portpair
#define sk_num __sk_common.skc_num
#define sk_dport __sk_common.skc_dport
#define sk_addrpair __sk_common.skc_addrpair
#define sk_daddr __sk_common.skc_daddr
#define sk_rcv_saddr __sk_common.skc_rcv_saddr
#define sk_family __sk_common.skc_family
#define sk_state __sk_common.skc_state
#define sk_reuse __sk_common.skc_reuse
#define sk_reuseport __sk_common.skc_reuseport
#define sk_ipv6only __sk_common.skc_ipv6only
#define sk_net_refcnt __sk_common.skc_net_refcnt
#define sk_bound_dev_if __sk_common.skc_bound_dev_if
#define sk_bind_node __sk_common.skc_bind_node
#define sk_prot __sk_common.skc_prot
#define sk_net __sk_common.skc_net
#define sk_v6_daddr __sk_common.skc_v6_daddr
#define sk_v6_rcv_saddr __sk_common.skc_v6_rcv_saddr
#define sk_cookie __sk_common.skc_cookie
#define sk_incoming_cpu __sk_common.skc_incoming_cpu
#define sk_flags __sk_common.skc_flags
#define sk_rxhash __sk_common.skc_rxhash
#define sk_rmem_alloc sk_backlog.rmem_alloc

#define tw_family __tw_common.skc_family
#define tw_state __tw_common.skc_state
#define tw_reuse __tw_common.skc_reuse
#define tw_reuseport __tw_common.skc_reuseport
#define tw_ipv6only __tw_common.skc_ipv6only
#define tw_bound_dev_if __tw_common.skc_bound_dev_if
#define tw_node __tw_common.skc_nulls_node
#define tw_bind_node __tw_common.skc_bind_node
#define tw_refcnt __tw_common.skc_refcnt
#define tw_hash __tw_common.skc_hash
#define tw_prot __tw_common.skc_prot
#define tw_net __tw_common.skc_net
#define tw_daddr __tw_common.skc_daddr
#define tw_v6_daddr __tw_common.skc_v6_daddr
#define tw_rcv_saddr __tw_common.skc_rcv_saddr
#define tw_v6_rcv_saddr __tw_common.skc_v6_rcv_saddr
#define tw_dport __tw_common.skc_dport
#define tw_num __tw_common.skc_num
#define tw_cookie __tw_common.skc_cookie
#define tw_dr __tw_common.skc_tw_dr

#define ir_loc_addr req.__req_common.skc_rcv_saddr
#define ir_rmt_addr req.__req_common.skc_daddr
#define ir_num req.__req_common.skc_num
#define ir_rmt_port req.__req_common.skc_dport
#define ir_v6_rmt_addr req.__req_common.skc_v6_daddr
#define ir_v6_loc_addr req.__req_common.skc_v6_rcv_saddr
#define ir_iif req.__req_common.skc_bound_dev_if
#define ir_cookie req.__req_common.skc_cookie
#define ireq_net req.__req_common.skc_net
#define ireq_state req.__req_common.skc_state
#define ireq_family req.__req_common.skc_family