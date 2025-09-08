/**
 * @file tc-if.bpf.c
 * @brief 网络接口级别的流量控制 eBPF 程序
 * 
 * 该文件实现了基于网络接口的流量控制功能，
 * 用于监控和控制特定网络接口的数据流量。
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

/// 添加缺失的常量定义
#define EGRESS 1
#define INGRESS 0

/**
 * Flow rate information structure
 */
struct flow_rate_info
{
	__u64 window_start_ns; // Start of current time window
	__u64 total_packets;   // Total packets in window
	__u64 total_bytes;	   // Total bytes in window
	__u64 rate_bps;		   // Calculated rate in bps
	__u64 peak_rate_bps;   // Peak rate observed
	__u64 smooth_rate_bps; // Smoothed rate using EMA
};

/**
 * Event structure for traffic monitoring
 */
struct event_t
{
	__u32 action;				// Action taken (pass/drop)
	__u32 bytes_sent;			// Bytes sent
	__u32 bytes_dropped;		// Bytes dropped
	__u32 packets_sent;			// Packets sent
	__u32 packets_dropped;		// Packets dropped
	__u64 timestamp;			// Timestamp
	__u8 eth_src[6];			// Source MAC address
	__u8 eth_dst[6];			// Destination MAC address
	__u16 eth_type;				// Ethernet type
	__u32 packet_size;			// Total packet size
	__u32 packet_type;			// Packet type identifier
	__u64 type_rate_bps;		// Current rate for this packet type
	__u64 type_smooth_rate_bps; // Smoothed rate using EMA
};

/**
 * Event parameters structure to reduce function arguments
 */
struct event_params_t
{
	__u64 bytes_sent;
	__u64 bytes_dropped;
	const __u8 *src_mac;
	const __u8 *dst_mac;
	__u16 eth_type;
	__u32 packet_size;
	__u32 packet_type_id;
	struct flow_rate_info *flow_info;
};

/**
 * Traffic control rule structure
 */
struct traffic_rule
{
	__u64 rate_bps;	  // Rate limit in bps
	__u8 gress;		  // Traffic direction (0=ingress, 1=egress)
	__u32 time_scale; // Time scale for burst tolerance
};

/**
 * Rate limiting bucket structure
 */
struct rate_bucket
{
	__u64 tokens;	   // Current token count
	__u64 last_update; // Last update timestamp
	__u64 max_tokens;  // Maximum token capacity
};

/**
 * Ring buffer for events
 */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

/**
 * Flow rate statistics map
 */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u32)); // Packet type as key
	__uint(value_size, sizeof(struct flow_rate_info));
	__uint(max_entries, 64); // Support up to 64 packet types
} flow_rate_stats SEC(".maps");

/**
 * Traffic control rules map
 */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct traffic_rule));
	__uint(max_entries, 1);
} traffic_rules SEC(".maps");

/**
 * Rate limiting buckets map
 */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct rate_bucket));
	__uint(max_entries, 1024);
} buckets SEC(".maps");

#define NSEC_PER_SEC 1000000000ull

/// TC动作常量
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

/**
 * Get current timestamp
 */
static __inline __u64 now_ns(void)
{
	return bpf_ktime_get_ns();
}

/**
 * Parse Ethernet header
 */
static __inline bool parse_ethernet_header(
	struct __sk_buff *ctx,
	void *data,
	void *data_end,
	__u8 *src_mac,
	__u8 *dst_mac,
	__u16 *eth_type
)
{
	if (data + 14 > data_end)
	{
		return false;
	}

	struct ethhdr *eth = data;

#pragma unroll
	for (int i = 0; i < 6; i++)
	{
		src_mac[i] = eth->h_source[i];
	}

#pragma unroll
	for (int i = 0; i < 6; i++)
	{
		dst_mac[i] = eth->h_dest[i];
	}

	*eth_type = bpf_ntohs(eth->h_proto);

	return true;
}

/**
 * Get or create rate limiting bucket
 */
static __inline struct rate_bucket *
get_or_create_bucket(__u32 bucket_key, __u64 rate_bps, __u32 time_scale)
{
	struct rate_bucket *b = bpf_map_lookup_elem(&buckets, &bucket_key);

	if (!b)
	{
		struct rate_bucket new_bucket = {
			.tokens = rate_bps * time_scale, // Start with full tokens
			.last_update = now_ns(),
			.max_tokens = rate_bps * time_scale
		};

		bpf_map_update_elem(&buckets, &bucket_key, &new_bucket, BPF_ANY);
		b = bpf_map_lookup_elem(&buckets, &bucket_key);
	}

	return b;
}

/**
 * Update token bucket
 */
static __inline void
update_token_bucket(struct rate_bucket *b, __u64 rate_bps, __u32 time_scale)
{
	__u64 now = now_ns();
	__u64 time_elapsed = now - b->last_update;
	__u64 tokens_to_add = (time_elapsed * rate_bps) / NSEC_PER_SEC;

	b->tokens += tokens_to_add;
	if (b->tokens > b->max_tokens)
	{
		b->tokens = b->max_tokens; // Add tokens up to maximum capacity
	}

	b->last_update = now; // Update timestamp
}

/**
 * Check and consume tokens
 */
static __inline bool
check_and_consume_tokens(struct rate_bucket *b, __u32 packet_size)
{
	__u64 tokens_needed = packet_size; // Convert packet size to tokens

	if (b->tokens >= tokens_needed)
	{
		b->tokens -= tokens_needed;
		return true; // Allow packet
	}

	return false; // Drop packet
}

/**
 * Apply basic rate limiting
 */
static __inline int apply_basic_rate_limiting(
	__u32 bucket_key,
	__u64 rate_bps,
	__u32 time_scale,
	__u32 packet_size
)
{
	struct rate_bucket *b =
		get_or_create_bucket(bucket_key, rate_bps, time_scale);
	if (!b)
	{
		return TC_ACT_OK; // Allow if bucket creation fails
	}

	update_token_bucket(b, rate_bps, time_scale);
	if (check_and_consume_tokens(b, packet_size))
	{
		return TC_ACT_OK; // Allow packet
	}
	else
	{
		return TC_ACT_SHOT; // Drop packet
	}
}

/**
 * Apply advanced rate limiting with burst tolerance
 */
static __inline int apply_advanced_rate_limiting(
	__u32 bucket_key,
	__u64 rate_bps,
	__u32 time_scale,
	__u32 packet_size
)
{
	struct rate_bucket *b =
		get_or_create_bucket(bucket_key, rate_bps, time_scale);
	if (!b)
	{
		return TC_ACT_OK; // Allow if bucket creation fails
	}

	// Apply burst multiplier to max tokens
	__u64 burst_tokens = b->max_tokens * 2;
	if (b->tokens < burst_tokens)
	{
		b->tokens = burst_tokens;
	}

	update_token_bucket(b, rate_bps, time_scale);
	if (check_and_consume_tokens(b, packet_size))
	{
		return TC_ACT_OK; // Allow packet
	}
	else
	{
		return TC_ACT_SHOT; // Drop packet
	}
}

/**
 * Apply rate limiting policy
 */
static __inline int apply_rate_limiting_policy(
	__u32 bucket_key,
	__u64 rate_bps,
	__u32 time_scale,
	__u32 packet_size,
	__u8 policy
)
{
	switch (policy)
	{
	case 0: // Basic rate limiting
		return apply_basic_rate_limiting(
			bucket_key,
			rate_bps,
			time_scale,
			packet_size
		);
	case 1: // Advanced rate limiting with 2x burst tolerance
		return apply_advanced_rate_limiting(
			bucket_key,
			rate_bps,
			time_scale,
			packet_size
		);
	case 2: // Strict rate limiting (no burst tolerance)
		return apply_basic_rate_limiting(
			bucket_key,
			rate_bps,
			time_scale,
			packet_size
		);
	case 3: // Lenient rate limiting (3x burst tolerance)
		return apply_advanced_rate_limiting(
			bucket_key,
			rate_bps,
			time_scale,
			packet_size
		);
	default:
		return TC_ACT_OK; // Allow by default
	}
}

/**
 * Get traffic rule from map
 */
static __inline struct traffic_rule *get_traffic_rule(void)
{
	__u32 key = 0;
	return bpf_map_lookup_elem(&traffic_rules, &key);
}

/**
 * Report traffic event to ring buffer
 */
static __inline void report_traffic_event(
	__u64 bytes_sent,
	__u64 bytes_dropped,
	__u64 packets_sent,
	__u64 packets_dropped
)
{
	struct event_t *e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
	if (!e)
	{
		return; // Ring buffer full
	}

	e->action = (bytes_dropped > 0) ? 1 : 0; // 0=pass, 1=drop
	e->bytes_sent = bytes_sent;
	e->bytes_dropped = bytes_dropped;
	e->packets_sent = packets_sent;
	e->packets_dropped = packets_dropped;
	e->timestamp = now_ns();

	bpf_ringbuf_submit(e, 0);
}

/**
 * Enhanced event reporting with Ethernet header and statistics
 */
static __inline void
report_traffic_event_with_params(const struct event_params_t *params)
{
	struct event_t *e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
	if (!e)
	{
		return;
	}

	e->action = (params->bytes_dropped > 0) ? 1 : 0;
	e->bytes_sent = params->bytes_sent;
	e->bytes_dropped = params->bytes_dropped;
	if (params->bytes_sent)
	{
		e->packets_sent = 1;
		e->packets_dropped = 0;
	}
	else
	{
		e->packets_dropped = 1;
		e->packets_sent = 0;
	}
	e->timestamp = now_ns();

#pragma unroll
	for (int i = 0; i < 6; i++)
	{
		e->eth_src[i] = params->src_mac[i];
		e->eth_dst[i] = params->dst_mac[i];
	}
	e->eth_type = params->eth_type;
	e->packet_size = params->packet_size;

	e->packet_type = params->packet_type_id;

	if (params->flow_info)
	{
		e->type_rate_bps = params->flow_info->rate_bps;
		e->type_smooth_rate_bps = params->flow_info->smooth_rate_bps;
	}
	else
	{
		e->type_rate_bps = 0;
	}

	bpf_ringbuf_submit(e, 0);
}

/**
 * Get packet type identifier
 */
static __inline __u32 get_packet_type_id(__u16 eth_type)
{
	switch (eth_type)
	{
	case 0x0800:
		return 1; // IPv4
	case 0x0806:
		return 2; // ARP
	case 0x86DD:
		return 3; // IPv6
	case 0x8100:
		return 4; // 802.1Q VLAN
	case 0x8847:
		return 5; // MPLS
	case 0x8864:
		return 6; // PPPoE
	default:
		return 0; // Unknown/Other
	}
}

/**
 * Update flow rate statistics
 */
static __inline void
update_flow_rate_stats(__u32 packet_type_id, __u32 packet_size)
{
	if (packet_type_id == 0)
	{
		return;
	}

	struct flow_rate_info *flow_info =
		bpf_map_lookup_elem(&flow_rate_stats, &packet_type_id);
	__u64 now = bpf_ktime_get_ns();

	if (flow_info)
	{
		if (now - flow_info->window_start_ns >= NSEC_PER_SEC)
		{
			if (flow_info->total_bytes > 0)
			{
				flow_info->rate_bps =
					(flow_info->total_bytes * 8 * NSEC_PER_SEC) /
					(now - flow_info->window_start_ns);
				if (flow_info->rate_bps > flow_info->peak_rate_bps)
				{
					flow_info->peak_rate_bps = flow_info->rate_bps;
				}

				if (flow_info->smooth_rate_bps != 0)
				{
					flow_info->smooth_rate_bps =
						(flow_info->smooth_rate_bps -
						 (flow_info->smooth_rate_bps >> 3)) +
						(flow_info->rate_bps >> 3);
				}
				else
				{
					flow_info->smooth_rate_bps = flow_info->rate_bps;
				}
			}

			flow_info->window_start_ns = now;
			flow_info->total_packets = 1;
			flow_info->total_bytes = packet_size;
		}
		else
		{
			flow_info->total_packets++;
			flow_info->total_bytes += packet_size;
		}

		bpf_map_update_elem(
			&flow_rate_stats,
			&packet_type_id,
			flow_info,
			BPF_ANY
		);
	}
	else
	{
		struct flow_rate_info new_flow = {
			.window_start_ns = now,
			.total_packets = 1,
			.total_bytes = packet_size,
			.rate_bps = 0,
			.peak_rate_bps = 0
		};
		bpf_map_update_elem(
			&flow_rate_stats,
			&packet_type_id,
			&new_flow,
			BPF_ANY
		);
	}
}

/**
 * Get current flow rate for a packet type
 */
static __inline struct flow_rate_info *get_flow_rate_stats(__u32 packet_type_id)
{
	return bpf_map_lookup_elem(&flow_rate_stats, &packet_type_id);
}

// Main TC packet processing function - enhanced with Ethernet header parsing
// and statistics
static int tc_handle(struct __sk_buff *ctx, int gress)
{
	__u32 bucket_key = gress;

	void *data_end = (void *)(__u64)ctx->data_end;
	if (!data_end)
	{
		return TC_ACT_OK;
	}

	void *data = (void *)(__u64)ctx->data;
	if (!data)
	{
		return TC_ACT_OK;
	}

	__u8 src_mac[6] = {0};
	__u8 dst_mac[6] = {0};
	__u16 eth_type = 0;

	bool eth_parsed =
		parse_ethernet_header(ctx, data, data_end, src_mac, dst_mac, &eth_type);
	if (!eth_parsed)
	{
		report_traffic_event(ctx->len, 0, 1, 0);
		return TC_ACT_OK;
	}

	// Get packet type ID and update statistics
	__u32 packet_type_id = get_packet_type_id(eth_type);
	if (!packet_type_id)
	{
		return TC_ACT_OK;
	}

	update_flow_rate_stats(packet_type_id, ctx->len);

	struct flow_rate_info *flow_info = get_flow_rate_stats(packet_type_id);

	struct traffic_rule *rule = get_traffic_rule();
	if (!rule || (rule->gress != gress))
	{
		if (!flow_info)
		{
			return TC_ACT_OK;
		}

		struct event_params_t params = {
			.bytes_sent = 0,
			.bytes_dropped = 0,
			.src_mac = src_mac,
			.dst_mac = dst_mac,
			.eth_type = eth_type,
			.packet_size = ctx->len,
			.packet_type_id = packet_type_id,
			.flow_info = flow_info
		};
		report_traffic_event_with_params(&params);
		return TC_ACT_OK;
	}

	// Apply rate limiting using policy 0 (default)
	int result = apply_rate_limiting_policy(
		bucket_key,
		rule->rate_bps,
		rule->time_scale,
		ctx->len,
		0
	);

	if (result == TC_ACT_OK)
	{
		struct event_params_t params = {
			.bytes_sent = ctx->len,
			.bytes_dropped = 0,
			.src_mac = src_mac,
			.dst_mac = dst_mac,
			.eth_type = eth_type,
			.packet_size = ctx->len,
			.packet_type_id = packet_type_id,
			.flow_info = flow_info
		};
		report_traffic_event_with_params(&params);
	}
	else
	{
		struct event_params_t params = {
			.bytes_sent = 0,
			.bytes_dropped = ctx->len,
			.src_mac = src_mac,
			.dst_mac = dst_mac,
			.eth_type = eth_type,
			.packet_size = ctx->len,
			.packet_type_id = packet_type_id,
			.flow_info = flow_info
		};
		report_traffic_event_with_params(&params);
	}

	return result;
}

// Main TC egress program entry point
/**
 * @brief TC出站流量处理程序
 * @param ctx socket缓冲区上下文
 * @return TC返回值
 */
SEC("tc")
int tc_egress(struct __sk_buff *ctx)
{
	return tc_handle(ctx, EGRESS);
}

/**
 * @brief TC入站流量处理程序
 * @param ctx socket缓冲区上下文
 * @return TC返回值
 */
SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
	return tc_handle(ctx, INGRESS);
}