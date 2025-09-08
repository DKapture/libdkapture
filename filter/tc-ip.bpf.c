/**
 * @file tc-ip.bpf.c
 * @brief IP级别的流量控制 eBPF 程序
 * 
 * 该文件实现了基于IP地址和端口的网络流量控制功能，
 * 支持细粒度的流量限制和监控。
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "../include/Kcom.h"

char __license[] SEC("license") = "GPL";

#define DEBUG_ON 1

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define EGRESS 1
#define INGRESS 0

#define NF_INET_LOCAL_IN 1
#define NF_INET_LOCAL_OUT 3

#define NF_ACCEPT 1
#define NF_DROP 0

#define NSEC_PER_SEC 1000000000ull

// Event types
#define EVENT_PACKET_PASS 0	 // Packet passed through
#define EVENT_PACKET_DROP 1	 // Packet dropped
#define EVENT_RATE_LIMIT 2	 // Rate limit applied
#define EVENT_STATS_UPDATE 3 // Statistics updated

int bpf_dynptr_from_skb(
	struct sk_buff *skb,
	__u64 flags,
	struct bpf_dynptr *ptr__uninit
) __ksym;

void *bpf_dynptr_slice(
	const struct bpf_dynptr *ptr,
	uint32_t offset,
	void *buffer,
	uint32_t buffer__sz
) __ksym;

// 数据结构定义

// Event structure for traffic monitoring
struct event_t
{
	__u32 sip;			   // Source IP address
	__u32 dip;			   // Destination IP address
	__u32 sport;		   // Source port
	__u32 dport;		   // Destination port
	__u32 protocol;		   // Protocol type
	__u32 action;		   // Action taken (pass/drop)
	__u32 bytes_sent;	   // Bytes sent
	__u32 bytes_dropped;   // Bytes dropped
	__u32 packets_sent;	   // Packets sent
	__u32 packets_dropped; // Packets dropped
	__u64 timestamp;	   // Timestamp
	__u8 event_type;	   // Event type for different operations
};

// Traffic control rule structure - enhanced for combination matching
struct traffic_rule
{
	__u32 target_ip;	  // Target IP address to match (0 = any IP)
	__u16 target_port;	  // Target port to match (0 = any port)
	__u8 target_protocol; // Target protocol to match (0 = any protocol)
	__u64 rate_bps;		  // Rate limit in bytes per second
	__u8 gress;			  // Direction: EGRESS=1, INGRESS=0
	__u32 time_scale;	  // Time scale in seconds for burst tolerance
	__u32 match_mask;	  // Bit mask for which fields to match
	__u8 rule_type;		  // Rule type: 0=rate_limit, 1=drop, 2=log
};

// Simple token bucket structure for rate limiting
struct rate_bucket
{
	__u64 ts_ns;  // Last update timestamp in nanoseconds
	__u64 tokens; // Current token count
};

// Five-tuple structure for packet identification
struct packet_tuple
{
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8 protocol;
};

// Global traffic statistics structure
struct global_stats
{
	__u64 total_bytes;
	__u64 total_packets;
	__u64 dropped_bytes;
	__u64 dropped_packets;
	__u64 last_update_ns;
	__u64 current_rate_bps;
	__u64 peak_rate_bps;
};

// Encapsulated token bucket rate limiting algorithm result
struct token_bucket_result
{
	bool should_drop;
	__u64 tokens_consumed;
	__u64 current_tokens;
	int error_code;
};

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

// Traffic control rules mapping
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); // Rule index
	__type(value, struct traffic_rule);
	__uint(max_entries, 1024);
} traffic_rules SEC(".maps");

// Token bucket mapping - using IP+port as key
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64); // IP + port combination
	__type(value, struct rate_bucket);
	__uint(max_entries, 1024);
} buckets SEC(".maps");

// Global traffic statistics map
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct global_stats);
	__uint(max_entries, 1);
} global_stats_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, struct global_stats);
	__uint(max_entries, 10000);
} ip_stats_map SEC(".maps");

// Per-port traffic statistics map
struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u16); // Port number
	__type(value, struct global_stats);
	__uint(max_entries, 10000);
} port_stats_map SEC(".maps");

static __inline __u64 now_ns(void)
{
	return bpf_ktime_get_ns();
}

static __inline bool is_valid_packet_size(__u32 size)
{
	return size >= 64 && size <= 65535;
}

static __inline bool is_valid_time_scale(__u32 time_scale)
{
	return time_scale >= 1 && time_scale <= 3600;
}

static struct udphdr *udp_hdr(struct sk_buff *skb, u32 offset)
{
	struct bpf_dynptr ptr;
	struct udphdr *p, udph = {};

	if (skb->len <= offset)
	{
		return NULL;
	}

	if (bpf_dynptr_from_skb(skb, 0, &ptr))
	{
		return NULL;
	}

	p = bpf_dynptr_slice(&ptr, offset, &udph, sizeof(udph));
	if (!p)
	{
		return NULL;
	}

	return p;
}

// Parse TCP header using bpf_dynptr
static struct tcphdr *tcp_hdr(struct sk_buff *skb, u32 offset)
{
	struct bpf_dynptr ptr;
	struct tcphdr *p, tcph = {};

	if (skb->len <= offset)
	{
		return NULL;
	}

	if (bpf_dynptr_from_skb(skb, 0, &ptr))
	{
		return NULL;
	}

	p = bpf_dynptr_slice(&ptr, offset, &tcph, sizeof(tcph));
	if (!p)
	{
		return NULL;
	}

	return p;
}

// Parse IP header using bpf_dynptr
static struct iphdr *ip_hdr(struct sk_buff *skb)
{
	struct bpf_dynptr ptr;
	struct iphdr *p, iph = {};

	if (skb->len <= 20)
	{
		return NULL;
	}

	if (bpf_dynptr_from_skb(skb, 0, &ptr))
	{
		return NULL;
	}

	p = bpf_dynptr_slice(&ptr, 0, &iph, sizeof(iph));
	if (!p)
	{
		return NULL;
	}

	return p;
}

// ============================================================================
// EVENT HANDLING FUNCTIONS
// ============================================================================

// Enhanced send event function with event type
static __inline void send_event_enhanced(
	__u32 sip,
	__u32 dip,
	__u32 sport,
	__u32 dport,
	__u64 bytes_sent,
	__u64 bytes_dropped,
	__u64 packets_sent,
	__u64 packets_dropped,
	__u8 event_type
)
{
	struct event_t *e;

	e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
	if (!e)
	{
		return;
	}

	e->sip = sip;
	e->dip = dip;
	e->sport = sport;
	e->dport = dport;
	e->bytes_sent = bytes_sent;
	e->bytes_dropped = bytes_dropped;
	e->packets_sent = packets_sent;
	e->packets_dropped = packets_dropped;
	e->timestamp = now_ns();
	e->event_type = event_type;

	bpf_ringbuf_submit(e, 0);
}

// Check if packet matches the rule based on match mask
static __inline bool
packet_matches_rule(struct traffic_rule *rule, struct packet_tuple *tuple)
{
	if (rule->match_mask == 0)
	{
		DEBUG(DEBUG_ON, "Match all");
		return true;
	}

	DEBUG(DEBUG_ON, "Check match");

	__u32 check_ip = tuple->dst_ip;
	__u16 check_port = tuple->dst_port;

	DEBUG(
		DEBUG_ON,
		"Rule target_ip=%u, tuple dst_ip=%u, match_mask=%u",
		rule->target_ip,
		tuple->dst_ip,
		rule->match_mask
	);

	if ((rule->match_mask & 1) && rule->target_ip != 0 &&
		rule->target_ip != check_ip)
	{
		DEBUG(
			DEBUG_ON,
			"IP mismatch: target=%u, actual=%u",
			rule->target_ip,
			check_ip
		);
		return false;
	}

	if ((rule->match_mask & 2) && rule->target_port != 0 &&
		rule->target_port != check_port)
	{
		DEBUG(DEBUG_ON, "Port mismatch");
		return false;
	}

	if ((rule->match_mask & 4) && rule->target_protocol != 0 &&
		rule->target_protocol != tuple->protocol)
	{
		DEBUG(DEBUG_ON, "Protocol mismatch");
		return false;
	}

	DEBUG(DEBUG_ON, "Match passed");
	return true;
}

// Enhanced packet parsing function based on tc-process.bpf.c implementation
static __inline bool parse_sk_buff_enhanced(
	struct sk_buff *skb,
	__u8 direction,
	struct packet_tuple *tuple
)
{
	DEBUG(DEBUG_ON, "parse_sk_buff_enhanced");

	if (!skb || !tuple)
	{
		DEBUG(DEBUG_ON, "Invalid params");
		return false;
	}

	// Quick length check for minimum packet size
	if (skb->len < 28)
	{
		DEBUG(DEBUG_ON, "Too short");
		return false;
	}

	struct iphdr *iph = ip_hdr(skb);
	if (!iph)
	{
		DEBUG(DEBUG_ON, "No IP header");
		return false;
	}

	// Only handle IPv4
	if (iph->version != 4)
	{
		DEBUG(DEBUG_ON, "Not IPv4");
		return false;
	}

	__u32 iphl = iph->ihl * 4;
	if (iph->ihl < 5 || skb->len <= iphl)
	{
		DEBUG(DEBUG_ON, "Invalid IP header");
		return false;
	}

	// Fill in basic packet information
	tuple->src_ip = bpf_ntohl(iph->saddr);
	tuple->dst_ip = bpf_ntohl(iph->daddr);
	tuple->protocol = iph->protocol;

	DEBUG(
		DEBUG_ON,
		"Basic IP: src=%u, dst=%u, protocol=%u",
		tuple->src_ip,
		tuple->dst_ip,
		tuple->protocol
	);

	// Parse ports for TCP or UDP protocols only
	if (iph->protocol == IPPROTO_UDP)
	{
		if (skb->len < iphl + sizeof(struct udphdr))
		{
			return false;
		}

		struct udphdr *udph = udp_hdr(skb, iphl);
		if (!udph)
		{
			return false;
		}

		if (direction == EGRESS)
		{
			// For egress, use source IP and port (outgoing traffic)
			tuple->src_ip = bpf_ntohl(iph->saddr);
			tuple->dst_ip = bpf_ntohl(iph->daddr);
			tuple->src_port = bpf_ntohs(udph->source);
			tuple->dst_port = bpf_ntohs(udph->dest);
		}
		else
		{
			// For ingress, use destination IP and port (incoming traffic)
			tuple->src_ip = bpf_ntohl(iph->saddr);
			tuple->dst_ip = bpf_ntohl(iph->daddr);
			tuple->src_port = bpf_ntohs(udph->source);
			tuple->dst_port = bpf_ntohs(udph->dest);
		}
	}
	else if (iph->protocol == IPPROTO_TCP)
	{
		if (skb->len < iphl + sizeof(struct tcphdr))
		{
			return false;
		}

		struct tcphdr *tcph = tcp_hdr(skb, iphl);
		if (!tcph)
		{
			return false;
		}

		if (direction == EGRESS)
		{
			// For egress, use source IP and port (outgoing traffic)
			tuple->src_ip = bpf_ntohl(iph->saddr);
			tuple->dst_ip = bpf_ntohl(iph->daddr);
			tuple->src_port = bpf_ntohs(tcph->source);
			tuple->dst_port = bpf_ntohs(tcph->dest);
		}
		else
		{
			// For ingress, use destination IP and port (incoming traffic)
			tuple->src_ip = bpf_ntohl(iph->saddr);
			tuple->dst_ip = bpf_ntohl(iph->daddr);
			tuple->src_port = bpf_ntohs(tcph->source);
			tuple->dst_port = bpf_ntohs(tcph->dest);
		}
	}
	else
	{
		tuple->src_port = 0;
		tuple->dst_port = 0;
		DEBUG(DEBUG_ON, "Non-TCP/UDP");
	}

	DEBUG(DEBUG_ON, "Parse success");

	return true;
}

// Simplified packet validation function
static __inline int
validate_netfilter_packet(struct bpf_nf_ctx *ctx, struct packet_tuple *tuple)
{
	if (!ctx || !ctx->skb || !tuple)
	{
		return NF_DROP;
	}

	if (!is_valid_packet_size(ctx->skb->len))
	{
		return NF_DROP;
	}

	// Basic validation passed, actual parsing will be done later with direction
	return NF_ACCEPT;
}

static __inline void
update_stats_generic(void *map, const void *key, __u32 packet_len, bool dropped)
{
	struct global_stats *stats = bpf_map_lookup_elem(map, key);

	if (!stats)
	{
		struct global_stats new_stats = {
			.total_bytes = packet_len,
			.total_packets = 1,
			.dropped_bytes = dropped ? packet_len : 0,
			.dropped_packets = dropped ? 1 : 0,
			.last_update_ns = now_ns(),
			.current_rate_bps = 0,
			.peak_rate_bps = 0
		};
		bpf_map_update_elem(map, key, &new_stats, BPF_ANY);
		return;
	}

	__u64 now = now_ns();
	__u64 time_diff = now - stats->last_update_ns;

	stats->total_bytes += packet_len;
	stats->total_packets += 1;
	if (dropped)
	{
		stats->dropped_bytes += packet_len;
		stats->dropped_packets += 1;
	}

	if (time_diff > 0)
	{
		stats->current_rate_bps = (packet_len * NSEC_PER_SEC) / time_diff;
		if (stats->current_rate_bps > stats->peak_rate_bps)
		{
			stats->peak_rate_bps = stats->current_rate_bps;
		}
	}

	stats->last_update_ns = now;
	bpf_map_update_elem(map, key, stats, BPF_ANY);
}

static __inline void update_global_stats(__u32 packet_len, bool dropped)
{
	__u32 key = 0;
	update_stats_generic(&global_stats_map, &key, packet_len, dropped);
}

static __inline void update_ip_stats(__u32 ip, __u32 packet_len, bool dropped)
{
	update_stats_generic(&ip_stats_map, &ip, packet_len, dropped);
}

static __inline void
update_port_stats(__u16 port, __u32 packet_len, bool dropped)
{
	update_stats_generic(&port_stats_map, &port, packet_len, dropped);
}

static __inline void
update_all_stats(struct packet_tuple *tuple, __u32 packet_len, bool dropped)
{
	update_global_stats(packet_len, dropped);
	update_ip_stats(tuple->src_ip, packet_len, dropped);
	update_ip_stats(tuple->dst_ip, packet_len, dropped);
	update_port_stats(tuple->src_port, packet_len, dropped);
	update_port_stats(tuple->dst_port, packet_len, dropped);
}

static __inline struct rate_bucket *get_or_create_bucket_safe(
	__u64 bucket_key,
	__u64 rate_bps,
	__u32 time_scale,
	int *error_code
)
{
	DEBUG(DEBUG_ON, "get_or_create_bucket_safe");

	if (!is_valid_time_scale(time_scale) || rate_bps == 0)
	{
		DEBUG(
			DEBUG_ON,
			"Invalid params: time_scale=%u, rate_bps=%llu",
			time_scale,
			rate_bps
		);
		*error_code = 0;
		return NULL;
	}

	struct rate_bucket *b = bpf_map_lookup_elem(&buckets, &bucket_key);
	if (!b)
	{
		DEBUG(DEBUG_ON, "Create bucket");
		__u64 max_bucket = (rate_bps * time_scale) >> 2;
		if (max_bucket == 0)
		{
			DEBUG(DEBUG_ON, "max_bucket=0");
			*error_code = NF_DROP;
			return NULL;
		}

		struct rate_bucket init = {.ts_ns = now_ns(), .tokens = max_bucket};

		int update_result =
			bpf_map_update_elem(&buckets, &bucket_key, &init, BPF_ANY);
		if (update_result != 0)
		{
			DEBUG(DEBUG_ON, "Create failed");
			*error_code = 0;
			return NULL;
		}

		b = bpf_map_lookup_elem(&buckets, &bucket_key);
		if (!b)
		{
			DEBUG(DEBUG_ON, "Lookup failed");
			*error_code = 0;
			return NULL;
		}

		DEBUG(DEBUG_ON, "Created");
	}
	else
	{
		DEBUG(DEBUG_ON, "Found");
	}

	if (!b)
	{
		DEBUG(DEBUG_ON, "Unexpected NULL pointer");
		*error_code = 0;
		return NULL;
	}

	*error_code = 1;
	return b;
}

static __inline int update_token_bucket_safe(
	struct rate_bucket *b,
	__u64 rate_bps,
	__u32 time_scale
)
{
	DEBUG(DEBUG_ON, "update_token_bucket_safe");

	if (!b || rate_bps == 0 || time_scale == 0)
	{
		DEBUG(DEBUG_ON, "Invalid params");
		return 0;
	}

	__u64 now = now_ns();
	__u64 delta_ns = now - b->ts_ns;

	if (delta_ns > NSEC_PER_SEC * 3600)
	{
		delta_ns = NSEC_PER_SEC * 3600;
	}

	__u64 tokens_to_add = (delta_ns * rate_bps) / NSEC_PER_SEC;
	__u64 max_bucket = (rate_bps * time_scale) >> 2;

	DEBUG(
		DEBUG_ON,
		"delta_ns=%llu, tokens_to_add=%llu, max_bucket=%llu, "
		"current_tokens=%llu",
		delta_ns,
		tokens_to_add,
		max_bucket,
		b->tokens
	);

	b->tokens += tokens_to_add;
	if (b->tokens > max_bucket)
	{
		b->tokens = max_bucket;
	}

	b->ts_ns = now;
	DEBUG(DEBUG_ON, "Updated tokens=%llu", b->tokens);
	return 1;
}

// Apply rate limiting with comprehensive safety checks
static int apply_rate_limiting_safe(
	__u64 bucket_key,
	__u64 rate_bps,
	__u32 time_scale,
	__u32 packet_size,
	struct token_bucket_result *result
)
{
	DEBUG(
		DEBUG_ON,
		"apply_rate_limiting_safe: bucket_key=%llu, packet_size=%u",
		bucket_key,
		packet_size
	);

	if (!result)
	{
		return -1;
	}

	result->should_drop = false;
	result->tokens_consumed = 0;
	result->current_tokens = 0;
	result->error_code = NF_ACCEPT;

	if (!is_valid_packet_size(packet_size))
	{
		DEBUG(DEBUG_ON, "Invalid packet size");
		return 0;
	}

	if (rate_bps == 0 || time_scale == 0)
	{
		DEBUG(DEBUG_ON, "Invalid rate or time_scale");
		return 0;
	}

	int bucket_error = 0;
	struct rate_bucket *b = get_or_create_bucket_safe(
		bucket_key,
		rate_bps,
		time_scale,
		&bucket_error
	);
	if (!b || bucket_error != 1)
	{
		DEBUG(DEBUG_ON, "Bucket error: %d", bucket_error);
		result->error_code = bucket_error;
		return 0;
	}

	DEBUG(DEBUG_ON, "Bucket obtained successfully");

	int update_error = update_token_bucket_safe(b, rate_bps, time_scale);
	if (update_error != 1)
	{
		DEBUG(DEBUG_ON, "Bucket error: %d", update_error);
		result->error_code = update_error;
		return 0;
	}

	DEBUG(DEBUG_ON, "Bucket updated successfully");

	result->current_tokens = b->tokens;

	DEBUG(
		DEBUG_ON,
		"Current tokens: %llu, packet_size: %u",
		b->tokens,
		packet_size
	);

	if (b->tokens < packet_size)
	{
		result->should_drop = true;
		result->tokens_consumed = 0;
		DEBUG(DEBUG_ON, "Insufficient tokens, will drop");
	}
	else
	{
		result->should_drop = false;
		result->tokens_consumed = packet_size;
		b->tokens -= packet_size;
		DEBUG(
			DEBUG_ON,
			"Sufficient tokens, will pass, remaining: %llu",
			b->tokens
		);
	}

	return 1;
}

// Main Netfilter packet processing function
static int netfilter_handle(struct bpf_nf_ctx *ctx)
{
	struct traffic_rule *rule;
	__u32 rule_key = 0;
	struct packet_tuple tuple = {0};

	DEBUG(DEBUG_ON, "netfilter_handle entered");

	if (!ctx || !ctx->skb)
	{
		DEBUG(DEBUG_ON, "Invalid ctx or skb");
		return NF_ACCEPT;
	}

	__u32 packet_len = ctx->skb->len;

	__u8 direction = INGRESS;

	DEBUG(DEBUG_ON, "Direction: %u (0=INGRESS, 1=EGRESS)", direction);

	// Use enhanced packet validation with proper direction
	int validation_result = validate_netfilter_packet(ctx, &tuple);
	if (validation_result != NF_ACCEPT)
	{
		return NF_ACCEPT;
	}

	// Re-parse with correct direction for proper IP/port handling
	if (!parse_sk_buff_enhanced(ctx->skb, direction, &tuple))
	{
		return NF_ACCEPT; // Pass through on parsing error
	}

	update_all_stats(&tuple, packet_len, false);

	rule = bpf_map_lookup_elem(&traffic_rules, &rule_key);
	if (!rule)
	{
		DEBUG(DEBUG_ON, "No rule found");
		send_event_enhanced(
			tuple.src_ip,
			tuple.dst_ip,
			tuple.src_port,
			tuple.dst_port,
			packet_len,
			0,
			1,
			0,
			EVENT_PACKET_PASS
		);
		return NF_ACCEPT;
	}

	DEBUG(DEBUG_ON, "Rule found, type=%u", rule->rule_type);

	if (!packet_matches_rule(rule, &tuple))
	{
		DEBUG(DEBUG_ON, "No match");
		send_event_enhanced(
			tuple.src_ip,
			tuple.dst_ip,
			tuple.src_port,
			tuple.dst_port,
			packet_len,
			0,
			1,
			0,
			EVENT_PACKET_PASS
		);
		return NF_ACCEPT;
	}

	DEBUG(DEBUG_ON, "Rule matched");

	if (rule->rule_type == 1)
	{
		update_all_stats(&tuple, packet_len, true);
		send_event_enhanced(
			tuple.src_ip,
			tuple.dst_ip,
			tuple.src_port,
			tuple.dst_port,
			0,
			packet_len,
			0,
			1,
			EVENT_PACKET_DROP
		);
		return NF_DROP;
	}

	if (rule->rule_type == 2)
	{
		send_event_enhanced(
			tuple.src_ip,
			tuple.dst_ip,
			tuple.src_port,
			tuple.dst_port,
			packet_len,
			0,
			1,
			0,
			EVENT_STATS_UPDATE
		);
		return NF_ACCEPT;
	}

	// Rate limiting rule (rule_type == 0)
	if (rule->rate_bps == 0)
	{
		DEBUG(DEBUG_ON, "No rate limit");
		// No rate limit, pass through
		send_event_enhanced(
			tuple.src_ip,
			tuple.dst_ip,
			tuple.src_port,
			tuple.dst_port,
			packet_len,
			0,
			1,
			0,
			EVENT_PACKET_PASS
		);
		return NF_ACCEPT;
	}

	DEBUG(DEBUG_ON, "Rate limiting");

	__u64 bucket_key;
	if (rule->match_mask == 0)
	{
		bucket_key = 0;
		DEBUG(DEBUG_ON, "Global");
	}
	else
	{
		// Specific matching: always use destination IP+port (the target being
		// limited)
		bucket_key = ((__u64)tuple.dst_ip << 16) | tuple.dst_port;
		DEBUG(DEBUG_ON, "Specific");
	}

	// Apply rate limiting using encapsulated algorithm
	DEBUG(DEBUG_ON, "Apply rate limiting");
	struct token_bucket_result rate_result;
	int rate_result_code = apply_rate_limiting_safe(
		bucket_key,
		rule->rate_bps,
		rule->time_scale,
		packet_len,
		&rate_result
	);

	// Handle rate limiting errors
	if (rate_result_code != 1 || rate_result.error_code != 1)
	{
		send_event_enhanced(
			tuple.src_ip,
			tuple.dst_ip,
			tuple.src_port,
			tuple.dst_port,
			packet_len,
			0,
			1,
			0,
			EVENT_PACKET_PASS
		);
		return NF_ACCEPT;
	}

	DEBUG(DEBUG_ON, "Rate limit result: drop=%d", rate_result.should_drop);

	// Check rate limiting result
	if (rate_result.should_drop)
	{
		DEBUG(DEBUG_ON, "Drop packet");
		// Insufficient tokens, drop packet
		update_all_stats(&tuple, packet_len, true);
		send_event_enhanced(
			tuple.src_ip,
			tuple.dst_ip,
			tuple.src_port,
			tuple.dst_port,
			0,
			packet_len,
			0,
			1,
			EVENT_RATE_LIMIT
		);
		return NF_DROP;
	}

	DEBUG(DEBUG_ON, "Pass packet");
	// Sufficient tokens, pass packet
	send_event_enhanced(
		tuple.src_ip,
		tuple.dst_ip,
		tuple.src_port,
		tuple.dst_port,
		packet_len,
		0,
		1,
		0,
		EVENT_PACKET_PASS
	);
	return NF_ACCEPT;
}

// Netfilter program - attached to netfilter hooks
SEC("netfilter")
int netfilter_hook(struct bpf_nf_ctx *ctx)
{
	return netfilter_handle(ctx);
}