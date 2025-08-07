#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

// Add missing constant definitions
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define EGRESS   1
#define INGRESS  0

// Event structure for traffic monitoring
struct event_t {
    __u32    sip;           // Source IP address
    __u32    dip;           // Destination IP address
    __u32    sport;         // Source port
    __u32    dport;         // Destination port
    __u32    protocol;      // Protocol type
    __u32    action;        // Action taken (pass/drop)
    __u32    bytes_sent;    // Bytes sent
    __u32    bytes_dropped; // Bytes dropped
    __u32    packets_sent;  // Packets sent
    __u32    packets_dropped; // Packets dropped
    __u64    timestamp;     // Timestamp
};

// Traffic control rule structure
struct traffic_rule {
    __u32    target_ip;     // Target IP address to match
    __u16    target_port;   // Target port to match
    __u64    rate_bps;      // Rate limit in bytes per second
    __u8     gress;         // Direction: EGRESS=1, INGRESS=0
    __u32    time_scale;    // Time scale in seconds for burst tolerance
};

// Simple token bucket structure for rate limiting
struct rate_bucket {
    __u64    ts_ns;         // Last update timestamp in nanoseconds
    __u64    tokens;        // Current token count
};

// Ring buffer for event communication
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

// Traffic control rules mapping
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,  __u32);               // Rule index
    __type(value, struct traffic_rule);
    __uint(max_entries, 1024);
} traffic_rules SEC(".maps");

// Token bucket mapping - using IP+port as key
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,  __u64);               // IP + port combination
    __type(value, struct rate_bucket);
    __uint(max_entries, 1024);
} buckets SEC(".maps");

#define NSEC_PER_SEC 1000000000ull

// TC action constants
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

// Get current timestamp in nanoseconds
static __inline __u64 now_ns(void) {
    return bpf_ktime_get_ns();
}

// Send event to ring buffer
static __inline void send_event(__u32 sip, __u32 dip, __u32 sport, __u32 dport,
                               __u64 bytes_sent, __u64 bytes_dropped, 
                               __u64 packets_sent, __u64 packets_dropped) {
    struct event_t *e;
    
    e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
    if (!e) {
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
    
    bpf_ringbuf_submit(e, 0);
}

// Main TC packet processing function
static int tc_handle(struct __sk_buff *ctx, int gress)
{
    __u64 now = now_ns();
    __u64 delta_ns;
    struct rate_bucket *b;
    struct traffic_rule *rule;
    __u32 rule_key = 0;
    
    // Get packet data boundaries
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    
    // Check packet length for minimum required headers
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return TC_ACT_OK;
    }
    
    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)(eth + 1);
    
    // Check Ethernet type (must be IPv4)
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    
    // Check IP version (must be IPv4)
    if (ip->version != 4) {
        return TC_ACT_OK;
    }
    
    __u32 src_ip = bpf_ntohl(ip->saddr);
    __u32 dst_ip = bpf_ntohl(ip->daddr);
    __u16 src_port = 0, dst_port = 0;
    
    // Parse ports for TCP or UDP protocols
    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        // Calculate IP header length
        __u32 ip_hdr_len = ip->ihl * 4;
        
        // Check if there's enough space for TCP/UDP headers based on protocol
        if (ip->protocol == IPPROTO_TCP) {
            if (data + sizeof(struct ethhdr) + ip_hdr_len + sizeof(struct tcphdr) > data_end) {
                return TC_ACT_OK;
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            if (data + sizeof(struct ethhdr) + ip_hdr_len + sizeof(struct udphdr) > data_end) {
                return TC_ACT_OK;
            }
        }
        
        // Parse ports based on protocol type
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)((char *)ip + ip_hdr_len);
            src_port = bpf_ntohs(tcp->source);
            dst_port = bpf_ntohs(tcp->dest);
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)((char *)ip + ip_hdr_len);
            src_port = bpf_ntohs(udp->source);
            dst_port = bpf_ntohs(udp->dest);
        }
    }
    
    // Check if there's a traffic control rule
    rule = bpf_map_lookup_elem(&traffic_rules, &rule_key);
    if (!rule || (rule->gress != gress)) {
        // No rule or direction mismatch, pass through
        send_event(src_ip, dst_ip, src_port, dst_port, ctx->len, 0, 1, 0);
        return TC_ACT_OK;
    }
    
    // Check if packet matches target IP and port
    // Note: For both egress and ingress, we always match against the destination IP
    // - Egress: destination IP is the target host
    // - Ingress: destination IP is the local machine
    if (rule->target_ip != dst_ip || rule->target_port != dst_port) {
        // No match, pass through
        send_event(src_ip, dst_ip, src_port, dst_port, ctx->len, 0, 1, 0);
        return TC_ACT_OK;
    }
    
    // Create token bucket key (target IP + target port)
    __u64 bucket_key = ((__u64)dst_ip << 16) | dst_port;
    __u64 max_bucket = (rule->rate_bps * rule->time_scale) >> 2;
    
    // Look up or create token bucket
    b = bpf_map_lookup_elem(&buckets, &bucket_key);
    if (!b) {
        struct rate_bucket init = { 
            .ts_ns = now, 
            .tokens = max_bucket  // Initial capacity based on time scale
        };
        bpf_map_update_elem(&buckets, &bucket_key, &init, BPF_ANY);
        b = bpf_map_lookup_elem(&buckets, &bucket_key);
        if (!b) {
            send_event(src_ip, dst_ip, src_port, dst_port, ctx->len, 0, 1, 0);
            return TC_ACT_OK;
        }
    }
    
    // Calculate time difference and accumulate tokens
    delta_ns = now - b->ts_ns;
    b->tokens += (delta_ns * rule->rate_bps) / NSEC_PER_SEC;
    if (b->tokens > max_bucket)
        b->tokens = max_bucket;  // Limit maximum capacity based on time scale
    
    b->ts_ns = now;
    
    // Check if enough tokens are available
    if (b->tokens < ctx->len) {
        // Insufficient tokens, drop packet
        send_event(src_ip, dst_ip, src_port, dst_port, 0, ctx->len, 0, 1);
        return TC_ACT_SHOT;
    }
    
    // Consume tokens and pass packet
    b->tokens -= ctx->len;
    
    send_event(src_ip, dst_ip, src_port, dst_port, ctx->len, 0, 1, 0);
    return TC_ACT_OK;
}

// TC egress program - attached to TC egress hook
SEC("tc")
int tc_egress(struct __sk_buff *ctx) 
{
    return tc_handle(ctx, EGRESS);
}

// TC ingress program - attached to TC ingress hook
SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
    return tc_handle(ctx, INGRESS);
}
