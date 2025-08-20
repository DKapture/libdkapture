#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

#define EGRESS 1
#define INGRESS 0

// Event structure for traffic monitoring
struct event_t
{
	__u32 pid;
	__u32 bytes_sent;
	__u32 bytes_dropped;
	__u32 packets_sent;
	__u32 packets_dropped;
	__u64 timestamp;
};

// Rate limiting rule structure
struct cgroup_rule
{
	__u64 rate_bps;	  // Bandwidth limit (bytes/second)
	__u8 gress;		  // Direction: EGRESS=1, INGRESS=0
	__u32 time_scale; // Time scale (seconds)
};

// Token bucket for rate limiting
struct rate_bucket
{
	__u64 ts_ns;  // Last update time
	__u64 tokens; // Current token count
};

// Ring buffer for event communication
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

// Rate limiting rules map
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct cgroup_rule);
	__uint(max_entries, 1024);
} cgroup_rules SEC(".maps");

// Token bucket map - using cgroup ID as key
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct rate_bucket);
	__uint(max_entries, 1024);
} buckets SEC(".maps");

#define NSEC_PER_SEC 1000000000ull
#define CG_ACT_OK 1
#define CG_ACT_SHOT 0

static __inline __u64 now_ns(void)
{
	return bpf_ktime_get_ns();
}

// Send event to ring buffer
static __inline void send_event(
	__u32 pid,
	__u64 bytes_sent,
	__u64 bytes_dropped,
	__u64 packets_sent,
	__u64 packets_dropped
)
{
	struct event_t *e;

	e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
	if (!e)
	{
		return;
	}

	e->pid = pid;
	e->bytes_sent = bytes_sent;
	e->bytes_dropped = bytes_dropped;
	e->packets_sent = packets_sent;
	e->packets_dropped = packets_dropped;
	e->timestamp = now_ns();

	bpf_ringbuf_submit(e, 0);
}

// Get current process PID
static __inline __u32 get_current_pid(void)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (task)
	{
		__u32 pid = 0;
		bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
		return pid;
	}
	return 0;
}

// Get cgroup ID
static __inline __u64 get_cgroup_id(void)
{
	return bpf_get_current_cgroup_id();
}

// Rate limiting handler
static int cgroup_handle(struct __sk_buff *ctx, int gress)
{
	__u64 now = now_ns();
	__u64 delta_ns;
	struct rate_bucket *b;
	struct cgroup_rule *rule;
	__u32 rule_key = 0;
	__u32 pid = get_current_pid();
	__u64 cgroup_id = get_cgroup_id();

	// Check for rate limiting rules
	rule = bpf_map_lookup_elem(&cgroup_rules, &rule_key);
	if (!rule || (rule->gress != gress))
	{
		send_event(pid, ctx->len, 0, 1, 0);
		return CG_ACT_OK;
	}

	__u64 bucket_key = cgroup_id;
	__u64 max_bucket = (rule->rate_bps * rule->time_scale) >> 2;

	// Find or create token bucket
	b = bpf_map_lookup_elem(&buckets, &bucket_key);
	if (!b)
	{
		struct rate_bucket init = {.ts_ns = now, .tokens = max_bucket};
		bpf_map_update_elem(&buckets, &bucket_key, &init, BPF_ANY);
		b = bpf_map_lookup_elem(&buckets, &bucket_key);
		if (!b)
		{
			send_event(pid, ctx->len, 0, 1, 0);
			return CG_ACT_OK;
		}
	}

	// Calculate time difference and accumulate tokens
	delta_ns = now - b->ts_ns;
	b->tokens += (delta_ns * rule->rate_bps) / NSEC_PER_SEC;
	if (b->tokens > max_bucket)
	{
		b->tokens = max_bucket;
	}

	b->ts_ns = now;

	// Check if tokens are sufficient
	if (b->tokens < ctx->len)
	{
		send_event(pid, 0, ctx->len, 0, 1);
		return CG_ACT_SHOT;
	}

	// Deduct tokens and allow
	b->tokens -= ctx->len;

	send_event(pid, ctx->len, 0, 1, 0);
	return CG_ACT_OK;
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *ctx)
{
	return cgroup_handle(ctx, EGRESS);
}

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *ctx)
{
	return cgroup_handle(ctx, INGRESS);
}