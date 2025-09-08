/**
 * @file tc-cgroup.bpf.c
 * @brief Cgroup级别的流量控制 eBPF 程序
 * 
 * 该文件实现了基于 cgroup 的网络流量控制功能，
 * 用于限制特定 cgroup 中进程的网络带宽使用。
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

#define EGRESS 1
#define INGRESS 0

/**
 * @brief 流量监控事件结构体
 */
struct event_t
{
	__u32 pid;             ///< 进程ID
	__u32 bytes_sent;      ///< 发送字节数
	__u32 bytes_dropped;   ///< 丢弃字节数
	__u32 packets_sent;    ///< 发送包数
	__u32 packets_dropped; ///< 丢弃包数
	__u64 timestamp;       ///< 时间戳
};

/**
 * @brief 速率限制规则结构体
 */
struct cgroup_rule
{
	__u64 rate_bps;	  ///< 带宽限制（字节/秒）
	__u8 gress;		  ///< 方向：EGRESS=1, INGRESS=0
	__u32 time_scale; ///< 时间刻度（秒）
};

/**
 * @brief 令牌桶结构体用于速率限制
 */
struct rate_bucket
{
	__u64 ts_ns;  ///< 上次更新时间
	__u64 tokens; ///< 当前令牌数量
};

/**
 * @brief 事件通信环形缓冲区
 */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

/**
 * @brief 速率限制规则映射
 */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct cgroup_rule);
	__uint(max_entries, 1024);
} cgroup_rules SEC(".maps");

/**
 * @brief 令牌桶映射 - 使用cgroup ID作为键
 */
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

	/// 发送事件到环形缓冲区
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

	/// 获取当前进程PID
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

	/// 获取cgroup ID
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

/**
 * @brief Cgroup出站流量处理程序
 * @param ctx socket缓冲区上下文
 * @return TC返回值
 */
SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *ctx)
{
	return cgroup_handle(ctx, EGRESS);
}

/**
 * @brief Cgroup入站流量处理程序
 * @param ctx socket缓冲区上下文
 * @return TC返回值
 */
SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *ctx)
{
	return cgroup_handle(ctx, INGRESS);
}