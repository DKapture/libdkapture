#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define __KERNEL__
#include "tcp-insight.h"

char LICENSE[] SEC("license") = "GPL";

/* Maps */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CONNECTIONS);
	__type(key, __u64);
	__type(value, struct tcp_connection);
} connections SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CONNECTIONS);
	__type(key, __u64);
	__type(value, __u64);
} start_times SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RULES);
	__type(key, __u32);
	__type(value, struct tcp_filter_rule);
} rules_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_EVENTS);
} events SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tcp_global_stats);
} global_stats SEC(".maps");

/* Helper functions */
static __always_inline __u64
generate_conn_id(__u32 saddr, __u16 sport, __u32 daddr, __u16 dport)
{
	return ((__u64)saddr << 32) | ((__u64)sport << 16) | ((__u64)daddr >> 16) |
		   dport;
}

static __always_inline bool should_trace_pid(__u32 pid)
{
	struct tcp_filter_rule *rule;
	__u32 key = 0;

	rule = bpf_map_lookup_elem(&rules_map, &key);
	if (!rule)
	{
		return true;
	}

	return rule->pid == 0 || rule->pid == pid;
}

static __always_inline bool
should_trace_addr(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport)
{
	struct tcp_filter_rule *rule;
	__u32 key = 0;

	rule = bpf_map_lookup_elem(&rules_map, &key);
	if (!rule)
	{
		return true;
	}

	if (rule->addr.ipv4.saddr && rule->addr.ipv4.saddr != saddr)
	{
		return false;
	}
	if (rule->addr.ipv4.daddr && rule->addr.ipv4.daddr != daddr)
	{
		return false;
	}
	if (rule->sport && rule->sport != sport)
	{
		return false;
	}
	if (rule->dport && rule->dport != dport)
	{
		return false;
	}

	return true;
}

static __always_inline void update_global_stats(enum tcp_event_type type)
{
	__u32 key = 0;
	struct tcp_global_stats *stats;

	stats = bpf_map_lookup_elem(&global_stats, &key);
	if (!stats)
	{
		return;
	}

	__sync_fetch_and_add(&stats->total_events, 1);

	switch (type)
	{
	case TCP_EVENT_STATE_CHANGE:
		__sync_fetch_and_add(&stats->state_changes, 1);
		break;
	case TCP_EVENT_PERF_SAMPLE:
		/* Performance sample event */
		break;
	case TCP_EVENT_RETRANSMIT:
		__sync_fetch_and_add(&stats->retransmits, 1);
		break;
	case TCP_EVENT_SEND_RESET:
	case TCP_EVENT_RECV_RESET:
		__sync_fetch_and_add(&stats->resets, 1);
		break;
	case TCP_EVENT_SEND_DATA:
		__sync_fetch_and_add(&stats->bytes_sent, 1);
		break;
	case TCP_EVENT_RECV_DATA:
		__sync_fetch_and_add(&stats->bytes_received, 1);
		break;
	case TCP_EVENT_SOCK_DESTROY:
		/* Socket destroy event */
		break;
	case TCP_EVENT_CONG_STATE:
		__sync_fetch_and_add(&stats->cong_events, 1);
		break;
	case TCP_EVENT_WIN_ADJUST:
		__sync_fetch_and_add(&stats->window_adjusts, 1);
		break;
	case TCP_EVENT_KPROBE_SEND:
	case TCP_EVENT_KPROBE_RECV:
	case TCP_EVENT_KPROBE_RETRANS:
		/* Kprobe events */
		break;
	}
}

static __always_inline void submit_event(struct tcp_event *event)
{
	bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	update_global_stats(event->type);
}

/* Tracepoint handlers */

SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct tp_inet_sock_set_state *ctx)
{
	struct tcp_event event = {};
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Filter by protocol - only TCP */
	if (ctx->protocol != IPPROTO_TCP)
	{
		return 0;
	}

	/* Extract address info */
	__u32 saddr = 0, daddr = 0;
	if (ctx->family == AF_INET)
	{
		saddr = *(__u32 *)ctx->saddr;
		daddr = *(__u32 *)ctx->daddr;
	}

	/* Apply filters */
	if (!should_trace_pid(pid))
	{
		return 0;
	}
	if (!should_trace_addr(saddr, daddr, ctx->sport, ctx->dport))
	{
		return 0;
	}

	/* Fill event */
	event.timestamp = bpf_ktime_get_ns();
	event.pid = pid;
	event.tid = bpf_get_current_pid_tgid();
	event.type = TCP_EVENT_STATE_CHANGE;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	event.family = ctx->family;
	event.protocol = ctx->protocol;
	event.sport = __builtin_bswap16(ctx->sport);
	event.dport = __builtin_bswap16(ctx->dport);

	if (ctx->family == AF_INET)
	{
		event.addr.ipv4.saddr = saddr;
		event.addr.ipv4.daddr = daddr;
	}
	else
	{
		__builtin_memcpy(event.addr.ipv6.saddr, ctx->saddr_v6, 16);
		__builtin_memcpy(event.addr.ipv6.daddr, ctx->daddr_v6, 16);
	}

	event.data.state_change.oldstate = ctx->oldstate;
	event.data.state_change.newstate = ctx->newstate;
	event.data.state_change.skaddr = ctx->skaddr;

	/* Update connection tracking */
	__u64 conn_id = generate_conn_id(saddr, ctx->sport, daddr, ctx->dport);
	struct tcp_connection *conn = bpf_map_lookup_elem(&connections, &conn_id);
	if (!conn)
	{
		struct tcp_connection new_conn = {};
		new_conn.conn_id = conn_id;
		new_conn.start_time = event.timestamp;
		new_conn.last_seen = event.timestamp;
		new_conn.pid = pid;
		__builtin_memcpy(new_conn.comm, event.comm, sizeof(new_conn.comm));
		new_conn.family = ctx->family;
		new_conn.sport = event.sport;
		new_conn.dport = event.dport;
		new_conn.addr.ipv4.saddr = saddr;
		new_conn.addr.ipv4.daddr = daddr;
		new_conn.prev_state = ctx->oldstate;
		new_conn.current_state = ctx->newstate;

		bpf_map_update_elem(&connections, &conn_id, &new_conn, BPF_ANY);

		if (ctx->newstate == TCP_ESTABLISHED)
		{
			__u32 key = 0;
			struct tcp_global_stats *stats =
				bpf_map_lookup_elem(&global_stats, &key);
			if (stats)
			{
				__sync_fetch_and_add(&stats->connections_opened, 1);
			}
		}
	}
	else
	{
		conn->last_seen = event.timestamp;
		conn->prev_state = conn->current_state;
		conn->current_state = ctx->newstate;
		bpf_map_update_elem(&connections, &conn_id, conn, BPF_ANY);

		if (ctx->newstate == TCP_CLOSE)
		{
			__u32 key = 0;
			struct tcp_global_stats *stats =
				bpf_map_lookup_elem(&global_stats, &key);
			if (stats)
			{
				__sync_fetch_and_add(&stats->connections_closed, 1);
			}
		}
	}

	submit_event(&event);
	return 0;
}

SEC("tracepoint/tcp/tcp_probe")
int trace_tcp_probe(struct tp_tcp_probe *ctx)
{
	struct tcp_event event = {};
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Extract address info based on family */
	__u32 saddr = 0, daddr = 0;
	if (ctx->family == AF_INET)
	{
		saddr = *(__u32 *)ctx->saddr;
		daddr = *(__u32 *)ctx->daddr;
	}

	/* Apply filters */
	if (!should_trace_pid(pid))
	{
		return 0;
	}
	if (!should_trace_addr(saddr, daddr, ctx->sport, ctx->dport))
	{
		return 0;
	}

	/* Fill event */
	event.timestamp = bpf_ktime_get_ns();
	event.pid = pid;
	event.tid = bpf_get_current_pid_tgid();
	event.type = TCP_EVENT_PERF_SAMPLE;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	event.family = ctx->family;
	event.protocol = IPPROTO_TCP;
	event.sport = __builtin_bswap16(ctx->sport);
	event.dport = __builtin_bswap16(ctx->dport);

	if (ctx->family == AF_INET)
	{
		event.addr.ipv4.saddr = saddr;
		event.addr.ipv4.daddr = daddr;
	}
	else
	{
		__builtin_memcpy(event.addr.ipv6.saddr, ctx->saddr, 16);
		__builtin_memcpy(event.addr.ipv6.daddr, ctx->daddr, 16);
	}

	event.data.perf_sample.mark = ctx->mark;
	event.data.perf_sample.data_len = ctx->data_len;
	event.data.perf_sample.snd_nxt = ctx->snd_nxt;
	event.data.perf_sample.snd_una = ctx->snd_una;
	event.data.perf_sample.snd_cwnd = ctx->snd_cwnd;
	event.data.perf_sample.ssthresh = ctx->ssthresh;
	event.data.perf_sample.snd_wnd = ctx->snd_wnd;
	event.data.perf_sample.srtt = ctx->srtt;
	event.data.perf_sample.rcv_wnd = ctx->rcv_wnd;
	event.data.perf_sample.sock_cookie = ctx->sock_cookie;

	/* Update connection performance data */
	__u64 conn_id = generate_conn_id(saddr, ctx->sport, daddr, ctx->dport);
	struct tcp_connection *conn = bpf_map_lookup_elem(&connections, &conn_id);
	if (conn)
	{
		conn->snd_cwnd = ctx->snd_cwnd;
		conn->ssthresh = ctx->ssthresh;
		conn->srtt = ctx->srtt;
		conn->rcv_wnd = ctx->rcv_wnd;
		conn->last_seen = event.timestamp;
		bpf_map_update_elem(&connections, &conn_id, conn, BPF_ANY);
	}

	submit_event(&event);
	return 0;
}

SEC("tracepoint/tcp/tcp_retransmit_skb")
int trace_tcp_retransmit_skb(struct tp_tcp_retransmit_skb *ctx)
{
	struct tcp_event event = {};
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Extract address info */
	__u32 saddr = 0, daddr = 0;
	if (ctx->family == AF_INET)
	{
		saddr = *(__u32 *)ctx->saddr;
		daddr = *(__u32 *)ctx->daddr;
	}

	/* Apply filters */
	if (!should_trace_pid(pid))
	{
		return 0;
	}
	if (!should_trace_addr(saddr, daddr, ctx->sport, ctx->dport))
	{
		return 0;
	}

	/* Fill event */
	event.timestamp = bpf_ktime_get_ns();
	event.pid = pid;
	event.tid = bpf_get_current_pid_tgid();
	event.type = TCP_EVENT_RETRANSMIT;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	event.family = ctx->family;
	event.protocol = IPPROTO_TCP;
	event.sport = __builtin_bswap16(ctx->sport);
	event.dport = __builtin_bswap16(ctx->dport);

	if (ctx->family == AF_INET)
	{
		event.addr.ipv4.saddr = saddr;
		event.addr.ipv4.daddr = daddr;
	}
	else
	{
		__builtin_memcpy(event.addr.ipv6.saddr, ctx->saddr_v6, 16);
		__builtin_memcpy(event.addr.ipv6.daddr, ctx->daddr_v6, 16);
	}

	event.data.retransmit.skbaddr = ctx->skbaddr;
	event.data.retransmit.skaddr = ctx->skaddr;
	event.data.retransmit.state = ctx->state;

	/* Update connection retransmit count */
	__u64 conn_id = generate_conn_id(saddr, ctx->sport, daddr, ctx->dport);
	struct tcp_connection *conn = bpf_map_lookup_elem(&connections, &conn_id);
	if (conn)
	{
		conn->retransmits++;
		conn->last_seen = event.timestamp;
		bpf_map_update_elem(&connections, &conn_id, conn, BPF_ANY);
	}

	submit_event(&event);
	return 0;
}

SEC("tracepoint/tcp/tcp_send_reset")
int trace_tcp_send_reset(struct tp_tcp_send_reset *ctx)
{
	struct tcp_event event = {};
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Extract address info */
	__u32 saddr = 0, daddr = 0;
	if (ctx->family == AF_INET)
	{
		saddr = *(__u32 *)ctx->saddr;
		daddr = *(__u32 *)ctx->daddr;
	}

	/* Apply filters */
	if (!should_trace_pid(pid))
	{
		return 0;
	}
	if (!should_trace_addr(saddr, daddr, ctx->sport, ctx->dport))
	{
		return 0;
	}

	/* Fill event */
	event.timestamp = bpf_ktime_get_ns();
	event.pid = pid;
	event.tid = bpf_get_current_pid_tgid();
	event.type = TCP_EVENT_SEND_RESET;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	event.family = ctx->family;
	event.protocol = IPPROTO_TCP;
	event.sport = __builtin_bswap16(ctx->sport);
	event.dport = __builtin_bswap16(ctx->dport);

	if (ctx->family == AF_INET)
	{
		event.addr.ipv4.saddr = saddr;
		event.addr.ipv4.daddr = daddr;
	}
	else
	{
		__builtin_memcpy(event.addr.ipv6.saddr, ctx->saddr_v6, 16);
		__builtin_memcpy(event.addr.ipv6.daddr, ctx->daddr_v6, 16);
	}

	event.data.reset.skbaddr = ctx->skbaddr;
	event.data.reset.skaddr = ctx->skaddr;
	event.data.reset.state = ctx->state;
	event.data.reset.sock_cookie = 0; /* Not available in send_reset */

	/* Update connection reset count */
	__u64 conn_id = generate_conn_id(saddr, ctx->sport, daddr, ctx->dport);
	struct tcp_connection *conn = bpf_map_lookup_elem(&connections, &conn_id);
	if (conn)
	{
		conn->resets_sent++;
		conn->last_seen = event.timestamp;
		bpf_map_update_elem(&connections, &conn_id, conn, BPF_ANY);
	}

	submit_event(&event);
	return 0;
}

SEC("tracepoint/tcp/tcp_receive_reset")
int trace_tcp_receive_reset(struct tp_tcp_receive_reset *ctx)
{
	struct tcp_event event = {};
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Extract address info */
	__u32 saddr = 0, daddr = 0;
	if (ctx->family == AF_INET)
	{
		saddr = *(__u32 *)ctx->saddr;
		daddr = *(__u32 *)ctx->daddr;
	}

	/* Apply filters */
	if (!should_trace_pid(pid))
	{
		return 0;
	}
	if (!should_trace_addr(saddr, daddr, ctx->sport, ctx->dport))
	{
		return 0;
	}

	/* Fill event */
	event.timestamp = bpf_ktime_get_ns();
	event.pid = pid;
	event.tid = bpf_get_current_pid_tgid();
	event.type = TCP_EVENT_RECV_RESET;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	event.family = ctx->family;
	event.protocol = IPPROTO_TCP;
	event.sport = __builtin_bswap16(ctx->sport);
	event.dport = __builtin_bswap16(ctx->dport);

	if (ctx->family == AF_INET)
	{
		event.addr.ipv4.saddr = saddr;
		event.addr.ipv4.daddr = daddr;
	}
	else
	{
		__builtin_memcpy(event.addr.ipv6.saddr, ctx->saddr_v6, 16);
		__builtin_memcpy(event.addr.ipv6.daddr, ctx->daddr_v6, 16);
	}

	event.data.reset.skbaddr = NULL;
	event.data.reset.skaddr = ctx->skaddr;
	event.data.reset.state = 0; /* Not available in receive_reset */
	event.data.reset.sock_cookie = ctx->sock_cookie;

	/* Update connection reset count */
	__u64 conn_id = generate_conn_id(saddr, ctx->sport, daddr, ctx->dport);
	struct tcp_connection *conn = bpf_map_lookup_elem(&connections, &conn_id);
	if (conn)
	{
		conn->resets_received++;
		conn->last_seen = event.timestamp;
		bpf_map_update_elem(&connections, &conn_id, conn, BPF_ANY);
	}

	submit_event(&event);
	return 0;
}

SEC("tracepoint/sock/sock_send_length")
int trace_sock_send_length(struct tp_sock_send_length *ctx)
{
	struct tcp_event event = {};
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Filter by protocol - only TCP */
	if (ctx->protocol != IPPROTO_TCP)
	{
		return 0;
	}

	/* Apply filters */
	if (!should_trace_pid(pid))
	{
		return 0;
	}

	/* Fill event */
	event.timestamp = bpf_ktime_get_ns();
	event.pid = pid;
	event.tid = bpf_get_current_pid_tgid();
	event.type = TCP_EVENT_SEND_DATA;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	event.family = ctx->family;
	event.protocol = ctx->protocol;

	event.data.data_transfer.sk = ctx->sk;
	event.data.data_transfer.ret = ctx->ret;
	event.data.data_transfer.flags = ctx->flags;
	event.data.data_transfer.length = (ctx->ret > 0) ? ctx->ret : 0;

	submit_event(&event);
	return 0;
}

SEC("tracepoint/sock/sock_recv_length")
int trace_sock_recv_length(struct tp_sock_recv_length *ctx)
{
	struct tcp_event event = {};
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Filter by protocol - only TCP */
	if (ctx->protocol != IPPROTO_TCP)
	{
		return 0;
	}

	/* Apply filters */
	if (!should_trace_pid(pid))
	{
		return 0;
	}

	/* Fill event */
	event.timestamp = bpf_ktime_get_ns();
	event.pid = pid;
	event.tid = bpf_get_current_pid_tgid();
	event.type = TCP_EVENT_RECV_DATA;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	event.family = ctx->family;
	event.protocol = ctx->protocol;

	event.data.data_transfer.sk = ctx->sk;
	event.data.data_transfer.ret = ctx->ret;
	event.data.data_transfer.flags = ctx->flags;
	event.data.data_transfer.length = (ctx->ret > 0) ? ctx->ret : 0;

	submit_event(&event);
	return 0;
}

SEC("tracepoint/tcp/tcp_destroy_sock")
int trace_tcp_destroy_sock(struct tp_tcp_destroy_sock *ctx)
{
	struct tcp_event event = {};
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Extract address info */
	__u32 saddr = 0, daddr = 0;
	if (ctx->family == AF_INET)
	{
		saddr = *(__u32 *)ctx->saddr;
		daddr = *(__u32 *)ctx->daddr;
	}

	/* Apply filters */
	if (!should_trace_pid(pid))
	{
		return 0;
	}
	if (!should_trace_addr(saddr, daddr, ctx->sport, ctx->dport))
	{
		return 0;
	}

	/* Fill event */
	event.timestamp = bpf_ktime_get_ns();
	event.pid = pid;
	event.tid = bpf_get_current_pid_tgid();
	event.type = TCP_EVENT_SOCK_DESTROY;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	event.family = ctx->family;
	event.protocol = IPPROTO_TCP;
	event.sport = __builtin_bswap16(ctx->sport);
	event.dport = __builtin_bswap16(ctx->dport);

	if (ctx->family == AF_INET)
	{
		event.addr.ipv4.saddr = saddr;
		event.addr.ipv4.daddr = daddr;
	}
	else
	{
		__builtin_memcpy(event.addr.ipv6.saddr, ctx->saddr_v6, 16);
		__builtin_memcpy(event.addr.ipv6.daddr, ctx->daddr_v6, 16);
	}

	event.data.destroy.skaddr = ctx->skaddr;
	event.data.destroy.sock_cookie = ctx->sock_cookie;

	/* Remove connection from tracking */
	__u64 conn_id = generate_conn_id(saddr, ctx->sport, daddr, ctx->dport);
	bpf_map_delete_elem(&connections, &conn_id);

	submit_event(&event);
	return 0;
}

SEC("tracepoint/tcp/tcp_cong_state_set")
int trace_tcp_cong_state_set(struct tp_tcp_cong_state_set *ctx)
{
	struct tcp_event event = {};
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Extract address info */
	__u32 saddr = 0, daddr = 0;
	if (ctx->family == AF_INET)
	{
		saddr = *(__u32 *)ctx->saddr;
		daddr = *(__u32 *)ctx->daddr;
	}

	/* Apply filters */
	if (!should_trace_pid(pid))
	{
		return 0;
	}
	if (!should_trace_addr(saddr, daddr, ctx->sport, ctx->dport))
	{
		return 0;
	}

	/* Fill event */
	event.timestamp = bpf_ktime_get_ns();
	event.pid = pid;
	event.tid = bpf_get_current_pid_tgid();
	event.type = TCP_EVENT_CONG_STATE;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	event.family = ctx->family;
	event.protocol = IPPROTO_TCP;
	event.sport = __builtin_bswap16(ctx->sport);
	event.dport = __builtin_bswap16(ctx->dport);

	if (ctx->family == AF_INET)
	{
		event.addr.ipv4.saddr = saddr;
		event.addr.ipv4.daddr = daddr;
	}
	else
	{
		__builtin_memcpy(event.addr.ipv6.saddr, ctx->saddr_v6, 16);
		__builtin_memcpy(event.addr.ipv6.daddr, ctx->daddr_v6, 16);
	}

	event.data.cong_state.skaddr = ctx->skaddr;
	event.data.cong_state.cong_state = ctx->cong_state;

	submit_event(&event);
	return 0;
}

SEC("tracepoint/tcp/tcp_rcv_space_adjust")
int trace_tcp_rcv_space_adjust(struct tp_tcp_rcv_space_adjust *ctx)
{
	struct tcp_event event = {};
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Extract address info */
	__u32 saddr = 0, daddr = 0;
	if (ctx->family == AF_INET)
	{
		saddr = *(__u32 *)ctx->saddr;
		daddr = *(__u32 *)ctx->daddr;
	}

	/* Apply filters */
	if (!should_trace_pid(pid))
	{
		return 0;
	}
	if (!should_trace_addr(saddr, daddr, ctx->sport, ctx->dport))
	{
		return 0;
	}

	/* Fill event */
	event.timestamp = bpf_ktime_get_ns();
	event.pid = pid;
	event.tid = bpf_get_current_pid_tgid();
	event.type = TCP_EVENT_WIN_ADJUST;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	event.family = ctx->family;
	event.protocol = IPPROTO_TCP;
	event.sport = __builtin_bswap16(ctx->sport);
	event.dport = __builtin_bswap16(ctx->dport);

	if (ctx->family == AF_INET)
	{
		event.addr.ipv4.saddr = saddr;
		event.addr.ipv4.daddr = daddr;
	}
	else
	{
		__builtin_memcpy(event.addr.ipv6.saddr, ctx->saddr_v6, 16);
		__builtin_memcpy(event.addr.ipv6.daddr, ctx->daddr_v6, 16);
	}

	event.data.win_adjust.skaddr = ctx->skaddr;
	event.data.win_adjust.sock_cookie = ctx->sock_cookie;

	submit_event(&event);
	return 0;
}

/* Kprobe handlers - kept for additional data collection */

SEC("kprobe/tcp_sendmsg")
int trace_tcp_send(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	size_t size = (size_t)PT_REGS_PARM3(ctx);

	struct tcp_event event = {};
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (!should_trace_pid(pid))
	{
		return 0;
	}

	event.timestamp = bpf_ktime_get_ns();
	event.pid = pid;
	event.tid = bpf_get_current_pid_tgid();
	event.type = TCP_EVENT_KPROBE_SEND;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	event.data.kprobe.sk = sk;
	event.data.kprobe.size = size;
	event.data.kprobe.flags = 0;

	submit_event(&event);
	return 0;
}

SEC("kprobe/tcp_recvmsg")
int trace_tcp_receive(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	size_t len = (size_t)PT_REGS_PARM3(ctx);

	struct tcp_event event = {};
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (!should_trace_pid(pid))
	{
		return 0;
	}

	event.timestamp = bpf_ktime_get_ns();
	event.pid = pid;
	event.tid = bpf_get_current_pid_tgid();
	event.type = TCP_EVENT_KPROBE_RECV;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	event.data.kprobe.sk = sk;
	event.data.kprobe.size = len;
	event.data.kprobe.flags = 0;

	submit_event(&event);
	return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int trace_tcp_retransmit(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

	struct tcp_event event = {};
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (!should_trace_pid(pid))
	{
		return 0;
	}

	event.timestamp = bpf_ktime_get_ns();
	event.pid = pid;
	event.tid = bpf_get_current_pid_tgid();
	event.type = TCP_EVENT_KPROBE_RETRANS;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	event.data.kprobe.sk = sk;
	event.data.kprobe.size = 0;
	event.data.kprobe.flags = 0;

	submit_event(&event);
	return 0;
}
