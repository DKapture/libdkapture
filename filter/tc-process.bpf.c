/**
 * @file tc-process.bpf.c
 * @brief 进程级别的流量控制 eBPF 程序
 * 
 * 该文件实现了基于进程ID的网络流量控制功能，
 * 用于监控和限制特定进程的网络活动。
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "GPL";

#define EGRESS 1
#define INGRESS 0

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

struct ProcInfo
{
	__u32 pid;
	char comm[16];
};

struct net_group
{
	__u32 ip;	   // IPv4 address (host order)
	__u16 port;	   // Port (host order)
	__u8 protocol; // L4 protocol (IPPROTO_*)
};

struct event_t
{
	struct ProcInfo proc; // Process info (PID, comm)
	__u32 bytes_sent;
	__u32 bytes_dropped;
	__u32 packets_sent;
	__u32 packets_dropped;
	__u64 timestamp;
	__u8 flag;			  // Event type
	struct net_group net; // Network tuple
};

struct process_rule
{
	__u32 target_pid; // Target PID
	__u64 rate_bps;	  // Bandwidth limit (bytes/sec)
	__u8 gress;		  // Direction: EGRESS=1, INGRESS=0
	__u32 time_scale; // Time window (seconds)
};

struct rate_bucket
{
	__u64 ts_ns;  // Last update time
	__u64 tokens; // Available tokens
};

// Map: socket* -> process info
struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct sock *);
	__type(value, struct ProcInfo);
	__uint(max_entries, 20000);
} sock_map SEC(".maps");

// Ring buffer for emitting events
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

// Map: single process rate-limit rule (key=0)
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); // 规则索引
	__type(value, struct process_rule);
	__uint(max_entries, 1024);
} process_rules SEC(".maps");

// Map: token buckets keyed by PID
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); // Process PID
	__type(value, struct rate_bucket);
	__uint(max_entries, 1024);
} buckets SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct net_group);
	__type(value, struct ProcInfo);
	__uint(max_entries, 20000);
} tuple_map SEC(".maps");

// Network protocol constants
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define NSEC_PER_SEC 1000000000ull

// Netfilter hook constants
#define NF_INET_PRE_ROUTING 0
#define NF_INET_LOCAL_IN 1
#define NF_INET_FORWARD 2
#define NF_INET_LOCAL_OUT 3
#define NF_INET_POST_ROUTING 4

// Cgroup action constants
#define CG_ACT_OK 1
#define CG_ACT_SHOT 0

// Event types
#define PROCESS_MAP 0  // Process-to-socket map
#define PACKET_PARSE 1 // Parsed packet tuple
#define SEND_DROP 2	   // Rate-limit accounting
#define IP_AND_PORT 3  // Local IP:port learned

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);	  // Fixed key 0
	__type(value, __u32); // Local IPv4 address (network order)
	__uint(max_entries, 1);
} local_ip_map SEC(".maps");

static __inline __u64 now_ns(void)
{
	return bpf_ktime_get_ns();
}

static __inline void send_event(
	struct ProcInfo *proc,
	__u32 bytes_sent,
	__u32 bytes_dropped,
	__u32 packets_sent,
	__u32 packets_dropped,
	__u8 flag
)
{
	struct event_t *e;

	e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
	if (!e)
	{
		return;
	}

	if (proc)
	{
		e->proc = *proc;
	}
	else
	{
		e->proc.pid = 0;
		e->proc.comm[0] = '\0';
	}

	e->bytes_sent = bytes_sent;
	e->bytes_dropped = bytes_dropped;
	e->packets_sent = packets_sent;
	e->packets_dropped = packets_dropped;
	e->timestamp = now_ns();
	e->flag = flag;

	bpf_ringbuf_submit(e, 0);
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

static __attribute__((noinline)) bool
parse_sk_buff(struct sk_buff *skb, __u8 direction, struct net_group *tuple)
{
	if (!skb)
	{
		return false;
	}

	if (!tuple)
	{
		return false;
	}

	struct iphdr *iph;
	struct udphdr *udph;
	struct tcphdr *tcph;
	unsigned int iphl;

	// Quick length check
	if (skb->len < 28)
	{
		return false;
	}

	iph = ip_hdr(skb);
	if (!iph)
	{
		return false;
	}

	// Only handle IPv4
	if (iph->version != 4)
	{
		return false;
	}

	iphl = iph->ihl * 4;

	if (iph->ihl < 5)
	{
		return false;
	}

	if (skb->len <= iphl)
	{
		return false;
	}
	if (iph->protocol == IPPROTO_UDP)
	{
		if (skb->len < iphl + sizeof(struct udphdr))
		{
			return false;
		}

		udph = udp_hdr(skb, iphl);
		if (!udph)
		{
			return false;
		}

		tuple->protocol = IPPROTO_UDP;
		if (direction == EGRESS)
		{
			tuple->ip = bpf_ntohl(iph->saddr);
			tuple->port = bpf_ntohs(udph->source);
		}
		else
		{ // INGRESS
			// no need to convert
			tuple->ip = (iph->daddr);
			tuple->port = (udph->dest);
		}
	}
	else if (iph->protocol == IPPROTO_TCP)
	{
		if (skb->len < iphl + sizeof(struct tcphdr))
		{
			return false;
		}

		tcph = tcp_hdr(skb, iphl);
		if (!tcph)
		{
			return false;
		}

		tuple->protocol = IPPROTO_TCP;
		if (direction == EGRESS)
		{
			tuple->ip = bpf_ntohl(iph->saddr);
			tuple->port = bpf_ntohs(tcph->source);
		}
		else
		{ // INGRESS
			tuple->ip = bpf_ntohl(iph->daddr);
			tuple->port = bpf_ntohs(tcph->dest);
		}
	}
	else
	{
		// Ignore non-UDP/TCP
		return false;
	}

	// Emit parsed tuple event
	struct event_t *e;
	e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
	if (!e)
	{
		return 0;
	}

	e->net.ip = bpf_ntohl(tuple->ip); // Host order
	e->net.port = tuple->port;		  // Host order
	e->net.protocol = tuple->protocol;
	e->flag = PACKET_PARSE;
	e->timestamp = bpf_ktime_get_ns();
	e->bytes_sent = 0;
	e->bytes_dropped = 0;
	e->packets_sent = 0;
	e->packets_dropped = 0;

	bpf_ringbuf_submit(e, 0);
	return true;
}

static void save_sock(struct socket *sock)
{
	struct sock *sk = BPF_CORE_READ(sock, sk);
	if (!sk)
	{
		return;
	}

	struct ProcInfo proc = {};
	proc.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(proc.comm, sizeof(proc.comm));

	bpf_map_update_elem(&sock_map, &sk, &proc, BPF_ANY);
}

SEC("kprobe/security_socket_recvmsg")
int BPF_KPROBE(security_socket_recvmsg, struct socket *sock, struct msghdr *msg)
{
	if (!sock)
	{
		return 0;
	}

	save_sock(sock);

	// Learn local UDP socket tuple for INGRESS lookup
	struct sock *sk = BPF_CORE_READ(sock, sk);
	if (sk)
	{
		// Only handle UDP sockets
		__u16 skproto = BPF_CORE_READ(sk, sk_protocol);
		if (skproto != IPPROTO_UDP)
		{
			return 0;
		}

		// Read local IP and port
		__u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__u16 dport = BPF_CORE_READ(sk, __sk_common.skc_num);

		// If IP is 0.0.0.0, get it from map
		if (daddr == 0)
		{
			__u32 key = 0;
			__u32 *local_ip = bpf_map_lookup_elem(&local_ip_map, &key);
			if (local_ip)
			{
				daddr = bpf_ntohl(*local_ip);
			}
		}

		struct net_group key = {};
		key.ip = bpf_ntohl(daddr);
		key.port = bpf_ntohs(dport);
		key.protocol = IPPROTO_UDP;

		struct ProcInfo proc = {};
		proc.pid = bpf_get_current_pid_tgid() >> 32;
		bpf_get_current_comm(proc.comm, sizeof(proc.comm));
		// Update UDP tuple -> process map
		bpf_map_update_elem(&tuple_map, &key, &proc, BPF_ANY);

		// Emit IP:port learned event
		struct event_t *e;
		e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
		if (!e)
		{
			return 0;
		}

		e->proc = proc;
		e->net.ip = bpf_ntohl(daddr);
		e->net.port = bpf_ntohs(dport);
		e->net.protocol = IPPROTO_UDP;
		e->flag = IP_AND_PORT;
		e->timestamp = bpf_ktime_get_ns();
		e->bytes_sent = 0;
		e->bytes_dropped = 0;
		e->packets_sent = 0;
		e->packets_dropped = 0;

		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

SEC("kprobe/security_socket_sendmsg")
int BPF_KPROBE(security_socket_sendmsg, struct socket *sock)
{
	if (!sock)
	{
		return 0;
	}

	save_sock(sock);
	return 0;
}

SEC("kprobe/security_socket_connect")
int BPF_KPROBE(security_socket_connect, struct socket *sock)
{
	if (!sock)
	{
		return 0;
	}
	save_sock(sock);
	return 0;
}

// Get the hand packet
SEC("kprobe/security_socket_listen")
int BPF_KPROBE(security_socket_listen, struct socket *sock, int backlog)
{
	if (!sock)
	{
		return 0;
	}
	save_sock(sock);
	return 0;
}

// Token bucket rate-limit check
static __inline int rate_limit_check(struct ProcInfo *proc, __u32 packet_len)
{
	__u64 now = now_ns();
	__u64 delta_ns;
	struct rate_bucket *b;
	struct process_rule *rule;
	__u32 rule_key = 0;

	if (!proc)
	{
		return CG_ACT_OK;
	}

	// Load rule (single entry keyed by 0)
	rule = bpf_map_lookup_elem(&process_rules, &rule_key);
	if (!rule)
	{
		// No rule, allow
		goto send_event_ok;
	}

	// Check target PID
	if (rule->target_pid != proc->pid)
	{
		// Not target, allow
		goto send_event_ok;
	}

	// Use PID as bucket key
	__u32 bucket_key = proc->pid;
	__u64 max_bucket = (rule->rate_bps * rule->time_scale) >> 2;

	// Lookup or create bucket
	b = bpf_map_lookup_elem(&buckets, &bucket_key);
	if (!b)
	{
		struct rate_bucket init = {.ts_ns = now, .tokens = max_bucket};
		bpf_map_update_elem(&buckets, &bucket_key, &init, BPF_ANY);
		b = bpf_map_lookup_elem(&buckets, &bucket_key);
		if (!b)
		{
			goto send_event_ok;
		}
	}

	// Refill tokens
	delta_ns = now - b->ts_ns;
	b->tokens += (delta_ns * rule->rate_bps) / NSEC_PER_SEC;
	if (b->tokens > max_bucket)
	{
		b->tokens = max_bucket;
	}

	b->ts_ns = now;

	// Check tokens
	if (b->tokens < packet_len)
	{
		// Drop
		send_event(proc, 0, packet_len, 0, 1, SEND_DROP);
		return CG_ACT_SHOT;
	}

	// Consume and pass
	b->tokens -= packet_len;

send_event_ok:
	send_event(proc, packet_len, 0, 1, 0, SEND_DROP);
	return CG_ACT_OK;
}

SEC("netfilter")
int netfilter_hook(struct bpf_nf_ctx *ctx)
{
	struct process_rule *rule;
	__u32 rule_key = 0;

	rule = bpf_map_lookup_elem(&process_rules, &rule_key);

	if (!rule)
	{
		return CG_ACT_OK;
	}

	if (!ctx || !ctx->skb)
	{
		return CG_ACT_OK;
	}

	// Read hook index (CO-RE)
	__u32 hook_state = BPF_CORE_READ(ctx->state, hook);

	// Match desired direction
	// NF_INET_LOCAL_OUT (3) => EGRESS
	// NF_INET_LOCAL_IN  (1) => INGRESS
	if (rule->gress == EGRESS && hook_state != NF_INET_LOCAL_OUT)
	{
		return CG_ACT_OK;
	}

	if (rule->gress == INGRESS && hook_state != NF_INET_LOCAL_IN)
	{
		return CG_ACT_OK;
	}

	// Preload sock pointer before parsing (avoid dynptr + probe_read overlap)
	volatile struct sock *pre_sk = BPF_CORE_READ(ctx->skb, sk);
	if (pre_sk == 0)
	{
		// keep execution; just force read ordering
	}

	struct ProcInfo *proc;
	struct net_group key = {};
	int i = parse_sk_buff(ctx->skb, INGRESS, &key);
	if (i == false)
	{
		return CG_ACT_OK; // Parsing failed
	}

	if (hook_state == NF_INET_LOCAL_IN && key.protocol == IPPROTO_UDP)
	{
		proc = bpf_map_lookup_elem(&tuple_map, &key);
	}
	else
	{
		// Lookup process by preloaded sock pointer
		if (!pre_sk)
		{
			return CG_ACT_OK;
		}
		struct sock *sk_ptr = (struct sock *)pre_sk;
		proc = bpf_map_lookup_elem(&sock_map, &sk_ptr);
	}

	if (!proc)
	{
		return CG_ACT_OK;
	}

	__u32 pid = proc->pid;
	if (pid == 0)
	{
		// No PID, allow
		return CG_ACT_OK;
	}

	// Apply rate limit
	return rate_limit_check(proc, ctx->skb->len);
}
