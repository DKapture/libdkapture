// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Cloudflare */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#include "Kcom.h"
#include "net.h"
#include "Kstr-utils.h"

#define ITER_PASS_STRING 0
#define SWITCH_TCP (1 << 0)
#define SWITCH_UDP (1 << 1)
#define SWITCH_UNX (1 << 2)
#define SWITCH_IPV4 (1 << 8)
#define SWITCH_IPV6 (1 << 9)

#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

#define __SO_ACCEPTCON (1 << 16)
#define MAX_SK_NAME_LEN                                                        \
	(sizeof(struct sockaddr_un) - sizeof(__kernel_sa_family_t))
#define LOG_PATH_BUF_SIZE                                                      \
	(MAX_SK_NAME_LEN % 8 ? MAX_SK_NAME_LEN + 8 - MAX_SK_NAME_LEN % 8           \
						 : MAX_SK_NAME_LEN)

char _license[] SEC("license") = "GPL";

#if ITER_PASS_STRING
static const char *tcp_titles = "  sl  "
								"local_address "
								"rem_address   "
								"st "
								"tx_queue "
								"rx_queue "
								"tr "
								"tm->when "
								"retrnsmt   "
								"uid  "
								"timeout "
								"inode";

static const char *tcp6_titles = "  sl  "
								 "local_address                         "
								 "remote_address                        "
								 "st "
								 "tx_queue "
								 "rx_queue "
								 "tr "
								 "tm->when "
								 "retrnsmt   "
								 "uid  "
								 "timeout "
								 "inode";

static const char *udp_titles = "   sl  "
								"local_address "
								"rem_address   "
								"st "
								"tx_queue "
								"rx_queue "
								"tr "
								"tm->when "
								"retrnsmt   "
								"uid  "
								"timeout "
								"inode "
								"ref "
								"pointer "
								"drops";

static const char *udp6_titles = "  sl  "
								 "local_address                         "
								 "remote_address                        "
								 "st "
								 "tx_queue "
								 "rx_queue "
								 "tr "
								 "tm->when "
								 "retrnsmt   "
								 "uid  "
								 "timeout "
								 "inode "
								 "ref "
								 "pointer "
								 "drops";

static const char *unix_titles = "Num               "
								 "RefCount "
								 "Protocol "
								 "Flags    "
								 "Type "
								 "St    "
								 "Inode "
								 "Path";
#endif

struct Rule
{
	u32 bit_switch;

	unsigned int lip;
	unsigned int rip;
	unsigned int lip_end;
	unsigned int rip_end;

	struct in6_addr lipv6;
	struct in6_addr ripv6;
	struct in6_addr lipv6_end;
	struct in6_addr ripv6_end;

	unsigned short lport;
	unsigned short rport;
	unsigned short lport_end;
	unsigned short rport_end;
	uid_t uid;
};

enum LogType
{
	LOG_UNIX,
	LOG_UDP_IPV4,
	LOG_UDP_IPV6,
	LOG_TCP_IPV4,
	LOG_TCP_IPV6,
};

struct BpfData
{
	union
	{
		unsigned int lip; // local ip address
		struct in6_addr lipv6;
	};
	union
	{
		unsigned int rip; // remote ip address
		struct in6_addr ripv6;
	};

	u16 lport; // local port
	u16 rport; // remote port
	int state;

	u32 tx_queue;
	u32 rx_queue;

	union
	{
		u16 sk_type; // for unix socket
		int tr;
	};
	enum LogType log_type;

	u8 retrnsmt; // 重传次数
	u8 timeout;
	uid_t uid;
	char sk_addr[18];

	u64 tm_when;
	u64 ino;
	// fields below normally used for debug only
	u64 icsk_rto;
	u64 icsk_ack;
	u32 bit_flags;
	u32 snd_cwnd; // 发送窗口大小
	u32 sk_ref;
	union
	{
		int plen;	  // path length for unix socket
		int ssthresh; // slow start thresh
	};
	char path[]; // for unix socket only
} __attribute__((aligned(8)));

static int ipv6_cmp(const struct in6_addr *ipa, const struct in6_addr *ipb)
{
	u32 *a = (u32 *)ipa;
	u32 *b = (u32 *)ipb;
	u32 mem_sz = sizeof(*ipa) / sizeof(*a);

	for (int i = mem_sz - 1; i >= 0; i--)
	{
		if (a[i] != b[i])
		{
			return a[i] > b[i] ? 1 : -1;
		}
	}
	return 0;
}

static struct Rule rule = {};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct Rule);
	__uint(max_entries, 1);
} filter SEC(".maps");

u32 elems = 0;
u32 socks = 0;

#define PF_INET 2	/* IP protocol family.  */
#define PF_INET6 10 /* IP version 6.  */
#define USER_HZ 100
#define NSEC_PER_SEC 1000000000ULL

typedef unsigned long jiffy_t;

static void get_rule(void)
{
	struct Rule *tmp;
	u32 rkey;
	static bool job_done = false;

	if (job_done)
	{
		return;
	}

	DEBUG(0, "======= get rule =======");
	rkey = 0;
	job_done = true;
	tmp = bpf_map_lookup_elem(&filter, &rkey);
	if (!tmp)
	{
		bpf_err("no filter rule specified");
		return;
	}

	rule = *tmp;
}

static bool ipv6_zero(const struct in6_addr *ip)
{
	u32 *a = (u32 *)ip;
	u32 mem_sz = sizeof(*ip) / sizeof(*a);

	for (u32 i = 0; i < mem_sz; i++)
	{
		if (a[i] != 0)
		{
			return false;
		}
	}
	return true;
}

static bool rule_match(const struct BpfData *log)
{
	bool ret = false;

	// if process comm exists, it means pkg comes from process layer
	if (rule.uid != -1 && log->uid != rule.uid)
	{
		DEBUG(0, "uid not match: %d %d", log->uid, rule.uid);
		return false;
	}

	ret = (rule.lport == 0 ||
		   (rule.lport <= log->lport && log->lport <= rule.lport_end)) &&
		  (rule.rport == 0 ||
		   (rule.rport <= log->rport && log->rport <= rule.rport_end));

	if (!ret)
	{
		DEBUG(0, "filtered by port: %d %d", log->uid, rule.uid);
		return ret;
	}

	if (log->log_type == LOG_UDP_IPV4 || log->log_type == LOG_TCP_IPV4)
	{
		ret = (rule.lip == 0 ||
			   (rule.lip <= log->lip && log->lip <= rule.lip_end)) &&
			  (rule.rip == 0 ||
			   (rule.rip <= log->rip && log->rip <= rule.rip_end));
	}
	else
	{
		ret = (ipv6_zero(&rule.lipv6) ||
			   (ipv6_cmp(&rule.lipv6, &log->lipv6) <= 0 &&
				ipv6_cmp(&log->lipv6, &rule.lipv6_end) <= 0)) &&
			  (ipv6_zero(&rule.ripv6) ||
			   (ipv6_cmp(&rule.ripv6, &log->ripv6) <= 0 &&
				ipv6_cmp(&log->ripv6, &rule.ripv6_end) <= 0));
	}

	return ret;
}

static clock_t to_clock(jiffy_t x)
{
	// Nanosecond Per Hz of systemtick timer.
	u64 nph;
	// user nph
	u64 unph;
	nph = (NSEC_PER_SEC + CONFIG_HZ / 2) / CONFIG_HZ;
	unph = NSEC_PER_SEC / USER_HZ;

	if ((nph % unph) == 0)
	{
		if (CONFIG_HZ < USER_HZ)
		{
			return x * (USER_HZ / CONFIG_HZ);
		}
		else
		{
			return x / (CONFIG_HZ / USER_HZ);
		}
	}
	return x * nph / unph;
}

static clock_t to_clock_safe(long jiffies)
{
	if (jiffies <= 0)
	{
		return 0;
	}

	return to_clock(jiffies);
}

static int timer_pending(const struct timer_list *timer)
{
	const struct hlist_node *h;
	h = &timer->entry;
	return !(h->pprev);
}

#define ICSK_TIME_RETRANS 1
#define ICSK_TIME_PROBE0 3
#define ICSK_TIME_LOSS_PROBE 5
#define ICSK_TIME_REO_TIMEOUT 6

#define TCP_INFINITE_SSTHRESH 0x7fffffff
#define TCP_PINGPONG_THRESH 3

static u64 sock_ino(const struct sock *sk)
{
	const struct socket *sk_socket;
	const struct inode *inode;
	struct socket_alloc *ska;
	u64 ino;

	sk_socket = sk->sk_socket;
	if (!sk_socket)
	{
		bpf_warn("no socket handle found");
		return 0;
	}

	ska = container_of(sk_socket, struct socket_alloc, socket);
	inode = &ska->vfs_inode;
	bpf_read_kmem_ret(&ino, &inode->i_ino, return 0);
	return ino;
}

#ifndef BUILTIN
static bool pingpong_mode(const struct inet_connection_sock *icsk)
{
	return icsk->icsk_ack.pingpong >= TCP_PINGPONG_THRESH;
}

static bool initial_slowstart(const struct tcp_sock *tcp)
{
	return tcp->snd_ssthresh >= TCP_INFINITE_SSTHRESH;
}

static int dump_tcp_normal(
	struct seq_file *seq,
	struct tcp_sock *ts,
	uid_t uid,
	u32 seq_num,
	struct BpfData *log
)
{
	const struct inet_connection_sock *icsk;
	const struct fastopen_queue *fastopenq;
	const struct inet_sock *inet;
	unsigned long timer_expires;
	const struct sock *sp;
	u16 rport, lport;
	__be32 rip, lip;
	int timer_active;
	int rx_queue;
	int state;

	icsk = &ts->inet_conn;
	inet = &icsk->icsk_inet;
	sp = &inet->sk;
	fastopenq = &icsk->icsk_accept_queue.fastopenq;

	rip = inet->inet_daddr;
	lip = inet->inet_rcv_saddr;
	rport = bpf_ntohs(inet->inet_dport);
	lport = bpf_ntohs(inet->inet_sport);

	switch (icsk->icsk_pending)
	{
	case ICSK_TIME_RETRANS:
	case ICSK_TIME_REO_TIMEOUT:
	case ICSK_TIME_LOSS_PROBE:
		timer_active = 1;
		timer_expires = icsk->icsk_timeout;
		break;
	case ICSK_TIME_PROBE0:
		timer_active = 4;
		timer_expires = icsk->icsk_timeout;
		break;
	default:
		if (timer_pending(&sp->sk_timer))
		{
			timer_active = 2;
			timer_expires = sp->sk_timer.expires;
		}
		else
		{
			timer_active = 0;
			timer_expires = bpf_jiffies64();
		}
		break;
	}

	state = sp->sk_state;
	if (state == TCP_LISTEN)
	{
		rx_queue = sp->sk_ack_backlog;
	}
	else
	{
		rx_queue = ts->rcv_nxt - ts->copied_seq;
		if (rx_queue < 0)
		{
			rx_queue = 0;
		}
	}

	log->log_type = LOG_TCP_IPV4;
	log->lip = lip;
	log->lport = lport;
	log->rip = rip;
	log->rport = rport;
	log->state = state;
	log->tx_queue = ts->write_seq - ts->snd_una;
	log->rx_queue = rx_queue;
	log->tr = timer_active;
	log->tm_when = to_clock_safe(timer_expires - bpf_jiffies64());
	log->retrnsmt = icsk->icsk_retransmits;
	log->uid = uid;
	log->timeout = icsk->icsk_probes_out;
	log->ino = sock_ino(sp);
	log->sk_ref = sp->sk_refcnt.refs.counter;
	BPF_SNPRINTF(log->sk_addr, sizeof(log->sk_addr), "%pK", ts);
	log->icsk_rto = to_clock(icsk->icsk_rto);
	log->icsk_ack = to_clock(icsk->icsk_ack.ato);
	log->bit_flags = (icsk->icsk_ack.quick << 1) | pingpong_mode(icsk);
	log->snd_cwnd = ts->snd_cwnd;

	if (state == TCP_LISTEN)
	{
		log->ssthresh = fastopenq->max_qlen;
	}
	else if (initial_slowstart(ts))
	{
		log->ssthresh = -1;
	}
	else
	{
		log->ssthresh = ts->snd_ssthresh;
	}

	if (!rule_match(log))
	{
		return -1;
	}

#if ITER_PASS_STRING == 1

	BPF_SEQ_PRINTF(
		seq,
		"%4d: %08X:%04X %08X:%04X ",
		seq_num,
		lip,
		lport,
		rip,
		rport
	);
	BPF_SEQ_PRINTF(
		seq,
		"%02X %08X:%08X %02X:%08lX %08X %5u %8d %lu %d ",
		state,
		log->tx_queue,
		rx_queue,
		timer_active,
		log->tm_when,
		log->retrnsmt,
		uid,
		log->timeout,
		log->ino,
		log->sk_ref
	);
	BPF_SEQ_PRINTF(
		seq,
		"%pK %lu %lu %u %u %d\n",
		ts,
		log->icsk_rto,
		log->icsk_ack,
		log->bit_flags,
		ts->snd_cwnd,
		log->ssthresh
	);
#endif

	return 0;
}

static int dump_tcp_timewait(
	struct seq_file *seq,
	struct tcp_timewait_sock *tws,
	uid_t uid,
	u32 seq_num,
	struct BpfData *log
)
{
	struct inet_timewait_sock *itws;
	u16 rport, lport;
	__be32 rip, lip;
	long expires_left;

	itws = &tws->tw_sk;
	expires_left = itws->tw_timer.expires - bpf_jiffies64();
	rip = itws->tw_daddr;
	lip = itws->tw_rcv_saddr;
	rport = bpf_ntohs(itws->tw_dport);
	lport = bpf_ntohs(itws->tw_sport);

	log->log_type = LOG_TCP_IPV4;
	log->lip = lip;
	log->lport = lport;
	log->rip = rip;
	log->rport = rport;
	log->state = itws->tw_substate;
	log->tx_queue = 0;
	log->rx_queue = 0;
	log->tr = 3;
	log->tm_when = to_clock_safe(expires_left);
	log->retrnsmt = 0;
	log->uid = 0;
	log->timeout = 0;
	log->ino = 0;
	log->sk_ref = itws->tw_refcnt.refs.counter;
	BPF_SNPRINTF(log->sk_addr, sizeof(log->sk_addr), "%pK", itws);
	log->icsk_rto = 0;
	log->icsk_ack = 0;
	log->bit_flags = 0;
	log->snd_cwnd = 0;

	if (!rule_match(log))
	{
		return -1;
	}

#if ITER_PASS_STRING == 1
	BPF_SEQ_PRINTF(
		seq,
		"%4d: %08X:%04X %08X:%04X ",
		seq_num,
		lip,
		lport,
		rip,
		rport
	);

	BPF_SEQ_PRINTF(
		seq,
		"%02X %08X:%08X %02X:%08lX %08X %5d %8d %d %d %pK\n",
		log->state,
		0,
		0,
		3,
		log->tm_when,
		0,
		0,
		0,
		0,
		log->sk_ref,
		itws
	);
#endif

	return 0;
}

static int dump_tcp_request(
	struct seq_file *seq,
	struct tcp_request_sock *treq,
	uid_t uid,
	u32 seq_num,
	struct BpfData *log
)
{
	struct inet_request_sock *irsk;
	struct request_sock *req;
	long expires_left;

	irsk = &treq->req;
	req = &irsk->req;
	expires_left = req->rsk_timer.expires - bpf_jiffies64();

	if (expires_left < 0)
	{
		expires_left = 0;
	}

	log->log_type = LOG_TCP_IPV4;
	log->lip = irsk->ir_loc_addr;
	log->lport = irsk->ir_num;
	log->rip = irsk->ir_rmt_addr;
	log->rport = bpf_ntohs(irsk->ir_rmt_port);
	log->state = TCP_SYN_RECV;
	log->tx_queue = 0;
	log->rx_queue = 0;
	log->tr = 1;
	log->tm_when = to_clock(expires_left);
	log->retrnsmt = req->num_timeout;
	log->uid = uid;
	log->timeout = 0;
	log->ino = 0;
	log->sk_ref = 0;
	BPF_SNPRINTF(log->sk_addr, sizeof(log->sk_addr), "%pK", req);
	log->icsk_rto = 0;
	log->icsk_ack = 0;
	log->bit_flags = 0;
	log->snd_cwnd = 0;

	if (!rule_match(log))
	{
		return -1;
	}

#if ITER_PASS_STRING
	BPF_SEQ_PRINTF(
		seq,
		"%4d: %08X:%04X %08X:%04X ",
		seq_num,
		log->lip,
		log->lport,
		log->rip,
		log->rport
	);
	BPF_SEQ_PRINTF(
		seq,
		"%02X %08X:%08X %02X:%08lX %08X %5d %8d %d %d %pK\n",
		TCP_SYN_RECV,
		0,
		0,
		1,
		log->tm_when,
		log->retrnsmt,
		uid,
		0,
		0,
		0,
		req
	);
#endif

	return 0;
}

static int dump_tcp6_normal(
	struct seq_file *seq,
	struct tcp6_sock *ts,
	uid_t uid,
	u32 seq_num,
	struct BpfData *log
)
{
	const struct inet_connection_sock *icsk;
	const struct fastopen_queue *fastopenq;
	const struct in6_addr *dest, *src;
	const struct inet_sock *inet;
	unsigned long timer_expires;
	const struct sock *sp;
	int timer_active;
	int rx_queue;
	int state;

	icsk = &ts->tcp.inet_conn;
	inet = &icsk->icsk_inet;
	sp = &inet->sk;
	fastopenq = &icsk->icsk_accept_queue.fastopenq;

	dest = &sp->sk_v6_daddr;
	src = &sp->sk_v6_rcv_saddr;

	if (icsk->icsk_pending == ICSK_TIME_RETRANS ||
		icsk->icsk_pending == ICSK_TIME_REO_TIMEOUT ||
		icsk->icsk_pending == ICSK_TIME_LOSS_PROBE)
	{
		timer_active = 1;
		timer_expires = icsk->icsk_timeout;
	}
	else if (icsk->icsk_pending == ICSK_TIME_PROBE0)
	{
		timer_active = 4;
		timer_expires = icsk->icsk_timeout;
	}
	else if (timer_pending(&sp->sk_timer))
	{
		timer_active = 2;
		timer_expires = sp->sk_timer.expires;
	}
	else
	{
		timer_active = 0;
		timer_expires = bpf_jiffies64();
	}

	state = sp->sk_state;
	if (state == TCP_LISTEN)
	{
		rx_queue = sp->sk_ack_backlog;
	}
	else
	{
		rx_queue = ts->tcp.rcv_nxt - ts->tcp.copied_seq;
		if (rx_queue < 0)
		{
			rx_queue = 0;
		}
	}

	log->log_type = LOG_TCP_IPV6;
	log->lipv6 = *src;
	log->lport = bpf_ntohs(inet->inet_sport);
	log->ripv6 = *dest;
	log->rport = bpf_ntohs(inet->inet_dport);
	log->state = state;
	log->tx_queue = ts->tcp.write_seq - ts->tcp.snd_una;
	log->rx_queue = rx_queue;
	log->tr = timer_active;
	log->tm_when = to_clock_safe(timer_expires - bpf_jiffies64());
	log->retrnsmt = icsk->icsk_retransmits;
	log->uid = uid;
	log->timeout = icsk->icsk_probes_out;
	log->ino = sock_ino(sp);
	log->sk_ref = sp->sk_refcnt.refs.counter;
	BPF_SNPRINTF(log->sk_addr, sizeof(log->sk_addr), "%pK", ts);
	log->icsk_rto = to_clock(icsk->icsk_rto);
	log->icsk_ack = to_clock(icsk->icsk_ack.ato);
	log->bit_flags = (icsk->icsk_ack.quick << 1) | pingpong_mode(icsk);
	log->snd_cwnd = ts->tcp.snd_cwnd;

	if (state == TCP_LISTEN)
	{
		log->ssthresh = fastopenq->max_qlen;
	}
	else if (initial_slowstart(&ts->tcp))
	{
		log->ssthresh = -1;
	}
	else
	{
		log->ssthresh = ts->tcp.snd_ssthresh;
	}

	if (!rule_match(log))
	{
		return -1;
	}
#if ITER_PASS_STRING == 1
	BPF_SEQ_PRINTF(
		seq,
		"%4d: %08X%08X%08X%08X:%04X %08X%08X%08X%08X:%04X ",
		seq_num,
		src->s6_addr32[0],
		src->s6_addr32[1],
		src->s6_addr32[2],
		src->s6_addr32[3],
		log->lport,
		dest->s6_addr32[0],
		dest->s6_addr32[1],
		dest->s6_addr32[2],
		dest->s6_addr32[3],
		log->rport
	);
	BPF_SEQ_PRINTF(
		seq,
		"%02X %08X:%08X %02X:%08lX %08X %5u %8d %lu %d ",
		state,
		log->tx_queue,
		rx_queue,
		log->tr,
		log->tm_when,
		log->retrnsmt,
		uid,
		log->timeout,
		log->ino,
		log->sk_ref
	);
	BPF_SEQ_PRINTF(
		seq,
		"%pK %lu %lu %u %u %d\n",
		ts,
		log->icsk_rto,
		log->icsk_ack,
		log->bit_flags,
		log->snd_cwnd,
		log->ssthresh
	);
#endif

	return 0;
}

static int dump_tcp6_timewait(
	struct seq_file *seq,
	struct tcp_timewait_sock *ttw,
	uid_t uid,
	u32 seq_num,
	struct BpfData *log
)
{
	struct inet_timewait_sock *tw = &ttw->tw_sk;
	const struct in6_addr *dest, *src;
	long delta;

	delta = tw->tw_timer.expires - bpf_jiffies64();
	dest = &tw->tw_v6_daddr;
	src = &tw->tw_v6_rcv_saddr;

	log->log_type = LOG_TCP_IPV6;
	log->lipv6 = *src;
	log->lport = bpf_ntohs(tw->tw_sport);
	log->ripv6 = *dest;
	log->rport = bpf_ntohs(tw->tw_dport);
	log->state = tw->tw_substate;
	log->tx_queue = 0;
	log->rx_queue = 0;
	log->tr = 3;
	log->tm_when = to_clock_safe(delta);
	log->retrnsmt = 0;
	log->uid = 0;
	log->timeout = 0;
	log->ino = 0;
	log->sk_ref = tw->tw_refcnt.refs.counter;
	BPF_SNPRINTF(log->sk_addr, sizeof(log->sk_addr), "%pK", tw);
	log->icsk_rto = 0;
	log->icsk_ack = 0;
	log->bit_flags = 0;
	log->snd_cwnd = 0;

	if (!rule_match(log))
	{
		return -1;
	}

#if ITER_PASS_STRING == 1
	BPF_SEQ_PRINTF(
		seq,
		"%4d: %08X%08X%08X%08X:%04X %08X%08X%08X%08X:%04X ",
		seq_num,
		src->s6_addr32[0],
		src->s6_addr32[1],
		src->s6_addr32[2],
		src->s6_addr32[3],
		log->lport,
		dest->s6_addr32[0],
		dest->s6_addr32[1],
		dest->s6_addr32[2],
		dest->s6_addr32[3],
		log->rport
	);

	BPF_SEQ_PRINTF(
		seq,
		"%02X %08X:%08X %02X:%08lX %08X %5d %8d %d %d %pK\n",
		tw->tw_substate,
		0,
		0,
		3,
		log->tm_when,
		0,
		0,
		0,
		0,
		tw->tw_refcnt.refs.counter,
		tw
	);
#endif
	return 0;
}

static int dump_tcp6_request(
	struct seq_file *seq,
	struct tcp_request_sock *treq,
	uid_t uid,
	u32 seq_num,
	struct BpfData *log
)
{
	struct inet_request_sock *irsk = &treq->req;
	struct request_sock *req = &irsk->req;
	struct in6_addr *src, *dest;
	long expires_left;

	expires_left = req->rsk_timer.expires - bpf_jiffies64();
	src = &irsk->ir_v6_loc_addr;
	dest = &irsk->ir_v6_rmt_addr;

	if (expires_left < 0)
	{
		expires_left = 0;
	}

	log->log_type = LOG_TCP_IPV6;
	log->lipv6 = *src;
	log->lport = irsk->ir_num;
	log->ripv6 = *dest;
	log->rport = bpf_ntohs(irsk->ir_rmt_port);
	log->state = TCP_SYN_RECV;
	log->tx_queue = 0;
	log->rx_queue = 0;
	log->tr = 1;
	log->tm_when = to_clock(expires_left);
	log->retrnsmt = req->num_timeout;
	log->uid = uid;
	log->timeout = 0;
	log->ino = 0;
	log->sk_ref = 0;
	BPF_SNPRINTF(log->sk_addr, sizeof(log->sk_addr), "%pK", req);
	log->icsk_rto = 0;
	log->icsk_ack = 0;
	log->bit_flags = 0;
	log->snd_cwnd = 0;

	if (!rule_match(log))
	{
		return -1;
	}

#if ITER_PASS_STRING == 1
	BPF_SEQ_PRINTF(
		seq,
		"%4d: %08X%08X%08X%08X:%04X %08X%08X%08X%08X:%04X ",
		seq_num,
		src->s6_addr32[0],
		src->s6_addr32[1],
		src->s6_addr32[2],
		src->s6_addr32[3],
		log->lport,
		dest->s6_addr32[0],
		dest->s6_addr32[1],
		dest->s6_addr32[2],
		dest->s6_addr32[3],
		log->rport
	);
	BPF_SEQ_PRINTF(
		seq,
		"%02X %08X:%08X %02X:%08lX %08X %5d %8d %d %d %pK\n",
		TCP_SYN_RECV,
		0,
		0,
		1,
		log->tm_when,
		log->retrnsmt,
		uid,
		0,
		0,
		0,
		req
	);
#endif
	return 0;
}

SEC("iter/tcp")
int dump_tcp(struct bpf_iter__tcp *ctx)
{
	long ret = -1;
	struct sock_common *sk_common;
	struct seq_file *seq;
	struct tcp_timewait_sock *itws;
	struct tcp_request_sock *req;
	struct tcp_sock *ts;
	struct tcp_timewait_sock *itws6;
	struct tcp_request_sock *req6;
	struct tcp6_sock *ts6;
	uid_t uid;
	u32 seq_num;
	struct BpfData log;

	get_rule();
	if (!(rule.bit_switch & SWITCH_TCP))
	{
		return 0;
	}

	sk_common = ctx->sk_common;
	seq = ctx->meta->seq;
	uid = ctx->uid;

	if (sk_common == NULL)
	{
		return 0;
	}

	seq_num = ctx->meta->seq_num;

	switch (sk_common->skc_family)
	{
	case PF_INET:
		if (!(rule.bit_switch & SWITCH_IPV4))
		{
			break;
		}
#if ITER_PASS_STRING
		if (seq_num == 0)
		{
			BPF_SEQ_PRINTF(seq, "%s\n", tcp_titles);
		}
#endif
		ts = bpf_skc_to_tcp_sock(sk_common);
		if (ts)
		{
			DEBUG(0, "normal tcp socket dump");
			ret = dump_tcp_normal(seq, ts, uid, seq_num, &log);
			break;
		}

		itws = bpf_skc_to_tcp_timewait_sock(sk_common);
		if (itws)
		{
			DEBUG(0, "timewait tcp socket dump");
			ret = dump_tcp_timewait(seq, itws, uid, seq_num, &log);
			break;
		}

		req = bpf_skc_to_tcp_request_sock(sk_common);
		if (req)
		{
			DEBUG(0, "request tcp socket dump");
			ret = dump_tcp_request(seq, req, uid, seq_num, &log);
			break;
		}
		break;
	case PF_INET6:
		if (!(rule.bit_switch & SWITCH_IPV6))
		{
			break;
		}
#if ITER_PASS_STRING
		if (seq_num == 0)
		{
			BPF_SEQ_PRINTF(seq, "%s\n", tcp6_titles);
		}
#endif
		ts6 = bpf_skc_to_tcp6_sock(sk_common);
		if (ts6)
		{
			DEBUG(0, "normal tcp6 socket dump");
			ret = dump_tcp6_normal(seq, ts6, uid, seq_num, &log);
			break;
		}

		itws6 = bpf_skc_to_tcp_timewait_sock(sk_common);
		if (itws6)
		{
			DEBUG(0, "timewait tcp6 socket dump");
			ret = dump_tcp6_timewait(seq, itws6, uid, seq_num, &log);
			break;
		}

		req6 = bpf_skc_to_tcp_request_sock(sk_common);
		if (req6)
		{
			DEBUG(0, "request tcp6 socket dump");
			ret = dump_tcp6_request(seq, req6, uid, seq_num, &log);
			break;
		}
		break;
	default:
		return 0;
	}

#if !ITER_PASS_STRING
	if (ret == 0)
	{
		DEBUG(0, "tcp log size: %d", sizeof(log));
		ret = bpf_seq_write(seq, &log, sizeof(log));
		if (ret)
		{
			bpf_err("bpf_seq_write: %d", ret);
		}
	}
#else
	// suppress warning
	(void)ret;
#endif

	return 0;
}

static int dump_udp_normal(struct bpf_iter__udp *ctx, struct BpfData *log)
{
	struct udp_sock *udp_sk;
	struct inet_sock *inet;
	u16 lport, rport;
	__be32 rip, lip;
	int rqueue;

	udp_sk = ctx->udp_sk;
	if (udp_sk == NULL)
	{
		return -1;
	}

	/* filter out udp4 sockets */
	inet = &udp_sk->inet;
	if (inet->sk.sk_family != PF_INET)
	{
		return -1;
	}

	rip = inet->inet_daddr;
	lip = inet->inet_rcv_saddr;
	lport = bpf_ntohs(inet->inet_sport);
	rport = bpf_ntohs(inet->inet_dport);
	rqueue = inet->sk.sk_rmem_alloc.counter - udp_sk->forward_deficit;
	DEBUG(0, "%d %p %p %d", lport + rport, lip, rip, rqueue);

	log->log_type = LOG_UDP_IPV4;
	log->lip = lip;
	log->lport = lport;
	log->rip = rip;
	log->rport = rport;
	log->state = inet->sk.sk_state;
	log->tx_queue = inet->sk.sk_wmem_alloc.refs.counter - 1;
	log->rx_queue = rqueue;
	log->tr = 0;
	log->tm_when = 0;
	log->retrnsmt = 0;
	log->uid = ctx->uid;
	log->timeout = 0;
	log->ino = sock_ino(&inet->sk);
	log->sk_ref = inet->sk.sk_refcnt.refs.counter;
	BPF_SNPRINTF(log->sk_addr, sizeof(log->sk_addr), "%pK", udp_sk);
	log->icsk_rto = inet->sk.sk_drops.counter;
	log->icsk_ack = 0;
	log->bit_flags = 0;
	log->snd_cwnd = 0;

	if (!rule_match(log))
	{
		return -1;
	}

#if ITER_PASS_STRING
	struct seq_file *seq;
	u32 seq_num;
	seq = ctx->meta->seq;
	seq_num = ctx->meta->seq_num;
	if (seq_num == 0)
	{
		BPF_SEQ_PRINTF(seq, "%s\n", udp_titles);
	}
	BPF_SEQ_PRINTF(
		seq,
		"%5d: %08X:%04X %08X:%04X ",
		ctx->bucket,
		lip,
		lport,
		rip,
		rport
	);

	BPF_SEQ_PRINTF(
		seq,
		"%02X %08X:%08X %02X:%08lX %08X %5u %8d %lu %d %pK %u\n",
		inet->sk.sk_state,
		log->tx_queue,
		rqueue,
		0,
		0L,
		0,
		ctx->uid,
		0,
		log->ino,
		inet->sk.sk_refcnt.refs.counter,
		udp_sk,
		log->icsk_rto
	);
#endif
	return 0;
}

static int dump_udp6_normal(struct bpf_iter__udp *ctx, struct BpfData *log)
{
	struct udp_sock *udp_sk;
	const struct in6_addr *rip, *lip;
	struct udp6_sock *udp6_sk;
	struct inet_sock *inet;
	u16 lport, rport;
	int rqueue;

	udp_sk = ctx->udp_sk;
	if (udp_sk == NULL)
	{
		return -1;
	}

	inet = &udp_sk->inet;
	if (inet->sk.sk_family != PF_INET6)
	{
		return -1;
	}

	udp6_sk = bpf_skc_to_udp6_sock(udp_sk);
	if (udp6_sk == NULL)
	{
		return -1;
	}

	rip = &inet->sk.sk_v6_daddr;
	lip = &inet->sk.sk_v6_rcv_saddr;
	lport = bpf_ntohs(inet->inet_sport);
	rport = bpf_ntohs(inet->inet_dport);
	rqueue = inet->sk.sk_rmem_alloc.counter - udp_sk->forward_deficit;
	DEBUG(0, "%d %p %p %d", lport + rport, lip, rip, rqueue);

	log->log_type = LOG_UDP_IPV6;
	log->lipv6 = *lip;
	log->lport = lport;
	log->ripv6 = *rip;
	log->rport = rport;
	log->state = inet->sk.sk_state;
	log->tx_queue = inet->sk.sk_wmem_alloc.refs.counter - 1;
	log->rx_queue = rqueue;
	log->tr = 0;
	log->tm_when = 0;
	log->retrnsmt = 0;
	log->uid = ctx->uid;
	log->timeout = 0;
	log->ino = sock_ino(&inet->sk);
	log->sk_ref = inet->sk.sk_refcnt.refs.counter;
	BPF_SNPRINTF(log->sk_addr, sizeof(log->sk_addr), "%pK", udp_sk);
	log->icsk_rto = inet->sk.sk_drops.counter;
	log->icsk_ack = 0;
	log->bit_flags = 0;
	log->snd_cwnd = 0;

	if (!rule_match(log))
	{
		return -1;
	}

#if ITER_PASS_STRING
	struct seq_file *seq;
	u32 seq_num;
	seq = ctx->meta->seq;
	seq_num = ctx->meta->seq_num;
	if (seq_num == 0)
	{
		BPF_SEQ_PRINTF(seq, "%s\n", udp6_titles);
	}
	BPF_SEQ_PRINTF(
		seq,
		"%5d: %08X%08X%08X%08X:%04X %08X%08X%08X%08X:%04X ",
		ctx->bucket,
		lip->s6_addr32[0],
		lip->s6_addr32[1],
		lip->s6_addr32[2],
		lip->s6_addr32[3],
		lport,
		rip->s6_addr32[0],
		rip->s6_addr32[1],
		rip->s6_addr32[2],
		rip->s6_addr32[3],
		rport
	);

	BPF_SEQ_PRINTF(
		seq,
		"%02X %08X:%08X %02X:%08lX %08X %5u %8d %lu %d %pK %u\n",
		inet->sk.sk_state,
		log->tx_queue,
		rqueue,
		0,
		0L,
		0,
		ctx->uid,
		0,
		log->ino,
		log->sk_ref,
		udp_sk,
		log->icsk_rto
	);
#endif
	return 0;
}

SEC("iter/udp")
int dump_udp(struct bpf_iter__udp *ctx)
{
	long ret = 0;
	get_rule();
	if (!(rule.bit_switch & SWITCH_UDP))
	{
		return 0;
	}
	struct BpfData log;
	do
	{
		if (rule.bit_switch & SWITCH_IPV4)
		{
			ret = dump_udp_normal(ctx, &log);
			if (ret == 0)
			{
				break;
			}
		}
		if (rule.bit_switch & SWITCH_IPV6)
		{
			ret = dump_udp6_normal(ctx, &log);
			if (ret == 0)
			{
				break;
			}
		}
		return 0;
	} while (0);

#if !ITER_PASS_STRING
	struct seq_file *seq;
	seq = ctx->meta->seq;
	ret = bpf_seq_write(seq, &log, sizeof(log));
	if (ret)
	{
		bpf_err("bpf_seq_write: %d", ret);
	}
#endif
	return 0;
}

static int dump_unix_normal(struct bpf_iter__unix *ctx, struct BpfData *log)
{
	struct unix_sock *unix_sk = ctx->unix_sk;
	struct sock *sk = (struct sock *)unix_sk;
	const char *path = NULL;
	u64 len = 0;
	int state;

	if (!unix_sk)
	{
		return -1;
	}

	state = sk->sk_state;

	log->log_type = LOG_UNIX;
	log->lipv6 = (struct in6_addr){0};
	log->lport = 0;
	log->ripv6 = (struct in6_addr){0};
	log->rport = 0;
	log->state =
		sk->sk_socket
			? (state == TCP_ESTABLISHED ? SS_CONNECTED : SS_UNCONNECTED)
			: (state == TCP_ESTABLISHED ? SS_CONNECTING : SS_DISCONNECTING);
	log->tx_queue = 0;
	log->rx_queue = 0;
	log->tr = 0;
	log->retrnsmt = 0;
	log->uid = ctx->uid;
	log->timeout = 0;
	log->ino = sock_ino(sk);
	log->sk_ref = sk->sk_refcnt.refs.counter;
	BPF_SNPRINTF(log->sk_addr, sizeof(log->sk_addr), "%pK", unix_sk);
	log->icsk_rto = 0;
	log->icsk_ack = 0;
	log->bit_flags = state == TCP_LISTEN ? __SO_ACCEPTCON : 0;
	log->snd_cwnd = 0;
	if (unix_sk->addr)
	{
		path = unix_sk->addr->name->sun_path;
		len = unix_sk->addr->len - sizeof(__kernel_sa_family_t);
		if (len > MAX_SK_NAME_LEN)
		{
			len = MAX_SK_NAME_LEN;
		}
		bpf_probe_read_kernel(log->path, len, path);
		log->path[len] = '\0';
	}
	log->plen = len;
	log->sk_type = sk->sk_type;
	DEBUG(0, "%u path: %s", ctx->meta->seq_num, log->path);

	if (!rule_match(log))
	{
		return -1;
	}

#if ITER_PASS_STRING
	struct seq_file *seq;
	u32 seq_num;
	seq = ctx->meta->seq;
	seq_num = ctx->meta->seq_num;
	if (seq_num == 0)
	{
		BPF_SEQ_PRINTF(seq, "%s\n", unix_titles);
	}
	BPF_SEQ_PRINTF(
		seq,
		"%pK: %08X %08X %08X %04X %02X %8lu ",
		unix_sk,
		log->sk_ref,
		0,
		log->bit_flags,
		log->sk_type,
		log->state,
		log->ino
	);

	if (path)
	{
		if (path[0])
		{
			BPF_SEQ_PRINTF(seq, "%s", path);
		}
		else
		{
			/* The name of the abstract UNIX domain socket starts
			 * with '\0' and can contain '\0'.  The null bytes
			 * should be escaped as done in unix_seq_show().
			 */
			len = log->plen;
			BPF_SEQ_PRINTF(seq, "@");
			u64 i;
			for (i = 1; i < len; i++)
			{
				/* unix_validate_addr() tests this upper bound. */
				if (i >= sizeof(struct sockaddr_un))
				{
					break;
				}

				BPF_SEQ_PRINTF(seq, "%c", path[i] ?: '@');
			}
		}
	}

	BPF_SEQ_PRINTF(seq, "\n");
#endif
	return 0;
}

SEC("iter/unix")
int dump_unix(struct bpf_iter__unix *ctx)
{
	long ret;
	char buf[sizeof(struct BpfData) + LOG_PATH_BUF_SIZE]
		__attribute__((aligned(8)));
	struct BpfData *log = (struct BpfData *)buf;
	get_rule();
	if (!(rule.bit_switch & SWITCH_UNX))
	{
		return 0;
	}

	ret = dump_unix_normal(ctx, log);
	if (ret)
	{
		return 0;
	}

#if !ITER_PASS_STRING

	struct seq_file *seq;
	u64 len;
	seq = ctx->meta->seq;
	len = log->plen;
	if (len % 8)
	{ // make sure each peer Log is aligned to 8 bytes
		len += 8 - len % 8;
	}
	if (len > LOG_PATH_BUF_SIZE)
	{
		len = LOG_PATH_BUF_SIZE;
	}
	// debug for memory layout checking
	DEBUG(
		0,
		"len: %lu logtype: %ld %d",
		len,
		(long)&log->log_type - (long)log,
		log->log_type
	);
	ret = bpf_seq_write(seq, log, sizeof(*log) + len);
	if (ret)
	{
		bpf_err("bpf_seq_write: %d", ret);
	}
#endif

	return 0;
}
#endif

struct TaskSock
{
	pid_t pid;
	u32 fd;
	char comm[16];
	u64 ino;
	unsigned int family; // 套接字协议族，例如 AF_INET, AF_INET6 等
	unsigned int type;	 // 套接字类型，例如 SOCK_STREAM, SOCK_DGRAM 等
	unsigned int protocol;
	unsigned int state; // 套接字状态，例如 TCP_ESTABLISHED, TCP_LISTEN 等
	union
	{ // 本地 IP 地址，使用网络字节序
		u32 lip;
		struct in6_addr lipv6;
	};
	union
	{ // 远程 IP 地址，使用网络字节序
		u32 rip;
		struct in6_addr ripv6;
	};
	short lport; // 本地端口
	short rport; // 远端端口
};

SEC("iter/task_file")
int dump_task_ino(struct bpf_iter__task_file *ctx)
{
	struct task_struct *task;
	struct file *file;
	struct inode *ino;
	u32 fd;
	long ret;

	task = ctx->task;
	file = ctx->file;
	fd = ctx->fd;

	if (!task || !file)
	{
		return 0;
	}

	if (task->tgid != task->pid)
	{
		bpf_info("task->tgid: %d task->pid: %d\n", task->tgid, task->pid);
		return 0;
	}

	ino = file->f_inode;
	// filter out socket file descriptor
	if (!S_ISSOCK(ino->i_mode))
	{
		return 0;
	}

	struct socket_alloc *ska;
	struct socket *sock;
	struct sock *sk;
	struct TaskSock ts = {};
	ska = container_of(ino, struct socket_alloc, vfs_inode);
	sock = &ska->socket;
	sk = BPF_CORE_READ(sock, sk);
	if (!sk)
	{
		return 0;
	}

	int sock_state = BPF_CORE_READ(sk, __sk_common.skc_state);
	u16 pf;
	pf = BPF_CORE_READ(sk, __sk_common.skc_family);
	ts.type = BPF_CORE_READ(sk, sk_type);
	ts.protocol = BPF_CORE_READ(sk, sk_protocol);
	ts.family = pf;
	ts.state = sock_state;
	ts.ino = ino->i_ino;
	ts.pid = task->tgid;
	ts.fd = fd;
	legacy_strncpy(ts.comm, task->comm, sizeof(ts.comm));

	if (pf == PF_INET)
	{
		ts.lip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		ts.rip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		ts.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
		ts.rport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	}
	else if (pf == PF_INET6)
	{
		ts.lipv6 = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);
		ts.ripv6 = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
		ts.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
		ts.rport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	}

	DEBUG(
		0,
		"TaskSock: pid=%d comm=%s family=%u type=%u"
		" protocol=%u state=%u lip=%u rip=%u lport=%d rport=%d",
		ts.pid,
		ts.comm,
		ts.family,
		ts.type,
		ts.protocol,
		ts.state,
		ts.lip,
		ts.rip,
		ts.lport,
		ts.rport
	);
	ret = bpf_seq_write(ctx->meta->seq, &ts, sizeof(ts));
	if (ret)
	{
		bpf_err("bpf_seq_write: %d", ret);
	}
	return 0;
}