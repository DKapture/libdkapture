// SPDX-License-Identifier: GPL-2.0

/**
 * @file net-filter.bpf.c
 * @brief 网络过滤器 eBPF 程序
 * 
 * 该文件实现了基于 eBPF 的网络数据包过滤和监控功能，主要用于：
 * - Netfilter 钩子点的数据包过滤
 * - LSM (Linux Security Module) 钩子的进程监控
 * - 网络数据包的深度分析和统计
 * - 实时的网络事件日志记录
 */

#include "vmlinux.h"

#if defined(__sw_64__)
#define bpf_target_sw64
#define bpf_target_defined

/* sw64 provides struct user_pt_regs instead of struct pt_regs to userspace */
#define __PT_PARM1_REG regs[16]
#define __PT_PARM2_REG regs[17]
#define __PT_PARM3_REG regs[18]
#define __PT_PARM4_REG regs[19]
#define __PT_PARM5_REG regs[20]

/* loongarch does not select ARCH_HAS_SYSCALL_WRAPPER. */
#define PT_REGS_SYSCALL_REGS(ctx) ctx
#define __PT_PARM1_SYSCALL_REG __PT_PARM1_REG
#define __PT_PARM2_SYSCALL_REG __PT_PARM2_REG
#define __PT_PARM3_SYSCALL_REG __PT_PARM3_REG
#define __PT_PARM4_SYSCALL_REG __PT_PARM4_REG
#define __PT_PARM5_SYSCALL_REG __PT_PARM5_REG

#define __PT_RET_REG regs[26]
#define __PT_FP_REG regs[15]
#define __PT_RC_REG regs[0]
#define __PT_SP_REG regs[30]
#define __PT_IP_REG pc
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "Kcom.h"
#include "net-filter.h"

#define NF_DROP 0
#define NF_ACCEPT 1
#define NF_STOLEN 2
#define NF_QUEUE 3
#define NF_REPEAT 4
#define NF_STOP 5

#define IPPROTO_ICMPV6 58
#define PF_INET 2	/* IP protocol family.  */
#define PF_INET6 10 /* IP version 6.  */

#if !__x86_64__ && !__arm__ && !__aarch64__ && !__loongarch__ && !__sw_64__
#error                                                                         \
	"net-monitor support only x86 arm loongarch and __sw_64__ four architecture now"
#endif

/**
 * @brief 从内核内存读取数据到BPF内存
 * @param kaddr 内核地址指针
 * @param bpf_addr BPF内存地址
 */
#define bpf_read_mem(kaddr, bpf_addr)                                          \
	bpf_probe_read_kernel(kaddr, sizeof(*(kaddr)), bpf_addr)

/**
 * @brief 从内核内存读取数据到BPF内存，出错时返回指定值
 * @param kaddr 内核地址指针
 * @param bpf_addr BPF内存地址
 * @param ret 出错时的返回值
 */
#define bpf_read_mem_ret(kaddr, bpf_addr, ret)                                 \
	{                                                                          \
		int err = 0;                                                           \
		err = bpf_read_mem(kaddr, bpf_addr);                                   \
		if (err < 0)                                                           \
		{                                                                      \
			bpf_printk(                                                        \
				"error: bpf read kernel"                                       \
				"(%d:%d)\n",                                                   \
				err,                                                           \
				__LINE__                                                       \
			);                                                                 \
			return ret;                                                        \
		}                                                                      \
	}

#if !defined(__sw_64__)
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
#endif

static void
debug_tuple(const struct ip_tuple *tuple, const char *title, int type);

/**
 * @brief 过滤规则映射
 * 存储网络过滤规则，键为规则ID，值为Rule结构体
 */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct Rule);
	__uint(max_entries, MAX_RULES_LEN);
} rules SEC(".maps"); // TODO lock guarded

/**
 * @brief 日志环形缓冲区
 * 用于向用户空间传递网络事件日志
 */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} logs SEC(".maps");

/**
 * @brief 配置映射
 * 存储网络过滤器的全局配置参数
 */
struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct Configs);
} configs SEC(".maps"); // TODO lock guarded

/**
 * @brief Socket映射
 * 存储进程ID到网络数据的映射关系
 */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct BpfData);
	__uint(max_entries, 10000);
} sk_map SEC(".maps");

/**
 * @brief 获取配置结构体指针
 * 从BPF映射中获取全局配置，如果映射为空则返回默认配置
 * @return 配置结构体指针
 */
static inline struct Configs *conf(void)
{
	static struct Configs _configs = {
		.enable = true,
		.debug = DEBUG_NONE,
	};

	int key = 0;
	static struct Configs *pc;
	pc = bpf_map_lookup_elem(&configs, &key);
	if (pc)
	{
		return pc;
	}

	return &_configs;
}

/**
 * @brief 比较两个IPv6地址
 * @param ipa 第一个IPv6地址指针
 * @param ipb 第二个IPv6地址指针
 * @return 0表示相等，1表示ipa>ipb，-1表示ipa<ipb
 */
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

/**
 * @brief 检查IPv6地址是否为零
 * @param ip IPv6地址指针
 * @return true表示为零地址，false表示非零地址
 */
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

#if !defined(__sw_64__)
/**
 * @brief 从socket缓冲区解析IPv4头部
 * @param skb socket缓冲区指针
 * @return IPv4头部指针，失败返回NULL
 */
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
	return p;
}

/**
 * @brief 从socket缓冲区解析IPv6头部
 * @param skb socket缓冲区指针
 * @return IPv6头部指针，失败返回NULL
 */
static struct ipv6hdr *ipv6_hdr(struct sk_buff *skb)
{
	struct bpf_dynptr ptr;
	struct ipv6hdr *p, iph = {};

	if (skb->len <= 40)
	{
		return NULL;
	}

	if (bpf_dynptr_from_skb(skb, 0, &ptr))
	{
		return NULL;
	}

	p = bpf_dynptr_slice(&ptr, 0, &iph, sizeof(iph));
	return p;
}

/**
 * @brief 从socket缓冲区解析TCP头部
 * @param skb socket缓冲区指针
 * @param offset 偏移量
 * @return TCP头部指针，失败返回NULL
 */
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
	return p;
}

/**
 * @brief 从socket缓冲区解析UDP头部
 * @param skb socket缓冲区指针
 * @param offset 偏移量
 * @return UDP头部指针，失败返回NULL
 */
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
	return p;
}

/**
 * @brief 从socket缓冲区解析ICMP头部
 * @param skb socket缓冲区指针
 * @param offset 偏移量
 * @return ICMP头部指针，失败返回NULL
 */
static struct icmphdr *icmp_hdr(struct sk_buff *skb, u32 offset)
{
	struct bpf_dynptr ptr;
	struct icmphdr *p, icmph = {};

	if (skb->len <= offset)
	{
		return NULL;
	}

	if (bpf_dynptr_from_skb(skb, 0, &ptr))
	{
		return NULL;
	}

	p = bpf_dynptr_slice(&ptr, offset, &icmph, sizeof(icmph));
	return p;
}

/**
 * @brief 从socket缓冲区解析ICMPv6头部
 * @param skb socket缓冲区指针
 * @param offset 偏移量
 * @return ICMPv6头部指针，失败返回NULL
 */
static struct icmp6hdr *icmp6_hdr(struct sk_buff *skb, u32 offset)
{
	struct bpf_dynptr ptr;
	struct icmp6hdr *p, icmph = {};

	if (skb->len <= offset)
	{
		return NULL;
	}

	if (bpf_dynptr_from_skb(skb, 0, &ptr))
	{
		return NULL;
	}

	p = bpf_dynptr_slice(&ptr, offset, &icmph, sizeof(icmph));
	return p;
}

/**
 * @brief 解析socket缓冲区数据包
 * 从数据包中提取网络层和传输层信息，填充到BpfData结构体中
 * @param skb socket缓冲区指针
 * @param log 输出的BPF数据结构指针
 * @return true表示解析成功，false表示解析失败
 */
static bool parse_sk_buff(struct sk_buff *skb, struct BpfData *log)
{
	struct iphdr *iph;
	struct ipv6hdr *ipv6h;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmphdr *icmph;
	struct icmp6hdr *icmp6h;
	unsigned int iphl;

	u16 ip_proto = bpf_ntohs(skb->protocol);

	switch (ip_proto)
	{
	case ETH_P_IP:
		iph = ip_hdr(skb);
		if (!iph)
		{
			return false;
		}
		if (iph->saddr == iph->daddr)
		{
			return false;
		}
		iphl = iph->ihl * 4;
		log->tuple.ip_proto = 4; // ipv4
		log->tuple.tl_proto = iph->protocol;
		log->tuple.sip = bpf_ntohl(iph->saddr);
		log->tuple.dip = bpf_ntohl(iph->daddr);
		break;
	case ETH_P_IPV6:
		ipv6h = ipv6_hdr(skb);
		if (!ipv6h)
		{
			return false;
		}
		if (ipv6_cmp(&ipv6h->saddr, &ipv6h->daddr) == 0)
		{
			return false;
		}
		iphl = 40;
		log->tuple.ip_proto = 6; // ipv6
		log->tuple.tl_proto = ipv6h->nexthdr;
		log->tuple.sipv6 = ipv6h->saddr;
		log->tuple.dipv6 = ipv6h->daddr;
		ntoh16(&log->tuple.sipv6);
		ntoh16(&log->tuple.dipv6);
		log->tuple.comm[0] = 0;
		break;
	default:
		return false;
	}

	struct task_struct *task;
	log->data_len = skb->len - iphl;
	log->tuple.comm[0] = 0;
	task = (struct task_struct *)bpf_get_current_task();
	bpf_read_mem(&log->pid, &task->pid);
	log->timestamp = bpf_ktime_get_boot_ns() / 1000;
	bpf_read_mem(&log->start_time, &task->start_time);

	switch (log->tuple.tl_proto)
	{
	case IPPROTO_TCP:
		tcph = tcp_hdr(skb, iphl);
		if (tcph == NULL)
		{
			return false;
		}
		log->data_len -= tcph->doff;
		log->tuple.sport = bpf_ntohs(tcph->source);
		log->tuple.dport = bpf_ntohs(tcph->dest);
		debug_tuple(&log->tuple, "NF-TCP", DEBUG_NF_TCP_PKG);
		break;
	case IPPROTO_UDP:
		udph = udp_hdr(skb, iphl);
		if (udph == NULL)
		{
			return false;
		}
		log->data_len -= 8;
		log->tuple.sport = bpf_ntohs(udph->source);
		log->tuple.dport = bpf_ntohs(udph->dest);
		debug_tuple(&log->tuple, "NF-UDP", DEBUG_NF_UDP_PKG);
		break;
	case IPPROTO_ICMP:
		icmph = icmp_hdr(skb, iphl);
		if (icmph == NULL)
		{
			return false;
		}
		log->data_len -= 8;
		log->tuple.sport = icmph->un.echo.id;
		log->tuple.dport = icmph->un.echo.id;
		debug_tuple(&log->tuple, "NF-ICMP", DEBUG_NF_ICMP_PKG);
	case IPPROTO_ICMPV6:
		icmp6h = icmp6_hdr(skb, iphl);
		if (icmp6h == NULL)
		{
			return false;
		}
		log->data_len -= 8;
		log->tuple.sport = icmp6h->icmp6_dataun.u_echo.identifier;
		log->tuple.dport = icmp6h->icmp6_dataun.u_echo.identifier;
		debug_tuple(&log->tuple, "NF-ICMPv6", DEBUG_NF_ICMP_PKG);
		break;
	default:
		bpf_printk("Unknown protocol: %d\n", log->tuple.tl_proto);
		return false;
	}

	debug_tuple(&log->tuple, "NF", DEBUG_NF_ALL_PKG);

	return true;
}
#endif

/**
 * @brief 回调上下文结构体
 * 用于在BPF映射回调中传递数据
 */
struct CbCtx
{
	const struct ip_tuple *tuple; ///< IP元组指针
	int action;                   ///< 动作类型
};

/**
 * @brief 字符串比较函数
 * @param s1 第一个字符串
 * @param s2 第二个字符串
 * @param n 比较的字符数
 * @return 0表示相等，非0表示不等
 */
static int strncmp(const char *s1, const char *s2, int n)
{
	for (int i = 0; i < n; i++)
	{
		if (s1[i] != s2[i])
		{
			return s1[i] - s2[i];
		}
		if (s1[i] == 0)
		{
			return 0;
		}
	}
	return 0;
}

/**
 * @brief 检查IP元组是否匹配规则
 * @param t1 待检查的IP元组
 * @param rule 过滤规则
 * @return true表示匹配，false表示不匹配
 */
static bool rule_match(const struct ip_tuple *t1, const struct Rule *rule)
{
	bool ret = false;

	debug_tuple(t1, "rule_match_1", DEBUG_RULE_MATCH);

	if (rule->ip_proto != t1->ip_proto)
	{
		return false;
	}

	if (t1->tl_proto != rule->tl_proto)
	{
		return false;
	}

	if (!(t1->pkg_dir & rule->pkg_dir))
	{
		return false;
	}

	/// 如果进程信息存在，说明数据包来自进程层
	if (t1->comm[0])
	{
		if (!rule->comm[0])
		{
			return false;
		}

		if (strncmp(t1->comm, rule->comm, 16) != 0)
		{
			return false;
		}

		debug_tuple(t1, "rule_match_2", DEBUG_RULE_MATCH);
	}
	else
	{
		if (rule->comm[0])
		{
			return false;
		}
	}

	debug_tuple(t1, "rule_match_3", DEBUG_RULE_MATCH);

	ret = (rule->sport == 0 ||
		   (rule->sport <= t1->sport && t1->sport <= rule->sport_end)) &&
		  (rule->dport == 0 ||
		   (rule->dport <= t1->dport && t1->dport <= rule->dport_end));

	if (!ret)
	{
		return ret;
	}

	debug_tuple(t1, "rule_match_4", DEBUG_RULE_MATCH);

	if (rule->ip_proto == 4)
	{
		ret = (rule->sip == 0 ||
			   (rule->sip <= t1->sip && t1->sip <= rule->sip_end)) &&
			  (rule->dip == 0 ||
			   (rule->dip <= t1->dip && t1->dip <= rule->dip_end));
	}
	else
	{
		ret = (ipv6_zero(&rule->sipv6) ||
			   (ipv6_cmp(&rule->sipv6, &t1->sipv6) <= 0 &&
				ipv6_cmp(&t1->sipv6, &rule->sipv6_end) <= 0)) &&
			  (ipv6_zero(&rule->dipv6) ||
			   (ipv6_cmp(&rule->dipv6, &t1->dipv6) <= 0 &&
				ipv6_cmp(&t1->dipv6, &rule->dipv6_end) <= 0));
	}

	return ret;
}

static void
debug_tuple(const struct ip_tuple *tuple, const char *title, int type)
{
	if (conf()->debug != type)
	{
		return;
	}

	if (tuple->ip_proto == 4)
	{
		bpf_printk(
			"%s: %u.%u.%u.%u:%u %s %u.%u.%u.%u:%u",
			title,
			SLICE_IP(tuple->sip),
			tuple->sport,
			tuple->pkg_dir == PKG_DIR_IN ? "<-" : "->",
			SLICE_IP(tuple->dip),
			tuple->dport
		);
	}
	else
	{
		bpf_printk(
			"%s: src: %x:%x:%x:%x:%x:%x:%x:%x:%u",
			title,
			SLICE_IPv6(tuple->sipv6),
			tuple->sport
		);
		bpf_printk(
			"%s: dst: %x:%x:%x:%x:%x:%x:%x:%x:%u",
			title,
			SLICE_IPv6(tuple->dipv6),
			tuple->dport
		);
	}
}

/**
 * @brief 规则匹配回调函数
 * 在遍历规则映射时被调用，检查每个规则是否匹配
 * @param map BPF映射指针
 * @param key 映射键指针
 * @param value 映射值指针（规则）
 * @param ctx 回调上下文指针
 * @return 0继续遍历，1停止遍历
 */
static long
match_callback(struct bpf_map *map, const void *key, void *value, void *ctx)
{
	struct Rule *rule = (struct Rule *)value;
	struct CbCtx *ctx_ip = (struct CbCtx *)ctx;

	if (!rule_match(ctx_ip->tuple, rule))
	{
		return 0;
	}

	if (rule->action == NM_DROP)
	{
		debug_tuple(ctx_ip->tuple, "rule_match", DEBUG_RULE_MATCH);
	}

	ctx_ip->action = rule->action;

	return 1;
}

/**
 * @brief 检查IP元组是否匹配任何规则
 * @param tuple 待检查的IP元组
 * @return 匹配规则的动作类型
 */
static int rules_match(const struct ip_tuple *tuple)
{
	struct CbCtx ctx = {.tuple = tuple, .action = NM_ACCEPT};

	bpf_for_each_map_elem(&rules, match_callback, &ctx, 0);

	return ctx.action;
}

static bool parse_sock(struct socket *sock, struct BpfData *log);
#define comtainer_of(ptr, type, member)                                        \
	(type *)((char *)ptr - offsetof(type, member))

/**
 * @brief Netfilter钩子函数
 * 在网络数据包经过netfilter框架时被调用，用于分析和过滤数据包
 * @param ctx Netfilter BPF上下文，包含数据包信息和钩子状态
 * @return NF_ACCEPT允许数据包通过，NF_DROP丢弃数据包
 */
SEC("netfilter")
int netfilter_hook(struct bpf_nf_ctx *ctx)
{
	if (!conf()->enable)
	{
		return NF_ACCEPT;
	}

	struct sk_buff *skb = ctx->skb;
	const struct nf_hook_state *state = ctx->state;

	bool ret;
	int action = NM_ACCEPT;
	struct BpfData log;

	if (state->hook == NF_INET_LOCAL_IN)
	{
		log.tuple.pkg_dir = PKG_DIR_IN;
	}
	else
	{
		log.tuple.pkg_dir = PKG_DIR_OUT;
	}

#if defined(__sw_64__)
	struct socket *sock;
	sock = comtainer_of(&skb->sk, struct socket, sk);
	ret = parse_sock(sock, &log);
#else
	ret = parse_sk_buff(skb, &log);
#endif
	if (!ret)
	{
		return NF_ACCEPT;
	}

	action = rules_match(&log.tuple);

	if (action & NM_LOG)
	{
		ret = bpf_ringbuf_output(&logs, &log, sizeof(log), 0);
		if (ret != 0)
		{
			bpf_printk("bpf_map_push_elem: %d\n", ret);
		}
	}

	if (action & NM_DROP)
	{
		return NF_DROP;
	}

	return NF_ACCEPT;
}

static bool parse_sock(struct socket *sock, struct BpfData *log)
{
	struct sock *sk;
	u16 sk_protocol;
	u16 pf;

#if defined(__loongarch__) || defined(__sw_64__)
	/// kprobe无法直接访问内核内存
	bpf_read_mem_ret(&sk, &sock->sk, false);
	if (!sk)
	{
		return false;
	}
	bpf_read_mem_ret(&sk_protocol, &sk->sk_protocol, false);
	bpf_read_mem_ret(&pf, &sk->__sk_common.skc_family, false);
#else
	sk = sock->sk;
	if (!sk)
	{
		return false;
	}
	sk_protocol = sk->sk_protocol;
	pf = sk->__sk_common.skc_family;
#endif

	switch (pf)
	{
	case PF_INET:
	{
		u32 dst_addr;
		u32 src_addr;
#if !defined(__loongarch__) && !defined(__sw_64__)
		dst_addr = bpf_ntohl(sk->__sk_common.skc_daddr);
		src_addr = bpf_ntohl(sk->__sk_common.skc_rcv_saddr);
#else
		bpf_read_mem_ret(&dst_addr, &sk->__sk_common.skc_daddr, false);
		bpf_read_mem_ret(&src_addr, &sk->__sk_common.skc_rcv_saddr, false);
		dst_addr = bpf_ntohl(dst_addr);
		src_addr = bpf_ntohl(src_addr);
#endif

		if (dst_addr == src_addr)
		{
			return false;
		}

		log->tuple.sip = src_addr;
		log->tuple.dip = dst_addr;
		log->tuple.ip_proto = 4;

		break;
	}
	case PF_INET6:
	{
		struct in6_addr dst_addr;
		struct in6_addr src_addr;
#if !defined(__loongarch__) && !defined(__sw_64__)
		dst_addr = sk->__sk_common.skc_v6_daddr;
		src_addr = sk->__sk_common.skc_v6_rcv_saddr;
#else
		bpf_read_mem_ret(&dst_addr, &sk->__sk_common.skc_v6_daddr, false);
		bpf_read_mem_ret(&src_addr, &sk->__sk_common.skc_v6_rcv_saddr, false);
#endif

		if (ipv6_cmp(&src_addr, &dst_addr) == 0)
		{
			return false;
		}

		ntoh16(&dst_addr);
		ntoh16(&src_addr);

		log->tuple.sipv6 = src_addr;
		log->tuple.dipv6 = dst_addr;
		log->tuple.ip_proto = 6;

		break;
	}
	default:
		return false;
	}

#if !defined(__loongarch__) && !defined(__sw_64__)
	log->tuple.sport = sk->__sk_common.skc_num;
	log->tuple.dport = bpf_ntohs(sk->__sk_common.skc_dport);
#else
	bpf_read_mem_ret(&log->tuple.sport, &sk->__sk_common.skc_num, false);
	u16 dport;
	bpf_read_mem_ret(&dport, &sk->__sk_common.skc_dport, false);
	log->tuple.dport = bpf_ntohs(dport);
#endif
	struct task_struct *task;
	log->tuple.tl_proto = sk_protocol;
	task = (struct task_struct *)bpf_get_current_task();
	bpf_read_mem(&log->pid, &task->pid);
	bpf_probe_read_kernel(log->tuple.comm, sizeof(task->comm), task->comm);
	log->timestamp = bpf_ktime_get_boot_ns() / 1000;
	bpf_read_mem(&log->start_time, &task->start_time);

	switch (log->tuple.tl_proto)
	{
	case IPPROTO_TCP:
		debug_tuple(&log->tuple, "LSM-TCP", DEBUG_LSM_TCP_PKG);
		break;
	case IPPROTO_UDP:
		debug_tuple(&log->tuple, "LSM-UDP", DEBUG_LSM_UDP_PKG);
		break;
	case IPPROTO_ICMP:
		debug_tuple(&log->tuple, "LSM-ICMP", DEBUG_LSM_ICMP_PKG);
	case IPPROTO_ICMPV6:
		debug_tuple(&log->tuple, "LSM-ICMPv6", DEBUG_LSM_ICMP_PKG);
		break;
	default:
		break;
	}

	debug_tuple(&log->tuple, "LSM", DEBUG_LSM_ALL_PKG);
	return true;
}

#if !defined(__loongarch__) && !defined(__sw_64__)
/**
 * @brief LSM socket发送消息钩子
 * 在socket发送消息时被调用，用于监控出站网络流量
 * @param sock socket结构体指针
 * @param msg 消息头结构体指针
 * @param size 消息大小
 * @param ret 返回值
 * @return LSM钩子返回值
 */
SEC("lsm/socket_sendmsg")
int BPF_PROG(
	lsm_socket_sendmsg,
	struct socket *sock,
	struct msghdr *msg,
	int size,
	int ret
)
#else
/**
 * loongarch bpf-lsm isn't complete, so kprobe is used instead,
 * as a result, the 'drop' function won't work as kprobe return
 * value is ignored by the bpf subsystem
 */
SEC("kprobe/security_socket_sendmsg")
int BPF_KPROBE(
	k_socket_sendmsg,
	struct socket *sock,
	struct msghdr *msg,
	int size
)
#endif
{
#if !defined(__loongarch__) && !defined(__sw_64__)
	if (ret)
	{
		return ret;
	}
#endif

	if (!conf()->enable)
	{
		return 0;
	}

	int action = NM_ACCEPT;

	struct BpfData log = {.tuple.pkg_dir = PKG_DIR_OUT};

	if (!parse_sock(sock, &log))
	{
		return 0;
	}

	action = rules_match(&log.tuple);
	log.action = action;

	if (action & NM_LOG)
	{
		int ret;
		ret = bpf_map_update_elem(&sk_map, &log.pid, &log, BPF_ANY);
		if (0 != ret)
		{
			bpf_printk("error: bpf_map_update_elem(%d)", ret);
		}
	}

#if !defined(__loongarch__) && !defined(__sw_64__)
	if (action & NM_DROP)
	{
		return -1; // EPERM
	}
#endif

	return 0;
}

#if !defined(__loongarch__) && !defined(__sw_64__)
SEC("lsm/socket_recvmsg")
int BPF_PROG(
	lsm_socket_recvmsg,
	struct socket *sock,
	struct msghdr *msg,
	int size,
	int flags,
	int ret
)
#else
/**
 * loongarch bpf-lsm isn't complete, so kprobe is used instead,
 * as a result, the 'drop' function won't work as kprobe return
 * value is ignored by the bpf subsystem
 */
SEC("kprobe/security_socket_recvmsg")
int BPF_KPROBE(
	k_socket_recvmsg,
	struct socket *sock,
	struct msghdr *msg,
	int size,
	int flags
)
#endif
{
#if !defined(__loongarch__) && !defined(__sw_64__)
	if (ret)
	{
		return ret;
	}
#endif

	if (!conf()->enable)
	{
		return 0;
	}

	int action = NM_ACCEPT;

	struct BpfData log = {.tuple.pkg_dir = PKG_DIR_IN};

	if (!parse_sock(sock, &log))
	{
		return 0;
	}

	/// 对于接收，socket中的地址是反向的
	swap(log.tuple.sport, log.tuple.dport);
	if (log.tuple.ip_proto == 4)
	{
		swap(log.tuple.sip, log.tuple.dip);
	}
	else
	{
		swap(log.tuple.sipv6, log.tuple.dipv6);
	}

	action = rules_match(&log.tuple);
	log.action = action;

	if (action & NM_LOG)
	{
		int ret;
		ret = bpf_map_update_elem(&sk_map, &log.pid, &log, BPF_ANY);
		if (0 != ret)
		{
			bpf_printk("error: bpf_map_update_elem(%d)", ret);
		}
	}

#if !defined(__loongarch__) && !defined(__sw_64__)
	if (action & NM_DROP)
	{
		return -1; // EPERM
	}
#endif

	return 0;
}

/**
 * @brief 统计数据包大小并输出日志
 * @param sz 数据包大小
 * @return 0表示成功，非0表示失败
 */
static int stat_pkg_sz(int sz)
{
	if (!conf()->enable)
	{
		return 0;
	}

	pid_t pid = bpf_get_current_pid_tgid();
	struct BpfData *log = bpf_map_lookup_elem(&sk_map, &pid);
	if (!log)
	{
		return 0;
	}

	if (sz > 0)
	{
		log->data_len = sz;
	}

	int bpf_ret = bpf_ringbuf_output(&logs, log, sizeof(*log), 0);
	if (bpf_ret != 0)
	{
		bpf_printk("bpf_map_push_elem: %d\n", bpf_ret);
	}

	bpf_ret = bpf_map_delete_elem(&sk_map, &pid);
	if (bpf_ret)
	{
		bpf_printk("bpf_map_delete_elem: %d\n", bpf_ret);
	}
	return 0;
}

SEC("kretprobe/__sock_sendmsg")
int BPF_KRETPROBE(kr_sock_sendmsg, int ret)
{
	return stat_pkg_sz(ret);
}

SEC("kretprobe/sock_recvmsg")
int BPF_KRETPROBE(kr_sock_recvmsg, int ret)
{
	return stat_pkg_sz(ret);
}

char _license[] SEC("license") = "GPL";
