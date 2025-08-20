#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// 协议相关宏定义
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_RST 0x04

// 协议类型枚举
enum protocol_type
{
	PROTO_UNKNOWN = 0,
	PROTO_TCP = 1,
	PROTO_UDP = 2,
	PROTO_ICMP = 3
};

enum app_protocol
{
	APP_UNKNOWN = 0,
	APP_HTTP = 1,
	APP_DNS = 2,
	APP_SSH = 3
};

// netif_receive_skb tracepoint参数 (基于实际格式)
struct tp_netif_receive_skb
{
	u64 __unused__;
	void *skbaddr;
	unsigned int len;
	u32 name_loc; // __data_loc for device name
};

// net_dev_queue tracepoint参数
struct tp_net_dev_queue
{
	u64 __unused__;
	void *skbaddr;
	unsigned int len;
	u32 name_loc; // __data_loc for device name
};

// net_dev_xmit tracepoint参数
struct tp_net_dev_xmit
{
	u64 __unused__;
	void *skbaddr;
	unsigned int len;
	int rc;
	u32 name_loc; // __data_loc for device name
};

// net_dev_start_xmit tracepoint参数（复杂格式）
struct tp_net_dev_start_xmit
{
	u64 __unused__;
	u32 name_loc; // __data_loc for device name
	u16 queue_mapping;
	const void *skbaddr;
	bool vlan_tagged;
	u16 vlan_proto;
	u16 vlan_tci;
	u16 protocol;
	u8 ip_summed;
	unsigned int len;
	unsigned int data_len;
	int network_offset;
	bool transport_offset_valid;
	int transport_offset;
	u8 tx_flags;
	u16 gso_size;
	u16 gso_segs;
	u16 gso_type;
};

// 统一事件输出结构体
struct net_event
{
	u64 ts;
	u32 pid;
	u32 tid;
	char comm[16];
	char dev_name[16];
	void *skb_addr;
	u32 len;
	u32 data_len;
	u16 protocol;
	u8 event_type; // 0:queue, 1:start_xmit, 2:xmit, 3:receive
	int return_code;
	u16 queue_id;
	bool vlan_tagged;
	u16 vlan_proto;
	u8 ip_summed;
	u16 gso_size;
	u32 flags;

	// 新增L3层信息
	u8 ip_version;	// 4 or 6
	u32 src_ip;		// IPv4源地址
	u32 dst_ip;		// IPv4目标地址
	u8 ip_protocol; // TCP/UDP/ICMP等
	u8 tos;			// Type of Service
	u8 ttl;			// Time to Live

	// 新增L4层信息
	u16 src_port;	 // 源端口
	u16 dst_port;	 // 目标端口
	u16 tcp_flags;	 // TCP标志位
	u32 seq_num;	 // TCP序列号
	u32 ack_num;	 // TCP确认号
	u16 window_size; // TCP窗口大小
};

// 过滤规则结构体
struct net_rule
{
	pid_t target_pid;
	char target_dev[16];
	char target_comm[16];
	u32 min_len;
	u32 max_len;
	u16 target_protocol;
	bool filter_loopback;
	u8 event_mask; // 位掩码控制监控哪些事件类型
};

// eBPF Map定义
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, void *); // skb_addr作为key
	__type(value, u64);	 // 时间戳
} start_times SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct net_rule);
} rules_map SEC(".maps");

// 辅助函数：简单的字符串比较（eBPF兼容）
static bool strings_equal(const char *s1, const char *s2, int max_len)
{
	for (int i = 0; i < max_len; i++)
	{
		if (s1[i] != s2[i])
		{
			return false;
		}
		if (s1[i] == '\0')
		{
			break;
		}
	}
	return true;
}

// 辅助函数：应用过滤规则
static bool
should_trace(struct net_rule *rule, u32 pid, u32 len, const char *dev_name)
{
	if (rule->target_pid && rule->target_pid != pid)
	{
		return false;
	}

	if (rule->min_len && len < rule->min_len)
	{
		return false;
	}

	if (rule->max_len && len > rule->max_len)
	{
		return false;
	}

	if (rule->target_dev[0] != '\0')
	{
		if (!strings_equal(dev_name, rule->target_dev, 16))
		{
			return false;
		}
	}

	return true;
}

// 辅助函数：解析IP头部信息
static void parse_ip_header(struct sk_buff *skb, struct net_event *event)
{
	// 初始化IP字段
	event->ip_version = 0;
	event->src_ip = 0;
	event->dst_ip = 0;
	event->ip_protocol = 0;
	event->tos = 0;
	event->ttl = 0;

	// 检查是否为IP包
	if (event->protocol != 0x0800) // ETH_P_IP
	{
		return;
	}

	// 获取网络头部偏移
	u32 network_offset = BPF_CORE_READ(skb, network_header);
	if (network_offset == 0)
	{
		return;
	}

	// 读取IP头部
	struct iphdr ip_hdr;
	if (bpf_probe_read(
			&ip_hdr,
			sizeof(ip_hdr),
			(void *)(long)BPF_CORE_READ(skb, head) + network_offset
		) != 0)
	{
		return;
	}

	// 检查IP版本
	if ((ip_hdr.version & 0xF0) != 0x40) // IPv4
	{
		return;
	}

	// 填充IP信息
	event->ip_version = 4;
	event->src_ip = ip_hdr.saddr;
	event->dst_ip = ip_hdr.daddr;
	event->ip_protocol = ip_hdr.protocol;
	event->tos = ip_hdr.tos;
	event->ttl = ip_hdr.ttl;
}

// 辅助函数：解析TCP头部信息
static void parse_tcp_header(struct sk_buff *skb, struct net_event *event)
{
	// 初始化TCP字段
	event->src_port = 0;
	event->dst_port = 0;
	event->tcp_flags = 0;
	event->seq_num = 0;
	event->ack_num = 0;
	event->window_size = 0;

	// 检查是否为TCP协议
	if (event->ip_protocol != IPPROTO_TCP)
	{
		return;
	}

	// 获取传输层头部偏移
	u32 transport_offset = BPF_CORE_READ(skb, transport_header);
	if (transport_offset == 0)
	{
		return;
	}

	// 读取TCP头部
	struct tcphdr tcp_hdr;
	if (bpf_probe_read(
			&tcp_hdr,
			sizeof(tcp_hdr),
			(void *)(long)BPF_CORE_READ(skb, head) + transport_offset
		) != 0)
	{
		return;
	}

	// 填充TCP信息
	event->src_port = __builtin_bswap16(tcp_hdr.source);
	event->dst_port = __builtin_bswap16(tcp_hdr.dest);
	event->seq_num = __builtin_bswap32(tcp_hdr.seq);
	event->ack_num = __builtin_bswap32(tcp_hdr.ack_seq);
	event->window_size = __builtin_bswap16(tcp_hdr.window);

	// 解析TCP标志位
	event->tcp_flags = 0;
	if (tcp_hdr.syn)
	{
		event->tcp_flags |= TCP_FLAG_SYN;
	}
	if (tcp_hdr.ack)
	{
		event->tcp_flags |= TCP_FLAG_ACK;
	}
	if (tcp_hdr.fin)
	{
		event->tcp_flags |= TCP_FLAG_FIN;
	}
	if (tcp_hdr.rst)
	{
		event->tcp_flags |= TCP_FLAG_RST;
	}
}

// 辅助函数：解析UDP头部信息
static void parse_udp_header(struct sk_buff *skb, struct net_event *event)
{
	// 初始化UDP字段
	event->src_port = 0;
	event->dst_port = 0;

	// 检查是否为UDP协议
	if (event->ip_protocol != IPPROTO_UDP)
	{
		return;
	}

	// 获取传输层头部偏移
	u32 transport_offset = BPF_CORE_READ(skb, transport_header);
	if (transport_offset == 0)
	{
		return;
	}

	// 读取UDP头部
	struct udphdr udp_hdr;
	if (bpf_probe_read(
			&udp_hdr,
			sizeof(udp_hdr),
			(void *)(long)BPF_CORE_READ(skb, head) + transport_offset
		) != 0)
	{
		return;
	}

	// 填充UDP信息
	event->src_port = __builtin_bswap16(udp_hdr.source);
	event->dst_port = __builtin_bswap16(udp_hdr.dest);

	// UDP没有序列号、确认号等字段，保持为0
	event->tcp_flags = 0;
	event->seq_num = 0;
	event->ack_num = 0;
	event->window_size = 0;
}

// 辅助函数：统一的包信息提取函数
static void extract_packet_info(struct sk_buff *skb, struct net_event *event)
{
	// 首先解析IP头部信息
	parse_ip_header(skb, event);

	// 根据协议类型解析传输层头部
	if (event->ip_protocol == IPPROTO_TCP)
	{
		parse_tcp_header(skb, event);
	}
	else if (event->ip_protocol == IPPROTO_UDP)
	{
		parse_udp_header(skb, event);
	}
	// 对于其他协议（如ICMP），端口等字段保持为0
}

// 辅助函数：填充通用事件字段
static void fill_common_event_fields(struct net_event *event)
{
	event->ts = bpf_ktime_get_ns();
	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->tid = bpf_get_current_pid_tgid();
	bpf_get_current_comm(event->comm, sizeof(event->comm));
}

// Tracepoint处理函数：netif_receive_skb
SEC("tracepoint/net/netif_receive_skb")
int trace_netif_receive_skb(struct tp_netif_receive_skb *ctx)
{
	u32 key = 0;
	struct net_rule *rule = bpf_map_lookup_elem(&rules_map, &key);
	if (!rule || !(rule->event_mask & (1 << 3)))
	{
		return 0;
	}

	char dev_name[16] = {0};
	char *name_ptr = (char *)ctx + (ctx->name_loc & 0xFFFF);
	bpf_probe_read_str(dev_name, sizeof(dev_name), name_ptr);

	if (!should_trace(
			rule,
			bpf_get_current_pid_tgid() >> 32,
			ctx->len,
			dev_name
		))
	{
		return 0;
	}

	struct net_event event = {};
	fill_common_event_fields(&event);

	event.skb_addr = ctx->skbaddr;
	event.len = ctx->len;
	event.event_type = 3; // receive
	__builtin_memcpy(event.dev_name, dev_name, sizeof(event.dev_name));

	// 集成协议解析
	struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
	if (skb)
	{
		extract_packet_info(skb, &event);
	}

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Tracepoint处理函数：net_dev_queue
SEC("tracepoint/net/net_dev_queue")
int trace_net_dev_queue(struct tp_net_dev_queue *ctx)
{
	u32 key = 0;
	struct net_rule *rule = bpf_map_lookup_elem(&rules_map, &key);
	if (!rule || !(rule->event_mask & (1 << 0)))
	{
		return 0;
	}

	char dev_name[16] = {0};
	char *name_ptr = (char *)ctx + (ctx->name_loc & 0xFFFF);
	bpf_probe_read_str(dev_name, sizeof(dev_name), name_ptr);

	if (!should_trace(
			rule,
			bpf_get_current_pid_tgid() >> 32,
			ctx->len,
			dev_name
		))
	{
		return 0;
	}

	// 记录开始时间
	u64 ts = bpf_ktime_get_ns();
	void *skb_key = ctx->skbaddr;
	bpf_map_update_elem(&start_times, &skb_key, &ts, BPF_ANY);

	struct net_event event = {};
	fill_common_event_fields(&event);

	event.skb_addr = ctx->skbaddr;
	event.len = ctx->len;
	event.event_type = 0; // queue
	__builtin_memcpy(event.dev_name, dev_name, sizeof(event.dev_name));

	// 集成协议解析
	struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
	if (skb)
	{
		extract_packet_info(skb, &event);
	}

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Tracepoint处理函数：net_dev_xmit
SEC("tracepoint/net/net_dev_xmit")
int trace_net_dev_xmit(struct tp_net_dev_xmit *ctx)
{
	u32 key = 0;
	struct net_rule *rule = bpf_map_lookup_elem(&rules_map, &key);
	if (!rule || !(rule->event_mask & (1 << 2)))
	{
		return 0;
	}

	char dev_name[16] = {0};
	char *name_ptr = (char *)ctx + (ctx->name_loc & 0xFFFF);
	bpf_probe_read_str(dev_name, sizeof(dev_name), name_ptr);

	if (!should_trace(
			rule,
			bpf_get_current_pid_tgid() >> 32,
			ctx->len,
			dev_name
		))
	{
		return 0;
	}

	struct net_event event = {};
	fill_common_event_fields(&event);

	event.skb_addr = ctx->skbaddr;
	event.len = ctx->len;
	event.event_type = 2; // xmit
	event.return_code = ctx->rc;
	__builtin_memcpy(event.dev_name, dev_name, sizeof(event.dev_name));

	// 集成协议解析
	struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
	if (skb)
	{
		extract_packet_info(skb, &event);
	}

	// 查找开始时间，计算延迟
	void *skb_key = ctx->skbaddr;
	u64 *start_ts = bpf_map_lookup_elem(&start_times, &skb_key);
	if (start_ts)
	{
		event.flags = (u32)((event.ts - *start_ts) / 1000); // 转换为微秒
		bpf_map_delete_elem(&start_times, &skb_key);
	}

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}

// Tracepoint处理函数：net_dev_start_xmit
SEC("tracepoint/net/net_dev_start_xmit")
int trace_net_dev_start_xmit(struct tp_net_dev_start_xmit *ctx)
{
	u32 key = 0;
	struct net_rule *rule = bpf_map_lookup_elem(&rules_map, &key);
	if (!rule || !(rule->event_mask & (1 << 1)))
	{
		return 0;
	}

	char dev_name[16] = {0};
	char *name_ptr = (char *)ctx + (ctx->name_loc & 0xFFFF);
	bpf_probe_read_str(dev_name, sizeof(dev_name), name_ptr);

	if (!should_trace(
			rule,
			bpf_get_current_pid_tgid() >> 32,
			ctx->len,
			dev_name
		))
	{
		return 0;
	}

	struct net_event event = {};
	fill_common_event_fields(&event);

	event.skb_addr = (void *)ctx->skbaddr;
	event.len = ctx->len;
	event.data_len = ctx->data_len;
	event.protocol = ctx->protocol;
	event.event_type = 1; // start_xmit
	event.queue_id = ctx->queue_mapping;
	event.vlan_tagged = ctx->vlan_tagged;
	event.vlan_proto = ctx->vlan_proto;
	event.ip_summed = ctx->ip_summed;
	event.gso_size = ctx->gso_size;
	__builtin_memcpy(event.dev_name, dev_name, sizeof(event.dev_name));

	// 集成协议解析
	struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
	if (skb)
	{
		extract_packet_info(skb, &event);
	}

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	return 0;
}