// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
#include <limits.h>
#include <getopt.h>
#include <string>
#include <signal.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <algorithm>
#include <pthread.h>
#include <map>

#include <fstream>
#include <sstream>
#include <unordered_map>
#include <string>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "net-snoop.skel.h"
#include "com.h"

#define TASK_COMM_LEN 16
#define DEV_NAME_LEN 16

// 协议相关宏定义
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
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

// 重复定义结构体（与.bpf.c中的定义保持一致）
struct net_event
{
	uint64_t ts;
	uint32_t pid;
	uint32_t tid;
	char comm[16];
	char dev_name[16];
	void *skb_addr;
	uint32_t len;
	uint32_t data_len;
	uint16_t protocol;
	uint8_t event_type; // 0:queue, 1:start_xmit, 2:xmit, 3:receive
	int return_code;
	uint16_t queue_id;
	bool vlan_tagged;
	uint16_t vlan_proto;
	uint8_t ip_summed;
	uint16_t gso_size;
	uint32_t flags;

	// 新增L3层信息
	uint8_t ip_version;	 // 4 or 6
	uint32_t src_ip;	 // IPv4源地址
	uint32_t dst_ip;	 // IPv4目标地址
	uint8_t ip_protocol; // TCP/UDP/ICMP等
	uint8_t tos;		 // Type of Service
	uint8_t ttl;		 // Time to Live

	// 新增L4层信息
	uint16_t src_port;	  // 源端口
	uint16_t dst_port;	  // 目标端口
	uint16_t tcp_flags;	  // TCP标志位
	uint32_t seq_num;	  // TCP序列号
	uint32_t ack_num;	  // TCP确认号
	uint16_t window_size; // TCP窗口大小
};

struct net_rule
{
	pid_t target_pid;
	char target_dev[16];
	char target_comm[16];
	uint32_t min_len;
	uint32_t max_len;
	uint16_t target_protocol;
	bool filter_loopback;
	uint8_t event_mask; // 位掩码控制监控哪些事件类型

	// 新增过滤字段
	uint8_t l4_protocol_filter; // 0=all, 1=tcp, 2=udp, 3=icmp
	uint16_t port_filter;		// 0=all, >0=specific port
	uint32_t ip_filter;			// 0=all, >0=specific IP
	bool show_details;			// 是否显示协议详细信息
	bool show_stats;			// 是否显示协议统计信息
} rule;

static net_snoop_bpf *obj;
static struct ring_buffer *rb = NULL;
static int filter_fd;
static int interval = 1;
static std::atomic<bool> exit_flag(false);

static struct option lopts[] = {
	{"pid",			 required_argument, 0, 'p'},
	{"comm",			 required_argument, 0, 'c'},
	{"dev",			 required_argument, 0, 'd'},
	{"min-len",			required_argument, 0, 'm'},
	{"max-len",			required_argument, 0, 'M'},
	{"protocol",		 required_argument, 0, 'P'},
	{"events",		   required_argument, 0, 'e'},
	{"interval",		 required_argument, 0, 'i'},
	{"protocol-filter", required_argument, 0, 'f'},
	{"port-filter",		required_argument, 0, 'o'},
	{"ip-filter",		  required_argument, 0, 'a'},
	{"show-details",	 no_argument,		  0, 's'},
	{"protocol-stats",  no_argument,		0, 't'},
	{"help",			 no_argument,		  0, 'h'},
	{0,				 0,				 0, 0  }
};

struct HelpMsg
{
	const char *argparam;
	const char *msg;
};

static HelpMsg help_msg[] = {
	{"[pid]",		  "filter output by the pid\n"								  },
	{"[comm]",		   "filter output by the process comm.\n"						 },
	{"[dev]",		  "filter output by network device name (e.g., eth0, lo)\n"   },
	{"[len]",		  "filter output by minimum packet length\n"					},
	{"[len]",		  "filter output by maximum packet length\n"					},
	{"[protocol]",	   "filter output by protocol number (e.g., 0x0800 for IPv4)\n"
	},
	{"[mask]",
	 "event mask: 1=queue, 2=start_xmit, 4=xmit, 8=receive (default: 15=all)\n"
	},
	{"[interval]",	   "statistic interval\n"										 },
	{"[tcp|udp|icmp]", "filter output by L4 protocol type\n"						},
	{"[port]",		   "filter output by source or destination port\n"			  },
	{"[ip]",			 "filter output by source or destination IP address\n"		  },
	{"",			   "show detailed protocol information\n"					   },
	{"",			   "show protocol statistics summary\n"						 },
	{"",			   "print this help message\n"									},
};

void Usage(const char *arg0)
{
	printf("Usage: %s [option]\n", arg0);
	printf("  To monitor network packet transmission events with deep protocol "
		   "analysis.\n");
	printf("  Enhanced with L3/L4 protocol parsing and application layer "
		   "identification.\n\n");
	printf("Options:\n");
	for (int i = 0; lopts[i].name; i++)
	{
		printf(
			"  -%c, --%s %s\n\t%s\n",
			lopts[i].val,
			lopts[i].name,
			help_msg[i].argparam,
			help_msg[i].msg
		);
	}

	printf("\nExamples:\n");
	printf("  %s --protocol-filter tcp --show-details\n", arg0);
	printf("  %s --port-filter 80 --ip-filter 192.168.1.100\n", arg0);
	printf("  %s --protocol-stats\n", arg0);
}

std::string long_opt2short_opt(const option lopts[])
{
	std::string sopts = "";
	for (int i = 0; lopts[i].name; i++)
	{
		sopts += lopts[i].val;
		switch (lopts[i].has_arg)
		{
		case no_argument:
			break;
		case required_argument:
			sopts += ":";
			break;
		case optional_argument:
			sopts += "::";
			break;
		default:
			DIE("Code internal bug!!!\n");
			abort();
		}
	}
	return sopts;
}

void parse_args(int argc, char **argv)
{
	int opt, opt_idx;
	optind = 1;
	// 初始化默认规则
	memset(&rule, 0, sizeof(rule));
	rule.event_mask = 15; // 默认监控所有事件类型

	std::string sopts = long_opt2short_opt(lopts);
	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0)
	{
		switch (opt)
		{
		case 'p':
			rule.target_pid = atoi(optarg);
			break;
		case 'c':
			strncpy(rule.target_comm, optarg, 16);
			rule.target_comm[15] = 0;
			break;
		case 'd':
			strncpy(rule.target_dev, optarg, 16);
			rule.target_dev[15] = 0;
			break;
		case 'm':
			rule.min_len = atoi(optarg);
			break;
		case 'M':
			rule.max_len = atoi(optarg);
			break;
		case 'P':
			rule.target_protocol = strtol(optarg, NULL, 0);
			break;
		case 'e':
			rule.event_mask = atoi(optarg) & 15;
			break;
		case 'i':
			interval = atoi(optarg);
			break;
		case 'f':
			if (strcmp(optarg, "tcp") == 0)
			{
				rule.l4_protocol_filter = 1;
			}
			else if (strcmp(optarg, "udp") == 0)
			{
				rule.l4_protocol_filter = 2;
			}
			else if (strcmp(optarg, "icmp") == 0)
			{
				rule.l4_protocol_filter = 3;
			}
			else
			{
				fprintf(
					stderr,
					"Invalid protocol filter: %s. Must be tcp, udp, or icmp.\n",
					optarg
				);
				exit(-1);
			}
			break;
		case 'o':
		{
			long port = strtol(optarg, NULL, 10);
			if (port <= 0 || port > 65535)
			{
				fprintf(
					stderr,
					"Invalid port number: %s. Must be between 1 and 65535.\n",
					optarg
				);
				exit(-1);
			}
			rule.port_filter = (uint16_t)port;
		}
		break;
		case 'a':
			rule.ip_filter = inet_addr(optarg);
			if (rule.ip_filter == INADDR_NONE)
			{
				fprintf(stderr, "Invalid IP address: %s\n", optarg);
				exit(-1);
			}
			break;
		case 's':
			rule.show_details = true;
			break;
		case 't':
			rule.show_stats = true;
			break;
		case 'h':
			Usage(argv[0]);
			exit(0);
			break;
		default:
			Usage(argv[0]);
			exit(-1);
			break;
		}
	}
}

void register_signal()
{
	struct sigaction sa;
	sa.sa_handler = [](int) { exit_flag = true; };
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		perror("sigaction");
		exit(EXIT_FAILURE);
	}
}

static const char *event_type_str(uint8_t type)
{
	switch (type)
	{
	case 0:
		return "QUEUE";
	case 1:
		return "START_XMIT";
	case 2:
		return "XMIT";
	case 3:
		return "RECEIVE";
	default:
		return "UNKNOWN";
	}
}

static const char *protocol_str(uint16_t protocol)
{
	switch (protocol)
	{
	case 0x0800:
		return "IPv4";
	case 0x0806:
		return "ARP";
	case 0x86DD:
		return "IPv6";
	case 0x8100:
		return "VLAN";
	default:
		return "OTHER";
	}
}

// 格式化IP层信息显示
static std::string format_ip_info(const struct net_event *e)
{
	if (!e)
	{
		return "IP: Invalid event";
	}

	if (e->ip_version == 0)
	{
		return "IP: N/A";
	}

	std::string result = "IP: ";

	if (e->ip_version == 4)
	{
		// 验证IP地址是否有效
		if (e->src_ip == 0 && e->dst_ip == 0)
		{
			return "IP: Invalid addresses";
		}

		struct in_addr src_addr = {e->src_ip};
		struct in_addr dst_addr = {e->dst_ip};

		char *src_str = inet_ntoa(src_addr);
		if (!src_str)
		{
			return "IP: Address conversion failed";
		}

		result += src_str;
		result += " -> ";

		char *dst_str = inet_ntoa(dst_addr);
		if (!dst_str)
		{
			result += "INVALID";
		}
		else
		{
			result += dst_str;
		}

		// 添加协议信息
		switch (e->ip_protocol)
		{
		case IPPROTO_TCP:
			result += " (TCP)";
			break;
		case IPPROTO_UDP:
			result += " (UDP)";
			break;
		case IPPROTO_ICMP:
			result += " (ICMP)";
			break;
		default:
			if (e->ip_protocol > 0 && e->ip_protocol < 256)
			{
				result += " (Proto:" + std::to_string(e->ip_protocol) + ")";
			}
			else
			{
				result += " (Proto:INVALID)";
			}
			break;
		}

		// 添加TOS和TTL信息（带范围检查）
		if (e->tos != 0 && e->tos <= 255)
		{
			result += " TOS:" + std::to_string(e->tos);
		}
		if (e->ttl != 0 && e->ttl <= 255)
		{
			result += " TTL:" + std::to_string(e->ttl);
		}
	}
	else if (e->ip_version == 6)
	{
		result += "IPv6 (not supported)";
	}
	else
	{
		result += "Invalid IP version (" + std::to_string(e->ip_version) + ")";
	}

	return result;
}

// 格式化TCP层信息显示
static std::string format_tcp_info(const struct net_event *e)
{
	if (!e)
	{
		return "TCP: Invalid event";
	}

	if (e->ip_protocol != IPPROTO_TCP || e->src_port == 0)
	{
		return "TCP: N/A";
	}

	// 验证端口号范围
	if (e->src_port > 65535 || e->dst_port > 65535)
	{
		return "TCP: Invalid port numbers";
	}

	std::string result = "TCP: ";

	// 端口信息
	result +=
		std::to_string(e->src_port) + " -> " + std::to_string(e->dst_port);

	// TCP标志位信息
	if (e->tcp_flags != 0)
	{
		result += " [";
		bool first = true;

		// 检查标志位是否在有效范围内
		if (e->tcp_flags &
			~(TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_FIN | TCP_FLAG_RST))
		{
			result += "INVALID_FLAGS";
		}
		else
		{
			if (e->tcp_flags & TCP_FLAG_SYN)
			{
				result += "SYN";
				first = false;
			}
			if (e->tcp_flags & TCP_FLAG_ACK)
			{
				if (!first)
				{
					result += ",";
				}
				result += "ACK";
				first = false;
			}
			if (e->tcp_flags & TCP_FLAG_FIN)
			{
				if (!first)
				{
					result += ",";
				}
				result += "FIN";
				first = false;
			}
			if (e->tcp_flags & TCP_FLAG_RST)
			{
				if (!first)
				{
					result += ",";
				}
				result += "RST";
				first = false;
			}
		}

		result += "]";
	}

	// 序列号信息（32位范围检查）
	if (e->seq_num != 0)
	{
		result += " Seq:" + std::to_string(e->seq_num);
	}
	if (e->ack_num != 0 && (e->tcp_flags & TCP_FLAG_ACK))
	{
		result += " Ack:" + std::to_string(e->ack_num);
	}

	// 窗口大小信息（16位范围检查）
	if (e->window_size != 0 && e->window_size <= 65535)
	{
		result += " Win:" + std::to_string(e->window_size);
	}

	return result;
}

// 格式化UDP层信息显示
static std::string format_udp_info(const struct net_event *e)
{
	if (e->ip_protocol != IPPROTO_UDP || e->src_port == 0)
	{
		return "UDP: N/A";
	}

	std::string result = "UDP: ";

	// 端口信息
	result +=
		std::to_string(e->src_port) + " -> " + std::to_string(e->dst_port);

	// UDP相对简单，主要显示端口信息
	// 可以根据端口推断常见的应用协议
	if (e->src_port == 53 || e->dst_port == 53)
	{
		result += " (DNS)";
	}
	else if (e->src_port == 67 || e->dst_port == 67 || e->src_port == 68 || e->dst_port == 68)
	{
		result += " (DHCP)";
	}
	else if (e->src_port == 123 || e->dst_port == 123)
	{
		result += " (NTP)";
	}
	else if (e->src_port == 161 || e->dst_port == 161)
	{
		result += " (SNMP)";
	}

	return result;
}

// 应用层协议识别模块
static app_protocol identify_application_protocol(const struct net_event *e)
{
	if (e->ip_protocol == IPPROTO_TCP)
	{
		// TCP协议的常见应用识别
		if (e->src_port == 80 || e->dst_port == 80 || e->src_port == 8080 ||
			e->dst_port == 8080)
		{
			return APP_HTTP;
		}
		if (e->src_port == 22 || e->dst_port == 22)
		{
			return APP_SSH;
		}
		if (e->src_port == 443 || e->dst_port == 443)
		{
			return APP_HTTP; // HTTPS也归类为HTTP
		}
	}
	else if (e->ip_protocol == IPPROTO_UDP)
	{
		// UDP协议的常见应用识别
		if (e->src_port == 53 || e->dst_port == 53)
		{
			return APP_DNS;
		}
	}

	return APP_UNKNOWN;
}

// 检查是否为HTTP流量
static bool __attribute__((unused)) is_http_traffic(const struct net_event *e)
{
	return (
		e->ip_protocol == IPPROTO_TCP &&
		(e->src_port == 80 || e->dst_port == 80 || e->src_port == 8080 ||
		 e->dst_port == 8080 || e->src_port == 443 || e->dst_port == 443)
	);
}

// 检查是否为DNS流量
static bool __attribute__((unused)) is_dns_traffic(const struct net_event *e)
{
	return (
		e->ip_protocol == IPPROTO_UDP &&
		(e->src_port == 53 || e->dst_port == 53)
	);
}

// 检查是否为SSH流量
static bool __attribute__((unused)) is_ssh_traffic(const struct net_event *e)
{
	return (
		e->ip_protocol == IPPROTO_TCP &&
		(e->src_port == 22 || e->dst_port == 22)
	);
}

// 获取应用协议名称
static const char *app_protocol_name(app_protocol proto)
{
	switch (proto)
	{
	case APP_HTTP:
		return "HTTP";
	case APP_DNS:
		return "DNS";
	case APP_SSH:
		return "SSH";
	default:
		return "UNKNOWN";
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	// 数据验证
	if (!data || data_sz < sizeof(struct net_event))
	{
		fprintf(stderr, "Invalid event data received\n");
		return -1;
	}

	const struct net_event *e = (const struct net_event *)data;

	// 基本数据完整性检查
	if (e->len == 0 || e->len > 65535)
	{
		// 跳过明显无效的包长度
		return 0;
	}

	// 检查进程信息的合理性
	if (e->pid == 0 && e->tid == 0)
	{
		// 可能是内核线程或系统调用，允许通过但记录
	}

	// 检查事件类型范围
	if (e->event_type > 3)
	{
		fprintf(stderr, "Invalid event type: %d\n", e->event_type);
		return -1;
	}

	// 应用新的过滤逻辑

	// L4协议过滤
	if (rule.l4_protocol_filter != 0)
	{
		if (rule.l4_protocol_filter == 1 && e->ip_protocol != IPPROTO_TCP)
		{
			return 0; // 过滤非TCP包
		}
		if (rule.l4_protocol_filter == 2 && e->ip_protocol != IPPROTO_UDP)
		{
			return 0; // 过滤非UDP包
		}
		if (rule.l4_protocol_filter == 3 && e->ip_protocol != IPPROTO_ICMP)
		{
			return 0; // 过滤非ICMP包
		}
	}

	// 端口过滤
	if (rule.port_filter != 0)
	{
		if (e->src_port != rule.port_filter && e->dst_port != rule.port_filter)
		{
			return 0; // 过滤不匹配端口的包
		}
	}

	// IP地址过滤
	if (rule.ip_filter != 0)
	{
		if (e->src_ip != rule.ip_filter && e->dst_ip != rule.ip_filter)
		{
			return 0; // 过滤不匹配IP的包
		}
	}

	struct timespec ct;
	struct tm *tm;
	char time_buf[64];

	clock_gettime(CLOCK_REALTIME, &ct);
	tm = localtime(&ct.tv_sec);
	strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm);

	printf(
		"%-8s %-16s %-6d %-6d %-10s %-8s %-6u",
		time_buf,
		e->comm,
		e->pid,
		e->tid,
		event_type_str(e->event_type),
		e->dev_name,
		e->len
	);

	if (e->event_type == 1)
	{ // start_xmit 显示更多详细信息
		printf(
			" %-8s Q:%-3u GSO:%-4u",
			protocol_str(e->protocol),
			e->queue_id,
			e->gso_size
		);
		if (e->vlan_tagged)
		{
			printf(" VLAN:%04x", e->vlan_proto);
		}
	}
	else if (e->event_type == 2)
	{ // xmit 显示返回码和延迟
		printf(" RC:%-2d", e->return_code);
		if (e->flags > 0)
		{
			printf(" LAT:%u us", e->flags);
		}
	}

	// 显示协议详细信息（如果启用）
	if (rule.show_details)
	{
		printf("\n  %s", format_ip_info(e).c_str());
		if (e->ip_protocol == IPPROTO_TCP)
		{
			printf("\n  %s", format_tcp_info(e).c_str());
		}
		else if (e->ip_protocol == IPPROTO_UDP)
		{
			printf("\n  %s", format_udp_info(e).c_str());
		}

		// 显示应用层协议识别结果
		app_protocol app_proto = identify_application_protocol(e);
		if (app_proto != APP_UNKNOWN)
		{
			printf("\n  APP: %s", app_protocol_name(app_proto));
		}
	}

	printf(" SKB:%p\n", e->skb_addr);

	return 0;
}

static void print_header()
{
	printf(
		"%-8s %-16s %-6s %-6s %-10s %-8s %-6s %-20s %-12s\n",
		"TIME",
		"COMM",
		"PID",
		"TID",
		"EVENT",
		"DEV",
		"LEN",
		"DETAILS",
		"SKB"
	);
}

int main(int argc, char *args[])
{
	int err;
	uint32_t key = 0;

	parse_args(argc, args);
	register_signal();

	// 加载并打开BPF程序
	obj = net_snoop_bpf__open();
	if (!obj)
	{
		fprintf(stderr, "Failed to open BPF object\n");
		return 1;
	}

	err = net_snoop_bpf__load(obj);
	if (err)
	{
		fprintf(stderr, "Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = net_snoop_bpf__attach(obj);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	// 设置过滤规则
	filter_fd = bpf_map__fd(obj->maps.rules_map);
	err = bpf_map_update_elem(filter_fd, &key, &rule, BPF_ANY);
	if (err)
	{
		fprintf(stderr, "Failed to update filter map: %d\n", err);
		goto cleanup;
	}

	// 设置ring buffer
	rb = ring_buffer__new(
		bpf_map__fd(obj->maps.events),
		handle_event,
		NULL,
		NULL
	);
	if (!rb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	print_header();

	// 主事件循环
	while (!exit_flag)
	{
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	net_snoop_bpf__destroy(obj);
	return err < 0 ? -err : 0;
}