// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

// This file uses/derives from googletest
// Copyright 2008, Google Inc.
// Licensed under the BSD 3-Clause License
// See NOTICE for full license text

#include "gtest/gtest.h"
#include <vector>
#include <atomic>
#include <thread>
#include <chrono>
#include <climits>
#include <cstdint>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "dkapture.h"

// 声明net_snoop_init函数，这是在BUILTIN模式下的入口点
extern int
net_snoop_init(int argc, char **argv, DKapture::DKCallback cb, void *ctx);

// 定义网络事件结构体
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

// 网络事件结构体
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

	// L3层信息
	uint8_t ip_version;	 // 4 or 6
	uint32_t src_ip;	 // IPv4源地址
	uint32_t dst_ip;	 // IPv4目标地址
	uint8_t ip_protocol; // TCP/UDP/ICMP等
	uint8_t tos;		 // Type of Service
	uint8_t ttl;		 // Time to Live

	// L4层信息
	uint16_t src_port;	// 源端口
	uint16_t dst_port;	// 目标端口
	uint16_t tcp_flags; // TCP标志位
	uint32_t seq_num;	// TCP序列号
};

// 测试常量定义
const std::string TEST_ROOT = "/tmp/net_snoop_test_dir";

// 测试回调函数，用于接收和验证BPF事件
static std::vector<struct net_event> captured_events;
static std::atomic<bool> event_received(false);

// 回调函数，用于接收BPF事件
static int test_callback(void *ctx, const void *data, size_t data_sz)
{
	// 数据验证
	if (data == nullptr || data_sz == 0)
	{
		return -1;
	}

	// 数据大小检查
	if (data_sz < sizeof(struct net_event))
	{
		return -1;
	}

	// 处理事件
	const struct net_event *event = static_cast<const struct net_event *>(data);
	captured_events.push_back(*event);
	event_received = true;
	return 0;
}

// 测试类
class NetSnoopBasicTest : public ::testing::Test
{
  protected:
	void SetUp() override
	{
		// 创建测试目录
		mkdir(TEST_ROOT.c_str(), 0755);

		// 清除之前捕获的事件
		captured_events.clear();
		event_received = false;
	}

	void TearDown() override
	{
		// 清理测试目录
		std::string cmd = "rm -rf " + TEST_ROOT;
		system(cmd.c_str());
	}

	// 辅助函数：模拟网络事件
	void simulateNetEvent(
		uint8_t event_type,
		const char *dev_name,
		uint32_t len,
		uint8_t ip_protocol,
		uint32_t src_ip,
		uint32_t dst_ip,
		uint16_t src_port,
		uint16_t dst_port
	)
	{
		struct net_event event;
		memset(&event, 0, sizeof(event));

		event.ts = getCurrentTimestampNs();
		event.pid = 1000;
		event.tid = 1001;
		strncpy(event.comm, "test_process", sizeof(event.comm) - 1);
		strncpy(event.dev_name, dev_name, sizeof(event.dev_name) - 1);
		event.skb_addr = nullptr;
		event.len = len;
		event.data_len = len;
		event.protocol = 0x0800; // ETH_P_IP
		event.event_type = event_type;
		event.return_code = 0;
		event.queue_id = 0;
		event.vlan_tagged = false;
		event.vlan_proto = 0;
		event.ip_summed = 0;
		event.gso_size = 0;
		event.flags = 0;

		event.ip_version = 4;
		event.src_ip = src_ip;
		event.dst_ip = dst_ip;
		event.ip_protocol = ip_protocol;
		event.tos = 0;
		event.ttl = 64;

		event.src_port = src_port;
		event.dst_port = dst_port;
		event.tcp_flags = 0;
		event.seq_num = 0;

		test_callback(nullptr, &event, sizeof(event));
	}

	// 辅助函数：获取当前时间戳（纳秒）
	uint64_t getCurrentTimestampNs()
	{
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
	}

	// 辅助函数：将IPv4地址字符串转换为整数
	uint32_t ipv4ToInt(const char *ip_str)
	{
		struct in_addr addr;
		inet_pton(AF_INET, ip_str, &addr);
		return ntohl(addr.s_addr);
	}

	// 辅助函数：将整数转换为IPv4地址字符串
	std::string intToIpv4(uint32_t ip)
	{
		struct in_addr addr;
		addr.s_addr = htonl(ip);
		char ip_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
		return std::string(ip_str);
	}
};

// 测试基本事件处理
TEST_F(NetSnoopBasicTest, EventHandling)
{
	// 模拟网络事件 - 发送TCP数据包
	simulateNetEvent(
		2,
		"eth0",
		1500,
		IPPROTO_TCP,
		ipv4ToInt("192.168.1.100"),
		ipv4ToInt("8.8.8.8"),
		12345,
		80
	);

	// 验证事件是否被捕获
	EXPECT_TRUE(event_received) << "Event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture one event";

	if (!captured_events.empty())
	{
		const auto &event = captured_events[0];
		EXPECT_EQ(event.event_type, 2) << "Event type should be xmit (2)";
		EXPECT_STREQ(event.dev_name, "eth0") << "Device name should match";
		EXPECT_EQ(event.len, 1500) << "Packet length should match";
		EXPECT_EQ(event.ip_protocol, IPPROTO_TCP) << "IP protocol should be "
													 "TCP";
		EXPECT_EQ(event.src_ip, ipv4ToInt("192.168.1.100")) << "Source IP "
															   "should match";
		EXPECT_EQ(event.dst_ip, ipv4ToInt("8.8.8.8")) << "Destination IP "
														 "should match";
		EXPECT_EQ(event.src_port, 12345) << "Source port should match";
		EXPECT_EQ(event.dst_port, 80) << "Destination port should match";
	}
}

// 测试不同类型的网络事件
TEST_F(NetSnoopBasicTest, DifferentEventTypes)
{
	// 模拟网络事件 - 入队
	simulateNetEvent(
		0,
		"eth0",
		1500,
		IPPROTO_TCP,
		ipv4ToInt("192.168.1.100"),
		ipv4ToInt("8.8.8.8"),
		12345,
		80
	);

	// 模拟网络事件 - 开始传输
	simulateNetEvent(
		1,
		"eth0",
		1500,
		IPPROTO_TCP,
		ipv4ToInt("192.168.1.100"),
		ipv4ToInt("8.8.8.8"),
		12345,
		80
	);

	// 模拟网络事件 - 传输
	simulateNetEvent(
		2,
		"eth0",
		1500,
		IPPROTO_TCP,
		ipv4ToInt("192.168.1.100"),
		ipv4ToInt("8.8.8.8"),
		12345,
		80
	);

	// 模拟网络事件 - 接收
	simulateNetEvent(
		3,
		"eth0",
		1500,
		IPPROTO_TCP,
		ipv4ToInt("8.8.8.8"),
		ipv4ToInt("192.168.1.100"),
		80,
		12345
	);

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 4) << "Should capture four events";

	if (captured_events.size() >= 4)
	{
		// 验证入队事件
		EXPECT_EQ(captured_events[0].event_type, 0) << "First event type "
													   "should be queue (0)";

		// 验证开始传输事件
		EXPECT_EQ(captured_events[1].event_type, 1) << "Second event type "
													   "should be start_xmit "
													   "(1)";

		// 验证传输事件
		EXPECT_EQ(captured_events[2].event_type, 2) << "Third event type "
													   "should be xmit (2)";

		// 验证接收事件
		EXPECT_EQ(captured_events[3].event_type, 3) << "Fourth event type "
													   "should be receive (3)";
		EXPECT_EQ(captured_events[3].src_ip, ipv4ToInt("8.8.8.8"))
			<< "Source IP should be swapped in receive event";
		EXPECT_EQ(captured_events[3].dst_ip, ipv4ToInt("192.168.1.100"))
			<< "Destination IP should be swapped in receive event";
	}
}

// 测试不同的协议类型
TEST_F(NetSnoopBasicTest, DifferentProtocols)
{
	// 模拟TCP事件
	simulateNetEvent(
		2,
		"eth0",
		1500,
		IPPROTO_TCP,
		ipv4ToInt("192.168.1.100"),
		ipv4ToInt("8.8.8.8"),
		12345,
		80
	);

	// 模拟UDP事件
	simulateNetEvent(
		2,
		"eth0",
		500,
		IPPROTO_UDP,
		ipv4ToInt("192.168.1.100"),
		ipv4ToInt("8.8.8.8"),
		53535,
		53
	);

	// 模拟ICMP事件
	simulateNetEvent(
		2,
		"eth0",
		84,
		IPPROTO_ICMP,
		ipv4ToInt("192.168.1.100"),
		ipv4ToInt("8.8.8.8"),
		0,
		0
	);

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 3) << "Should capture three events";

	if (captured_events.size() >= 3)
	{
		// 验证TCP事件
		EXPECT_EQ(captured_events[0].ip_protocol, IPPROTO_TCP) << "First event "
																  "protocol "
																  "should be "
																  "TCP";
		EXPECT_EQ(captured_events[0].len, 1500) << "TCP packet length should "
												   "match";

		// 验证UDP事件
		EXPECT_EQ(captured_events[1].ip_protocol, IPPROTO_UDP)
			<< "Second event protocol should be UDP";
		EXPECT_EQ(captured_events[1].len, 500) << "UDP packet length should "
												  "match";

		// 验证ICMP事件
		EXPECT_EQ(captured_events[2].ip_protocol, IPPROTO_ICMP)
			<< "Third event protocol should be ICMP";
		EXPECT_EQ(captured_events[2].len, 84) << "ICMP packet length should "
												 "match";
	}
}

// 测试不同的网络接口
TEST_F(NetSnoopBasicTest, DifferentInterfaces)
{
	// 模拟eth0接口事件
	simulateNetEvent(
		2,
		"eth0",
		1500,
		IPPROTO_TCP,
		ipv4ToInt("192.168.1.100"),
		ipv4ToInt("8.8.8.8"),
		12345,
		80
	);

	// 模拟lo接口事件
	simulateNetEvent(
		2,
		"lo",
		1500,
		IPPROTO_TCP,
		ipv4ToInt("127.0.0.1"),
		ipv4ToInt("127.0.0.1"),
		12345,
		80
	);

	// 模拟wlan0接口事件
	simulateNetEvent(
		2,
		"wlan0",
		1500,
		IPPROTO_TCP,
		ipv4ToInt("192.168.1.100"),
		ipv4ToInt("8.8.8.8"),
		12345,
		80
	);

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 3) << "Should capture three events";

	if (captured_events.size() >= 3)
	{
		// 验证eth0接口事件
		EXPECT_STREQ(captured_events[0].dev_name, "eth0") << "First event "
															 "interface should "
															 "be eth0";

		// 验证lo接口事件
		EXPECT_STREQ(captured_events[1].dev_name, "lo") << "Second event "
														   "interface should "
														   "be lo";
		EXPECT_EQ(captured_events[1].src_ip, ipv4ToInt("127.0.0.1"))
			<< "Loopback source IP should match";
		EXPECT_EQ(captured_events[1].dst_ip, ipv4ToInt("127.0.0.1"))
			<< "Loopback destination IP should match";

		// 验证wlan0接口事件
		EXPECT_STREQ(captured_events[2].dev_name, "wlan0") << "Third event "
															  "interface "
															  "should be wlan0";
	}
}

// 测试错误处理
TEST_F(NetSnoopBasicTest, ErrorHandling)
{
	// 测试空数据
	int result = test_callback(nullptr, nullptr, 0);
	EXPECT_EQ(result, -1) << "Null data should be rejected";

	// 清除之前的事件
	captured_events.clear();
	event_received = false;

	// 测试数据大小不足
	char small_data[1];
	result = test_callback(nullptr, small_data, sizeof(small_data));
	EXPECT_EQ(result, -1) << "Incomplete data should be rejected";

	// 清除之前的事件
	captured_events.clear();
	event_received = false;

	// 测试错误返回值
	struct net_event event;
	memset(&event, 0, sizeof(event));
	event.return_code = -ENOBUFS;

	result = test_callback(nullptr, &event, sizeof(event));

	// 验证事件是否被捕获
	EXPECT_TRUE(event_received) << "Event with error should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture event with error";

	if (!captured_events.empty())
	{
		EXPECT_EQ(captured_events[0].return_code, -ENOBUFS) << "Error code "
															   "should match";
	}
}

// 测试边界条件
TEST_F(NetSnoopBasicTest, BoundaryConditions)
{
	// 测试极大值
	struct net_event event;
	memset(&event, 0, sizeof(event));

	event.ts = UINT64_MAX;
	event.pid = UINT32_MAX;
	event.tid = UINT32_MAX;
	strncpy(event.comm, "test_process", sizeof(event.comm) - 1);
	strncpy(event.dev_name, "eth0", sizeof(event.dev_name) - 1);
	event.len = UINT32_MAX;
	event.data_len = UINT32_MAX;
	event.protocol = UINT16_MAX;
	event.event_type = UINT8_MAX;
	event.ip_version = 4;
	event.src_ip = UINT32_MAX;
	event.dst_ip = UINT32_MAX;
	event.src_port = UINT16_MAX;
	event.dst_port = UINT16_MAX;

	test_callback(nullptr, &event, sizeof(event));

	// 验证事件是否被捕获
	EXPECT_TRUE(event_received) << "Max value event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture max value event";

	if (!captured_events.empty())
	{
		const auto &captured = captured_events[0];
		EXPECT_EQ(captured.ts, UINT64_MAX) << "Max timestamp should match";
		EXPECT_EQ(captured.pid, UINT32_MAX) << "Max PID should match";
		EXPECT_EQ(captured.len, UINT32_MAX) << "Max length should match";
		EXPECT_EQ(captured.src_ip, UINT32_MAX) << "Max source IP should match";
		EXPECT_EQ(captured.src_port, UINT16_MAX) << "Max source port should "
													"match";
	}

	// 清除事件
	captured_events.clear();
	event_received = false;

	// 测试极小值
	memset(&event, 0, sizeof(event));
	strncpy(event.comm, "test_process", sizeof(event.comm) - 1);
	strncpy(event.dev_name, "eth0", sizeof(event.dev_name) - 1);
	event.ip_version = 4;

	test_callback(nullptr, &event, sizeof(event));

	// 验证事件是否被捕获
	EXPECT_TRUE(event_received) << "Min value event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture min value event";

	if (!captured_events.empty())
	{
		const auto &captured = captured_events[0];
		EXPECT_EQ(captured.ts, 0) << "Min timestamp should match";
		EXPECT_EQ(captured.pid, 0) << "Min PID should match";
		EXPECT_EQ(captured.len, 0) << "Min length should match";
		EXPECT_EQ(captured.src_ip, 0) << "Min source IP should match";
		EXPECT_EQ(captured.src_port, 0) << "Min source port should match";
	}
}

// 测试性能
TEST_F(NetSnoopBasicTest, Performance)
{
	// 清除之前捕获的事件
	captured_events.clear();
	event_received = false;

	// 记录开始时间
	auto start_time = std::chrono::high_resolution_clock::now();

	// 模拟大量事件
	const int NUM_EVENTS = 1000;
	for (int i = 0; i < NUM_EVENTS; i++)
	{
		uint32_t src_ip = ipv4ToInt("192.168.1.100");
		uint32_t dst_ip = ipv4ToInt("8.8.8.8");
		uint16_t src_port = 12345 + (i % 1000);
		uint16_t dst_port = 80;

		simulateNetEvent(
			2,
			"eth0",
			1500,
			IPPROTO_TCP,
			src_ip,
			dst_ip,
			src_port,
			dst_port
		);
	}

	// 记录结束时间
	auto end_time = std::chrono::high_resolution_clock::now();

	// 计算处理时间
	auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
		end_time - start_time
	);

	// 输出性能指标
	std::cout << "Processing " << NUM_EVENTS << " events took "
			  << duration.count() << " microseconds" << std::endl;
	std::cout << "Average time per event: "
			  << static_cast<double>(duration.count()) / NUM_EVENTS
			  << " microseconds" << std::endl;

	// 验证所有事件都被处理
	EXPECT_EQ(captured_events.size(), NUM_EVENTS) << "All events should be "
													 "processed";

	// 验证处理时间是否在合理范围内（这里设置一个宽松的上限）
	EXPECT_LT(duration.count(), 1000000) << "Event processing should be "
											"reasonably fast";
}

// 测试常见应用协议端口
TEST_F(NetSnoopBasicTest, CommonProtocolPorts)
{
	// 测试常见的应用协议端口
	struct
	{
		const char *name;
		uint16_t port;
		uint8_t ip_protocol;
	} common_ports[] = {
		{"HTTP",	 80,	 IPPROTO_TCP},
		{"HTTPS", 443, IPPROTO_TCP},
		{"DNS",	53,	IPPROTO_UDP},
		{"SSH",	22,	IPPROTO_TCP},
		{"SMTP",	 25,	 IPPROTO_TCP},
		{"POP3",	 110, IPPROTO_TCP},
		{"IMAP",	 143, IPPROTO_TCP},
		{"FTP",	21,	IPPROTO_TCP},
		{"NTP",	123, IPPROTO_UDP}
	};

	// 清除之前捕获的事件
	captured_events.clear();
	event_received = false;

	// 模拟各种常见协议的事件
	for (const auto &port_info : common_ports)
	{
		simulateNetEvent(
			2,
			"eth0",
			1500,
			port_info.ip_protocol,
			ipv4ToInt("192.168.1.100"),
			ipv4ToInt("8.8.8.8"),
			12345,
			port_info.port
		);
	}

	// 验证事件是否被捕获
	EXPECT_EQ(
		captured_events.size(),
		sizeof(common_ports) / sizeof(common_ports[0])
	) << "Should capture all protocol events";

	// 验证每个协议的事件
	for (size_t i = 0; i < captured_events.size(); i++)
	{
		EXPECT_EQ(captured_events[i].ip_protocol, common_ports[i].ip_protocol)
			<< "Protocol should match for " << common_ports[i].name;
		EXPECT_EQ(captured_events[i].dst_port, common_ports[i].port)
			<< "Port should match for " << common_ports[i].name;
	}
}
