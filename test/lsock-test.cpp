// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1-only

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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "dkapture.h"

// 声明lsock_init函数，这是在BUILTIN模式下的入口点
extern int
lsock_init(int argc, char **argv, DKapture::DKCallback cb, void *ctx);

// 定义套接字事件结构体
enum LogType
{
	LOG_UNIX,
	LOG_UDP_IPV4,
	LOG_UDP_IPV6,
	LOG_TCP_IPV4,
	LOG_TCP_IPV6,
};

enum TcpState
{
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT = 2,
	TCP_SYN_RECV = 3,
	TCP_FIN_WAIT1 = 4,
	TCP_FIN_WAIT2 = 5,
	TCP_TIME_WAIT = 6,
	TCP_CLOSE = 7,
	TCP_CLOSE_WAIT = 8,
	TCP_LAST_ACK = 9,
	TCP_LISTEN = 10,
	TCP_CLOSING = 11,
	TCP_NEW_SYN_RECV = 12,
	TCP_MAX_STATES = 13,
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
	unsigned short lport;
	unsigned short rport;
	uid_t uid;
	pid_t pid;
	char comm[16];
	enum LogType log_type;
	int state;
	int backlog;
	int sk_err;
	int sk_err_soft;
	int sk_ack_backlog;
	int sk_max_ack_backlog;
	int sk_rcvbuf;
	int sk_sndbuf;
	int sk_wmem_queued;
	int sk_fwd_alloc;
	int sk_wmem_alloc;
	int sk_rmem_alloc;
	int sk_rcv_qlen;
	int sk_snd_qlen;
	int sk_forward_alloc;
	int sk_omem_alloc;
	int sk_drops;
	int sk_rcvlowat;
	int sk_rcvtimeo;
	int sk_sndtimeo;
	int sk_sendmsg_off;
	int sk_write_pending;
	int sk_peercred_uid;
	int sk_peercred_gid;
	int sk_peercred_pid;
	int sk_cookie;
	char unix_path[108];
};

// 测试常量定义
const std::string TEST_ROOT = "/tmp/lsock_test_dir";

// 测试回调函数，用于接收和验证BPF事件
static std::vector<BpfData> captured_events;
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
	if (data_sz < sizeof(struct BpfData))
	{
		return -1;
	}

	// 处理事件
	const struct BpfData *event = static_cast<const struct BpfData *>(data);
	captured_events.push_back(*event);
	event_received = true;
	return 0;
}

// 测试类
class LsockBasicTest : public ::testing::Test
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

	// 辅助函数：模拟TCP IPv4套接字事件
	void simulateTcpIpv4Socket(
		unsigned int lip,
		unsigned short lport,
		unsigned int rip,
		unsigned short rport,
		uid_t uid,
		pid_t pid,
		int state
	)
	{
		struct BpfData event;
		memset(&event, 0, sizeof(event));

		event.lip = lip;
		event.rip = rip;
		event.lport = lport;
		event.rport = rport;
		event.uid = uid;
		event.pid = pid;
		strncpy(event.comm, "test_process", sizeof(event.comm) - 1);
		event.log_type = LOG_TCP_IPV4;
		event.state = state;

		test_callback(nullptr, &event, sizeof(event));
	}

	// 辅助函数：模拟TCP IPv6套接字事件
	void simulateTcpIpv6Socket(
		struct in6_addr lipv6,
		unsigned short lport,
		struct in6_addr ripv6,
		unsigned short rport,
		uid_t uid,
		pid_t pid,
		int state
	)
	{
		struct BpfData event;
		memset(&event, 0, sizeof(event));

		event.lipv6 = lipv6;
		event.ripv6 = ripv6;
		event.lport = lport;
		event.rport = rport;
		event.uid = uid;
		event.pid = pid;
		strncpy(event.comm, "test_process", sizeof(event.comm) - 1);
		event.log_type = LOG_TCP_IPV6;
		event.state = state;

		test_callback(nullptr, &event, sizeof(event));
	}

	// 辅助函数：模拟UDP IPv4套接字事件
	void simulateUdpIpv4Socket(
		unsigned int lip,
		unsigned short lport,
		unsigned int rip,
		unsigned short rport,
		uid_t uid,
		pid_t pid
	)
	{
		struct BpfData event;
		memset(&event, 0, sizeof(event));

		event.lip = lip;
		event.rip = rip;
		event.lport = lport;
		event.rport = rport;
		event.uid = uid;
		event.pid = pid;
		strncpy(event.comm, "test_process", sizeof(event.comm) - 1);
		event.log_type = LOG_UDP_IPV4;

		test_callback(nullptr, &event, sizeof(event));
	}

	// 辅助函数：模拟UDP IPv6套接字事件
	void simulateUdpIpv6Socket(
		struct in6_addr lipv6,
		unsigned short lport,
		struct in6_addr ripv6,
		unsigned short rport,
		uid_t uid,
		pid_t pid
	)
	{
		struct BpfData event;
		memset(&event, 0, sizeof(event));

		event.lipv6 = lipv6;
		event.ripv6 = ripv6;
		event.lport = lport;
		event.rport = rport;
		event.uid = uid;
		event.pid = pid;
		strncpy(event.comm, "test_process", sizeof(event.comm) - 1);
		event.log_type = LOG_UDP_IPV6;

		test_callback(nullptr, &event, sizeof(event));
	}

	// 辅助函数：模拟Unix套接字事件
	void simulateUnixSocket(uid_t uid, pid_t pid, const char *path)
	{
		struct BpfData event;
		memset(&event, 0, sizeof(event));

		event.uid = uid;
		event.pid = pid;
		strncpy(event.comm, "test_process", sizeof(event.comm) - 1);
		event.log_type = LOG_UNIX;

		if (path)
		{
			strncpy(event.unix_path, path, sizeof(event.unix_path) - 1);
		}

		test_callback(nullptr, &event, sizeof(event));
	}

	// 辅助函数：将IPv4地址字符串转换为整数
	unsigned int ipv4ToInt(const char *ip_str)
	{
		struct in_addr addr;
		inet_pton(AF_INET, ip_str, &addr);
		return ntohl(addr.s_addr);
	}

	// 辅助函数：将IPv6地址字符串转换为in6_addr
	struct in6_addr ipv6ToAddr(const char *ip_str)
	{
		struct in6_addr addr;
		inet_pton(AF_INET6, ip_str, &addr);
		return addr;
	}
};

// 测试基本事件处理
TEST_F(LsockBasicTest, EventHandling)
{
	// 模拟TCP IPv4套接字事件
	simulateTcpIpv4Socket(
		ipv4ToInt("127.0.0.1"),
		8080,
		ipv4ToInt("192.168.1.1"),
		12345,
		1000,
		2000,
		TCP_ESTABLISHED
	);

	// 验证事件是否被捕获
	EXPECT_TRUE(event_received) << "Event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture one event";

	if (!captured_events.empty())
	{
		const auto &event = captured_events[0];
		EXPECT_EQ(event.log_type, LOG_TCP_IPV4) << "Event type should be TCP "
												   "IPv4";
		EXPECT_EQ(event.lip, ipv4ToInt("127.0.0.1")) << "Local IP should match";
		EXPECT_EQ(event.lport, 8080) << "Local port should match";
		EXPECT_EQ(event.rip, ipv4ToInt("192.168.1.1")) << "Remote IP should "
														  "match";
		EXPECT_EQ(event.rport, 12345) << "Remote port should match";
		EXPECT_EQ(event.uid, 1000) << "UID should match";
		EXPECT_EQ(event.pid, 2000) << "PID should match";
		EXPECT_EQ(event.state, TCP_ESTABLISHED) << "TCP state should match";
		EXPECT_STREQ(event.comm, "test_process") << "Process name should match";
	}
}

// 测试不同类型的套接字
TEST_F(LsockBasicTest, DifferentSocketTypes)
{
	// 模拟TCP IPv4套接字
	simulateTcpIpv4Socket(
		ipv4ToInt("127.0.0.1"),
		8080,
		ipv4ToInt("192.168.1.1"),
		12345,
		1000,
		2000,
		TCP_ESTABLISHED
	);

	// 模拟UDP IPv4套接字
	simulateUdpIpv4Socket(
		ipv4ToInt("127.0.0.1"),
		8081,
		ipv4ToInt("192.168.1.1"),
		12346,
		1001,
		2001
	);

	// 模拟Unix套接字
	simulateUnixSocket(1002, 2002, "/tmp/test.sock");

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 3) << "Should capture three events";

	if (captured_events.size() >= 3)
	{
		// 验证TCP IPv4套接字
		const auto &tcp_event = captured_events[0];
		EXPECT_EQ(tcp_event.log_type, LOG_TCP_IPV4) << "First event type "
													   "should be TCP IPv4";
		EXPECT_EQ(tcp_event.lport, 8080) << "TCP local port should match";

		// 验证UDP IPv4套接字
		const auto &udp_event = captured_events[1];
		EXPECT_EQ(udp_event.log_type, LOG_UDP_IPV4) << "Second event type "
													   "should be UDP IPv4";
		EXPECT_EQ(udp_event.lport, 8081) << "UDP local port should match";

		// 验证Unix套接字
		const auto &unix_event = captured_events[2];
		EXPECT_EQ(unix_event.log_type, LOG_UNIX) << "Third event type should "
													"be Unix";
		EXPECT_STREQ(unix_event.unix_path, "/tmp/test.sock") << "Unix socket "
																"path should "
																"match";
	}
}

// 测试IPv6套接字
TEST_F(LsockBasicTest, IPv6Sockets)
{
	// 模拟TCP IPv6套接字
	struct in6_addr local_ipv6 = ipv6ToAddr("::1");
	struct in6_addr remote_ipv6 = ipv6ToAddr("2001:db8::1");

	simulateTcpIpv6Socket(
		local_ipv6,
		8080,
		remote_ipv6,
		12345,
		1000,
		2000,
		TCP_ESTABLISHED
	);

	// 模拟UDP IPv6套接字
	simulateUdpIpv6Socket(local_ipv6, 8081, remote_ipv6, 12346, 1001, 2001);

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 2) << "Should capture two events";

	if (captured_events.size() >= 2)
	{
		// 验证TCP IPv6套接字
		const auto &tcp_event = captured_events[0];
		EXPECT_EQ(tcp_event.log_type, LOG_TCP_IPV6) << "First event type "
													   "should be TCP IPv6";
		EXPECT_EQ(tcp_event.lport, 8080) << "TCP local port should match";

		// 验证UDP IPv6套接字
		const auto &udp_event = captured_events[1];
		EXPECT_EQ(udp_event.log_type, LOG_UDP_IPV6) << "Second event type "
													   "should be UDP IPv6";
		EXPECT_EQ(udp_event.lport, 8081) << "UDP local port should match";
	}
}

// 测试不同的TCP状态
TEST_F(LsockBasicTest, TcpStates)
{
	// 测试不同的TCP状态
	const int states[] = {
		TCP_ESTABLISHED,
		TCP_SYN_SENT,
		TCP_SYN_RECV,
		TCP_FIN_WAIT1,
		TCP_FIN_WAIT2,
		TCP_TIME_WAIT,
		TCP_CLOSE,
		TCP_CLOSE_WAIT,
		TCP_LAST_ACK,
		TCP_LISTEN,
		TCP_CLOSING,
		TCP_NEW_SYN_RECV
	};

	for (int i = 0; i < sizeof(states) / sizeof(states[0]); i++)
	{
		simulateTcpIpv4Socket(
			ipv4ToInt("127.0.0.1"),
			8080 + i,
			ipv4ToInt("192.168.1.1"),
			12345 + i,
			1000,
			2000,
			states[i]
		);
	}

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), sizeof(states) / sizeof(states[0]))
		<< "Should capture all TCP state events";

	// 验证每个TCP状态
	for (size_t i = 0; i < captured_events.size(); i++)
	{
		const auto &event = captured_events[i];
		EXPECT_EQ(event.log_type, LOG_TCP_IPV4) << "Event type should be TCP "
												   "IPv4";
		EXPECT_EQ(event.state, states[i])
			<< "TCP state should match for event " << i;
		EXPECT_EQ(event.lport, 8080 + i)
			<< "Local port should match for event " << i;
	}
}

// 测试错误处理
TEST_F(LsockBasicTest, ErrorHandling)
{
	// 测试空数据
	int result = test_callback(nullptr, nullptr, 0);
	EXPECT_EQ(result, -1) << "Null data should be rejected";

	// 测试数据大小不足
	char small_data[sizeof(struct BpfData) - 1];
	result = test_callback(nullptr, small_data, sizeof(small_data));
	EXPECT_EQ(result, -1) << "Incomplete data should be rejected";

	// 验证没有事件被捕获
	EXPECT_FALSE(event_received) << "No event should be received for invalid "
									"data";
	EXPECT_EQ(captured_events.size(), 0) << "No events should be captured for "
											"invalid data";
}

// 测试边界条件
TEST_F(LsockBasicTest, BoundaryConditions)
{
	// 测试极大值
	simulateTcpIpv4Socket(
		UINT_MAX,
		UINT16_MAX,
		UINT_MAX,
		UINT16_MAX,
		UINT_MAX,
		INT_MAX,
		TCP_ESTABLISHED
	);

	// 验证事件是否被捕获
	EXPECT_TRUE(event_received) << "Max value event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture max value event";

	if (!captured_events.empty())
	{
		const auto &event = captured_events[0];
		EXPECT_EQ(event.lip, UINT_MAX) << "Max local IP should match";
		EXPECT_EQ(event.lport, UINT16_MAX) << "Max local port should match";
		EXPECT_EQ(event.rip, UINT_MAX) << "Max remote IP should match";
		EXPECT_EQ(event.rport, UINT16_MAX) << "Max remote port should match";
		EXPECT_EQ(event.uid, UINT_MAX) << "Max UID should match";
		EXPECT_EQ(event.pid, INT_MAX) << "Max PID should match";
	}

	// 测试极小值
	captured_events.clear();
	event_received = false;

	simulateTcpIpv4Socket(0, 0, 0, 0, 0, 0, TCP_ESTABLISHED);

	EXPECT_TRUE(event_received) << "Min value event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture min value event";

	if (!captured_events.empty())
	{
		const auto &event = captured_events[0];
		EXPECT_EQ(event.lip, 0) << "Min local IP should match";
		EXPECT_EQ(event.lport, 0) << "Min local port should match";
		EXPECT_EQ(event.rip, 0) << "Min remote IP should match";
		EXPECT_EQ(event.rport, 0) << "Min remote port should match";
		EXPECT_EQ(event.uid, 0) << "Min UID should match";
		EXPECT_EQ(event.pid, 0) << "Min PID should match";
	}

	// 测试长路径名
	captured_events.clear();
	event_received = false;

	char long_path[108];
	memset(long_path, 'a', sizeof(long_path) - 1);
	long_path[sizeof(long_path) - 1] = '\0';

	simulateUnixSocket(1000, 2000, long_path);

	EXPECT_TRUE(event_received) << "Long path event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture long path event";

	if (!captured_events.empty())
	{
		const auto &event = captured_events[0];
		EXPECT_STREQ(event.unix_path, long_path) << "Long Unix socket path "
													"should match";
	}
}

// 测试性能
TEST_F(LsockBasicTest, Performance)
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
		simulateTcpIpv4Socket(
			ipv4ToInt("127.0.0.1"),
			8080 + i % 100,
			ipv4ToInt("192.168.1.1"),
			12345 + i % 100,
			1000 + i % 100,
			2000 + i % 100,
			TCP_ESTABLISHED
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

// 测试套接字统计信息
TEST_F(LsockBasicTest, SocketStatistics)
{
	// 模拟带有统计信息的TCP套接字
	struct BpfData event;
	memset(&event, 0, sizeof(event));

	event.lip = ipv4ToInt("127.0.0.1");
	event.rip = ipv4ToInt("192.168.1.1");
	event.lport = 8080;
	event.rport = 12345;
	event.uid = 1000;
	event.pid = 2000;
	strncpy(event.comm, "test_process", sizeof(event.comm) - 1);
	event.log_type = LOG_TCP_IPV4;
	event.state = TCP_ESTABLISHED;

	// 设置套接字统计信息
	event.sk_rcvbuf = 212992;
	event.sk_sndbuf = 212992;
	event.sk_wmem_queued = 0;
	event.sk_rmem_alloc = 0;
	event.sk_wmem_alloc = 0;
	event.sk_rcv_qlen = 0;
	event.sk_snd_qlen = 0;
	event.sk_err = 0;
	event.sk_err_soft = 0;

	test_callback(nullptr, &event, sizeof(event));

	// 验证事件是否被捕获
	EXPECT_TRUE(event_received) << "Socket statistics event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture socket statistics "
											"event";

	if (!captured_events.empty())
	{
		const auto &captured = captured_events[0];
		EXPECT_EQ(captured.sk_rcvbuf, 212992) << "Receive buffer size should "
												 "match";
		EXPECT_EQ(captured.sk_sndbuf, 212992) << "Send buffer size should "
												 "match";
		EXPECT_EQ(captured.sk_wmem_queued, 0) << "Write memory queued should "
												 "match";
		EXPECT_EQ(captured.sk_rmem_alloc, 0) << "Read memory allocated should "
												"match";
		EXPECT_EQ(captured.sk_wmem_alloc, 0) << "Write memory allocated should "
												"match";
		EXPECT_EQ(captured.sk_rcv_qlen, 0) << "Receive queue length should "
											  "match";
		EXPECT_EQ(captured.sk_snd_qlen, 0) << "Send queue length should match";
		EXPECT_EQ(captured.sk_err, 0) << "Socket error should match";
		EXPECT_EQ(captured.sk_err_soft, 0) << "Socket soft error should match";
	}
}

// 测试监听套接字
TEST_F(LsockBasicTest, ListeningSockets)
{
	// 模拟TCP监听套接字
	simulateTcpIpv4Socket(ipv4ToInt("0.0.0.0"), 80, 0, 0, 0, 1000, TCP_LISTEN);

	// 验证事件是否被捕获
	EXPECT_TRUE(event_received) << "Listening socket event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture listening socket "
											"event";

	if (!captured_events.empty())
	{
		const auto &event = captured_events[0];
		EXPECT_EQ(event.log_type, LOG_TCP_IPV4) << "Event type should be TCP "
												   "IPv4";
		EXPECT_EQ(event.lip, ipv4ToInt("0.0.0.0")) << "Local IP should be "
													  "wildcard";
		EXPECT_EQ(event.lport, 80) << "Local port should match";
		EXPECT_EQ(event.state, TCP_LISTEN) << "TCP state should be LISTEN";
	}
}

// 测试多个套接字的过滤
TEST_F(LsockBasicTest, SocketFiltering)
{
	// 模拟多个不同类型的套接字
	simulateTcpIpv4Socket(
		ipv4ToInt("127.0.0.1"),
		8080,
		ipv4ToInt("192.168.1.1"),
		12345,
		1000,
		2000,
		TCP_ESTABLISHED
	);

	simulateUdpIpv4Socket(
		ipv4ToInt("127.0.0.1"),
		8081,
		ipv4ToInt("192.168.1.1"),
		12346,
		1001,
		2001
	);

	simulateUnixSocket(1002, 2002, "/tmp/test.sock");

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 3) << "Should capture three events";

	// 模拟过滤：只保留TCP套接字
	std::vector<BpfData> tcp_sockets;
	for (const auto &event : captured_events)
	{
		if (event.log_type == LOG_TCP_IPV4 || event.log_type == LOG_TCP_IPV6)
		{
			tcp_sockets.push_back(event);
		}
	}

	// 验证过滤结果
	EXPECT_EQ(tcp_sockets.size(), 1) << "Should have 1 TCP socket";

	// 模拟过滤：只保留UDP套接字
	std::vector<BpfData> udp_sockets;
	for (const auto &event : captured_events)
	{
		if (event.log_type == LOG_UDP_IPV4 || event.log_type == LOG_UDP_IPV6)
		{
			udp_sockets.push_back(event);
		}
	}

	// 验证过滤结果
	EXPECT_EQ(udp_sockets.size(), 1) << "Should have 1 UDP socket";

	// 模拟过滤：只保留Unix套接字
	std::vector<BpfData> unix_sockets;
	for (const auto &event : captured_events)
	{
		if (event.log_type == LOG_UNIX)
		{
			unix_sockets.push_back(event);
		}
	}

	// 验证过滤结果
	EXPECT_EQ(unix_sockets.size(), 1) << "Should have 1 Unix socket";
}
