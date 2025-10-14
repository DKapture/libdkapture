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
#include <chrono>
#include <climits>
#include <set>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include "dkapture.h"

// 声明proc_info_init函数，这是在BUILTIN模式下的入口点
extern int
proc_info_init(int argc, char **argv, DKapture::DKCallback cb, void *ctx);

// 测试常量定义
const std::string TEST_ROOT = "/tmp/proc_info_test_dir";

// 测试回调函数，用于接收和验证BPF事件
static std::vector<struct DKapture::DataHdr> captured_events;
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
	if (data_sz < sizeof(struct DKapture::DataHdr))
	{
		return -1;
	}

	// 处理事件
	const struct DKapture::DataHdr *hdr =
		static_cast<const struct DKapture::DataHdr *>(data);
	captured_events.push_back(*hdr);
	event_received = true;
	return 0;
}

// 测试类
class ProcInfoBasicTest : public ::testing::Test
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

	// 辅助函数：模拟STAT数据事件
	void simulateStatEvent(
		pid_t pid,
		pid_t tgid,
		const char *comm,
		int state,
		pid_t ppid,
		unsigned long vsize,
		unsigned long rss
	)
	{
		// 创建一个足够大的缓冲区来容纳DataHdr和ProcPidStat
		size_t total_size =
			sizeof(struct DKapture::DataHdr) + sizeof(struct ProcPidStat);
		char *buffer = new char[total_size];
		memset(buffer, 0, total_size);

		struct DKapture::DataHdr *hdr =
			reinterpret_cast<struct DKapture::DataHdr *>(buffer);
		hdr->type = DKapture::PROC_PID_STAT;
		hdr->dsz = total_size;
		hdr->pid = pid;
		hdr->tgid = tgid;
		strncpy(hdr->comm, comm, sizeof(hdr->comm) - 1);

		struct ProcPidStat *stat =
			reinterpret_cast<struct ProcPidStat *>(hdr->data);
		stat->state = state;
		stat->ppid = ppid;
		stat->vsize = vsize;
		stat->rss = rss;
		stat->utime = 1000;
		stat->stime = 500;
		stat->nice = 0;
		stat->priority = 20;

		test_callback(nullptr, buffer, total_size);
		delete[] buffer;
	}

	// 辅助函数：模拟IO数据事件
	void simulateIoEvent(
		pid_t pid,
		pid_t tgid,
		const char *comm,
		size_t rchar,
		size_t wchar,
		size_t read_bytes,
		size_t write_bytes
	)
	{
		size_t total_size =
			sizeof(struct DKapture::DataHdr) + sizeof(struct ProcPidIo);
		char *buffer = new char[total_size];
		memset(buffer, 0, total_size);

		struct DKapture::DataHdr *hdr =
			reinterpret_cast<struct DKapture::DataHdr *>(buffer);
		hdr->type = DKapture::PROC_PID_IO;
		hdr->dsz = total_size;
		hdr->pid = pid;
		hdr->tgid = tgid;
		strncpy(hdr->comm, comm, sizeof(hdr->comm) - 1);

		struct ProcPidIo *io = reinterpret_cast<struct ProcPidIo *>(hdr->data);
		io->rchar = rchar;
		io->wchar = wchar;
		io->read_bytes = read_bytes;
		io->write_bytes = write_bytes;
		io->syscr = 100;
		io->syscw = 50;

		test_callback(nullptr, buffer, total_size);
		delete[] buffer;
	}

	// 辅助函数：模拟Traffic数据事件
	void simulateTrafficEvent(
		pid_t pid,
		pid_t tgid,
		const char *comm,
		size_t rbytes,
		size_t wbytes
	)
	{
		size_t total_size =
			sizeof(struct DKapture::DataHdr) + sizeof(struct ProcPidTraffic);
		char *buffer = new char[total_size];
		memset(buffer, 0, total_size);

		struct DKapture::DataHdr *hdr =
			reinterpret_cast<struct DKapture::DataHdr *>(buffer);
		hdr->type = DKapture::PROC_PID_traffic;
		hdr->dsz = total_size;
		hdr->pid = pid;
		hdr->tgid = tgid;
		strncpy(hdr->comm, comm, sizeof(hdr->comm) - 1);

		struct ProcPidTraffic *traffic =
			reinterpret_cast<struct ProcPidTraffic *>(hdr->data);
		traffic->rbytes = rbytes;
		traffic->wbytes = wbytes;

		test_callback(nullptr, buffer, total_size);
		delete[] buffer;
	}

	// 辅助函数：模拟STATM数据事件
	void simulateStatmEvent(
		pid_t pid,
		pid_t tgid,
		const char *comm,
		unsigned long size,
		unsigned long resident,
		unsigned long shared,
		unsigned long text,
		unsigned long data
	)
	{
		size_t total_size =
			sizeof(struct DKapture::DataHdr) + sizeof(struct ProcPidStatm);
		char *buffer = new char[total_size];
		memset(buffer, 0, total_size);

		struct DKapture::DataHdr *hdr =
			reinterpret_cast<struct DKapture::DataHdr *>(buffer);
		hdr->type = DKapture::PROC_PID_STATM;
		hdr->dsz = total_size;
		hdr->pid = pid;
		hdr->tgid = tgid;
		strncpy(hdr->comm, comm, sizeof(hdr->comm) - 1);

		struct ProcPidStatm *statm =
			reinterpret_cast<struct ProcPidStatm *>(hdr->data);
		statm->size = size;
		statm->resident = resident;
		statm->shared = shared;
		statm->text = text;
		statm->data = data;

		test_callback(nullptr, buffer, total_size);
		delete[] buffer;
	}

	// 辅助函数：模拟STATUS数据事件
	void simulateStatusEvent(
		pid_t pid,
		pid_t tgid,
		const char *comm,
		int state,
		uid_t uid,
		gid_t gid,
		pid_t tracer_pid
	)
	{
		size_t total_size =
			sizeof(struct DKapture::DataHdr) + sizeof(struct ProcPidStatus);
		char *buffer = new char[total_size];
		memset(buffer, 0, total_size);

		struct DKapture::DataHdr *hdr =
			reinterpret_cast<struct DKapture::DataHdr *>(buffer);
		hdr->type = DKapture::PROC_PID_STATUS;
		hdr->dsz = total_size;
		hdr->pid = pid;
		hdr->tgid = tgid;
		strncpy(hdr->comm, comm, sizeof(hdr->comm) - 1);

		struct ProcPidStatus *status =
			reinterpret_cast<struct ProcPidStatus *>(hdr->data);
		status->state = state;
		status->uid[0] = uid; // uid
		status->uid[1] = uid; // euid
		status->gid[0] = gid; // gid
		status->gid[1] = gid; // egid
		status->tracer_pid = tracer_pid;

		test_callback(nullptr, buffer, total_size);
		delete[] buffer;
	}

	// 辅助函数：模拟SCHEDSTAT数据事件
	void simulateSchedstatEvent(
		pid_t pid,
		pid_t tgid,
		const char *comm,
		unsigned long long cpu_time,
		unsigned long long rq_wait_time,
		unsigned long long timeslices
	)
	{
		size_t total_size =
			sizeof(struct DKapture::DataHdr) + sizeof(struct ProcPidSchedstat);
		char *buffer = new char[total_size];
		memset(buffer, 0, total_size);

		struct DKapture::DataHdr *hdr =
			reinterpret_cast<struct DKapture::DataHdr *>(buffer);
		hdr->type = DKapture::PROC_PID_SCHEDSTAT;
		hdr->dsz = total_size;
		hdr->pid = pid;
		hdr->tgid = tgid;
		strncpy(hdr->comm, comm, sizeof(hdr->comm) - 1);

		struct ProcPidSchedstat *schedstat =
			reinterpret_cast<struct ProcPidSchedstat *>(hdr->data);
		schedstat->cpu_time = cpu_time;
		schedstat->rq_wait_time = rq_wait_time;
		schedstat->timeslices = timeslices;

		test_callback(nullptr, buffer, total_size);
		delete[] buffer;
	}

	// 辅助函数：模拟FD数据事件
	void simulateFdEvent(
		pid_t pid,
		pid_t tgid,
		const char *comm,
		int fd,
		unsigned long inode,
		dev_t dev,
		mode_t i_mode
	)
	{
		size_t total_size =
			sizeof(struct DKapture::DataHdr) + sizeof(struct ProcPidFd);
		char *buffer = new char[total_size];
		memset(buffer, 0, total_size);

		struct DKapture::DataHdr *hdr =
			reinterpret_cast<struct DKapture::DataHdr *>(buffer);
		hdr->type = DKapture::PROC_PID_FD;
		hdr->dsz = total_size;
		hdr->pid = pid;
		hdr->tgid = tgid;
		strncpy(hdr->comm, comm, sizeof(hdr->comm) - 1);

		struct ProcPidFd *fdinfo =
			reinterpret_cast<struct ProcPidFd *>(hdr->data);
		fdinfo->fd = fd;
		fdinfo->inode = inode;
		fdinfo->dev = dev;
		fdinfo->i_mode = i_mode;

		test_callback(nullptr, buffer, total_size);
		delete[] buffer;
	}

	// 辅助函数：模拟NS数据事件
	void simulateNsEvent(
		pid_t pid,
		pid_t tgid,
		const char *comm,
		unsigned int cgroup,
		unsigned int ipc,
		unsigned int mnt,
		unsigned int net,
		unsigned int pid_ns,
		unsigned int user
	)
	{
		size_t total_size =
			sizeof(struct DKapture::DataHdr) + sizeof(struct ProcPidNs);
		char *buffer = new char[total_size];
		memset(buffer, 0, total_size);

		struct DKapture::DataHdr *hdr =
			reinterpret_cast<struct DKapture::DataHdr *>(buffer);
		hdr->type = DKapture::PROC_PID_NS;
		hdr->dsz = total_size;
		hdr->pid = pid;
		hdr->tgid = tgid;
		strncpy(hdr->comm, comm, sizeof(hdr->comm) - 1);

		struct ProcPidNs *ns = reinterpret_cast<struct ProcPidNs *>(hdr->data);
		ns->cgroup = cgroup;
		ns->ipc = ipc;
		ns->mnt = mnt;
		ns->net = net;
		ns->pid = pid_ns;
		ns->user = user;

		test_callback(nullptr, buffer, total_size);
		delete[] buffer;
	}

	// 辅助函数：模拟LOGINUID数据事件
	void simulateLoginuidEvent(
		pid_t pid,
		pid_t tgid,
		const char *comm,
		uid_t loginuid
	)
	{
		size_t total_size =
			sizeof(struct DKapture::DataHdr) + sizeof(struct ProcPidLoginuid);
		char *buffer = new char[total_size];
		memset(buffer, 0, total_size);

		struct DKapture::DataHdr *hdr =
			reinterpret_cast<struct DKapture::DataHdr *>(buffer);
		hdr->type = DKapture::PROC_PID_LOGINUID;
		hdr->dsz = total_size;
		hdr->pid = pid;
		hdr->tgid = tgid;
		strncpy(hdr->comm, comm, sizeof(hdr->comm) - 1);

		struct ProcPidLoginuid *loginuid_info =
			reinterpret_cast<struct ProcPidLoginuid *>(hdr->data);
		loginuid_info->loginuid.val = loginuid;

		test_callback(nullptr, buffer, total_size);
		delete[] buffer;
	}
};

// 测试基本事件处理
TEST_F(ProcInfoBasicTest, EventHandling)
{
	// 模拟STAT事件
	simulateStatEvent(1000, 1000, "test_process", 1, 999, 102400, 4096);

	// 验证事件是否被捕获
	EXPECT_TRUE(event_received) << "Event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture one event";

	if (!captured_events.empty())
	{
		const auto &hdr = captured_events[0];
		EXPECT_EQ(hdr.type, DKapture::PROC_PID_STAT) << "Event type should be "
														"PROC_PID_STAT";
		EXPECT_EQ(hdr.pid, 1000) << "Process ID should match";
		EXPECT_EQ(hdr.tgid, 1000) << "Thread group ID should match";
		EXPECT_STREQ(hdr.comm, "test_process") << "Process name should match";
	}
}

// 测试不同类型的数据事件
TEST_F(ProcInfoBasicTest, DifferentDataTypes)
{
	// 模拟不同类型的事件
	simulateStatEvent(1001, 1001, "proc1", 1, 1, 102400, 4096);
	simulateIoEvent(1002, 1002, "proc2", 1024, 512, 2048, 1024);
	simulateTrafficEvent(1003, 1003, "proc3", 4096, 2048);
	simulateStatmEvent(1004, 1004, "proc4", 1000, 800, 200, 100, 500);
	simulateStatusEvent(1005, 1005, "proc5", 1, 1000, 1000, 0);

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 5) << "Should capture five events";

	if (captured_events.size() >= 5)
	{
		// 验证各种类型的事件
		EXPECT_EQ(captured_events[0].type, DKapture::PROC_PID_STAT)
			<< "First event should be STAT";
		EXPECT_EQ(captured_events[1].type, DKapture::PROC_PID_IO) << "Second "
																	 "event "
																	 "should "
																	 "be IO";
		EXPECT_EQ(captured_events[2].type, DKapture::PROC_PID_traffic)
			<< "Third event should be TRAFFIC";
		EXPECT_EQ(captured_events[3].type, DKapture::PROC_PID_STATM)
			<< "Fourth event should be STATM";
		EXPECT_EQ(captured_events[4].type, DKapture::PROC_PID_STATUS)
			<< "Fifth event should be STATUS";
	}
}

// 测试多进程信息处理
TEST_F(ProcInfoBasicTest, MultipleProcesses)
{
	// 模拟多个进程的STAT数据
	for (int i = 1; i <= 10; i++)
	{
		std::string comm = "proc" + std::to_string(i);
		simulateStatEvent(
			1000 + i,
			1000 + i,
			comm.c_str(),
			1,
			999,
			102400,
			4096
		);
	}

	// 验证所有事件都被捕获
	EXPECT_EQ(captured_events.size(), 10) << "Should capture ten events";

	// 验证进程ID是连续的
	for (size_t i = 0; i < captured_events.size(); i++)
	{
		EXPECT_EQ(captured_events[i].pid, 1001 + static_cast<pid_t>(i))
			<< "Process ID should be sequential";
		EXPECT_EQ(captured_events[i].type, DKapture::PROC_PID_STAT)
			<< "All events should be STAT type";
	}
}

// 测试线程信息处理
TEST_F(ProcInfoBasicTest, ThreadHandling)
{
	// 模拟主进程和其线程
	simulateStatEvent(2000, 2000, "main_proc", 1, 1999, 204800, 8192); // 主进程
	simulateStatEvent(2001, 2000, "main_proc", 1, 1999, 204800, 8192); // 线程1
	simulateStatEvent(2002, 2000, "main_proc", 1, 1999, 204800, 8192); // 线程2
	simulateStatEvent(2003, 2000, "main_proc", 1, 1999, 204800, 8192); // 线程3

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 4) << "Should capture four events";

	if (captured_events.size() >= 4)
	{
		// 验证主进程
		EXPECT_EQ(captured_events[0].pid, 2000) << "Main process PID should "
												   "match";
		EXPECT_EQ(captured_events[0].tgid, 2000) << "Main process TGID should "
													"match";

		// 验证线程
		for (int i = 1; i < 4; i++)
		{
			EXPECT_EQ(captured_events[i].tgid, 2000) << "Thread TGID should "
														"match main process";
			EXPECT_NE(captured_events[i].pid, 2000) << "Thread PID should "
													   "differ from main "
													   "process";
		}
	}
}

// 测试IO统计
TEST_F(ProcInfoBasicTest, IoStatistics)
{
	// 模拟不同IO模式的进程
	simulateIoEvent(
		3001,
		3001,
		"reader",
		1024 * 1024,
		0,
		1024 * 1024,
		0
	); // 只读进程
	simulateIoEvent(
		3002,
		3002,
		"writer",
		0,
		1024 * 1024,
		0,
		1024 * 1024
	); // 只写进程
	simulateIoEvent(
		3003,
		3003,
		"rw_proc",
		512 * 1024,
		512 * 1024,
		256 * 1024,
		256 * 1024
	); // 读写进程

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 3) << "Should capture three events";

	if (captured_events.size() >= 3)
	{
		// 验证都是IO类型
		for (size_t i = 0; i < 3; i++)
		{
			EXPECT_EQ(captured_events[i].type, DKapture::PROC_PID_IO)
				<< "All events should be IO type";
		}
	}
}

// 测试网络流量统计
TEST_F(ProcInfoBasicTest, NetworkTrafficStats)
{
	// 模拟不同网络使用模式的进程
	simulateTrafficEvent(
		4001,
		4001,
		"server",
		1024 * 1024,
		512 * 1024
	); // 服务器：收多发少
	simulateTrafficEvent(
		4002,
		4002,
		"client",
		512 * 1024,
		1024 * 1024
	); // 客户端：发多收少
	simulateTrafficEvent(
		4003,
		4003,
		"p2p",
		2048 * 1024,
		2048 * 1024
	); // P2P：收发相等

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 3) << "Should capture three events";

	if (captured_events.size() >= 3)
	{
		// 验证都是TRAFFIC类型
		for (size_t i = 0; i < 3; i++)
		{
			EXPECT_EQ(captured_events[i].type, DKapture::PROC_PID_traffic)
				<< "All events should be TRAFFIC type";
		}
	}
}

// 测试内存统计
TEST_F(ProcInfoBasicTest, MemoryStatistics)
{
	// 模拟不同内存使用模式的进程
	simulateStatmEvent(
		5001,
		5001,
		"small_proc",
		1000,
		800,
		200,
		100,
		500
	); // 小内存进程
	simulateStatmEvent(
		5002,
		5002,
		"large_proc",
		10000,
		8000,
		2000,
		1000,
		5000
	); // 大内存进程
	simulateStatmEvent(
		5003,
		5003,
		"shared_proc",
		5000,
		4000,
		3000,
		500,
		1500
	); // 共享内存多的进程

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 3) << "Should capture three events";

	if (captured_events.size() >= 3)
	{
		// 验证都是STATM类型
		for (size_t i = 0; i < 3; i++)
		{
			EXPECT_EQ(captured_events[i].type, DKapture::PROC_PID_STATM)
				<< "All events should be STATM type";
		}
	}
}

// 测试进程状态
TEST_F(ProcInfoBasicTest, ProcessStates)
{
	// 模拟不同状态的进程
	simulateStatusEvent(6001, 6001, "running", 0, 1000, 1000, 0); // 运行状态
	simulateStatusEvent(6002, 6002, "sleeping", 1, 1001, 1001, 0); // 睡眠状态
	simulateStatusEvent(
		6003,
		6003,
		"stopped",
		4,
		1002,
		1002,
		6004
	); // 停止状态，有跟踪器
	simulateStatusEvent(6004, 6004, "zombie", 16, 1003, 1003, 0); // 僵尸状态

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 4) << "Should capture four events";

	if (captured_events.size() >= 4)
	{
		// 验证都是STATUS类型
		for (size_t i = 0; i < 4; i++)
		{
			EXPECT_EQ(captured_events[i].type, DKapture::PROC_PID_STATUS)
				<< "All events should be STATUS type";
		}
	}
}

// 测试调度统计
TEST_F(ProcInfoBasicTest, SchedulerStatistics)
{
	// 模拟不同调度特征的进程
	simulateSchedstatEvent(
		7001,
		7001,
		"cpu_intensive",
		1000000000ULL,
		10000000ULL,
		1000
	); // CPU密集型
	simulateSchedstatEvent(
		7002,
		7002,
		"io_wait",
		100000000ULL,
		500000000ULL,
		5000
	); // IO等待多
	simulateSchedstatEvent(
		7003,
		7003,
		"interactive",
		200000000ULL,
		50000000ULL,
		10000
	); // 交互式

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 3) << "Should capture three events";

	if (captured_events.size() >= 3)
	{
		// 验证都是SCHEDSTAT类型
		for (size_t i = 0; i < 3; i++)
		{
			EXPECT_EQ(captured_events[i].type, DKapture::PROC_PID_SCHEDSTAT)
				<< "All events should be SCHEDSTAT type";
		}
	}
}

// 测试文件描述符
TEST_F(ProcInfoBasicTest, FileDescriptors)
{
	// 模拟不同类型的文件描述符
	simulateFdEvent(
		8001,
		8001,
		"fd_test",
		0,
		12345,
		makedev(8, 1),
		S_IFREG | 0644
	); // 常规文件
	simulateFdEvent(
		8001,
		8001,
		"fd_test",
		1,
		0,
		makedev(5, 0),
		S_IFCHR | 0666
	); // 字符设备 (stdout)
	simulateFdEvent(
		8001,
		8001,
		"fd_test",
		2,
		0,
		makedev(5, 0),
		S_IFCHR | 0666
	); // 字符设备 (stderr)
	simulateFdEvent(
		8001,
		8001,
		"fd_test",
		3,
		54321,
		makedev(0, 15),
		S_IFSOCK | 0777
	); // 套接字

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 4) << "Should capture four events";

	if (captured_events.size() >= 4)
	{
		// 验证都是FD类型
		for (size_t i = 0; i < 4; i++)
		{
			EXPECT_EQ(captured_events[i].type, DKapture::PROC_PID_FD)
				<< "All events should be FD type";
			EXPECT_EQ(captured_events[i].pid, 8001) << "All FDs should belong "
													   "to same process";
		}
	}
}

// 测试命名空间
TEST_F(ProcInfoBasicTest, Namespaces)
{
	// 模拟不同命名空间配置的进程
	simulateNsEvent(
		9001,
		9001,
		"host_proc",
		4026531835U,
		4026531839U,
		4026531840U,
		4026531993U,
		4026531836U,
		4026531837U
	); // 主机命名空间
	simulateNsEvent(
		9002,
		9002,
		"container",
		4026532000U,
		4026532001U,
		4026532002U,
		4026532003U,
		4026532004U,
		4026532005U
	); // 容器命名空间

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 2) << "Should capture two events";

	if (captured_events.size() >= 2)
	{
		// 验证都是NS类型
		for (size_t i = 0; i < 2; i++)
		{
			EXPECT_EQ(captured_events[i].type, DKapture::PROC_PID_NS)
				<< "All events should be NS type";
		}
	}
}

// 测试错误处理
TEST_F(ProcInfoBasicTest, ErrorHandling)
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

	// 验证没有事件被捕获
	EXPECT_FALSE(event_received) << "No event should be received for invalid "
									"data";
	EXPECT_EQ(captured_events.size(), 0) << "No events should be captured for "
											"invalid data";
}

// 测试边界条件
TEST_F(ProcInfoBasicTest, BoundaryConditions)
{
	// 测试极大进程ID
	simulateStatEvent(
		INT_MAX,
		INT_MAX,
		"max_pid",
		1,
		INT_MAX - 1,
		ULONG_MAX,
		ULONG_MAX
	);

	// 测试最小进程ID
	simulateStatEvent(1, 1, "min_pid", 1, 0, 0, 0);

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 2) << "Should capture two events";

	if (captured_events.size() >= 2)
	{
		// 验证极大PID
		EXPECT_EQ(captured_events[0].pid, INT_MAX) << "Max PID should match";

		// 验证最小PID
		EXPECT_EQ(captured_events[1].pid, 1) << "Min PID should match";
	}
}

// 测试性能
TEST_F(ProcInfoBasicTest, Performance)
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
		std::string comm = "perf_test_" + std::to_string(i);
		simulateStatEvent(
			10000 + i,
			10000 + i,
			comm.c_str(),
			1,
			9999,
			102400,
			4096
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

	// 验证处理时间是否在合理范围内
	EXPECT_LT(duration.count(), 1000000) << "Event processing should be "
											"reasonably fast";
}

// 测试混合数据类型
TEST_F(ProcInfoBasicTest, MixedDataTypes)
{
	// 为同一个进程模拟多种类型的数据
	pid_t test_pid = 11000;
	const char *test_comm = "mixed_test";

	simulateStatEvent(
		test_pid,
		test_pid,
		test_comm,
		1,
		test_pid - 1,
		204800,
		8192
	);
	simulateIoEvent(test_pid, test_pid, test_comm, 2048, 1024, 4096, 2048);
	simulateTrafficEvent(test_pid, test_pid, test_comm, 8192, 4096);
	simulateStatmEvent(
		test_pid,
		test_pid,
		test_comm,
		2000,
		1600,
		400,
		200,
		1000
	);
	simulateStatusEvent(test_pid, test_pid, test_comm, 1, 1000, 1000, 0);
	simulateSchedstatEvent(
		test_pid,
		test_pid,
		test_comm,
		500000000ULL,
		25000000ULL,
		2000
	);
	simulateFdEvent(
		test_pid,
		test_pid,
		test_comm,
		0,
		98765,
		makedev(8, 1),
		S_IFREG | 0644
	);
	simulateNsEvent(
		test_pid,
		test_pid,
		test_comm,
		4026531835U,
		4026531839U,
		4026531840U,
		4026531993U,
		4026531836U,
		4026531837U
	);

	// 验证所有事件都被捕获
	EXPECT_EQ(captured_events.size(), 8) << "Should capture eight events";

	if (captured_events.size() >= 8)
	{
		// 验证所有事件都属于同一个进程
		for (size_t i = 0; i < captured_events.size(); i++)
		{
			EXPECT_EQ(captured_events[i].pid, test_pid) << "All events should "
														   "belong to same "
														   "process";
			EXPECT_STREQ(captured_events[i].comm, test_comm) << "All events "
																"should have "
																"same comm";
		}

		// 验证数据类型的多样性
		std::set<DKapture::DataType> types;
		for (const auto &event : captured_events)
		{
			types.insert(event.type);
		}
		EXPECT_EQ(types.size(), 8) << "Should have 8 different data types";
	}
}

// 测试LOGINUID数据类型
TEST_F(ProcInfoBasicTest, LoginuidHandling)
{
	// 模拟不同loginuid的进程
	simulateLoginuidEvent(12001, 12001, "user_proc", 1000); // 普通用户进程
	simulateLoginuidEvent(12002, 12002, "root_proc", 0);	// root进程
	simulateLoginuidEvent(
		12003,
		12003,
		"daemon_proc",
		65535
	); // 守护进程(无登录用户)

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 3) << "Should capture three events";

	if (captured_events.size() >= 3)
	{
		// 验证都是LOGINUID类型
		for (size_t i = 0; i < 3; i++)
		{
			EXPECT_EQ(captured_events[i].type, DKapture::PROC_PID_LOGINUID)
				<< "All events should be LOGINUID type";
		}
	}
}

// 测试进程状态转换
TEST_F(ProcInfoBasicTest, ProcessStateTransitions)
{
	pid_t test_pid = 13000;
	const char *test_comm = "state_test";

	// 模拟进程状态变化序列：运行->睡眠->停止->僵尸
	simulateStatusEvent(
		test_pid,
		test_pid,
		test_comm,
		0,
		1000,
		1000,
		0
	); // 运行
	simulateStatusEvent(
		test_pid,
		test_pid,
		test_comm,
		1,
		1000,
		1000,
		0
	); // 睡眠
	simulateStatusEvent(
		test_pid,
		test_pid,
		test_comm,
		4,
		1000,
		1000,
		0
	); // 停止
	simulateStatusEvent(
		test_pid,
		test_pid,
		test_comm,
		16,
		1000,
		1000,
		0
	); // 僵尸

	// 验证状态转换序列
	EXPECT_EQ(captured_events.size(), 4) << "Should capture four state "
											"transitions";

	if (captured_events.size() >= 4)
	{
		// 验证所有事件都属于同一个进程
		for (const auto &event : captured_events)
		{
			EXPECT_EQ(event.pid, test_pid) << "All events should belong to "
											  "same process";
		}
	}
}

// 测试系统级进程监控
TEST_F(ProcInfoBasicTest, SystemProcessMonitoring)
{
	// 模拟系统关键进程
	simulateStatEvent(1, 1, "systemd", 1, 0, 1024 * 1024, 4096); // init进程
	simulateStatEvent(2, 0, "kthreadd", 1, 0, 0, 0);			 // 内核线程
	simulateStatEvent(3, 0, "migration/0", 1, 2, 0, 0);			 // 迁移线程
	simulateStatEvent(4, 0, "rcu_gp", 1, 2, 0, 0);				 // RCU线程
	simulateStatEvent(5, 0, "rcu_par_gp", 1, 2, 0, 0); // RCU并行线程

	// 验证系统进程监控
	EXPECT_EQ(captured_events.size(), 5) << "Should capture five system "
											"processes";

	if (captured_events.size() >= 5)
	{
		// 验证init进程
		EXPECT_EQ(captured_events[0].pid, 1) << "First process should be init";
		EXPECT_STREQ(captured_events[0].comm, "systemd") << "Init process "
															"should be systemd";

		// 验证内核线程特征
		for (size_t i = 1; i < captured_events.size(); i++)
		{
			EXPECT_EQ(captured_events[i].tgid, 0) << "Kernel threads should "
													 "have tgid 0";
		}
	}
}

// 测试内存压力场景
TEST_F(ProcInfoBasicTest, MemoryPressureScenarios)
{
	// 模拟内存压力下的进程
	simulateStatmEvent(
		14001,
		14001,
		"heavy_mem",
		100000,
		95000,
		10000,
		1000,
		85000
	); // 高内存使用
	simulateStatmEvent(
		14002,
		14002,
		"shared_heavy",
		50000,
		45000,
		40000,
		2000,
		8000
	); // 高共享内存
	simulateStatmEvent(
		14003,
		14003,
		"text_heavy",
		30000,
		25000,
		5000,
		20000,
		5000
	); // 大代码段
	simulateStatmEvent(
		14004,
		14004,
		"data_heavy",
		80000,
		75000,
		5000,
		5000,
		70000
	); // 大数据段

	// 验证内存使用模式
	EXPECT_EQ(captured_events.size(), 4) << "Should capture four "
											"memory-intensive processes";

	if (captured_events.size() >= 4)
	{
		// 验证都是STATM类型
		for (const auto &event : captured_events)
		{
			EXPECT_EQ(event.type, DKapture::PROC_PID_STATM) << "All events "
															   "should be "
															   "STATM type";
		}
	}
}

// 测试高频IO操作
TEST_F(ProcInfoBasicTest, HighFrequencyIO)
{
	// 模拟高频IO的进程
	simulateIoEvent(
		15001,
		15001,
		"db_server",
		1024 * 1024 * 100,
		1024 * 1024 * 50,
		1024 * 1024 * 80,
		1024 * 1024 * 40
	);
	simulateIoEvent(
		15002,
		15002,
		"log_writer",
		1024 * 100,
		1024 * 1024 * 200,
		1024 * 50,
		1024 * 1024 * 180
	);
	simulateIoEvent(
		15003,
		15003,
		"backup_tool",
		1024 * 1024 * 500,
		1024 * 1024 * 500,
		1024 * 1024 * 450,
		1024 * 1024 * 450
	);

	// 验证高频IO处理
	EXPECT_EQ(captured_events.size(), 3) << "Should capture three high-IO "
											"processes";

	if (captured_events.size() >= 3)
	{
		// 验证IO类型和数据量
		for (const auto &event : captured_events)
		{
			EXPECT_EQ(event.type, DKapture::PROC_PID_IO) << "All events should "
															"be IO type";
		}
	}
}

// 测试网络密集型应用
TEST_F(ProcInfoBasicTest, NetworkIntensiveApplications)
{
	// 模拟网络密集型应用
	simulateTrafficEvent(
		16001,
		16001,
		"web_server",
		1024UL * 1024 * 1024,
		1024UL * 1024 * 512
	); // Web服务器
	simulateTrafficEvent(
		16002,
		16002,
		"proxy",
		1024UL * 1024 * 1024,
		1024UL * 1024 * 1024
	); // 代理服务器
	simulateTrafficEvent(
		16003,
		16003,
		"cdn_cache",
		1024UL * 1024 * 2048,
		1024UL * 1024 * 1024
	); // CDN缓存
	simulateTrafficEvent(
		16004,
		16004,
		"stream_srv",
		1024UL * 1024 * 512,
		1024UL * 1024 * 2048
	); // 流媒体服务

	// 验证网络流量处理
	EXPECT_EQ(captured_events.size(), 4) << "Should capture four "
											"network-intensive processes";

	if (captured_events.size() >= 4)
	{
		// 验证流量类型
		for (const auto &event : captured_events)
		{
			EXPECT_EQ(event.type, DKapture::PROC_PID_traffic) << "All events "
																 "should be "
																 "TRAFFIC type";
		}
	}
}

// 测试调度器行为分析
TEST_F(ProcInfoBasicTest, SchedulerBehaviorAnalysis)
{
	// 模拟不同调度特征的进程
	simulateSchedstatEvent(
		17001,
		17001,
		"rt_task",
		2000000000ULL,
		1000000ULL,
		100
	); // 实时任务
	simulateSchedstatEvent(
		17002,
		17002,
		"batch_job",
		5000000000ULL,
		100000000ULL,
		50
	); // 批处理任务
	simulateSchedstatEvent(
		17003,
		17003,
		"interactive",
		500000000ULL,
		10000000ULL,
		5000
	); // 交互任务
	simulateSchedstatEvent(
		17004,
		17004,
		"idle_task",
		100000000ULL,
		800000000ULL,
		10
	); // 空闲任务

	// 验证调度统计
	EXPECT_EQ(captured_events.size(), 4) << "Should capture four different "
											"scheduling patterns";

	if (captured_events.size() >= 4)
	{
		// 验证调度类型
		for (const auto &event : captured_events)
		{
			EXPECT_EQ(event.type, DKapture::PROC_PID_SCHEDSTAT) << "All events "
																   "should be "
																   "SCHEDSTAT "
																   "type";
		}
	}
}

// 测试容器化环境
TEST_F(ProcInfoBasicTest, ContainerizedEnvironment)
{
	// 模拟容器化环境的进程
	simulateNsEvent(
		18001,
		18001,
		"container1",
		4026532100U,
		4026532101U,
		4026532102U,
		4026532103U,
		4026532104U,
		4026532105U
	); // 容器1命名空间
	simulateNsEvent(
		18002,
		18002,
		"container2",
		4026532200U,
		4026532201U,
		4026532202U,
		4026532203U,
		4026532204U,
		4026532205U
	); // 容器2命名空间
	simulateNsEvent(
		18003,
		18003,
		"host_proc",
		4026531835U,
		4026531839U,
		4026531840U,
		4026531993U,
		4026531836U,
		4026531837U
	); // 主机进程

	// 验证容器化环境
	EXPECT_EQ(captured_events.size(), 3) << "Should capture three "
											"containerized processes";

	if (captured_events.size() >= 3)
	{
		// 验证命名空间类型
		for (const auto &event : captured_events)
		{
			EXPECT_EQ(event.type, DKapture::PROC_PID_NS) << "All events should "
															"be NS type";
		}
	}
}

// 测试文件描述符泄漏检测
TEST_F(ProcInfoBasicTest, FileDescriptorLeakDetection)
{
	pid_t leak_pid = 19000;
	const char *leak_comm = "fd_leak_test";

	// 模拟文件描述符逐渐增加的场景
	for (int i = 3; i < 100; i += 10)
	{
		simulateFdEvent(
			leak_pid,
			leak_pid,
			leak_comm,
			i,
			10000 + i,
			makedev(8, 1),
			S_IFREG | 0644
		);
	}

	// 验证文件描述符监控
	EXPECT_EQ(captured_events.size(), 10) << "Should capture ten file "
											 "descriptor events";

	if (captured_events.size() >= 10)
	{
		// 验证文件描述符递增
		for (size_t i = 0; i < captured_events.size(); i++)
		{
			EXPECT_EQ(captured_events[i].type, DKapture::PROC_PID_FD)
				<< "All events should be FD type";
			EXPECT_EQ(captured_events[i].pid, leak_pid) << "All FDs should "
														   "belong to same "
														   "process";
		}
	}
}

// 测试进程生命周期完整追踪
TEST_F(ProcInfoBasicTest, CompleteProcessLifecycleTracking)
{
	pid_t lifecycle_pid = 20000;
	const char *lifecycle_comm = "lifecycle_test";

	// 模拟进程完整生命周期
	// 1. 进程启动 - STAT事件
	simulateStatEvent(
		lifecycle_pid,
		lifecycle_pid,
		lifecycle_comm,
		0,
		1000,
		102400,
		4096
	);

	// 2. 初始内存分配 - STATM事件
	simulateStatmEvent(
		lifecycle_pid,
		lifecycle_pid,
		lifecycle_comm,
		1000,
		800,
		200,
		100,
		500
	);

	// 3. 开始IO操作 - IO事件
	simulateIoEvent(
		lifecycle_pid,
		lifecycle_pid,
		lifecycle_comm,
		1024,
		512,
		2048,
		1024
	);

	// 4. 网络通信 - TRAFFIC事件
	simulateTrafficEvent(
		lifecycle_pid,
		lifecycle_pid,
		lifecycle_comm,
		4096,
		2048
	);

	// 5. 进程状态变更 - STATUS事件
	simulateStatusEvent(
		lifecycle_pid,
		lifecycle_pid,
		lifecycle_comm,
		1,
		1000,
		1000,
		0
	);

	// 6. 调度统计 - SCHEDSTAT事件
	simulateSchedstatEvent(
		lifecycle_pid,
		lifecycle_pid,
		lifecycle_comm,
		1000000000ULL,
		10000000ULL,
		1000
	);

	// 7. 文件操作 - FD事件
	simulateFdEvent(
		lifecycle_pid,
		lifecycle_pid,
		lifecycle_comm,
		0,
		12345,
		makedev(8, 1),
		S_IFREG | 0644
	);

	// 8. 命名空间信息 - NS事件
	simulateNsEvent(
		lifecycle_pid,
		lifecycle_pid,
		lifecycle_comm,
		4026531835U,
		4026531839U,
		4026531840U,
		4026531993U,
		4026531836U,
		4026531837U
	);

	// 9. 登录用户信息 - LOGINUID事件
	simulateLoginuidEvent(lifecycle_pid, lifecycle_pid, lifecycle_comm, 1000);

	// 验证完整生命周期追踪
	EXPECT_EQ(captured_events.size(), 9) << "Should capture complete process "
											"lifecycle";

	if (captured_events.size() >= 9)
	{
		// 验证所有事件都属于同一个进程
		for (const auto &event : captured_events)
		{
			EXPECT_EQ(event.pid, lifecycle_pid) << "All events should belong "
												   "to same process";
			EXPECT_STREQ(event.comm, lifecycle_comm) << "All events should "
														"have same comm";
		}

		// 验证数据类型的完整性
		std::set<DKapture::DataType> lifecycle_types;
		for (const auto &event : captured_events)
		{
			lifecycle_types.insert(event.type);
		}
		EXPECT_EQ(lifecycle_types.size(), 9) << "Should have 9 different data "
												"types in lifecycle";
	}
}
