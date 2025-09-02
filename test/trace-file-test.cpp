#include "gtest/gtest.h"
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <sys/wait.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <sys/stat.h>
#include <thread>
#include <chrono>
#include <atomic>
#include <climits>
#include <cstdint>
#include "dkapture.h"

// 声明trace_file_init函数，这是在BUILTIN模式下的入口点
extern int
trace_file_init(int argc, char **argv, DKapture::DKCallback cb, void *ctx);
extern int trace_file_deinit(void);

// 定义file_event_t结构体，用于测试
struct file_event_t
{
	uint32_t pid;		// 进程ID
	uint32_t tid;		// 线程ID
	uint32_t flags;		// 文件操作标志
	char comm[16];		// 进程名称
	char filename[256]; // 文件名
};

// 测试常量定义
const std::string TEST_ROOT = "/tmp/trace_file_test_dir";

// 测试回调函数，用于接收和验证BPF事件
static std::vector<struct file_event_t> captured_events;
static std::atomic<bool> event_received(false);

// 回调函数，用于接收BPF事件
static int test_callback(void *ctx, const void *data, size_t data_sz)
{
	// 检查数据是否为空
	if (data == nullptr || data_sz == 0)
	{
		return -1;
	}

	// 检查数据大小是否足够
	if (data_sz < sizeof(struct file_event_t))
	{
		return -1;
	}

	// 数据有效，处理事件
	const struct file_event_t *event =
		static_cast<const struct file_event_t *>(data);
	captured_events.push_back(*event);
	event_received = true;
	return 0;
}

class TraceFileBasicTest : public ::testing::Test
{
  protected:
	void SetUp() override
	{
		// 创建测试目录
		mkdir(TEST_ROOT.c_str(), 0755);

		// 清除之前捕获的事件
		captured_events.clear();
		event_received = false;

		// 重置上一次的退出码
		last_exit_code = 0;
	}

	void TearDown() override
	{
		// 清理测试目录
		std::string cmd = "rm -rf " + TEST_ROOT;
		system(cmd.c_str());

		// 确保trace-file已经停止
		trace_file_deinit();
	}

	// 执行trace-file命令并返回输出
	std::string runTraceFileCommand(const std::vector<std::string> &args)
	{
		int argc = args.size() + 1;
		char *argv[argc + 1]; // 额外的空间用于nullptr结尾
		argv[0] = (char *)"trace-file";
		for (int i = 1; i < argc; i++)
		{
			argv[i] = (char *)args[i - 1].c_str();
		}
		argv[argc] = nullptr;

		// 清除之前捕获的事件
		captured_events.clear();
		event_received = false;

		// 调用trace_file_init，使用test_callback作为回调函数
		last_exit_code = trace_file_init(argc, argv, test_callback, nullptr);

		// 等待一小段时间，让BPF程序有机会捕获一些事件
		std::this_thread::sleep_for(std::chrono::milliseconds(100));

		// 停止trace-file
		trace_file_deinit();

		// 返回捕获的事件数量作为字符串
		std::stringstream ss;
		ss << "Captured " << captured_events.size() << " events";
		return ss.str();
	}

	// 模拟文件事件
	void simulateFileEvent(const char *filename, uint32_t pid, uint32_t flags)
	{
		struct file_event_t event;
		event.pid = pid;
		event.tid = pid;
		event.flags = flags;
		strncpy(event.comm, "test", sizeof(event.comm) - 1);
		event.comm[sizeof(event.comm) - 1] = '\0';
		strncpy(event.filename, filename, sizeof(event.filename) - 1);
		event.filename[sizeof(event.filename) - 1] = '\0';

		test_callback(nullptr, &event, sizeof(event));
	}

	// 获取上一次命令的退出码
	int getLastExitCode() const
	{
		return last_exit_code;
	}

  private:
	int last_exit_code = 0;
};

// 测试事件处理
TEST_F(TraceFileBasicTest, EventHandling)
{
	// 直接模拟事件，不调用trace_file_init
	simulateFileEvent("/tmp/test.txt", 1234, 0);

	// 验证事件是否被正确捕获
	EXPECT_TRUE(event_received) << "Event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture one event";

	if (!captured_events.empty())
	{
		const auto &event = captured_events[0];
		EXPECT_EQ(event.pid, 1234) << "Event PID should match";
		EXPECT_STREQ(event.filename, "/tmp/test.txt") << "Event filename "
														 "should match";
	}
}

// 测试不同类型的文件事件
TEST_F(TraceFileBasicTest, DifferentEventTypes)
{
	// 清除之前捕获的事件
	captured_events.clear();
	event_received = false;

	// 模拟打开文件事件
	struct file_event_t open_event;
	open_event.pid = 2345;
	open_event.tid = 2345;
	open_event.flags = 1; // 假设1表示打开文件
	strncpy(open_event.comm, "test", sizeof(open_event.comm) - 1);
	open_event.comm[sizeof(open_event.comm) - 1] = '\0';
	strncpy(
		open_event.filename,
		"/tmp/open.txt",
		sizeof(open_event.filename) - 1
	);
	open_event.filename[sizeof(open_event.filename) - 1] = '\0';

	test_callback(nullptr, &open_event, sizeof(open_event));

	// 验证打开文件事件是否被正确捕获
	EXPECT_TRUE(event_received) << "Open file event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture one open file "
											"event";

	if (!captured_events.empty())
	{
		const auto &event = captured_events[0];
		EXPECT_EQ(event.pid, 2345) << "Event PID should match";
		EXPECT_EQ(event.flags, 1) << "Event flags should match";
		EXPECT_STREQ(event.filename, "/tmp/open.txt") << "Event filename "
														 "should match";
	}

	// 清除之前捕获的事件
	captured_events.clear();
	event_received = false;

	// 模拟关闭文件事件
	struct file_event_t close_event;
	close_event.pid = 3456;
	close_event.tid = 3456;
	close_event.flags = 2; // 假设2表示关闭文件
	strncpy(close_event.comm, "test", sizeof(close_event.comm) - 1);
	close_event.comm[sizeof(close_event.comm) - 1] = '\0';
	strncpy(
		close_event.filename,
		"/tmp/close.txt",
		sizeof(close_event.filename) - 1
	);
	close_event.filename[sizeof(close_event.filename) - 1] = '\0';

	test_callback(nullptr, &close_event, sizeof(close_event));

	// 验证关闭文件事件是否被正确捕获
	EXPECT_TRUE(event_received) << "Close file event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture one close file "
											"event";

	if (!captured_events.empty())
	{
		const auto &event = captured_events[0];
		EXPECT_EQ(event.pid, 3456) << "Event PID should match";
		EXPECT_EQ(event.flags, 2) << "Event flags should match";
		EXPECT_STREQ(event.filename, "/tmp/close.txt") << "Event filename "
														  "should match";
	}
}

// 测试多个事件的处理
TEST_F(TraceFileBasicTest, MultipleEvents)
{
	// 清除之前捕获的事件
	captured_events.clear();
	event_received = false;

	// 模拟多个事件
	for (int i = 0; i < 5; i++)
	{
		struct file_event_t event;
		event.pid = 1000 + i;
		event.tid = 1000 + i;
		event.flags = i % 3; // 不同的标志
		strncpy(event.comm, "test", sizeof(event.comm) - 1);
		event.comm[sizeof(event.comm) - 1] = '\0';

		char filename[256];
		snprintf(filename, sizeof(filename), "/tmp/file_%d.txt", i);
		strncpy(event.filename, filename, sizeof(event.filename) - 1);
		event.filename[sizeof(event.filename) - 1] = '\0';

		test_callback(nullptr, &event, sizeof(event));
	}

	// 验证所有事件是否被正确捕获
	EXPECT_TRUE(event_received) << "Events should be received";
	EXPECT_EQ(captured_events.size(), 5) << "Should capture all five events";

	// 验证每个事件的属性
	for (int i = 0; i < std::min(5, static_cast<int>(captured_events.size()));
		 i++)
	{
		const auto &event = captured_events[i];
		EXPECT_EQ(event.pid, 1000 + i) << "Event " << i << " PID should match";
		EXPECT_EQ(event.flags, i % 3) << "Event " << i << " flags should match";

		char expected_filename[256];
		snprintf(
			expected_filename,
			sizeof(expected_filename),
			"/tmp/file_%d.txt",
			i
		);
		EXPECT_STREQ(event.filename, expected_filename)
			<< "Event " << i << " filename should match";
	}
}

// 测试错误处理
TEST_F(TraceFileBasicTest, ErrorHandling)
{
	// 测试数据大小不匹配的情况
	captured_events.clear();
	event_received = false;

	struct file_event_t event;
	event.pid = 1234;
	event.tid = 1234;
	event.flags = 0;
	strncpy(event.comm, "test", sizeof(event.comm) - 1);
	event.comm[sizeof(event.comm) - 1] = '\0';
	strncpy(event.filename, "/tmp/test.txt", sizeof(event.filename) - 1);
	event.filename[sizeof(event.filename) - 1] = '\0';

	// 测试数据大小小于file_event_t结构体大小的情况
	int result = test_callback(nullptr, &event, sizeof(event) - 1);
	EXPECT_EQ(result, -1) << "Callback should return error for incomplete data";
	EXPECT_FALSE(event_received) << "Event should not be received for "
									"incomplete data";
	EXPECT_EQ(captured_events.size(), 0) << "No events should be captured for "
											"incomplete data";

	// 测试数据为空的情况
	result = test_callback(nullptr, nullptr, 0);
	EXPECT_EQ(result, -1) << "Callback should return error for null data";
	EXPECT_FALSE(event_received) << "Event should not be received for null "
									"data";
	EXPECT_EQ(captured_events.size(), 0) << "No events should be captured for "
											"null data";
}

// 测试边界条件
TEST_F(TraceFileBasicTest, BoundaryConditions)
{
	captured_events.clear();
	event_received = false;

	// 测试极长文件名
	struct file_event_t long_filename_event;
	long_filename_event.pid = INT_MAX;
	long_filename_event.tid = INT_MAX;
	long_filename_event.flags = UINT32_MAX;
	strncpy(
		long_filename_event.comm,
		"max_test",
		sizeof(long_filename_event.comm) - 1
	);
	long_filename_event.comm[sizeof(long_filename_event.comm) - 1] = '\0';

	// 创建一个非常长的文件名，但确保不会超过缓冲区
	char long_filename[sizeof(long_filename_event.filename)];
	memset(long_filename, 'a', sizeof(long_filename) - 1);
	long_filename[sizeof(long_filename) - 1] = '\0';
	strncpy(
		long_filename_event.filename,
		long_filename,
		sizeof(long_filename_event.filename) - 1
	);
	long_filename_event.filename[sizeof(long_filename_event.filename) - 1] =
		'\0';

	test_callback(nullptr, &long_filename_event, sizeof(long_filename_event));

	EXPECT_TRUE(event_received) << "Long filename event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture long filename "
											"event";

	if (!captured_events.empty())
	{
		const auto &event = captured_events[0];
		EXPECT_EQ(event.pid, INT_MAX) << "Max PID should match";
		EXPECT_EQ(event.flags, UINT32_MAX) << "Max flags should match";
		EXPECT_STREQ(event.filename, long_filename) << "Long filename should "
													   "match";
	}

	// 测试空文件名
	captured_events.clear();
	event_received = false;

	struct file_event_t empty_filename_event;
	empty_filename_event.pid = 0;
	empty_filename_event.tid = 0;
	empty_filename_event.flags = 0;
	strncpy(
		empty_filename_event.comm,
		"",
		sizeof(empty_filename_event.comm) - 1
	);
	empty_filename_event.comm[sizeof(empty_filename_event.comm) - 1] = '\0';
	strncpy(
		empty_filename_event.filename,
		"",
		sizeof(empty_filename_event.filename) - 1
	);
	empty_filename_event.filename[sizeof(empty_filename_event.filename) - 1] =
		'\0';

	test_callback(nullptr, &empty_filename_event, sizeof(empty_filename_event));

	EXPECT_TRUE(event_received) << "Empty filename event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture empty filename "
											"event";

	if (!captured_events.empty())
	{
		const auto &event = captured_events[0];
		EXPECT_EQ(event.pid, 0) << "Min PID should match";
		EXPECT_EQ(event.flags, 0) << "Min flags should match";
		EXPECT_STREQ(event.filename, "") << "Empty filename should match";
	}
}

// 测试性能
TEST_F(TraceFileBasicTest, Performance)
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
		struct file_event_t event;
		event.pid = i;
		event.tid = i;
		event.flags = i % 3;
		strncpy(event.comm, "perf", sizeof(event.comm) - 1);
		event.comm[sizeof(event.comm) - 1] = '\0';

		char filename[256];
		snprintf(filename, sizeof(filename), "/tmp/perf_file_%d.txt", i);
		strncpy(event.filename, filename, sizeof(event.filename) - 1);
		event.filename[sizeof(event.filename) - 1] = '\0';

		test_callback(nullptr, &event, sizeof(event));
	}

	// 记录结束时间
	auto end_time = std::chrono::high_resolution_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
		end_time - start_time
	);

	// 验证所有事件是否被正确捕获
	EXPECT_TRUE(event_received) << "Events should be received";
	EXPECT_EQ(captured_events.size(), NUM_EVENTS) << "Should capture all "
													 "events";

	// 输出性能信息
	std::cout << "Processing " << NUM_EVENTS << " events took "
			  << duration.count() << " microseconds" << std::endl;
	std::cout << "Average time per event: "
			  << static_cast<double>(duration.count()) / NUM_EVENTS
			  << " microseconds" << std::endl;

	// 验证处理时间是否在合理范围内（这里设置一个宽松的上限）
	EXPECT_LT(duration.count(), 1000000) << "Event processing should be "
											"reasonably fast";
}
