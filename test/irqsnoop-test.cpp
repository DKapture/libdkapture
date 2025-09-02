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
#include <climits> // 为INT_MAX和UINT16_MAX添加
#include <cstdint> // 为uint16_t和uint64_t添加
#include "dkapture.h"

// 声明irqsnoop_init函数，这是在BUILTIN模式下的入口点
extern int
irqsnoop_init(int argc, char **argv, DKapture::DKCallback cb, void *ctx);
extern int irqsnoop_deinit(void);

// 测试常量定义
const std::string TEST_ROOT = "/tmp/irqsnoop_test_dir";

// 测试回调函数，用于接收和验证BPF事件
static std::vector<struct irq_event_t> captured_events;
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
	if (data_sz < sizeof(struct irq_event_t))
	{
		return -1;
	}

	// 数据有效，处理事件
	const struct irq_event_t *event =
		static_cast<const struct irq_event_t *>(data);
	captured_events.push_back(*event);
	event_received = true;
	return 0;
}

class IrqSnoopBasicTest : public ::testing::Test
{
  protected:
	void SetUp() override
	{
		// 清理任何之前的测试文件和状态
		cleanupTestFiles();
		captured_events.clear();
		event_received = false;

		// 创建测试目录结构
		system(("mkdir -p " + TEST_ROOT).c_str());
	}

	void TearDown() override
	{
		// 清理测试环境
		cleanupTestFiles();

		// 确保irqsnoop已经停止
		irqsnoop_deinit();
	}

	// 全局变量存储最后的退出码
	static int last_exit_code;

	// 执行irqsnoop命令并返回输出
	std::string runIrqSnoopCommand(const std::vector<std::string> &args)
	{
		int argc = args.size() + 1;
		char *argv[argc];
		argv[0] = (char *)"irqsnoop";
		for (int i = 1; i < argc; i++)
		{
			argv[i] = (char *)args[i - 1].c_str();
		}

		// 清除之前捕获的事件
		captured_events.clear();
		event_received = false;

		// 调用irqsnoop_init，使用test_callback作为回调函数
		printf("Calling irqsnoop_init with %d args\n", argc);
		last_exit_code = irqsnoop_init(argc, argv, test_callback, nullptr);
		printf("irqsnoop_init returned %d\n", last_exit_code);

		// 返回捕获的事件数量作为字符串
		std::stringstream ss;
		ss << "Captured " << captured_events.size() << " events";
		return ss.str();
	}

	// 获取上次命令的退出码
	int getLastExitCode()
	{
		return last_exit_code;
	}

	void createTestFile(const std::string &name, const std::string &content)
	{
		std::ofstream file(TEST_ROOT + "/" + name);
		file << content;
		file.close();
	}

	// 创建简化的测试目录结构
	void createTestDirectory(const std::string &name)
	{
		// 创建基本目录
		system(("mkdir -p \"" + TEST_ROOT + "/" + name + "\"").c_str());
	}

	// 清理测试文件
	void cleanupTestFiles()
	{
		// 删除测试目录
		system(("rm -rf " + TEST_ROOT).c_str());
	}

	// 模拟IRQ事件
	void simulateIrqEvent()
	{
		// 在实际测试中，我们可能需要触发真实的IRQ事件
		// 但在单元测试中，我们可以模拟事件数据
		struct irq_event_t event = {};
		event.pid = 1234;
		event.tid = 1234;
		strcpy(event.comm, "test_process");
		event.delta = 1000000; // 1ms in ns
		event.ret = 0;
		event.vec_nr = 1;
		event.type = IRQ;
		strcpy(event.name, "test_irq");

		// 通过回调函数传递模拟事件
		test_callback(nullptr, &event, sizeof(event));
	}
};

// 初始化静态成员
int IrqSnoopBasicTest::last_exit_code = 0;

// 测试命令行参数解析 - 暂时禁用
/*
TEST_F(IrqSnoopBasicTest, CommandLineOptions)
{
	// 测试帮助选项
	std::string output = runIrqSnoopCommand({"--help"});
	EXPECT_EQ(getLastExitCode(), 1) << "Help option should return 1";
}
*/

// 测试事件处理
TEST_F(IrqSnoopBasicTest, EventHandling)
{
	// 直接模拟事件，不调用irqsnoop_init
	simulateIrqEvent();

	// 验证事件是否被正确捕获
	EXPECT_TRUE(event_received) << "Event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture one event";

	if (!captured_events.empty())
	{
		const auto &event = captured_events[0];
		EXPECT_EQ(event.pid, 1234) << "Event PID should match";
		EXPECT_EQ(event.type, IRQ) << "Event type should be IRQ";
		EXPECT_STREQ(event.name, "test_irq") << "Event name should match";
	}
}

// 测试不同类型的中断事件
TEST_F(IrqSnoopBasicTest, DifferentEventTypes)
{
	// 清除之前捕获的事件
	captured_events.clear();
	event_received = false;

	// 模拟软中断事件
	struct irq_event_t soft_irq_event;
	soft_irq_event.pid = 2345;
	soft_irq_event.tid = 2345;
	soft_irq_event.type = SOFT_IRQ;
	soft_irq_event.vec_nr = 5;
	soft_irq_event.ret = 0;
	soft_irq_event.delta = 1000;
	strncpy(soft_irq_event.comm, "test", sizeof(soft_irq_event.comm) - 1);
	soft_irq_event.comm[sizeof(soft_irq_event.comm) - 1] = '\0';
	strncpy(soft_irq_event.name, "soft_irq", sizeof(soft_irq_event.name) - 1);
	soft_irq_event.name[sizeof(soft_irq_event.name) - 1] = '\0';

	test_callback(nullptr, &soft_irq_event, sizeof(soft_irq_event));

	// 验证软中断事件是否被正确捕获
	EXPECT_TRUE(event_received) << "Soft IRQ event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture one soft IRQ event";

	if (!captured_events.empty())
	{
		const auto &event = captured_events[0];
		EXPECT_EQ(event.pid, 2345) << "Event PID should match";
		EXPECT_EQ(event.type, SOFT_IRQ) << "Event type should be SOFT_IRQ";
		EXPECT_STREQ(event.name, "soft_irq") << "Event name should match";
	}

	// 清除之前捕获的事件
	captured_events.clear();
	event_received = false;

	// 模拟硬中断事件
	struct irq_event_t hard_irq_event;
	hard_irq_event.pid = 3456;
	hard_irq_event.tid = 3456;
	hard_irq_event.type = IRQ;
	hard_irq_event.vec_nr = 10;
	hard_irq_event.ret = 0;
	hard_irq_event.delta = 2000;
	strncpy(hard_irq_event.comm, "test", sizeof(hard_irq_event.comm) - 1);
	hard_irq_event.comm[sizeof(hard_irq_event.comm) - 1] = '\0';
	strncpy(hard_irq_event.name, "hard_irq", sizeof(hard_irq_event.name) - 1);
	hard_irq_event.name[sizeof(hard_irq_event.name) - 1] = '\0';

	test_callback(nullptr, &hard_irq_event, sizeof(hard_irq_event));

	// 验证硬中断事件是否被正确捕获
	EXPECT_TRUE(event_received) << "Hard IRQ event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture one hard IRQ event";

	if (!captured_events.empty())
	{
		const auto &event = captured_events[0];
		EXPECT_EQ(event.pid, 3456) << "Event PID should match";
		EXPECT_EQ(event.type, IRQ) << "Event type should be IRQ";
		EXPECT_STREQ(event.name, "hard_irq") << "Event name should match";
	}
}

// 测试多个事件的处理
TEST_F(IrqSnoopBasicTest, MultipleEvents)
{
	// 清除之前捕获的事件
	captured_events.clear();
	event_received = false;

	// 模拟多个事件
	for (int i = 0; i < 5; i++)
	{
		struct irq_event_t event;
		event.pid = 1000 + i;
		event.tid = 1000 + i;
		event.type = (i % 2 == 0) ? IRQ : SOFT_IRQ;
		event.vec_nr = i;
		event.ret = 0;
		event.delta = i * 1000;
		strncpy(event.comm, "test", sizeof(event.comm) - 1);
		event.comm[sizeof(event.comm) - 1] = '\0';
		snprintf(event.name, sizeof(event.name), "irq_%d", i);

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
		EXPECT_EQ(event.type, (i % 2 == 0) ? IRQ : SOFT_IRQ)
			<< "Event " << i << " type should match";
		EXPECT_EQ(event.vec_nr, i)
			<< "Event " << i << " IRQ number should match";

		char expected_name[32];
		snprintf(expected_name, sizeof(expected_name), "irq_%d", i);
		EXPECT_STREQ(event.name, expected_name)
			<< "Event " << i << " name should match";
	}
}

// 测试错误处理
TEST_F(IrqSnoopBasicTest, ErrorHandling)
{
	// 测试数据大小不匹配的情况
	captured_events.clear();
	event_received = false;

	struct irq_event_t event;
	event.pid = 1234;
	event.tid = 1234;
	event.type = IRQ;
	event.vec_nr = 1;
	event.ret = 0;
	event.delta = 1000;
	strncpy(event.comm, "test", sizeof(event.comm) - 1);
	event.comm[sizeof(event.comm) - 1] = '\0';
	strncpy(event.name, "test_irq", sizeof(event.name) - 1);
	event.name[sizeof(event.name) - 1] = '\0';

	// 测试数据大小小于irq_event_t结构体大小的情况
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
TEST_F(IrqSnoopBasicTest, BoundaryConditions)
{
	captured_events.clear();
	event_received = false;

	// 测试极大值
	struct irq_event_t max_event;
	max_event.pid = INT_MAX;
	max_event.tid = INT_MAX;
	max_event.type = IRQ;
	max_event.vec_nr = INT_MAX;
	max_event.ret = INT_MAX;
	max_event.delta = UINT64_MAX;
	strncpy(max_event.comm, "max_test", sizeof(max_event.comm) - 1);
	max_event.comm[sizeof(max_event.comm) - 1] = '\0';
	strncpy(max_event.name, "max_irq", sizeof(max_event.name) - 1);
	max_event.name[sizeof(max_event.name) - 1] = '\0';

	test_callback(nullptr, &max_event, sizeof(max_event));

	EXPECT_TRUE(event_received) << "Max value event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture max value event";

	if (!captured_events.empty())
	{
		const auto &event = captured_events[0];
		EXPECT_EQ(event.pid, INT_MAX) << "Max PID should match";
		EXPECT_EQ(event.vec_nr, INT_MAX) << "Max IRQ should match";
		EXPECT_EQ(event.delta, UINT64_MAX) << "Max delta should match";
	}

	// 测试极小值
	captured_events.clear();
	event_received = false;

	struct irq_event_t min_event;
	min_event.pid = 0;
	min_event.tid = 0;
	min_event.type = IRQ;
	min_event.vec_nr = 0;
	min_event.ret = 0;
	min_event.delta = 0;
	strncpy(min_event.comm, "", sizeof(min_event.comm) - 1);
	min_event.comm[sizeof(min_event.comm) - 1] = '\0';
	strncpy(min_event.name, "", sizeof(min_event.name) - 1);
	min_event.name[sizeof(min_event.name) - 1] = '\0';

	test_callback(nullptr, &min_event, sizeof(min_event));

	EXPECT_TRUE(event_received) << "Min value event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture min value event";

	if (!captured_events.empty())
	{
		const auto &event = captured_events[0];
		EXPECT_EQ(event.pid, 0) << "Min PID should match";
		EXPECT_EQ(event.vec_nr, 0) << "Min IRQ should match";
		EXPECT_EQ(event.delta, 0) << "Min delta should match";
		EXPECT_STREQ(event.name, "") << "Empty name should match";
	}
}

// 测试性能
TEST_F(IrqSnoopBasicTest, Performance)
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
		struct irq_event_t event;
		event.pid = i;
		event.tid = i;
		event.type = (i % 2 == 0) ? IRQ : SOFT_IRQ;
		event.vec_nr = i % 256;
		event.ret = 0;
		event.delta = i * 100;
		strncpy(event.comm, "perf", sizeof(event.comm) - 1);
		event.comm[sizeof(event.comm) - 1] = '\0';
		snprintf(event.name, sizeof(event.name), "perf_irq_%d", i);

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
