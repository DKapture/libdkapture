#include "gtest/gtest.h"
#include <vector>
#include <atomic>
#include <thread>
#include <chrono>
#include <climits>
#include <cstdint>
#include "dkapture.h"

// 声明kmemleak_init函数，这是在BUILTIN模式下的入口点
extern int
kmemleak_init(int argc, char **argv, DKapture::DKCallback cb, void *ctx);

// 定义内存泄漏事件结构体
struct alloc_info
{
	uint64_t size;
	uint64_t timestamp_ns;
	int stack_id;
};

struct stack_trace_t
{
	int stack_id;
	int nr_entries;
	unsigned long *ip;
};

// 测试常量定义
const std::string TEST_ROOT = "/tmp/kmemleak_test_dir";

// 测试回调函数，用于接收和验证BPF事件
static std::vector<alloc_info> captured_allocs;
static std::vector<stack_trace_t> captured_stacks;
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
	if (data_sz < sizeof(struct alloc_info))
	{
		return -1;
	}

	// 处理事件
	const struct alloc_info *alloc =
		static_cast<const struct alloc_info *>(data);
	captured_allocs.push_back(*alloc);
	event_received = true;
	return 0;
}

// 测试类
class KmemleakBasicTest : public ::testing::Test
{
  protected:
	void SetUp() override
	{
		// 创建测试目录
		mkdir(TEST_ROOT.c_str(), 0755);

		// 清除之前捕获的事件
		captured_allocs.clear();
		captured_stacks.clear();
		event_received = false;
	}

	void TearDown() override
	{
		// 清理测试目录
		std::string cmd = "rm -rf " + TEST_ROOT;
		system(cmd.c_str());
	}

	// 辅助函数：模拟内存分配事件
	void simulateAlloc(size_t size, int stack_id, uint64_t timestamp_ns = 0)
	{
		struct alloc_info alloc;
		alloc.size = size;
		alloc.stack_id = stack_id;
		alloc.timestamp_ns =
			timestamp_ns > 0 ? timestamp_ns : getCurrentTimestampNs();

		test_callback(nullptr, &alloc, sizeof(alloc));
	}

	// 辅助函数：获取当前时间戳（纳秒）
	uint64_t getCurrentTimestampNs()
	{
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
	}

	// 辅助函数：模拟堆栈跟踪
	void simulateStackTrace(int stack_id, int nr_entries, unsigned long *ip)
	{
		struct stack_trace_t stack;
		stack.stack_id = stack_id;
		stack.nr_entries = nr_entries;
		stack.ip = ip;

		captured_stacks.push_back(stack);
	}
};

// 测试基本事件处理
TEST_F(KmemleakBasicTest, EventHandling)
{
	// 模拟内存分配事件
	simulateAlloc(1024, 1);

	// 验证事件是否被捕获
	EXPECT_TRUE(event_received) << "Event should be received";
	EXPECT_EQ(captured_allocs.size(), 1) << "Should capture one event";

	if (!captured_allocs.empty())
	{
		const auto &alloc = captured_allocs[0];
		EXPECT_EQ(alloc.size, 1024) << "Allocation size should match";
		EXPECT_EQ(alloc.stack_id, 1) << "Stack ID should match";
	}
}

// 测试不同大小的内存分配
TEST_F(KmemleakBasicTest, DifferentAllocationSizes)
{
	// 模拟不同大小的内存分配
	simulateAlloc(1024, 1);		   // 1KB
	simulateAlloc(1024 * 1024, 2); // 1MB
	simulateAlloc(4096, 3);		   // 4KB

	// 验证事件是否被捕获
	EXPECT_EQ(captured_allocs.size(), 3) << "Should capture three events";

	if (captured_allocs.size() >= 3)
	{
		EXPECT_EQ(captured_allocs[0].size, 1024) << "First allocation size "
													"should be 1KB";
		EXPECT_EQ(captured_allocs[1].size, 1024 * 1024) << "Second allocation "
														   "size should be 1MB";
		EXPECT_EQ(captured_allocs[2].size, 4096) << "Third allocation size "
													"should be 4KB";
	}
}

// 测试多个内存分配事件
TEST_F(KmemleakBasicTest, MultipleAllocations)
{
	const int NUM_ALLOCS = 100;

	// 模拟多个内存分配事件
	for (int i = 0; i < NUM_ALLOCS; i++)
	{
		simulateAlloc(1024 * (i + 1), i);
	}

	// 验证事件是否被捕获
	EXPECT_EQ(captured_allocs.size(), NUM_ALLOCS) << "Should capture all "
													 "events";

	// 验证每个事件的属性
	for (int i = 0;
		 i < std::min(NUM_ALLOCS, static_cast<int>(captured_allocs.size()));
		 i++)
	{
		EXPECT_EQ(captured_allocs[i].size, 1024 * (i + 1))
			<< "Allocation " << i << " size should match";
		EXPECT_EQ(captured_allocs[i].stack_id, i)
			<< "Allocation " << i << " stack ID should match";
	}
}

// 测试错误处理
TEST_F(KmemleakBasicTest, ErrorHandling)
{
	// 测试空数据
	int result = test_callback(nullptr, nullptr, 0);
	EXPECT_EQ(result, -1) << "Null data should be rejected";

	// 测试数据大小不足
	char small_data[sizeof(struct alloc_info) - 1];
	result = test_callback(nullptr, small_data, sizeof(small_data));
	EXPECT_EQ(result, -1) << "Incomplete data should be rejected";

	// 验证没有事件被捕获
	EXPECT_FALSE(event_received) << "No event should be received for invalid "
									"data";
	EXPECT_EQ(captured_allocs.size(), 0) << "No events should be captured for "
											"invalid data";
}

// 测试边界条件
TEST_F(KmemleakBasicTest, BoundaryConditions)
{
	// 测试极大值
	simulateAlloc(UINT64_MAX, INT_MAX);

	// 验证事件是否被捕获
	EXPECT_TRUE(event_received) << "Max value event should be received";
	EXPECT_EQ(captured_allocs.size(), 1) << "Should capture max value event";

	if (!captured_allocs.empty())
	{
		const auto &alloc = captured_allocs[0];
		EXPECT_EQ(alloc.size, UINT64_MAX) << "Max size should match";
		EXPECT_EQ(alloc.stack_id, INT_MAX) << "Max stack ID should match";
	}

	// 测试极小值
	captured_allocs.clear();
	event_received = false;

	// 使用最小的有效值，而不是0（因为时间戳无法设置为0）
	simulateAlloc(0, 0, 1);

	EXPECT_TRUE(event_received) << "Min value event should be received";
	EXPECT_EQ(captured_allocs.size(), 1) << "Should capture min value event";

	if (!captured_allocs.empty())
	{
		const auto &alloc = captured_allocs[0];
		EXPECT_EQ(alloc.size, 0) << "Min size should match";
		EXPECT_EQ(alloc.stack_id, 0) << "Min stack ID should match";
		EXPECT_EQ(alloc.timestamp_ns, 1) << "Min timestamp should match";
	}
}

// 测试性能
TEST_F(KmemleakBasicTest, Performance)
{
	// 清除之前捕获的事件
	captured_allocs.clear();
	event_received = false;

	// 记录开始时间
	auto start_time = std::chrono::high_resolution_clock::now();

	// 模拟大量事件
	const int NUM_EVENTS = 1000;
	for (int i = 0; i < NUM_EVENTS; i++)
	{
		simulateAlloc(1024, i);
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
	EXPECT_EQ(captured_allocs.size(), NUM_EVENTS) << "All events should be "
													 "processed";

	// 验证处理时间是否在合理范围内（这里设置一个宽松的上限）
	EXPECT_LT(duration.count(), 1000000) << "Event processing should be "
											"reasonably fast";
}

// 测试时间戳处理
TEST_F(KmemleakBasicTest, TimestampHandling)
{
	// 获取当前时间戳
	uint64_t now = getCurrentTimestampNs();

	// 模拟不同时间戳的内存分配
	simulateAlloc(1024, 1, now - 1000000000ULL); // 1秒前
	simulateAlloc(2048, 2, now - 500000000ULL);	 // 0.5秒前
	simulateAlloc(4096, 3, now);				 // 现在

	// 验证事件是否被捕获
	EXPECT_EQ(captured_allocs.size(), 3) << "Should capture three events";

	if (captured_allocs.size() >= 3)
	{
		EXPECT_EQ(captured_allocs[0].timestamp_ns, now - 1000000000ULL)
			<< "First timestamp should match";
		EXPECT_EQ(captured_allocs[1].timestamp_ns, now - 500000000ULL)
			<< "Second timestamp should match";
		EXPECT_EQ(captured_allocs[2].timestamp_ns, now) << "Third timestamp "
														   "should match";
	}
}

// 测试堆栈跟踪
TEST_F(KmemleakBasicTest, StackTraceHandling)
{
	// 模拟堆栈跟踪
	unsigned long stack1[] = {0x1000, 0x2000, 0x3000};
	unsigned long stack2[] = {0x4000, 0x5000, 0x6000};

	simulateStackTrace(1, 3, stack1);
	simulateStackTrace(2, 3, stack2);

	// 模拟与堆栈关联的内存分配
	simulateAlloc(1024, 1);
	simulateAlloc(2048, 2);

	// 验证堆栈跟踪是否被捕获
	EXPECT_EQ(captured_stacks.size(), 2) << "Should capture two stack traces";

	if (captured_stacks.size() >= 2)
	{
		EXPECT_EQ(captured_stacks[0].stack_id, 1) << "First stack ID should "
													 "match";
		EXPECT_EQ(captured_stacks[0].nr_entries, 3) << "First stack should "
													   "have 3 entries";
		EXPECT_EQ(captured_stacks[0].ip[0], 0x1000) << "First stack entry "
													   "should match";
		EXPECT_EQ(captured_stacks[0].ip[1], 0x2000) << "Second stack entry "
													   "should match";
		EXPECT_EQ(captured_stacks[0].ip[2], 0x3000) << "Third stack entry "
													   "should match";

		EXPECT_EQ(captured_stacks[1].stack_id, 2) << "Second stack ID should "
													 "match";
		EXPECT_EQ(captured_stacks[1].nr_entries, 3) << "Second stack should "
													   "have 3 entries";
		EXPECT_EQ(captured_stacks[1].ip[0], 0x4000) << "First stack entry "
													   "should match";
		EXPECT_EQ(captured_stacks[1].ip[1], 0x5000) << "Second stack entry "
													   "should match";
		EXPECT_EQ(captured_stacks[1].ip[2], 0x6000) << "Third stack entry "
													   "should match";
	}

	// 验证内存分配是否与堆栈关联
	EXPECT_EQ(captured_allocs.size(), 2) << "Should capture two allocations";

	if (captured_allocs.size() >= 2)
	{
		EXPECT_EQ(captured_allocs[0].stack_id, 1) << "First allocation should "
													 "be associated with stack "
													 "1";
		EXPECT_EQ(captured_allocs[1].stack_id, 2) << "Second allocation should "
													 "be associated with stack "
													 "2";
	}
}

// 测试过滤条件
TEST_F(KmemleakBasicTest, FilterConditions)
{
	// 模拟不同大小的内存分配
	simulateAlloc(512, 1);	   // 小于1KB
	simulateAlloc(1024, 2);	   // 等于1KB
	simulateAlloc(2048, 3);	   // 大于1KB
	simulateAlloc(1048576, 4); // 1MB

	// 验证事件是否被捕获
	EXPECT_EQ(captured_allocs.size(), 4) << "Should capture all events";

	// 模拟过滤：只保留大于等于1KB的分配
	std::vector<alloc_info> filtered_allocs;
	for (const auto &alloc : captured_allocs)
	{
		if (alloc.size >= 1024)
		{
			filtered_allocs.push_back(alloc);
		}
	}

	// 验证过滤结果
	EXPECT_EQ(filtered_allocs.size(), 3) << "Should have 3 allocations >= 1KB";

	if (filtered_allocs.size() >= 3)
	{
		EXPECT_EQ(filtered_allocs[0].size, 1024) << "First filtered allocation "
													"should be 1KB";
		EXPECT_EQ(filtered_allocs[1].size, 2048) << "Second filtered "
													"allocation should be 2KB";
		EXPECT_EQ(filtered_allocs[2].size, 1048576) << "Third filtered "
													   "allocation should be "
													   "1MB";
	}

	// 模拟过滤：只保留小于1MB的分配
	filtered_allocs.clear();
	for (const auto &alloc : captured_allocs)
	{
		if (alloc.size < 1048576)
		{
			filtered_allocs.push_back(alloc);
		}
	}

	// 验证过滤结果
	EXPECT_EQ(filtered_allocs.size(), 3) << "Should have 3 allocations < 1MB";

	if (filtered_allocs.size() >= 3)
	{
		EXPECT_EQ(filtered_allocs[0].size, 512) << "First filtered allocation "
												   "should be 512B";
		EXPECT_EQ(filtered_allocs[1].size, 1024) << "Second filtered "
													"allocation should be 1KB";
		EXPECT_EQ(filtered_allocs[2].size, 2048) << "Third filtered allocation "
													"should be 2KB";
	}
}

// 测试内存泄漏检测
TEST_F(KmemleakBasicTest, LeakDetection)
{
	// 获取当前时间戳
	uint64_t now = getCurrentTimestampNs();

	// 模拟内存分配和释放
	// 分配1：10秒前分配，未释放 -> 泄漏
	simulateAlloc(1024, 1, now - 10000000000ULL);

	// 分配2：5秒前分配，未释放 -> 泄漏
	simulateAlloc(2048, 2, now - 5000000000ULL);

	// 分配3：1秒前分配，未释放 -> 不算泄漏（太新）
	simulateAlloc(4096, 3, now - 1000000000ULL);

	// 模拟泄漏检测：找出超过3秒未释放的分配
	std::vector<alloc_info> leaks;
	for (const auto &alloc : captured_allocs)
	{
		if (now - alloc.timestamp_ns > 3000000000ULL)
		{
			leaks.push_back(alloc);
		}
	}

	// 验证泄漏检测结果
	EXPECT_EQ(leaks.size(), 2) << "Should detect 2 leaks";

	if (leaks.size() >= 2)
	{
		EXPECT_EQ(leaks[0].size, 1024) << "First leak should be 1KB";
		EXPECT_EQ(leaks[0].stack_id, 1) << "First leak should be from stack 1";

		EXPECT_EQ(leaks[1].size, 2048) << "Second leak should be 2KB";
		EXPECT_EQ(leaks[1].stack_id, 2) << "Second leak should be from stack 2";
	}
}

// 测试组合分配信息
TEST_F(KmemleakBasicTest, CombinedAllocations)
{
	// 模拟来自相同堆栈的多个分配
	simulateAlloc(1024, 1);
	simulateAlloc(1024, 1);
	simulateAlloc(2048, 1);

	// 模拟来自不同堆栈的分配
	simulateAlloc(4096, 2);
	simulateAlloc(8192, 2);

	// 验证事件是否被捕获
	EXPECT_EQ(captured_allocs.size(), 5) << "Should capture all events";

	// 模拟组合分配信息：按堆栈ID分组
	std::map<int, std::pair<uint64_t, int>> combined_allocs;
	for (const auto &alloc : captured_allocs)
	{
		auto &entry = combined_allocs[alloc.stack_id];
		entry.first += alloc.size;
		entry.second++;
	}

	// 验证组合结果
	EXPECT_EQ(combined_allocs.size(), 2) << "Should have 2 combined "
											"allocations";

	auto stack1 = combined_allocs[1];
	EXPECT_EQ(stack1.first, 1024 + 1024 + 2048) << "Stack 1 should have total "
												   "size of 4KB";
	EXPECT_EQ(stack1.second, 3) << "Stack 1 should have 3 allocations";

	auto stack2 = combined_allocs[2];
	EXPECT_EQ(stack2.first, 4096 + 8192) << "Stack 2 should have total size of "
											"12KB";
	EXPECT_EQ(stack2.second, 2) << "Stack 2 should have 2 allocations";
}

// 测试采样率功能
TEST_F(KmemleakBasicTest, SamplingRate)
{
	// 模拟采样率为2的情况（只记录一半的分配）
	const int NUM_ALLOCS = 100;
	int recorded = 0;

	for (int i = 0; i < NUM_ALLOCS; i++)
	{
		// 模拟采样率为2：只记录偶数索引的分配
		if (i % 2 == 0)
		{
			simulateAlloc(1024, i);
			recorded++;
		}
	}

	// 验证事件是否被正确采样
	EXPECT_EQ(captured_allocs.size(), recorded) << "Should capture only "
												   "sampled events";
	EXPECT_EQ(recorded, NUM_ALLOCS / 2) << "Should record half of the "
										   "allocations";

	// 验证采样的分配是否正确
	for (size_t i = 0; i < captured_allocs.size(); i++)
	{
		EXPECT_EQ(captured_allocs[i].stack_id, static_cast<int>(i * 2))
			<< "Allocation " << i << " should have correct stack ID";
	}
}
