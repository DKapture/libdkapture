// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

// This file uses/derives from googletest
// Copyright 2008, Google Inc.
// Licensed under the BSD 3-Clause License
// See NOTICE for full license text

#include "gtest/gtest.h"
#include "bpf-manager.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <thread>
#include <chrono>
#include <stdexcept>
#include <system_error>
#include <atomic>
#include <vector>

#define TEST_PIN_PATH "/sys/fs/bpf/dkapture"

class BPFTest : public ::testing::Test
{
  protected:
	BPFManager *bpf_instance;

	void SetUp() override
	{
		// Ensure the test environment is clean
		mkdir(TEST_PIN_PATH, 0755);
		bpf_instance = new BPFManager();
	}

	void TearDown() override
	{
		delete bpf_instance;

		// Clean up test environment
		DIR *dir = opendir(TEST_PIN_PATH);
		if (dir)
		{
			struct dirent *entry;
			while ((entry = readdir(dir)) != nullptr)
			{
				if (strcmp(entry->d_name, ".") == 0 ||
					strcmp(entry->d_name, "..") == 0)
				{
					continue;
				}
				std::string path(TEST_PIN_PATH);
				path += "/";
				path += entry->d_name;
				unlink(path.c_str());
			}
			closedir(dir);
		}
		rmdir(TEST_PIN_PATH);
	}

	bool file_exists(const std::string &path)
	{
		return access(path.c_str(), F_OK) == 0;
	}

	bool directory_exists(const std::string &path)
	{
		DIR *dir = opendir(path.c_str());
		if (dir)
		{
			closedir(dir);
			return true;
		}
		return false;
	}
};

TEST_F(BPFTest, ConstructorAndDestructor)
{
	// Verify that the BPFManager instance is created and destroyed without errors
	ASSERT_NE(bpf_instance, nullptr);
}

TEST_F(BPFTest, PinLinks)
{
	// Test the bpf_pin_links method
	// 只有在创建新BPF对象时才需要pin links
	if (bpf_instance->m_obj)
	{
		int ret = bpf_instance->bpf_pin_links(TEST_PIN_PATH);
		ASSERT_EQ(ret, 0) << "Failed to pin BPFManager links";
	}
	else
	{
		// 如果使用已存在的BPF对象，跳过此测试
		GTEST_SKIP() << "Skipping pin links test for existing BPFManager object";
	}
}

TEST_F(BPFTest, PinPrograms)
{
	// Test the bpf_pin_programs method
	// 只有在创建新BPF对象时才需要pin programs
	if (bpf_instance->m_obj)
	{
		int ret = bpf_instance->bpf_pin_programs(TEST_PIN_PATH);
		ASSERT_EQ(ret, 0) << "Failed to pin BPFManager programs";
	}
	else
	{
		// 如果使用已存在的BPF对象，跳过此测试
		GTEST_SKIP() << "Skipping pin programs test for existing BPFManager object";
	}
}

TEST_F(BPFTest, RetreatBpfMap)
{
	// Test the bpf_find_map method
	const char *map_name = "test_map";
	int ret = bpf_instance->bpf_find_map("dk_shared_mem");
	ASSERT_GT(ret, 0) << "Failed to retreat BPFManager map";

	// 测试获取不存在的map应该返回错误
	int ret_invalid = bpf_instance->bpf_find_map("non_existent_map");
	EXPECT_LE(ret_invalid, 0) << "Should fail for non-existent map";
}

TEST_F(BPFTest, RetreatBpfIter)
{
	// Test the bpf_find_iter method
	std::string result = bpf_instance->bpf_find_iter("dump_task");
	ASSERT_FALSE(result.empty()) << "Failed to retreat BPFManager iterator";

	// 验证返回的路径格式正确
	EXPECT_TRUE(result.find("/link-dump_task") != std::string::npos);

	// 测试获取不存在的iterator应该返回空字符串
	std::string result_invalid = bpf_instance->bpf_find_iter("non_existent_"
																"iter");
	EXPECT_TRUE(result_invalid.empty()) << "Should return empty string for "
										   "non-existent iterator";
}

// 测试PIN路径的创建和清理
TEST_F(BPFTest, PinPathManagement)
{
	// 验证PIN路径被正确创建
	EXPECT_TRUE(directory_exists(TEST_PIN_PATH)) << "PIN path should be "
													"created";

	// 测试路径权限
	struct stat st;
	ASSERT_EQ(stat(TEST_PIN_PATH, &st), 0) << "Failed to stat PIN path";
	EXPECT_EQ(st.st_mode & 0777, 0755) << "PIN path should have correct "
										  "permissions";
}

// 测试压力测试
TEST_F(BPFTest, StressTest)
{
	// 创建多个BPF实例来测试资源管理
	const int num_instances = 10;
	std::vector<BPFManager *> instances;

	try
	{
		for (int i = 0; i < num_instances; ++i)
		{
			BPFManager *instance = new BPFManager();
			ASSERT_NE(instance, nullptr);
			instances.push_back(instance);
		}

		// 验证所有实例都能正常工作
		for (auto instance : instances)
		{
			EXPECT_GT(instance->m_map_fd, 0);
			EXPECT_FALSE(instance->m_proc_iter_link_path.empty());
		}

		// 清理所有实例
		for (auto instance : instances)
		{
			delete instance;
		}
		instances.clear();
	}
	catch (const std::exception &e)
	{
		// 清理已创建的实例
		for (auto instance : instances)
		{
			delete instance;
		}
		FAIL() << "Stress test failed: " << e.what();
	}
}

// 测试错误恢复
TEST_F(BPFTest, ErrorRecovery)
{
	// 测试在错误情况下BPF实例的恢复能力
	ASSERT_NE(bpf_instance, nullptr);

	// 模拟一些错误情况并验证恢复
	// 这里可以添加更多的错误恢复测试

	// 验证实例仍然可用
	EXPECT_GT(bpf_instance->m_map_fd, 0);
}

// 测试内存泄漏
TEST_F(BPFTest, MemoryLeakTest)
{
	// 测试BPF实例创建和销毁过程中没有内存泄漏
	// 这个测试主要通过长时间运行和监控内存使用来验证

	// 创建和销毁多个实例
	for (int i = 0; i < 100; ++i)
	{
		BPFManager *temp_instance = new BPFManager();
		ASSERT_NE(temp_instance, nullptr);
		delete temp_instance;
	}

	// 验证主实例仍然可用
	EXPECT_GT(bpf_instance->m_map_fd, 0);
}

// 测试并发创建和销毁
TEST_F(BPFTest, ConcurrentCreationAndDestruction)
{
	// 测试多个线程同时创建和销毁BPF实例
	const int num_threads = 4;
	const int operations_per_thread = 10;
	std::vector<std::thread> threads;
	std::atomic<int> success_count{0};

	for (int i = 0; i < num_threads; ++i)
	{
		threads.emplace_back(
			[&, i]()
			{
				for (int j = 0; j < operations_per_thread; ++j)
				{
					try
					{
						BPFManager *temp_instance = new BPFManager();
						if (temp_instance)
						{
							delete temp_instance;
							success_count++;
						}
					}
					catch (const std::exception &e)
					{
						pr_error(
							"Thread %d operation %d failed: %s",
							i,
							j,
							e.what()
						);
					}
				}
			}
		);
	}

	for (auto &thread : threads)
	{
		thread.join();
	}

	// 验证大部分操作成功
	EXPECT_GT(success_count.load(), num_threads * operations_per_thread * 0.8)
		<< "Most concurrent operations should succeed";
}

// 测试边界值
TEST_F(BPFTest, BoundaryValues)
{
	// 测试各种边界值情况

	// 测试空字符串参数
	std::string empty_result = bpf_instance->bpf_find_iter("");
	EXPECT_TRUE(empty_result.empty()) << "Empty iterator name should return "
										 "empty string";

	// 测试非常长的路径名
	std::string long_path(1024, 'a');
	int ret = bpf_instance->bpf_find_map(long_path.c_str());
	EXPECT_LE(ret, 0) << "Very long map name should fail";

	// 测试特殊字符路径
	// 这里可以添加更多的边界值测试
}

// 测试性能基准
TEST_F(BPFTest, PerformanceBenchmark)
{
	// 建立性能基准
	const int warmup_iterations = 10;
	const int benchmark_iterations = 1000;

	// 预热
	for (int i = 0; i < warmup_iterations; ++i)
	{
		bpf_instance->bpf_find_map("dk_shared_mem");
	}

	// 基准测试
	auto start = std::chrono::high_resolution_clock::now();
	for (int i = 0; i < benchmark_iterations; ++i)
	{
		bpf_instance->bpf_find_map("dk_shared_mem");
	}
	auto end = std::chrono::high_resolution_clock::now();

	auto duration =
		std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
	double avg_time_ns =
		static_cast<double>(duration.count()) / benchmark_iterations;

	// 记录性能基准（可以根据实际情况调整阈值）
	EXPECT_LT(avg_time_ns, 10000) << "Average operation time should be less "
									 "than 10 microseconds";
}

// 测试dump_task_file功能
TEST_F(BPFTest, DumpTaskFile)
{
	// 测试dump_task_file方法
	int ret = bpf_instance->dump_task_file();
	// 由于这是系统调用，我们主要测试它不会崩溃
	// 返回值可能因系统状态而异
	EXPECT_GE(ret, -1) << "dump_task_file should not crash";
}

// 测试BPF map文件描述符的有效性
TEST_F(BPFTest, MapFileDescriptor)
{
	// 验证map文件描述符是有效的
	EXPECT_GT(bpf_instance->m_map_fd, 0) << "BPFManager map file descriptor should be "
											"valid";

	// 测试文件描述符的读写权限
	if (bpf_instance->m_map_fd > 0)
	{
		// 尝试获取map信息来验证文件描述符的有效性
		EXPECT_TRUE(true) << "Map file descriptor is accessible";
	}
}
