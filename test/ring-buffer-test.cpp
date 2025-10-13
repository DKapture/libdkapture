// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1-only

// This file uses/derives from googletest
// Copyright 2008, Google Inc.
// Licensed under the BSD 3-Clause License
// See NOTICE for full license text

#include "gtest/gtest.h"
#include "ring-buffer.h"
#include "shm.h"
#include "spinlock.h"
#include <thread>
#include <vector>
#include <cstring>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <chrono>
#include <stdexcept>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <atomic>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bpf-manager.h"

extern FILE *gtest_fp;
// 测试用的回调函数
static int test_callback(void *ctx, void *data, size_t size)
{
	int *counter = static_cast<int *>(ctx);
	(*counter)++;
	return 0;
}

// 测试用的回调函数 - 返回错误
static int test_callback_error(void *ctx, void *data, size_t size)
{
	return -1; // 返回错误
}

class RingBufferTest : public ::testing::Test
{
  protected:
	BPFManager *bpf;
	void SetUp() override
	{
		// 清理可能存在的共享内存
		cleanup_shared_memory();
		Log::set_file(gtest_fp);
	}

	void TearDown() override
	{
		// 清理测试产生的共享内存
		cleanup_shared_memory();
	}

	void cleanup_shared_memory()
	{
		// 这里可以添加清理逻辑，但RingBuffer析构函数会自动清理
	}

	// 计算合适的缓冲区大小（必须是页面大小的2的幂次）
	size_t calculate_buffer_size(size_t min_size) const
	{
		size_t page_size = getpagesize();
		size_t size = page_size;
		while (size < min_size)
		{
			size *= 2;
		}
		return size;
	}

	// 创建测试用的BPF map
	int create_test_bpf_map(size_t size)
	{
		struct bpf_map_create_opts opts = {};
		opts.sz = sizeof(opts);

		bpf = new BPFManager();
		int map_fd = bpf->m_map_fd;
		return map_fd;
	}

	// 清理BPF map
	void cleanup_bpf_map(int map_fd)
	{
		if (bpf && bpf->m_map_fd == map_fd)
		{
			bpf->m_map_fd = -1;
			delete bpf;
		}
	}
};

// 测试普通RingBuffer的构造函数
TEST_F(RingBufferTest, ConstructorNormal)
{
	size_t buffer_size = calculate_buffer_size(1024);

	EXPECT_NO_THROW({
		RingBuffer rb(buffer_size);
		EXPECT_EQ(rb.get_bsz(), buffer_size);
		EXPECT_EQ(rb.get_consumer_index(), 0);
		EXPECT_EQ(rb.get_producer_index(), 0);
	});
}

// 测试普通RingBuffer的构造函数参数验证
TEST_F(RingBufferTest, ConstructorInvalidSize)
{
	size_t page_size = getpagesize();

	// 测试非页面大小倍数
	EXPECT_THROW({ RingBuffer rb(page_size + 1); }, std::system_error);

	// 测试非2的幂次
	EXPECT_THROW({ RingBuffer rb(page_size * 3); }, std::system_error);
}

// 测试普通RingBuffer的写操作
TEST_F(RingBufferTest, WriteOperation)
{
	size_t buffer_size = calculate_buffer_size(1024);
	RingBuffer rb(buffer_size);

	// 测试基本写操作
	char test_data[] = "Hello, RingBuffer!";
	size_t data_size = strlen(test_data);

	size_t written = rb.write(test_data, data_size);
	EXPECT_EQ(written, data_size);
	EXPECT_EQ(rb.get_producer_index(), data_size);
	EXPECT_EQ(rb.get_consumer_index(), 0);
}

// 测试普通RingBuffer的读操作
TEST_F(RingBufferTest, ReadOperation)
{
	size_t buffer_size = calculate_buffer_size(1024);
	RingBuffer rb(buffer_size);

	// 先写入数据
	char test_data[] = "Test data for reading";
	size_t data_size = strlen(test_data);
	rb.write(test_data, data_size);

	// 读取数据
	char read_buffer[256] = {};
	size_t read_size = rb.read(read_buffer, data_size);

	EXPECT_EQ(read_size, data_size);
	EXPECT_EQ(rb.get_consumer_index(), data_size);
	EXPECT_EQ(rb.get_producer_index(), data_size);
	EXPECT_STREQ(read_buffer, test_data);
}

// 测试普通RingBuffer的循环写入
TEST_F(RingBufferTest, CircularWrite)
{
	size_t buffer_size = calculate_buffer_size(1024);
	RingBuffer rb(buffer_size);

	// 写入超过缓冲区大小的数据
	std::string long_data(buffer_size + 100, 'A');

	size_t written =
		rb.write(const_cast<char *>(long_data.c_str()), long_data.length());

	// 应该只能写入缓冲区大小的数据
	EXPECT_EQ(written, buffer_size);
	EXPECT_EQ(rb.get_producer_index(), buffer_size);
}

// 测试普通RingBuffer的循环读取
TEST_F(RingBufferTest, CircularRead)
{
	size_t buffer_size = calculate_buffer_size(1024);
	RingBuffer rb(buffer_size);

	// 写入数据
	std::string test_data = "Test data";
	rb.write(const_cast<char *>(test_data.c_str()), test_data.length());

	// 读取超过可用数据的大小
	char read_buffer[256];
	size_t read_size = rb.read(read_buffer, 1000);

	// 应该只能读取实际可用的数据
	EXPECT_EQ(read_size, test_data.length());
}

// 测试普通RingBuffer的缓冲区访问
TEST_F(RingBufferTest, BufferAccess)
{
	size_t buffer_size = calculate_buffer_size(1024);
	RingBuffer rb(buffer_size);

	void *buffer_ptr = rb.buf(0);
	EXPECT_NE(buffer_ptr, nullptr);

	// 测试不同索引的缓冲区访问
	void *buffer_ptr2 = rb.buf(100);
	EXPECT_NE(buffer_ptr2, nullptr);
	EXPECT_NE(buffer_ptr, buffer_ptr2);
}

// 测试普通RingBuffer的并发访问
TEST_F(RingBufferTest, ConcurrentAccess)
{
	size_t buffer_size = calculate_buffer_size(10240);
	ASSERT_EQ(buffer_size, 16384);
	RingBuffer rb(buffer_size);

	const int num_threads = 20;
	const int writes_per_thread = 20;
	char buf[32] = {};
	std::vector<std::thread> threads;

	// 启动多个写线程
	for (int i = 0; i < num_threads; ++i)
	{
		threads.emplace_back(
			[&rb, buf, i, writes_per_thread]()
			{
				for (int j = 0; j < writes_per_thread; ++j)
				{
					sprintf(
						const_cast<char *>(buf),
						"Thread %2d Data: %2d",
						i,
						j
					);
					rb.write(const_cast<char *>(buf), sizeof(buf));
				}
			}
		);
	}

	// 等待所有线程完成
	for (auto &thread : threads)
	{
		thread.join();
	}

	// 验证总写入量
	EXPECT_EQ(
		rb.get_producer_index(),
		num_threads * writes_per_thread * sizeof(buf)
	); // 每个字符串16字节
}

// 测试普通RingBuffer的内存管理
TEST_F(RingBufferTest, MemoryManagement)
{
	size_t buffer_size = calculate_buffer_size(1024);

	// 测试多个RingBuffer实例共享内存
	RingBuffer *rb1 = new RingBuffer(buffer_size);
	RingBuffer *rb2 = new RingBuffer(buffer_size);

	// 写入数据到第一个实例
	char test_data[] = "Shared memory test";
	rb1->write(test_data, strlen(test_data));

	// 从第二个实例读取数据
	char read_buffer[256] = {};
	size_t read_size = rb2->read(read_buffer, strlen(test_data));

	EXPECT_EQ(read_size, strlen(test_data));
	EXPECT_STREQ(read_buffer, test_data);

	delete rb1;
	delete rb2;
}

// 测试BPF RingBuffer的构造函数
TEST_F(RingBufferTest, ConstructorBPF)
{
	// 创建测试用的BPF map
	int map_fd = create_test_bpf_map(4096);

	if (map_fd >= 0)
	{
		// 测试有效的BPF map
		EXPECT_NO_THROW({ RingBuffer rb(map_fd, test_callback, nullptr); });

		cleanup_bpf_map(map_fd);
	}
	else
	{
		// 如果BPF不可用，测试异常处理
		EXPECT_THROW(
			{ RingBuffer rb(-1, test_callback, nullptr); },
			std::system_error
		);
	}
}

// 测试BPF RingBuffer的poll操作
TEST_F(RingBufferTest, BPFPollOperation)
{
	int map_fd = create_test_bpf_map(4096);

	if (map_fd >= 0)
	{
		RingBuffer rb(map_fd, test_callback, nullptr);

		// 测试poll操作（超时）
		int result = rb.poll(100); // 100ms超时
		EXPECT_GE(result, 0); // 应该返回0（超时）或正数（事件数）

		cleanup_bpf_map(map_fd);
	}
	else
	{
		// 跳过BPF相关测试
		GTEST_SKIP() << "BPFManager not available, skipping BPFManager tests";
	}
}

// 测试BPF RingBuffer的索引获取
TEST_F(RingBufferTest, BPFIndexOperations)
{
	int map_fd = create_test_bpf_map(4096);

	if (map_fd >= 0)
	{
		RingBuffer rb(map_fd, test_callback, nullptr);

		// 测试消费者和生产者索引获取
		ulong consumer_idx = rb.get_consumer_index();
		ulong producer_idx = rb.get_producer_index();

		EXPECT_GE(producer_idx, consumer_idx);

		cleanup_bpf_map(map_fd);
	}
	else
	{
		GTEST_SKIP() << "BPFManager not available, skipping BPFManager tests";
	}
}

// 测试BPF RingBuffer的回调函数错误处理
TEST_F(RingBufferTest, BPFCallbackError)
{
	int map_fd = create_test_bpf_map(4096);

	if (map_fd >= 0)
	{
		RingBuffer rb(map_fd, test_callback_error, nullptr);

		// 测试回调函数返回错误的情况
		int result = rb.poll(100);
		// 由于没有实际数据，poll应该返回0或超时
		EXPECT_GE(result, 0);

		cleanup_bpf_map(map_fd);
	}
	else
	{
		GTEST_SKIP() << "BPFManager not available, skipping BPFManager tests";
	}
}

// 测试RingBuffer的析构函数
TEST_F(RingBufferTest, Destructor)
{
	size_t buffer_size = calculate_buffer_size(1024);

	// 测试正常析构
	{
		RingBuffer rb(buffer_size);
		// 写入一些数据
		char test_data[] = "Test data";
		rb.write(test_data, strlen(test_data));
	} // 这里rb应该被正确析构

	// 测试析构后内存是否被正确清理
	// 可以通过检查共享内存段来验证
}

// 测试RingBuffer的异常安全性
TEST_F(RingBufferTest, ExceptionSafety)
{
	size_t buffer_size = calculate_buffer_size(1024);

	// 测试在异常情况下资源是否被正确清理
	try
	{
		RingBuffer rb(buffer_size);
		throw std::runtime_error("Test exception");
	}
	catch (const std::runtime_error &)
	{
		// 异常被捕获，RingBuffer应该被正确析构
	}

	// 验证没有资源泄漏
}

// 测试RingBuffer的性能特性
TEST_F(RingBufferTest, Performance)
{
	size_t buffer_size = calculate_buffer_size(1024 * 1024); // 1MB
	RingBuffer rb(buffer_size);

	// 测试大量数据的写入性能
	std::vector<char> large_data(buffer_size / 2, 'X');

	auto start = std::chrono::high_resolution_clock::now();

	size_t written = rb.write(large_data.data(), large_data.size());

	auto end = std::chrono::high_resolution_clock::now();
	auto duration =
		std::chrono::duration_cast<std::chrono::microseconds>(end - start);

	EXPECT_EQ(written, large_data.size());
	EXPECT_LT(duration.count(), 10000); // 应该在10ms内完成

	// 测试读取性能
	std::vector<char> read_buffer(large_data.size());

	start = std::chrono::high_resolution_clock::now();

	size_t read_size = rb.read(read_buffer.data(), read_buffer.size());

	end = std::chrono::high_resolution_clock::now();
	duration =
		std::chrono::duration_cast<std::chrono::microseconds>(end - start);

	EXPECT_EQ(read_size, large_data.size());
	EXPECT_LT(duration.count(), 10000); // 应该在10ms内完成
	EXPECT_EQ(read_buffer, large_data);
}

// 测试RingBuffer的边界情况
TEST_F(RingBufferTest, EdgeCases)
{
	size_t buffer_size = calculate_buffer_size(1024);
	RingBuffer rb(buffer_size);

	// 测试写入刚好填满缓冲区
	std::vector<char> exact_data(buffer_size, 'F');
	size_t written = rb.write(exact_data.data(), exact_data.size());
	EXPECT_EQ(written, buffer_size);

	// 测试写入超过缓冲区大小
	std::vector<char> overflow_data(buffer_size + 100, 'O');
	written = rb.write(overflow_data.data(), overflow_data.size());
	EXPECT_EQ(written, 0); // 缓冲区已满，无法写入

	// 测试读取所有数据
	std::vector<char> read_buffer(buffer_size);
	size_t read_size = rb.read(read_buffer.data(), read_buffer.size());
	EXPECT_EQ(read_size, buffer_size);

	// 验证读取的数据
	for (size_t i = 0; i < buffer_size; ++i)
	{
		EXPECT_EQ(read_buffer[i], 'F');
	}
}

// 测试RingBuffer的跨进程共享
TEST_F(RingBufferTest, CrossProcessSharing)
{
	size_t buffer_size = calculate_buffer_size(1024);

	// 测试多个进程可以共享同一个RingBuffer
	// 这里我们通过创建多个实例来模拟
	std::vector<RingBuffer *> buffers;
	const int num_instances = 3;

	try
	{
		// 创建多个实例
		for (int i = 0; i < num_instances; ++i)
		{
			buffers.push_back(new RingBuffer(buffer_size));
		}

		// 在第一个实例中写入数据
		char test_data[] = "Cross process test data";
		buffers[0]->write(test_data, strlen(test_data));

		// 在其他实例中读取数据
		for (int i = 1; i < num_instances; ++i)
		{
			char read_buffer[256] = {};
			memcpy(read_buffer, buffers[i]->buf(0), strlen(test_data));
			EXPECT_STREQ(read_buffer, test_data);
		}

		// 清理
		for (auto *buf : buffers)
		{
			delete buf;
		}
	}
	catch (const std::exception &e)
	{
		// 清理
		for (auto *buf : buffers)
		{
			delete buf;
		}
		throw;
	}
}

// 测试RingBuffer的引用计数机制
TEST_F(RingBufferTest, ReferenceCounting)
{
	size_t buffer_size = calculate_buffer_size(1024);

	// 测试引用计数机制
	RingBuffer *rb1 = new RingBuffer(buffer_size);
	RingBuffer *rb2 = new RingBuffer(buffer_size);

	// 两个实例应该共享同一个共享内存段
	EXPECT_EQ(rb1->get_bsz(), rb2->get_bsz());

	// 删除第一个实例
	delete rb1;

	// 第二个实例应该仍然可用
	EXPECT_NO_THROW({
		char test_data[] = "Test";
		rb2->write(test_data, strlen(test_data));
	});

	delete rb2;
}

// 测试RingBuffer的异常构造函数
TEST_F(RingBufferTest, ConstructorExceptions)
{
	size_t page_size = getpagesize();

	// 测试各种无效参数
	EXPECT_THROW({ RingBuffer rb(0); }, std::system_error);

	EXPECT_THROW({ RingBuffer rb(1); }, std::system_error);

	EXPECT_THROW({ RingBuffer rb(page_size - 1); }, std::system_error);
}

// 测试RingBuffer的buf函数边界情况
TEST_F(RingBufferTest, BufferFunctionEdgeCases)
{
	size_t buffer_size = calculate_buffer_size(1024);
	RingBuffer rb(buffer_size);

	// 测试buf函数的边界情况
	void *ptr1 = rb.buf(0);
	void *ptr2 = rb.buf(buffer_size - 1);
	void *ptr3 = rb.buf(buffer_size);

	EXPECT_NE(ptr1, nullptr);
	EXPECT_NE(ptr2, nullptr);
	EXPECT_NE(ptr3, nullptr);

	// 验证指针地址关系
	EXPECT_GT(ptr2, ptr1);
	EXPECT_EQ(ptr3, ptr1);
}

// 测试RingBuffer的并发读写
TEST_F(RingBufferTest, ConcurrentReadWrite)
{
	size_t buffer_size = calculate_buffer_size(1024);
	RingBuffer rb(buffer_size);

	const int num_operations = 1000;
	std::atomic<int> write_count(0);
	std::atomic<int> read_count(0);
	bool writer_done = false;

	// 启动写线程
	std::thread writer(
		[&rb, &write_count, num_operations, &writer_done]()
		{
			for (int i = 0; i < num_operations; ++i)
			{
				std::string data = "Data " + std::to_string(i);
				size_t written =
					rb.write(const_cast<char *>(data.c_str()), data.length());
				write_count += written;
			}
			writer_done = true;
		}
	);

	// 启动读线程
	std::thread reader(
		[&rb, &read_count, num_operations, &writer_done, buffer_size]()
		{
			char buffer[buffer_size];
			bool reader_done = false;
			while (1)
			{
				if (writer_done)
				{
					reader_done = true;
				}
				size_t read = rb.read(buffer, sizeof(buffer));
				read_count += read;
				if (reader_done)
				{
					break;
				}
			}
		}
	);

	writer.join();
	reader.join();

	// 验证读写操作都成功执行
	EXPECT_EQ(write_count.load(), read_count.load());
}
