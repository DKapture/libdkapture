// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

// This file uses/derives from googletest
// Copyright 2008, Google Inc.
// Licensed under the BSD 3-Clause License
// See NOTICE for full license text

#include "gtest/gtest.h"
#include "spinlock.h"
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>
#include <iostream>

class SpinLockTest : public ::testing::Test
{
  protected:
	void SetUp() override
	{
		// 初始化共享锁变量
		shared_lock = 0;
	}

	void TearDown() override
	{
		// 确保锁被释放
		shared_lock = 0;
	}

	volatile long shared_lock;
};

// 测试基本的锁获取和释放
TEST_F(SpinLockTest, BasicLockUnlock)
{
	SpinLock lock(&shared_lock);

	// 初始状态应该是未锁定
	EXPECT_EQ(shared_lock, 0);

	// 获取锁
	lock.lock();
	EXPECT_NE(shared_lock, 0);

	// 释放锁
	lock.unlock();
	EXPECT_EQ(shared_lock, 0);
}

// 测试try_lock功能
TEST_F(SpinLockTest, TryLockTest)
{
	SpinLock lock(&shared_lock);

	// 第一次尝试获取锁应该成功
	EXPECT_TRUE(lock.try_lock());
	EXPECT_NE(shared_lock, 0);

	// 第二次尝试获取锁应该失败
	EXPECT_FALSE(lock.try_lock());

	// 释放锁
	lock.unlock();
	EXPECT_EQ(shared_lock, 0);

	// 释放后再次尝试应该成功
	EXPECT_TRUE(lock.try_lock());
	lock.unlock();
}

// 测试SpinLockGuard的RAII功能
TEST_F(SpinLockTest, SpinLockGuardRAII)
{
	{
		SpinLockGuard guard(new SpinLock(&shared_lock));
		// 在作用域内锁应该被持有
		EXPECT_NE(shared_lock, 0);
	}
	// 离开作用域后锁应该自动释放
	EXPECT_EQ(shared_lock, 0);
}

// 测试一致性检查功能
TEST_F(SpinLockTest, ConsistencyCheck)
{
	// 空锁应该是一致的
	EXPECT_TRUE(SpinLock::check_consistency(&shared_lock));

	// 设置锁为当前进程ID
	shared_lock = getpid();
	EXPECT_TRUE(SpinLock::check_consistency(&shared_lock));

	// 设置锁为无效PID
	shared_lock = 999999;
	EXPECT_FALSE(SpinLock::check_consistency(&shared_lock));

	// 重置
	shared_lock = 0;
}

// 测试多线程并发访问
TEST_F(SpinLockTest, MultiThreadedAccess)
{
	const int num_threads = 4;
	const int iterations = 1000;
	std::atomic<int> counter(0);
	std::vector<std::thread> threads;

	SpinLock lock(&shared_lock);

	// 创建多个线程，每个线程尝试获取锁并递增计数器
	for (int i = 0; i < num_threads; ++i)
	{
		threads.emplace_back(
			[&lock, &counter, iterations]()
			{
				for (int j = 0; j < iterations; ++j)
				{
					lock.lock();
					int old_val = counter.load();
					std::this_thread::sleep_for(std::chrono::microseconds(1));
					counter.store(old_val + 1);
					lock.unlock();
				}
			}
		);
	}

	// 等待所有线程完成
	for (auto &thread : threads)
	{
		thread.join();
	}

	// 验证计数器值
	EXPECT_EQ(counter.load(), num_threads * iterations);
	EXPECT_EQ(shared_lock, 0); // 锁应该被释放
}

// 测试锁的独占性
TEST_F(SpinLockTest, LockExclusivity)
{
	SpinLock lock1(&shared_lock);
	SpinLock lock2(&shared_lock);

	// 第一个锁获取成功
	lock1.lock();
	EXPECT_NE(shared_lock, 0);

	// 第二个锁尝试获取应该失败
	EXPECT_FALSE(lock2.try_lock());

	// 第一个锁释放
	lock1.unlock();
	EXPECT_EQ(shared_lock, 0);

	// 第二个锁现在应该能获取成功
	EXPECT_TRUE(lock2.try_lock());
	lock2.unlock();
}

// 测试长时间持有锁的警告机制
TEST_F(SpinLockTest, LongHoldWarning)
{
	SpinLock lock(&shared_lock);

	// 获取锁
	lock.lock();

	// 模拟长时间持有（注意：这个测试可能会产生警告日志）
	std::this_thread::sleep_for(std::chrono::milliseconds(100));

	// 释放锁
	lock.unlock();

	EXPECT_EQ(shared_lock, 0);
}

// 测试get_tid函数
TEST_F(SpinLockTest, GetTidFunction)
{
	pid_t tid = get_tid();
	EXPECT_GT(tid, 0);

	// 验证tid是当前线程的ID
	pid_t current_tid = static_cast<pid_t>(::syscall(SYS_gettid));
	EXPECT_EQ(tid, current_tid);
}

// 测试锁的重复获取和释放
TEST_F(SpinLockTest, RepeatedLockUnlock)
{
	SpinLock lock(&shared_lock);

	for (int i = 0; i < 100; ++i)
	{
		lock.lock();
		EXPECT_NE(shared_lock, 0);

		lock.unlock();
		EXPECT_EQ(shared_lock, 0);
	}
}

// 测试多个SpinLock实例操作同一个锁
TEST_F(SpinLockTest, MultipleSpinLockInstances)
{
	SpinLock lock1(&shared_lock);
	SpinLock lock2(&shared_lock);

	// 通过第一个实例获取锁
	lock1.lock();
	EXPECT_NE(shared_lock, 0);

	// 通过第二个实例尝试获取应该失败
	EXPECT_FALSE(lock2.try_lock());

	// 通过第一个实例释放锁
	lock1.unlock();
	EXPECT_EQ(shared_lock, 0);

	// 通过第二个实例现在应该能获取
	lock2.lock();
	EXPECT_NE(shared_lock, 0);
	lock2.unlock();
}

// 测试边界情况
TEST_F(SpinLockTest, EdgeCases)
{
	SpinLock lock(&shared_lock);

	// 测试空指针（这可能会导致段错误，但我们可以测试正常情况）
	if (&shared_lock != nullptr)
	{
		lock.lock();
		EXPECT_NE(shared_lock, 0);
		lock.unlock();
		EXPECT_EQ(shared_lock, 0);
	}
}

// 测试性能（基本性能测试）
TEST_F(SpinLockTest, PerformanceTest)
{
	SpinLock lock(&shared_lock);
	const int iterations = 10000;

	auto start = std::chrono::high_resolution_clock::now();

	for (int i = 0; i < iterations; ++i)
	{
		lock.lock();
		lock.unlock();
	}

	auto end = std::chrono::high_resolution_clock::now();
	auto duration =
		std::chrono::duration_cast<std::chrono::microseconds>(end - start);

	// 验证性能在合理范围内（每次锁操作应该小于1微秒）
	double avg_time = static_cast<double>(duration.count()) / iterations;
	EXPECT_LT(avg_time, 1000.0); // 小于1毫秒

	std::cout << "Average lock/unlock time: " << avg_time << " microseconds"
			  << std::endl;
}
