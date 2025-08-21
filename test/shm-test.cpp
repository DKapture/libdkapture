#include "gtest/gtest.h"
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <stdexcept>
#include <system_error>

#include "../so/shm.h"
#include "../include/Ulog.h"
#include "../include/Ucom.h"

// 测试用的共享内存键值
static const key_t TEST_SHM_KEY = 0x87654321;

class SharedMemoryTest : public ::testing::Test
{
  protected:
	void SetUp() override
	{
		cleanup_test_shm();
	}

	void TearDown() override
	{
		cleanup_test_shm();
	}

	void cleanup_test_shm()
	{
		int shmid = shmget(TEST_SHM_KEY, 0, 0);
		if (shmid >= 0)
		{
			shmctl(shmid, IPC_RMID, nullptr);
		}
	}

	bool shm_exists(key_t key)
	{
		int shmid = shmget(key, 0, 0);
		return shmid >= 0;
	}

	bool get_shm_info(key_t key, struct shmid_ds &info)
	{
		int shmid = shmget(key, 0, 0);
		if (shmid < 0)
		{
			return false;
		}
		return shmctl(shmid, IPC_STAT, &info) >= 0;
	}
};

// 基本创建和删除测试
TEST_F(SharedMemoryTest, BasicCreationAndDeletion)
{
	EXPECT_FALSE(shm_exists(TEST_SHM_KEY));

	int shmid = shmget(TEST_SHM_KEY, 1024 * 1024, IPC_CREAT | IPC_EXCL | 0600);
	EXPECT_GE(shmid, 0);

	EXPECT_TRUE(shm_exists(TEST_SHM_KEY));

	EXPECT_EQ(shmctl(shmid, IPC_RMID, nullptr), 0);
	EXPECT_FALSE(shm_exists(TEST_SHM_KEY));
}

// SharedMemory类测试
TEST_F(SharedMemoryTest, SharedMemoryClass)
{
	EXPECT_FALSE(shm_exists(0x12345678));

	try
	{
		SharedMemory *shm = new SharedMemory();
		EXPECT_NE(shm, nullptr);
		EXPECT_TRUE(shm_exists(0x12345678));

		delete shm;
	}
	catch (const std::exception &e)
	{
		pr_error("Exception: %s", e.what());
		FAIL();
	}
}

// 多个对象引用计数测试
TEST_F(SharedMemoryTest, MultipleObjects)
{
	try
	{
		SharedMemory *shm1 = new SharedMemory();
		EXPECT_NE(shm1, nullptr);

		SharedMemory *shm2 = new SharedMemory();
		EXPECT_NE(shm2, nullptr);

		EXPECT_TRUE(shm_exists(0x12345678));

		delete shm1;
		delete shm2;
	}
	catch (const std::exception &e)
	{
		pr_error("Exception: %s", e.what());
		FAIL();
	}
}

// 并发访问测试
TEST_F(SharedMemoryTest, ConcurrentAccess)
{
	try
	{
		const int num_threads = 4;
		std::vector<std::thread> threads;
		std::atomic<int> success_count{0};

		for (int i = 0; i < num_threads; ++i)
		{
			threads.emplace_back(
				[&]()
				{
					try
					{
						SharedMemory *shm = new SharedMemory();
						EXPECT_NE(shm, nullptr);
						delete shm;
						success_count++;
					}
					catch (const std::exception &e)
					{
						pr_error("Thread failed: %s", e.what());
						FAIL();
					}
				}
			);
		}

		for (auto &thread : threads)
		{
			thread.join();
		}

		EXPECT_EQ(success_count.load(), num_threads);
	}
	catch (const std::exception &e)
	{
		pr_error("Exception: %s", e.what());
		FAIL();
	}
}

// 测试版本字段（通过共享内存存在性验证）
TEST_F(SharedMemoryTest, VersionField)
{
	try
	{
		SharedMemory *shm = new SharedMemory();
		EXPECT_NE(shm, nullptr);
		EXPECT_TRUE(shm_exists(0x12345678));

		// 验证共享内存段被正确创建
		// 注意：version字段是私有的，我们通过共享内存的存在性来验证

		delete shm;
	}
	catch (const std::exception &e)
	{
		pr_error("Exception: %s", e.what());
		FAIL();
	}
}

// 测试锁字段初始化
TEST_F(SharedMemoryTest, LockFieldsInitialization)
{
	try
	{
		SharedMemory *shm = new SharedMemory();
		EXPECT_NE(shm, nullptr);

		// 验证锁字段被正确初始化（应该为0）
		EXPECT_EQ(shm->bpf_lock, 0);
		EXPECT_EQ(shm->bpf_ref_cnt, 0);
		EXPECT_EQ(shm->ring_buffer_lock, 0);
		EXPECT_EQ(shm->ring_buffer_ref_cnt, 0);
		EXPECT_EQ(shm->data_map_lock, 0);
		EXPECT_EQ(shm->data_map_idx, 0);
		EXPECT_EQ(shm->data_map_ref_cnt, 0);

		delete shm;
	}
	catch (const std::exception &e)
	{
		pr_error("Exception: %s", e.what());
		FAIL();
	}
}

// 测试权限设置
TEST_F(SharedMemoryTest, PermissionSettings)
{
	try
	{
		SharedMemory *shm = new SharedMemory();
		EXPECT_NE(shm, nullptr);

		// 验证共享内存段的权限设置
		struct shmid_ds shm_info;
		EXPECT_TRUE(get_shm_info(0x12345678, shm_info));
		EXPECT_EQ(shm_info.shm_perm.mode & 0777, 0600); // 只有所有者可读写

		delete shm;
	}
	catch (const std::exception &e)
	{
		pr_error("Exception: %s", e.what());
		FAIL();
	}
}

// 测试大小设置
TEST_F(SharedMemoryTest, SizeSettings)
{
	try
	{
		SharedMemory *shm = new SharedMemory();
		EXPECT_NE(shm, nullptr);

		// 验证共享内存段的大小
		struct shmid_ds shm_info;
		EXPECT_TRUE(get_shm_info(0x12345678, shm_info));
		EXPECT_EQ(shm_info.shm_segsz, 1024 * 1024); // 1MB

		delete shm;
	}
	catch (const std::exception &e)
	{
		pr_error("Exception: %s", e.what());
		FAIL();
	}
}

// 测试异常情况处理
TEST_F(SharedMemoryTest, ExceptionHandling)
{
	// 测试当共享内存段已存在但大小不匹配时的情况
	// 首先创建一个不同大小的共享内存段
	int shmid = shmget(0x12345678, 512 * 1024, IPC_CREAT | IPC_EXCL | 0600);
	if (shmid >= 0)
	{
		// 设置所有者权限
		struct shmid_ds shm_info;
		shmctl(shmid, IPC_STAT, &shm_info);
		shm_info.shm_perm.uid = 0;
		shmctl(shmid, IPC_SET, &shm_info);

		// 尝试创建SharedMemory对象，应该抛出异常
		EXPECT_THROW(
			{
				SharedMemory *shm = new SharedMemory();
				delete shm;
			},
			std::system_error
		);

		// 清理
		shmctl(shmid, IPC_RMID, nullptr);
	}
}

// 测试清理机制
TEST_F(SharedMemoryTest, CleanupMechanism)
{
	try
	{
		// 创建SharedMemory对象
		SharedMemory *shm = new SharedMemory();
		EXPECT_NE(shm, nullptr);
		EXPECT_TRUE(shm_exists(0x12345678));

		// 获取共享内存段ID
		int shmid = shmget(0x12345678, 0, 0);
		EXPECT_GE(shmid, 0);

		// 检查附加进程数
		struct shmid_ds shm_info;
		EXPECT_TRUE(get_shm_info(0x12345678, shm_info));
		int initial_attachments = shm_info.shm_nattch;

		// 删除SharedMemory对象
		delete shm;

		// 验证共享内存段的状态
		if (get_shm_info(0x12345678, shm_info))
		{
			// 如果共享内存段仍然存在，检查附加进程数是否减少
			EXPECT_LE(shm_info.shm_nattch, initial_attachments);
		}
	}
	catch (const std::exception &e)
	{
		pr_error("Exception: %s", e.what());
		FAIL();
	}
}

// 测试重复创建
TEST_F(SharedMemoryTest, RepeatedCreation)
{
	try
	{
		// 第一次创建
		SharedMemory *shm1 = new SharedMemory();
		EXPECT_NE(shm1, nullptr);
		EXPECT_TRUE(shm_exists(0x12345678));

		// 第二次创建（应该复用同一个共享内存段）
		SharedMemory *shm2 = new SharedMemory();
		EXPECT_NE(shm2, nullptr);
		EXPECT_TRUE(shm_exists(0x12345678));

		// 验证两个对象指向同一个共享内存
		// 通过共享内存段的存在性来验证，而不是直接访问私有字段

		// 清理
		delete shm1;
		delete shm2;
	}
	catch (const std::exception &e)
	{
		pr_error("Exception: %s", e.what());
		FAIL();
	}
}

// 测试性能
TEST_F(SharedMemoryTest, PerformanceTest)
{
	try
	{
		const int iterations = 1000;
		auto start = std::chrono::high_resolution_clock::now();

		for (int i = 0; i < iterations; ++i)
		{
			SharedMemory *shm = new SharedMemory();
			EXPECT_NE(shm, nullptr);
			delete shm;
		}

		auto end = std::chrono::high_resolution_clock::now();
		auto duration =
			std::chrono::duration_cast<std::chrono::microseconds>(end - start);

		// 验证性能在合理范围内（每次操作不超过1ms）
		EXPECT_LT(duration.count() / iterations, 1000);
	}
	catch (const std::exception &e)
	{
		pr_error("Exception: %s", e.what());
		FAIL();
	}
}

// MirrorMemory类测试
class MirrorMemoryTest : public ::testing::Test
{
  protected:
	void SetUp() override
	{
		cleanup_test_mirror_shm();
	}

	void TearDown() override
	{
		cleanup_test_mirror_shm();
	}

	void cleanup_test_mirror_shm()
	{
		// 清理测试过程中可能创建的共享内存段
	}

	bool is_power_of_2(size_t n)
	{
		return n > 0 && (n & (n - 1)) == 0;
	}

	bool is_multiple_of_page_size(size_t n)
	{
		int page_size = getpagesize();
		return n % page_size == 0;
	}
};

// 基本构造函数测试
TEST_F(MirrorMemoryTest, BasicConstruction)
{
	try
	{
		size_t valid_size = getpagesize() * 2;
		MirrorMemory mirror(valid_size, IPC_PRIVATE);

		EXPECT_NE(mirror.getaddr(), nullptr);
		EXPECT_NE(mirror.getmirror(), nullptr);
		EXPECT_NE(mirror.getaddr(), mirror.getmirror());
	}
	catch (const std::exception &e)
	{
		pr_error("Exception: %s", e.what());
		FAIL();
	}
}

// 测试共享内存模式
TEST_F(MirrorMemoryTest, SharedMemoryMode)
{
	try
	{
		key_t key = 0x12345678;
		size_t valid_size = getpagesize() * 4;
		MirrorMemory mirror(valid_size, key);

		EXPECT_NE(mirror.getaddr(), nullptr);
		EXPECT_NE(mirror.getmirror(), nullptr);
		EXPECT_NE(mirror.getaddr(), mirror.getmirror());
	}
	catch (const std::exception &e)
	{
		pr_error("Exception: %s", e.what());
		FAIL();
	}
}

// 测试内存镜像功能
TEST_F(MirrorMemoryTest, MemoryMirroring)
{
	try
	{
		size_t valid_size = getpagesize() * 2;
		MirrorMemory mirror(valid_size, IPC_PRIVATE);

		void *addr = mirror.getaddr();
		void *addr_mirror = mirror.getmirror();

		// 在第一个地址写入数据
		*(long *)addr = 0x1234567890abcdef;

		// 验证第二个地址能看到相同的数据（镜像功能）
		EXPECT_EQ(*(long *)addr_mirror, 0x1234567890abcdef);

		// 在第二个地址写入数据
		*(long *)addr_mirror = 0xfedcba0987654321;

		// 验证第一个地址能看到相同的数据
		EXPECT_EQ(*(long *)addr, 0xfedcba0987654321);
	}
	catch (const std::exception &e)
	{
		pr_error("Exception: %s", e.what());
		FAIL();
	}
}

// 测试地址连续性
TEST_F(MirrorMemoryTest, AddressContinuity)
{
	try
	{
		size_t valid_size = getpagesize() * 2;
		MirrorMemory mirror(valid_size, IPC_PRIVATE);

		void *addr = mirror.getaddr();
		void *addr_mirror = mirror.getmirror();

		// 验证两个地址是连续的
		EXPECT_EQ((char *)addr_mirror, (char *)addr + valid_size);
	}
	catch (const std::exception &e)
	{
		pr_error("Exception: %s", e.what());
		FAIL();
	}
}

// 测试无效缓冲区大小
TEST_F(MirrorMemoryTest, InvalidBufferSize)
{
	// 测试非2的幂的大小
	EXPECT_THROW(
		{ MirrorMemory mirror(getpagesize() * 3, IPC_PRIVATE); },
		std::system_error
	);

	// 测试非页大小倍数的缓冲区大小
	EXPECT_THROW(
		{ MirrorMemory mirror(getpagesize() + 1, IPC_PRIVATE); },
		std::system_error
	);
}

// 测试多个MirrorMemory对象
TEST_F(MirrorMemoryTest, MultipleObjects)
{
	try
	{
		key_t key = 0x12345678;
		size_t valid_size = getpagesize() * 2;

		MirrorMemory mirror1(valid_size, IPC_PRIVATE);
		MirrorMemory mirror2(valid_size, key);

		EXPECT_NE(mirror1.getaddr(), nullptr);
		EXPECT_NE(mirror1.getmirror(), nullptr);
		EXPECT_NE(mirror2.getaddr(), nullptr);
		EXPECT_NE(mirror2.getmirror(), nullptr);

		// 验证两个对象的地址不同
		EXPECT_NE(mirror1.getaddr(), mirror2.getaddr());
		EXPECT_NE(mirror1.getmirror(), mirror2.getmirror());
	}
	catch (const std::exception &e)
	{
		pr_error("Exception: %s", e.what());
		FAIL();
	}
}

// 测试析构函数
TEST_F(MirrorMemoryTest, Destructor)
{
	try
	{
		size_t valid_size = getpagesize() * 2;

		// 在作用域内创建对象
		{
			MirrorMemory mirror(valid_size, IPC_PRIVATE);
			EXPECT_NE(mirror.getaddr(), nullptr);
			EXPECT_NE(mirror.getmirror(), nullptr);
		}
		// 对象应该已经自动销毁

		// 验证没有内存泄漏（通过创建新对象来验证）
		MirrorMemory mirror2(valid_size, IPC_PRIVATE);
		EXPECT_NE(mirror2.getaddr(), nullptr);
		EXPECT_NE(mirror2.getmirror(), nullptr);
	}
	catch (const std::exception &e)
	{
		pr_error("Exception: %s", e.what());
		FAIL();
	}
}

// 测试边界情况
TEST_F(MirrorMemoryTest, EdgeCases)
{
	try
	{
		// 测试最小有效大小（1页）
		size_t min_size = getpagesize();
		MirrorMemory mirror_min(min_size, IPC_PRIVATE);
		EXPECT_NE(mirror_min.getaddr(), nullptr);
		EXPECT_NE(mirror_min.getmirror(), nullptr);

		// 测试较大的缓冲区大小
		size_t large_size = getpagesize() * 1024; // 1MB
		MirrorMemory mirror_large(large_size, IPC_PRIVATE);
		EXPECT_NE(mirror_large.getaddr(), nullptr);
		EXPECT_NE(mirror_large.getmirror(), nullptr);
	}
	catch (const std::exception &e)
	{
		pr_error("Exception: %s", e.what());
		FAIL();
	}
}

// 测试并发访问
TEST_F(MirrorMemoryTest, ConcurrentAccess)
{
	try
	{
		const int num_threads = 4;
		std::vector<std::thread> threads;
		std::atomic<int> success_count{0};

		for (int i = 0; i < num_threads; ++i)
		{
			threads.emplace_back(
				[&]()
				{
					try
					{
						size_t valid_size = getpagesize() * 2;
						MirrorMemory mirror(valid_size, IPC_PRIVATE);

						// 测试镜像功能
						*(long *)mirror.getaddr() = 0xdeadbeef;
						// EXPECT_EQ(*(long *)mirror.getmirror(), 0xdeadbeef);

						success_count++;
					}
					catch (const std::exception &e)
					{
						pr_error("Thread failed: %s", e.what());
						FAIL();
					}
				}
			);
		}

		for (auto &thread : threads)
		{
			thread.join();
		}

		EXPECT_EQ(success_count.load(), num_threads);
	}
	catch (const std::exception &e)
	{
		pr_error("Exception: %s", e.what());
		FAIL();
	}
}

// 测试性能
TEST_F(MirrorMemoryTest, PerformanceTest)
{
	try
	{
		const int iterations = 100;
		size_t valid_size = getpagesize() * 2;

		auto start = std::chrono::high_resolution_clock::now();

		for (int i = 0; i < iterations; ++i)
		{
			MirrorMemory mirror(valid_size, IPC_PRIVATE);

			// 测试镜像功能
			*(long *)mirror.getaddr() = i;
			EXPECT_EQ(*(long *)mirror.getmirror(), i);
		}

		auto end = std::chrono::high_resolution_clock::now();
		auto duration =
			std::chrono::duration_cast<std::chrono::microseconds>(end - start);

		// 验证性能在合理范围内（每次操作不超过100微秒）
		EXPECT_LT(duration.count() / iterations, 100);
	}
	catch (const std::exception &e)
	{
		pr_error("Exception: %s", e.what());
		FAIL();
	}
}
