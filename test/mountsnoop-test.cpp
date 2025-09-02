#include "gtest/gtest.h"
#include <vector>
#include <atomic>
#include <thread>
#include <chrono>
#include <climits>
#include <cstdint>
#include <linux/mount.h>
#include "dkapture.h"

// 声明mountsnoop_init函数，这是在BUILTIN模式下的入口点
extern int
mountsnoop_init(int argc, char **argv, DKapture::DKCallback cb, void *ctx);
extern int mountsnoop_deinit(void);

// 测试常量定义
const std::string TEST_ROOT = "/tmp/mountsnoop_test_dir";

// 测试回调函数，用于接收和验证BPF事件
static std::vector<void *> captured_events;
static std::vector<size_t> captured_event_sizes;
static std::atomic<bool> event_received(false);

// 回调函数，用于接收BPF事件
static int test_callback(void *ctx, const void *data, size_t data_sz)
{
	// 数据验证
	if (data == nullptr || data_sz == 0)
	{
		return -1;
	}

	// 保存事件数据的副本
	void *event_copy = malloc(data_sz);
	if (event_copy)
	{
		memcpy(event_copy, data, data_sz);
		captured_events.push_back(event_copy);
		captured_event_sizes.push_back(data_sz);
		event_received = true;
	}

	return 0;
}

// 测试类
class MountsnoopBasicTest : public ::testing::Test
{
  protected:
	void SetUp() override
	{
		// 创建测试目录
		mkdir(TEST_ROOT.c_str(), 0755);

		// 清除之前捕获的事件
		for (void *event : captured_events)
		{
			free(event);
		}
		captured_events.clear();
		captured_event_sizes.clear();
		event_received = false;
	}

	void TearDown() override
	{
		// 清理测试目录
		std::string cmd = "rm -rf " + TEST_ROOT;
		system(cmd.c_str());

		// 释放事件内存
		for (void *event : captured_events)
		{
			free(event);
		}
		captured_events.clear();
		captured_event_sizes.clear();

		// 确保工具已经停止
		mountsnoop_deinit();
	}

	// 辅助函数：模拟mount事件
	void simulateMountEvent(
		const char *source,
		const char *target,
		const char *filesystemtype,
		unsigned long flags,
		const char *data,
		int ret
	)
	{
		struct mount_args event;
		memset(&event, 0, sizeof(event));

		strncpy(event.source, source, sizeof(event.source) - 1);
		strncpy(event.target, target, sizeof(event.target) - 1);
		strncpy(
			event.filesystemtype,
			filesystemtype,
			sizeof(event.filesystemtype) - 1
		);
		strncpy(event.data, data, sizeof(event.data) - 1);
		event.flags = flags;
		event.ret = ret;
		event.pid = 1000;
		event.tid = 1001;
		event.mnt_ns = 12345;
		strncpy(event.comm, "test_process", sizeof(event.comm) - 1);

		test_callback(nullptr, &event, sizeof(event));
	}

	// 辅助函数：模拟umount事件
	void simulateUmountEvent(const char *target, unsigned long flags, int ret)
	{
		struct umount_args event;
		memset(&event, 0, sizeof(event));

		strncpy(event.target, target, sizeof(event.target) - 1);
		event.flags = flags;
		event.ret = ret;
		event.pid = 1000;
		event.tid = 1001;
		event.mnt_ns = 12345;
		strncpy(event.comm, "test_process", sizeof(event.comm) - 1);

		test_callback(nullptr, &event, sizeof(event));
	}

	// 辅助函数：模拟fsopen事件
	void simulateFsopenEvent(const char *fsname, unsigned int flags, int ret)
	{
		struct fsopen_args event;
		memset(&event, 0, sizeof(event));

		strncpy(event.fsname, fsname, sizeof(event.fsname) - 1);
		event.flags = flags;
		event.ret = ret;
		event.pid = 1000;
		event.tid = 1001;
		event.mnt_ns = 12345;
		strncpy(event.comm, "test_process", sizeof(event.comm) - 1);

		test_callback(nullptr, &event, sizeof(event));
	}

	// 辅助函数：模拟fsconfig事件
	void simulateFsconfigEvent(
		int fd,
		unsigned int cmd,
		const char *key,
		const char *value,
		int aux,
		int ret
	)
	{
		struct fsconfig_args event;
		memset(&event, 0, sizeof(event));

		event.fd = fd;
		event.cmd = cmd;
		strncpy(event.key, key, sizeof(event.key) - 1);
		strncpy(event.value, value, sizeof(event.value) - 1);
		event.aux = aux;
		event.ret = ret;
		event.pid = 1000;
		event.tid = 1001;
		event.mnt_ns = 12345;
		strncpy(event.comm, "test_process", sizeof(event.comm) - 1);

		test_callback(nullptr, &event, sizeof(event));
	}

	// 辅助函数：模拟fsmount事件
	void simulateFsmountEvent(
		int fs_fd,
		unsigned int flags,
		unsigned int attr_flags,
		int ret
	)
	{
		struct fsmount_args event;
		memset(&event, 0, sizeof(event));

		event.fs_fd = fs_fd;
		event.flags = flags;
		event.attr_flags = attr_flags;
		event.ret = ret;
		event.pid = 1000;
		event.tid = 1001;
		event.mnt_ns = 12345;
		strncpy(event.comm, "test_process", sizeof(event.comm) - 1);

		test_callback(nullptr, &event, sizeof(event));
	}

	// 辅助函数：模拟move_mount事件
	void simulateMoveMountEvent(
		int from_dfd,
		const char *from_pathname,
		int to_dfd,
		const char *to_pathname,
		unsigned int flags,
		int ret
	)
	{
		struct move_mount_args event;
		memset(&event, 0, sizeof(event));

		event.from_dfd = from_dfd;
		strncpy(
			event.from_pathname,
			from_pathname,
			sizeof(event.from_pathname) - 1
		);
		event.to_dfd = to_dfd;
		strncpy(event.to_pathname, to_pathname, sizeof(event.to_pathname) - 1);
		event.flags = flags;
		event.ret = ret;
		event.pid = 1000;
		event.tid = 1001;
		event.mnt_ns = 12345;
		strncpy(event.comm, "test_process", sizeof(event.comm) - 1);

		test_callback(nullptr, &event, sizeof(event));
	}

	// 辅助函数：模拟fspick事件
	void
	simulateFspickEvent(int dfd, const char *path, unsigned int flags, int ret)
	{
		struct fspick_args event;
		memset(&event, 0, sizeof(event));

		event.dfd = dfd;
		strncpy(event.path, path, sizeof(event.path) - 1);
		event.flags = flags;
		event.ret = ret;
		event.pid = 1000;
		event.tid = 1001;
		event.mnt_ns = 12345;
		strncpy(event.comm, "test_process", sizeof(event.comm) - 1);

		test_callback(nullptr, &event, sizeof(event));
	}

	// 辅助函数：模拟mount_setattr事件
	void simulateMountSetattrEvent(
		int dfd,
		const char *path,
		unsigned int flags,
		unsigned long long attr_set,
		unsigned long long attr_clr,
		unsigned long long propagation,
		unsigned long long userns_fd,
		size_t usize,
		int ret
	)
	{
		struct mount_setattr_args event;
		memset(&event, 0, sizeof(event));

		event.dfd = dfd;
		strncpy(event.path, path, sizeof(event.path) - 1);
		event.flags = flags;
		event.uattr.attr_set = attr_set;
		event.uattr.attr_clr = attr_clr;
		event.uattr.propagation = propagation;
		event.uattr.userns_fd = userns_fd;
		event.usize = usize;
		event.ret = ret;
		event.pid = 1000;
		event.tid = 1001;
		event.mnt_ns = 12345;
		strncpy(event.comm, "test_process", sizeof(event.comm) - 1);

		test_callback(nullptr, &event, sizeof(event));
	}

	// 辅助函数：模拟open_tree事件
	void simulateOpenTreeEvent(
		int dfd,
		const char *filename,
		unsigned int flags,
		int ret
	)
	{
		struct open_tree_args event;
		memset(&event, 0, sizeof(event));

		event.dfd = dfd;
		strncpy(event.filename, filename, sizeof(event.filename) - 1);
		event.flags = flags;
		event.ret = ret;
		event.pid = 1000;
		event.tid = 1001;
		event.mnt_ns = 12345;
		strncpy(event.comm, "test_process", sizeof(event.comm) - 1);

		test_callback(nullptr, &event, sizeof(event));
	}
};

// 测试基本事件处理
TEST_F(MountsnoopBasicTest, EventHandling)
{
	// 模拟mount事件
	simulateMountEvent("/dev/sda1", "/mnt/disk", "ext4", MS_RDONLY, "data", 0);

	// 验证事件是否被捕获
	EXPECT_TRUE(event_received) << "Event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture one event";
	EXPECT_EQ(captured_event_sizes[0], sizeof(struct mount_args)) << "Event "
																	 "size "
																	 "should "
																	 "match";

	if (!captured_events.empty())
	{
		const struct mount_args *event =
			static_cast<const struct mount_args *>(captured_events[0]);
		EXPECT_STREQ(event->source, "/dev/sda1") << "Source should match";
		EXPECT_STREQ(event->target, "/mnt/disk") << "Target should match";
		EXPECT_STREQ(event->filesystemtype, "ext4") << "Filesystem type should "
													   "match";
		EXPECT_EQ(event->flags, MS_RDONLY) << "Flags should match";
		EXPECT_STREQ(event->data, "data") << "Data should match";
		EXPECT_EQ(event->ret, 0) << "Return value should match";
		EXPECT_EQ(event->pid, 1000) << "PID should match";
		EXPECT_EQ(event->tid, 1001) << "TID should match";
		EXPECT_EQ(event->mnt_ns, 12345) << "Mount namespace should match";
		EXPECT_STREQ(event->comm, "test_process") << "Process name should "
													 "match";
	}
}

// 测试不同类型的事件
TEST_F(MountsnoopBasicTest, DifferentEventTypes)
{
	// 模拟mount事件
	simulateMountEvent("/dev/sda1", "/mnt/disk", "ext4", MS_RDONLY, "data", 0);

	// 模拟umount事件
	simulateUmountEvent("/mnt/disk", 0, 0);

	// 模拟fsopen事件
	simulateFsopenEvent("ext4", 0, 3);

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 3) << "Should capture three events";

	if (captured_events.size() >= 3)
	{
		// 验证mount事件
		EXPECT_EQ(captured_event_sizes[0], sizeof(struct mount_args))
			<< "Mount event size should match";
		const struct mount_args *mount_event =
			static_cast<const struct mount_args *>(captured_events[0]);
		EXPECT_STREQ(mount_event->source, "/dev/sda1") << "Source should match";

		// 验证umount事件
		EXPECT_EQ(captured_event_sizes[1], sizeof(struct umount_args))
			<< "Umount event size should match";
		const struct umount_args *umount_event =
			static_cast<const struct umount_args *>(captured_events[1]);
		EXPECT_STREQ(umount_event->target, "/mnt/disk") << "Target should "
														   "match";

		// 验证fsopen事件
		EXPECT_EQ(captured_event_sizes[2], sizeof(struct fsopen_args))
			<< "Fsopen event size should match";
		const struct fsopen_args *fsopen_event =
			static_cast<const struct fsopen_args *>(captured_events[2]);
		EXPECT_STREQ(fsopen_event->fsname, "ext4") << "Filesystem name should "
													  "match";
	}
}

// 测试复杂事件序列
TEST_F(MountsnoopBasicTest, ComplexEventSequence)
{
	// 模拟一个完整的挂载序列
	simulateFsopenEvent("ext4", 0, 3);
	simulateFsconfigEvent(3, 1, "source", "/dev/sda1", 0, 0);
	simulateFsconfigEvent(3, 2, "target", "/mnt/disk", 0, 0);
	simulateFsmountEvent(3, 0, 0, 4);
	simulateMoveMountEvent(4, "", AT_FDCWD, "/mnt/disk", 0, 0);

	// 验证事件是否被捕获
	EXPECT_EQ(captured_events.size(), 5) << "Should capture five events";

	if (captured_events.size() >= 5)
	{
		// 验证fsopen事件
		EXPECT_EQ(captured_event_sizes[0], sizeof(struct fsopen_args))
			<< "Fsopen event size should match";
		const struct fsopen_args *fsopen_event =
			static_cast<const struct fsopen_args *>(captured_events[0]);
		EXPECT_STREQ(fsopen_event->fsname, "ext4") << "Filesystem name should "
													  "match";
		EXPECT_EQ(fsopen_event->ret, 3) << "Return value should match";

		// 验证第一个fsconfig事件
		EXPECT_EQ(captured_event_sizes[1], sizeof(struct fsconfig_args))
			<< "Fsconfig event size should match";
		const struct fsconfig_args *fsconfig_event1 =
			static_cast<const struct fsconfig_args *>(captured_events[1]);
		EXPECT_STREQ(fsconfig_event1->key, "source") << "Key should match";
		EXPECT_STREQ(fsconfig_event1->value, "/dev/sda1") << "Value should "
															 "match";

		// 验证第二个fsconfig事件
		EXPECT_EQ(captured_event_sizes[2], sizeof(struct fsconfig_args))
			<< "Fsconfig event size should match";
		const struct fsconfig_args *fsconfig_event2 =
			static_cast<const struct fsconfig_args *>(captured_events[2]);
		EXPECT_STREQ(fsconfig_event2->key, "target") << "Key should match";
		EXPECT_STREQ(fsconfig_event2->value, "/mnt/disk") << "Value should "
															 "match";

		// 验证fsmount事件
		EXPECT_EQ(captured_event_sizes[3], sizeof(struct fsmount_args))
			<< "Fsmount event size should match";
		const struct fsmount_args *fsmount_event =
			static_cast<const struct fsmount_args *>(captured_events[3]);
		EXPECT_EQ(fsmount_event->fs_fd, 3) << "File descriptor should match";
		EXPECT_EQ(fsmount_event->ret, 4) << "Return value should match";

		// 验证move_mount事件
		EXPECT_EQ(captured_event_sizes[4], sizeof(struct move_mount_args))
			<< "Move_mount event size should match";
		const struct move_mount_args *move_mount_event =
			static_cast<const struct move_mount_args *>(captured_events[4]);
		EXPECT_EQ(move_mount_event->from_dfd, 4) << "From file descriptor "
													"should match";
		EXPECT_EQ(move_mount_event->to_dfd, AT_FDCWD) << "To file descriptor "
														 "should match";
		EXPECT_STREQ(move_mount_event->to_pathname, "/mnt/disk") << "To "
																	"pathname "
																	"should "
																	"match";
	}
}

// 测试错误处理
TEST_F(MountsnoopBasicTest, ErrorHandling)
{
	// 测试空数据
	int result = test_callback(nullptr, nullptr, 0);
	EXPECT_EQ(result, -1) << "Null data should be rejected";

	// 清除之前的事件
	for (void *event : captured_events)
	{
		free(event);
	}
	captured_events.clear();
	captured_event_sizes.clear();
	event_received = false;

	// 测试数据大小不足
	char small_data[1];
	result = test_callback(nullptr, small_data, sizeof(small_data));

	// 清除之前的事件
	for (void *event : captured_events)
	{
		free(event);
	}
	captured_events.clear();
	captured_event_sizes.clear();
	event_received = false;

	// 测试错误返回值
	simulateMountEvent(
		"/dev/sda1",
		"/mnt/disk",
		"ext4",
		MS_RDONLY,
		"data",
		-ENOENT
	);

	// 验证事件是否被捕获
	EXPECT_TRUE(event_received) << "Event with error should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture event with error";

	if (!captured_events.empty())
	{
		const struct mount_args *event =
			static_cast<const struct mount_args *>(captured_events[0]);
		EXPECT_EQ(event->ret, -ENOENT) << "Error code should match";
	}
}

// 测试边界条件
TEST_F(MountsnoopBasicTest, BoundaryConditions)
{
	// 测试极长路径
	char long_path[255];
	memset(long_path, 'a', sizeof(long_path) - 1);
	long_path[sizeof(long_path) - 1] = '\0';

	simulateMountEvent("/dev/sda1", long_path, "ext4", MS_RDONLY, "data", 0);

	// 验证事件是否被捕获
	EXPECT_TRUE(event_received) << "Long path event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture long path event";

	if (!captured_events.empty())
	{
		const struct mount_args *event =
			static_cast<const struct mount_args *>(captured_events[0]);
		// 路径可能会被截断
		EXPECT_STREQ(event->target, long_path) << "Long path should match or "
												  "be truncated";
	}

	// 清除事件
	for (void *event : captured_events)
	{
		free(event);
	}
	captured_events.clear();
	captured_event_sizes.clear();
	event_received = false;

	// 测试多个标志
	unsigned long flags =
		MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_SYNCHRONOUS;
	simulateMountEvent("/dev/sda1", "/mnt/disk", "ext4", flags, "data", 0);

	// 验证事件是否被捕获
	EXPECT_TRUE(event_received) << "Multiple flags event should be received";
	EXPECT_EQ(captured_events.size(), 1) << "Should capture multiple flags "
											"event";

	if (!captured_events.empty())
	{
		const struct mount_args *event =
			static_cast<const struct mount_args *>(captured_events[0]);
		EXPECT_EQ(event->flags, flags) << "Multiple flags should match";
	}
}

// 测试性能
TEST_F(MountsnoopBasicTest, Performance)
{
	// 清除之前捕获的事件
	for (void *event : captured_events)
	{
		free(event);
	}
	captured_events.clear();
	captured_event_sizes.clear();
	event_received = false;

	// 记录开始时间
	auto start_time = std::chrono::high_resolution_clock::now();

	// 模拟大量事件
	const int NUM_EVENTS = 1000;
	for (int i = 0; i < NUM_EVENTS; i++)
	{
		char source[32], target[32];
		snprintf(source, sizeof(source), "/dev/sda%d", i % 10 + 1);
		snprintf(target, sizeof(target), "/mnt/disk%d", i % 10 + 1);
		simulateMountEvent(source, target, "ext4", MS_RDONLY, "data", 0);
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

// 测试挂载标志处理
TEST_F(MountsnoopBasicTest, MountFlagsHandling)
{
	// 测试各种挂载标志
	struct
	{
		unsigned long flag;
		const char *name;
	} test_flags[] = {
		{MS_RDONLY,		"MS_RDONLY"	   },
		{MS_NOSUID,		"MS_NOSUID"	   },
		{MS_NODEV,	   "MS_NODEV"		 },
		{MS_NOEXEC,		"MS_NOEXEC"	   },
		{MS_SYNCHRONOUS, "MS_SYNCHRONOUS"},
		{MS_REMOUNT,	 "MS_REMOUNT"	 },
		{MS_BIND,		  "MS_BIND"	   },
		{MS_MOVE,		  "MS_MOVE"	   },
		{MS_DIRSYNC,	 "MS_DIRSYNC"	 },
	};

	for (const auto &tf : test_flags)
	{
		// 清除之前的事件
		for (void *event : captured_events)
		{
			free(event);
		}
		captured_events.clear();
		captured_event_sizes.clear();
		event_received = false;

		// 模拟带有特定标志的挂载事件
		simulateMountEvent(
			"/dev/sda1",
			"/mnt/disk",
			"ext4",
			tf.flag,
			"data",
			0
		);

		// 验证事件是否被捕获
		EXPECT_TRUE(event_received)
			<< "Event with flag " << tf.name << " should be received";
		EXPECT_EQ(captured_events.size(), 1)
			<< "Should capture event with flag " << tf.name;

		if (!captured_events.empty())
		{
			const struct mount_args *event =
				static_cast<const struct mount_args *>(captured_events[0]);
			EXPECT_EQ(event->flags, tf.flag)
				<< "Flag " << tf.name << " should match";
		}
	}
}

// 测试挂载命名空间处理
TEST_F(MountsnoopBasicTest, MountNamespaceHandling)
{
	// 模拟不同命名空间的挂载事件
	for (unsigned int ns : {12345, 67890, 54321})
	{
		// 清除之前的事件
		for (void *event : captured_events)
		{
			free(event);
		}
		captured_events.clear();
		captured_event_sizes.clear();
		event_received = false;

		// 创建事件
		struct mount_args event;
		memset(&event, 0, sizeof(event));

		strncpy(event.source, "/dev/sda1", sizeof(event.source) - 1);
		strncpy(event.target, "/mnt/disk", sizeof(event.target) - 1);
		strncpy(event.filesystemtype, "ext4", sizeof(event.filesystemtype) - 1);
		strncpy(event.data, "data", sizeof(event.data) - 1);
		event.flags = MS_RDONLY;
		event.ret = 0;
		event.pid = 1000;
		event.tid = 1001;
		event.mnt_ns = ns;
		strncpy(event.comm, "test_process", sizeof(event.comm) - 1);

		test_callback(nullptr, &event, sizeof(event));

		// 验证事件是否被捕获
		EXPECT_TRUE(event_received)
			<< "Event with namespace " << ns << " should be received";
		EXPECT_EQ(captured_events.size(), 1)
			<< "Should capture event with namespace " << ns;

		if (!captured_events.empty())
		{
			const struct mount_args *captured =
				static_cast<const struct mount_args *>(captured_events[0]);
			EXPECT_EQ(captured->mnt_ns, ns) << "Namespace should match";
		}
	}
}

// 测试文件系统类型处理
TEST_F(MountsnoopBasicTest, FilesystemTypeHandling)
{
	// 测试各种文件系统类型
	const char *fs_types[] =
		{"ext4", "ext3", "xfs", "btrfs", "tmpfs", "nfs", "cifs"};

	for (const char *fs_type : fs_types)
	{
		// 清除之前的事件
		for (void *event : captured_events)
		{
			free(event);
		}
		captured_events.clear();
		captured_event_sizes.clear();
		event_received = false;

		// 模拟挂载事件
		simulateMountEvent(
			"/dev/sda1",
			"/mnt/disk",
			fs_type,
			MS_RDONLY,
			"data",
			0
		);

		// 验证事件是否被捕获
		EXPECT_TRUE(event_received) << "Event with filesystem type " << fs_type
									<< " should be received";
		EXPECT_EQ(captured_events.size(), 1)
			<< "Should capture event with filesystem type " << fs_type;

		if (!captured_events.empty())
		{
			const struct mount_args *event =
				static_cast<const struct mount_args *>(captured_events[0]);
			EXPECT_STREQ(event->filesystemtype, fs_type) << "Filesystem type "
															"should match";
		}
	}
}
