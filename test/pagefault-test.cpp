#include "gtest/gtest.h"
#include <iostream>
#include <fstream>
#include <thread>
#include <unistd.h>
#include <vector>
#include <atomic>
#include <string>
#include <mutex>
#include <condition_variable>
#include <future>
#include <memory>
#include <bpf/bpf.h>
#include <filesystem>
#include <chrono>
#include "mock-data-generator.h"

struct page_fault_t
{
	pid_t pid;
	pid_t tid;
	char comm[16];
	int stack_id;
	__u64 timestamp;
	unsigned long address;
	unsigned long ip;
	unsigned long error_code;
};

struct PagefaultFds
{
	int filter_fd;
	int events_fd;
	int stack_traces_fd;
};

struct PagefaultSync
{
	std::mutex m;
	std::condition_variable cv;
	bool init_done = false;
	bool exit_requested = false;
};

struct PagefaultRuntime
{
	PagefaultSync sync;
	std::promise<PagefaultFds> fds_promise;
	volatile bool *exit_flag = nullptr;
	std::mutex consume_m;
	std::condition_variable consume_cv;
	size_t consumed = 0;
};

extern std::shared_ptr<PagefaultRuntime> pagefault_init(FILE *output);
extern void pagefault_deinit();
extern int pagefault_main(int argc, char **argv);
extern long bpf_for_each_map_elem(
	int fd,
	void *callback_fn,
	void *callback_ctx,
	__u64 flags
);
extern int ring_buffer__push(int fd, void *data, size_t sz);

#define TEST_EVENT_MAX 32
#define PAGEFAULT_STACK_DEPTH 127

struct PagefaultTestEvent
{
	enum EventType
	{
		EVENT_KERNEL,
		EVENT_USER,
	};
	struct page_fault_t event;
	EventType type;
	bool has_stack;
	MockStackCtx stack_ctx;
};

static PagefaultTestEvent g_test_events[TEST_EVENT_MAX] = {};
static size_t g_test_event_count = 0;

struct FilterCtx
{
	PagefaultTestEvent *event;
	bool trace_user;
	bool trace_kernel;
};

static long match_call(struct bpf_map *map, const void *key, void *value, void *ctx)
{
	struct FilterCtx *filter_ctx = (struct FilterCtx *)ctx;
	PagefaultTestEvent *event = filter_ctx->event;
	pid_t *rule = (pid_t *)value;
	if (event->type == PagefaultTestEvent::EVENT_USER && !filter_ctx->trace_user)
	{
		return 0;
	}
	if (event->type == PagefaultTestEvent::EVENT_KERNEL && !filter_ctx->trace_kernel)
	{
		return 0;
	}
	if (*rule > 0 && event->event.pid != *rule)
	{
		return 0;
	}
	return 1;
}

static bool rules_filter(
	int filter_fd,
	PagefaultTestEvent &event,
	bool trace_user,
	bool trace_kernel
)
{
	struct FilterCtx filter_ctx = {
		.event = &event,
		.trace_user = trace_user,
		.trace_kernel = trace_kernel,
	};

	if (event.type == PagefaultTestEvent::EVENT_USER && !trace_user)
	{
		return false;
	}
	if (event.type == PagefaultTestEvent::EVENT_KERNEL && !trace_kernel)
	{
		return false;
	}

	int next_key = 0;
	if (bpf_map_get_next_key(filter_fd, NULL, &next_key) == -ENOENT)
	{
		return true;
	}

	long ret =
		bpf_for_each_map_elem(filter_fd, (void *)match_call, &filter_ctx, 0);
	return ret == 1;
}

static void event_worker(
	PagefaultTestEvent *test_events,
	size_t test_event_count,
	bool trace_user,
	bool trace_kernel,
	std::shared_ptr<PagefaultRuntime> runtime,
	std::future<PagefaultFds> fds_future
)
{
	bool should_exit = false;
	{
		std::unique_lock<std::mutex> lock(runtime->sync.m);
		runtime->sync.cv.wait(lock, [&] {
			return runtime->sync.init_done || runtime->sync.exit_requested;
		});
		should_exit = runtime->sync.exit_requested;
	}
	if (should_exit)
	{
		*runtime->exit_flag = true;
		return;
	}

	auto request_exit = [&]() {
		std::lock_guard<std::mutex> lock(runtime->sync.m);
		runtime->sync.exit_requested = true;
		runtime->sync.cv.notify_all();
		*runtime->exit_flag = true;
	};

	if (fds_future.wait_for(std::chrono::seconds(5)) !=
		std::future_status::ready)
	{
		request_exit();
		return;
	}

	PagefaultFds fds;
	try
	{
		fds = fds_future.get();
	}
	catch (const std::future_error &)
	{
		request_exit();
		return;
	}

	size_t expected = 0;
	for (size_t i = 0; i < test_event_count; ++i)
	{
		auto &e = test_events[i];
		if (!rules_filter(fds.filter_fd, e, trace_user, trace_kernel))
		{
			continue;
		}
		if (e.has_stack && e.event.stack_id >= 0)
		{
			__u64 ips[PAGEFAULT_STACK_DEPTH] = {};
			size_t nr = e.stack_ctx.user_ips.size();
			if (nr > PAGEFAULT_STACK_DEPTH)
			{
				nr = PAGEFAULT_STACK_DEPTH;
			}
			for (size_t j = 0; j < nr; ++j)
			{
				ips[j] = e.stack_ctx.user_ips[j];
			}
			bpf_map_update_elem(
				fds.stack_traces_fd,
				&e.event.stack_id,
				ips,
				BPF_ANY
			);
		}
		ring_buffer__push(fds.events_fd, &e.event, sizeof(e.event));
		expected++;
	}
	{
		std::unique_lock<std::mutex> lock(runtime->consume_m);
		runtime->consume_cv.wait_for(
			lock,
			std::chrono::seconds(2),
			[&] { return runtime->consumed >= expected; }
		);
	}
	request_exit();
}

class PagefaultTest : public ::testing::Test
{
  protected:
	const std::string TEST_ROOT = "/tmp/pagefault_test_dir";
	const std::string TEST_LOG_FILE = TEST_ROOT + "/log.txt";
	std::shared_ptr<PagefaultRuntime> runtime;

	void SetUp() override
	{
		createTestFiles();
		memset(g_test_events, 0, sizeof(g_test_events));
		g_test_event_count = 0;
	}

	void TearDown() override
	{
		cleanTestFiles();
	}

	void createTestFiles()
	{
		mkdir(TEST_ROOT.c_str(), 0755);
	}

	void cleanTestFiles()
	{
		std::filesystem::remove_all(TEST_ROOT);
	}

	bool existStr(const std::string &str)
	{
		std::ifstream file(TEST_LOG_FILE, std::ios::binary | std::ios::ate);
		if (!file.is_open())
		{
			return false;
		}
		std::streamsize size = file.tellg();
		if (size <= 0)
		{
			return false;
		}
		file.seekg(0, std::ios::beg);
		std::string content(size, '\0');
		if (!file.read(&content[0], size))
		{
			return false;
		}
		return content.find(str) != std::string::npos;
	}

	void addTestEvent(
		PagefaultTestEvent::EventType type,
		pid_t pid,
		pid_t tid,
		const char *comm,
		int stack_id,
		__u64 timestamp,
		unsigned long address,
		unsigned long ip,
		unsigned long error_code
	)
	{
		ASSERT_LT(g_test_event_count, (size_t)TEST_EVENT_MAX);
		PagefaultTestEvent &e = g_test_events[g_test_event_count++];
		e.type = type;
		e.event.pid = pid;
		e.event.tid = tid;
		e.event.stack_id = stack_id;
		e.event.timestamp = timestamp;
		e.event.address = address;
		e.event.ip = ip;
		e.event.error_code = error_code;
		if (comm != nullptr)
		{
			strncpy(e.event.comm, comm, sizeof(e.event.comm) - 1);
			e.event.comm[sizeof(e.event.comm) - 1] = '\0';
		}
		else
		{
			e.event.comm[0] = '\0';
		}
	}

	void setTestEventStack(size_t idx, const std::vector<__u64> &user_ips)
	{
		ASSERT_LT(idx, g_test_event_count);
		g_test_events[idx].has_stack = true;
		g_test_events[idx].stack_ctx.user_ips = user_ips;
	}

	int runPagefault(const std::vector<std::string> &_args)
	{
		bool trace_user = false;
		bool trace_kernel = false;
		for (const auto &arg : _args)
		{
			if (arg == "-u" || arg == "--user")
			{
				trace_user = true;
			}
			if (arg == "-k" || arg == "--kernel")
			{
				trace_kernel = true;
			}
		}
		if (!trace_user && !trace_kernel)
		{
			trace_user = true;
			trace_kernel = true;
		}
		std::vector<std::string> t;
		t.push_back("pagefault");
		t.insert(t.end(), _args.begin(), _args.end());
		std::vector<char *> argv;
		argv.reserve(t.size());
		for (const auto &arg : t)
		{
			argv.push_back(const_cast<char *>(arg.c_str()));
		}
		FILE *log_file = fopen(TEST_LOG_FILE.c_str(), "w");
		if (!log_file)
		{
			ADD_FAILURE() << "Failed to create log file";
			return -1;
		}
		runtime = pagefault_init(log_file);
		std::future<PagefaultFds> fds_future = runtime->fds_promise.get_future();
		std::thread event_thread(
			event_worker,
			g_test_events,
			g_test_event_count,
			trace_user,
			trace_kernel,
			runtime,
			std::move(fds_future)
		);
		int ret = pagefault_main(argv.size(), argv.data());
		{
			std::lock_guard<std::mutex> lock(runtime->sync.m);
			runtime->sync.exit_requested = true;
		}
		runtime->sync.cv.notify_all();
		event_thread.join();
		pagefault_deinit();
		fclose(log_file);
		return ret;
	}
};

//SimpleTest1
TEST_F(PagefaultTest, SimpleTest1)
{
	runPagefault({"-h"});
	EXPECT_TRUE(existStr("Usage:"));
}

//测试能否正常输出
TEST_F(PagefaultTest, SimpleTest2)
{
	addTestEvent(
		PagefaultTestEvent::EVENT_USER,
		582,
		582,
		"systemd-journal",
		-1,
		21591971226431ULL,
		0x7fc5f4523b10UL,
		0x7fc5f644c00cUL,
		0x7UL
	);
	runPagefault({});
	EXPECT_TRUE(
		existStr(
			"PID:582 TID:582 COMM:systemd-journal ADDR:0x7fc5f4523b10 "
			"IP:0x7fc5f644c00c ERR:0x7"
		)
	);
}

//测试-p pid能否正常过滤
TEST_F(PagefaultTest, PidFilterApplied)
{
	addTestEvent(PagefaultTestEvent::EVENT_KERNEL, 582, 582, "systemd-journal", -1, 1, 0x1000UL, 0x2000UL, 0x7UL);
	addTestEvent(PagefaultTestEvent::EVENT_USER, 14922, 14922, "deepin-terminal", -1, 2, 0x3000UL, 0x4000UL, 0x6UL);
	runPagefault({"-p", "14922"});
	EXPECT_TRUE(!existStr("PID:582 TID:582 COMM:systemd-journal"));
	EXPECT_TRUE(existStr("PID:14922 TID:14922 COMM:deepin-terminal"));
}

//测试-t timestamp能否正常输出
TEST_F(PagefaultTest, TimestampOutputApplied)
{
	addTestEvent(PagefaultTestEvent::EVENT_KERNEL, 582, 582, "systemd-journal", -1, 21591971226431ULL, 0x1000UL, 0x2000UL, 0x7UL);
	runPagefault({"-t"});
	EXPECT_TRUE(existStr("TS:21591971226431"));
}

//测试-s stack能否正常输出
TEST_F(PagefaultTest, StackOutputApplied)
{
	addTestEvent(PagefaultTestEvent::EVENT_USER, 14922, 14922, "deepin-terminal", 3, 10, 0x7f36ffaf0000UL, 0x7f3726d2243aUL, 0x6UL);
	setTestEventStack(0, {0x1111ULL, 0x2222ULL, 0x3333ULL});
	runPagefault({"-s"});
	EXPECT_TRUE(existStr("User stack:"));
	EXPECT_TRUE(existStr("0x1111"));
	EXPECT_TRUE(existStr("0x2222"));
	EXPECT_TRUE(existStr("0x3333"));
}

//测试-u user能否正常过滤
TEST_F(PagefaultTest, UserFilterApplied)
{
	addTestEvent(PagefaultTestEvent::EVENT_KERNEL, 582, 582, "systemd-journal", -1, 1, 0x1000UL, 0x2000UL, 0x7UL);
	addTestEvent(PagefaultTestEvent::EVENT_USER, 14922, 14922, "deepin-terminal", -1, 2, 0x3000UL, 0x4000UL, 0x6UL);
	runPagefault({"-u"});
	EXPECT_TRUE(!existStr("PID:582 TID:582 COMM:systemd-journal"));
	EXPECT_TRUE(existStr("PID:14922 TID:14922 COMM:deepin-terminal"));
}

//测试-k kernel能否正常过滤
TEST_F(PagefaultTest, KernelFilterApplied)
{
	addTestEvent(PagefaultTestEvent::EVENT_KERNEL, 582, 582, "systemd-journal", -1, 1, 0x1000UL, 0x2000UL, 0x7UL);
	addTestEvent(PagefaultTestEvent::EVENT_USER, 14922, 14922, "deepin-terminal", -1, 2, 0x3000UL, 0x4000UL, 0x6UL);
	runPagefault({"-k"});
	EXPECT_TRUE(existStr("PID:582 TID:582 COMM:systemd-journal"));
	EXPECT_TRUE(!existStr("PID:14922 TID:14922 COMM:deepin-terminal"));
}

//测试-p 非法参数能否正常报错
TEST_F(PagefaultTest, InvalidPidRejected)
{
	EXPECT_EQ(runPagefault({"-p", "abc"}), -1);
	EXPECT_TRUE(existStr("wrong pid value: abc, must be a positive integer"));
}
