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

#define PATH_MAX 4096

union Rule
{
	char path[PATH_MAX];
	struct
	{
		uint64_t not_inode; // used for judging whether it's inode filter
		uint64_t inode;
		dev_t dev; // 设备号
	};
};
struct Test_Event
{
	char path[PATH_MAX];
	uint64_t inode;
	dev_t dev; // 设备号
	uid_t uid;
	pid_t pid;
	int fd;
	char comm[16];
};
struct BpfData
{
	uid_t uid;
	pid_t pid;
	int fd;
	char comm[16];
};
struct LsofFds
{
	int filter_fd;
	int logs_fd;
};
struct LsofSync
{
	std::mutex m;
	std::condition_variable cv;
	bool init_done = false;
	bool exit_requested = false;
};
struct LsofRuntime
{
	LsofSync sync;
	std::promise<LsofFds> fds_promise;
	std::atomic<bool> *exit_flag = nullptr;
};
extern std::shared_ptr<LsofRuntime> lsof_init(FILE *output);
extern void lsof_deinit();
extern int lsof_main(int argc, char *args[]);
extern long bpf_for_each_map_elem(int fd, void *callback_fn, void *callback_ctx, unsigned long long flags);

#define TEST_EVENT_MAX 32
static Test_Event g_test_events[TEST_EVENT_MAX] = {};
static size_t g_test_event_count = 0;

extern int ring_buffer__push(int fd, void *data, size_t sz);
static long match_call(struct bpf_map *map, const void *key, void *value, void *ctx)
{
	struct Test_Event *test_event = (struct Test_Event *)ctx;
    union Rule *rule = (union Rule *)value;
	if (rule->not_inode)
	{
		if (strncmp(test_event->path, rule->path, sizeof(rule->path)))
		{
			return 0;
		}
	}
	else
	{
		// 使用设备号进行比较
		if (rule->dev != test_event->dev)
		{
			return 0;
		}
		if (rule->inode != test_event->inode)
		{
			return 0;
		}
	}
	return 1;
}
static bool rules_filter(int filter_fd, struct Test_Event &event)
{
    return bpf_for_each_map_elem(filter_fd, (void *)match_call, &event, 0) == 1;
}
static void event_worker(
    Test_Event *test_events,
    size_t test_event_count,
    std::shared_ptr<LsofRuntime> runtime,
    std::future<LsofFds> fds_future
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
    if(should_exit)
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
    if (fds_future.wait_for(std::chrono::seconds(5)) != std::future_status::ready)
    {
        request_exit();
        return;
    }
    LsofFds fds;
    try
    {
        fds = fds_future.get();
    }
    catch (const std::future_error &)
    {
        request_exit();
        return;
    }
    auto filter_fd = fds.filter_fd;
    auto logs_fd = fds.logs_fd;
    for(size_t i = 0; i < test_event_count; ++i)
    {
        auto &e = test_events[i];
        if(rules_filter(filter_fd, e)){
           struct BpfData log_data = {};
           log_data.uid = e.uid;
		   log_data.pid = e.pid;
		   log_data.fd = e.fd;
		   strncpy(log_data.comm, e.comm, sizeof(log_data.comm) - 1);
		   ring_buffer__push(logs_fd, &log_data, sizeof(log_data));
        }    
    }
    request_exit();
}
class LsofTest : public ::testing::Test
{
    protected:
        const std::string TEST_ROOT = "/tmp/lsof_test_dir";
        const std::string TEST_LOG_FILE = TEST_ROOT + "/log.txt";
        std::shared_ptr<LsofRuntime> runtime;

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
            if(!file.is_open())
            {
                return false;
            }
            std::streamsize size = file.tellg();
            file.seekg(0, std::ios::beg);
            std::string content(size, '\0');
            if(!file.read(&content[0],size)){
                return false;
            }
            return content.find(str) != std::string::npos;
        }
          std::string readLog()
        {
            std::ifstream file(TEST_LOG_FILE, std::ios::binary | std::ios::ate);
            if (!file.is_open())
            {
                return "";
            }

            std::streamsize size = file.tellg();
            file.seekg(0, std::ios::beg);

            std::string content(size, '\0');
            if (!file.read(&content[0], size))
            {
                return "";
            }
            return content;
        }
        int countStr(const std::string &str)
        {
            std::ifstream file(TEST_LOG_FILE, std::ios::binary | std::ios::ate);
            if(!file.is_open())
            {
                return -1;
            }
            std::streamsize size = file.tellg();
            file.seekg(0, std::ios::beg);
            std::string content(size, '\0');
            if(!file.read(&content[0],size)){
                return -1;
            }
            int count = 0;
            size_t pos = 0;
            while((pos = content.find(str, pos)) != std::string::npos) {
                ++count;
                pos += str.length();
            }
            return count;
        }
        void addTestEvent(const char *path, uint64_t inode, dev_t dev, uid_t uid, pid_t pid, int fd, const char *comm){
            struct Test_Event e = {
                .inode = inode,
				.dev = dev,
				.uid = uid,
				.pid = pid,
                .fd = fd,
            };
            if (path != nullptr) {
                strncpy(e.path, path, sizeof(e.path) - 1);
                e.path[sizeof(e.path) - 1] = '\0';
            } else {
                e.path[0] = '\0'; // 如果为空，设为空字符串
            }
			if (comm != nullptr) {
                strncpy(e.comm, comm, sizeof(e.comm) - 1);
                e.comm[sizeof(e.comm) - 1] = '\0';
            } else {
                e.comm[0] = '\0'; // 如果为空，设为空字符串
            }
            ASSERT_LT(g_test_event_count, (size_t)TEST_EVENT_MAX);
            g_test_events[g_test_event_count++] = e;
        }
        int runLsof(const std::vector<std::string> &_args){
            std::vector<std::string> t;
            t.push_back("lsof");
            t.insert(t.end(),_args.begin(), _args.end());
            std::vector<char *> argv;
            argv.reserve(t.size());
            for(const auto &arg : t){
                argv.push_back(const_cast<char *>(arg.c_str()));
            }
            FILE *log_file = fopen(TEST_LOG_FILE.c_str(),"w");
            if (!log_file) 
            {
                ADD_FAILURE() << "Failed to create log file";
                return -1;
            }
            runtime = lsof_init(log_file);
            std::future<LsofFds> fds_future = runtime->fds_promise.get_future();
            std::thread event_thread(
                event_worker,
                g_test_events,
                g_test_event_count,
                runtime,
                std::move(fds_future));
        int ret = lsof_main(argv.size(), argv.data());
            {
                std::lock_guard<std::mutex> lock(runtime->sync.m);
                runtime->sync.exit_requested = true;
            }
            runtime->sync.cv.notify_all();
            event_thread.join();
            lsof_deinit();
            fclose(log_file);
            return ret;
        }
};
//SimpleTest1
TEST_F(LsofTest, SimpleTest1)
{
    runLsof({"-h"});
    EXPECT_TRUE(existStr("Usage:"));
}
//测试能否正常输出
TEST_F(LsofTest, SimpleTest2)
{
	addTestEvent("/tmp/tail.txt", 1, 2, 24812, 709769, 3, "tail");
    runLsof({"-p", "/tmp/tail.txt"});
    EXPECT_TRUE(existStr("Scanning for file /tmp/tail.txt..."));
	EXPECT_TRUE(existStr("tail  24812   709769   3"));
}
//测试-p path能否正常过滤
TEST_F(LsofTest, PathFilterApplied)
{
	addTestEvent("/tmp/tail.txt", 1, 2, 24812, 709769, 3, "tail");
	addTestEvent("/tmp/vma.txt", 2, 4, 24812, 710069,3, "python3");
    runLsof({"-p", "/tmp/vma.txt"});
    EXPECT_TRUE(!existStr("Scanning for file /tmp/tail.txt..."));
	EXPECT_TRUE(!existStr("tail  24812   709769   3"));
	EXPECT_TRUE(existStr("Scanning for file /tmp/vma.txt..."));
	EXPECT_TRUE(existStr("python3  24812   710069   3"));
}
//测试-d dev -i inode能否正常过滤
TEST_F(LsofTest, DevAndInodeFilterApplied)
{
	addTestEvent("/tmp/tail.txt", 1, 2, 24812, 709769, 3, "tail");
	addTestEvent("/tmp/vma.txt", 2, 4, 24812, 710069,3, "python3");
    runLsof({"-d", "2", "-i", "1"});
    EXPECT_TRUE(existStr("Scanning for file ..."));
	EXPECT_TRUE(existStr("tail  24812   709769   3"));
	EXPECT_TRUE(!existStr("python3  24812   710069   3 4 vma(1)"));
}

// 测试 -p 传空字符串时应报错
TEST_F(LsofTest, EmptyPathRejected)
{
	EXPECT_EQ(runLsof({"-p", ""}), -1);
	EXPECT_TRUE(existStr("error: -p requires a non-empty path"));
}

// 测试 -d 传非数字时应报错
TEST_F(LsofTest, InvalidDevAlphaRejected)
{
	EXPECT_EQ(runLsof({"-d", "abc", "-i", "1"}), -1);
	EXPECT_TRUE(existStr("error: invalid dev value: abc"));
}

// 测试 -d 传混合字符串时应报错
TEST_F(LsofTest, InvalidDevMixedRejected)
{
	EXPECT_EQ(runLsof({"-d", "12abc", "-i", "1"}), -1);
	EXPECT_TRUE(existStr("error: invalid dev value: 12abc"));
}

// 测试 -i 传非数字时应报错
TEST_F(LsofTest, InvalidInodeAlphaRejected)
{
	EXPECT_EQ(runLsof({"-d", "2", "-i", "abc"}), -1);
	EXPECT_TRUE(existStr("error: invalid inode value: abc"));
}

// 测试 -i 传混合字符串时应报错
TEST_F(LsofTest, InvalidInodeMixedRejected)
{
	EXPECT_EQ(runLsof({"-d", "2", "-i", "12abc"}), -1);
	EXPECT_TRUE(existStr("error: invalid inode value: 12abc"));
}

// 测试仅传 -d 时应报错
TEST_F(LsofTest, MissingInodeRejected)
{
	EXPECT_EQ(runLsof({"-d", "2"}), -1);
	EXPECT_TRUE(existStr("error: -d and -i must be used together"));
}

// 测试仅传 -i 时应报错
TEST_F(LsofTest, MissingDevRejected)
{
	EXPECT_EQ(runLsof({"-i", "1"}), -1);
	EXPECT_TRUE(existStr("error: -d and -i must be used together"));
}

// 测试 -p 和 -d/-i 混用时应报错
TEST_F(LsofTest, PathAndDevInodeMixedRejected)
{
	EXPECT_EQ(runLsof({"-p", "/tmp/tail.txt", "-d", "2", "-i", "1"}), -1);
	EXPECT_TRUE(existStr("error: -p can't be used together with -d/-i"));
}
