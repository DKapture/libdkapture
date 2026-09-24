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

#include "jhash.h"

struct Test_Event
{
    pid_t pid;
    uint32_t pathhash;
    char comm[16];
    int nr;
    int cnt;
    uint64_t time;
    long ret;
};

struct info
{
    uint64_t cnt;
    uint64_t time;
    long ret;
};
struct Rule
{
    pid_t pid;
    uint32_t pathhash;
    char comm[16];
};

struct SyscallStatSync
{
    std::mutex m;
    std::condition_variable cv;
    bool init_done = false;
    bool print_done = false;
    bool exit_requested = false;
};

struct SyscallStatFds
{
    int filter_fd;
    int stats_fd;
};

struct SyscallStatRuntime
{
    SyscallStatSync sync;
    std::promise<SyscallStatFds> fds_promise;
    std::atomic<bool> *exit_flag = nullptr;
};

extern std::shared_ptr<SyscallStatRuntime> syscall_stat_init(FILE *output);
extern void syscall_stat_deinit();
extern int syscall_stat_main(int argc, char *args[]);
extern long bpf_for_each_map_elem(int fd, void *callback_fn, void *callback_ctx, unsigned long long flags);

#define TEST_EVENT_MAX 32
static Test_Event g_test_events[TEST_EVENT_MAX] = {};
static size_t g_test_event_count = 0;

static long match_call(struct bpf_map *map, const void *key, void *value, void *ctx)
{
    struct Test_Event *test_event = (struct Test_Event *)ctx;
    struct Rule *rule = (struct Rule *)value;
    if(rule->pid > 0 && test_event->pid != rule->pid){
        return 0;
    }
    if (rule->pathhash != 0 && test_event->pathhash != rule->pathhash)
    {
        return 0;
    }
    if(rule->comm[0] != '\0' &&
          strncmp(test_event->comm, rule->comm, sizeof(rule->comm)) != 0)
    {
         return 0;
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
    std::shared_ptr<SyscallStatRuntime> runtime,
    std::future<SyscallStatFds> fds_future
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
    auto fds = fds_future.get();
    auto filter_fd = fds.filter_fd;
    auto stats_fd = fds.stats_fd;
    for(size_t i = 0; i < test_event_count; ++i)
    {
        auto &e = test_events[i];
        if(rules_filter(filter_fd, e)){
            struct info event = {
                .cnt = (uint64_t)e.cnt,
                .time = (uint64_t)e.time,
                .ret = e.ret
                };
            bpf_map_update_elem(stats_fd, &e.nr, &event, BPF_ANY);
        }    
    }
    {
        std::unique_lock<std::mutex> lock(runtime->sync.m);
        runtime->sync.cv.wait(lock, [&] {
            return runtime->sync.print_done || runtime->sync.exit_requested;
        });
    }
    {
        std::lock_guard<std::mutex> lock(runtime->sync.m);
        runtime->sync.exit_requested = true;
    }
    runtime->sync.cv.notify_all();
	*runtime->exit_flag = true;
}
class SyscallStatTest : public ::testing::Test
{
    protected:
        const std::string TEST_ROOT = "/tmp/syscall_stat_test_dir";
        const std::string TEST_LOG_FILE = TEST_ROOT + "/log.txt";
        std::shared_ptr<SyscallStatRuntime> runtime;

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
        void addTestEvent(pid_t pid, const char* path, const char *comm, int nr, int cnt, uint64_t time, long ret){
            uint32_t pathhash = 0;
            if(path != nullptr){
                char *buf = (char *)calloc(4096, sizeof(char)); // 从堆区申请内存
                if (!buf)
                {
                    perror("calloc");
                    exit(EXIT_FAILURE);
                }
                strncpy(buf, path, 4096);
                buf[4095] = '\0';
                pathhash =  jhash(buf, 4096, 0);
                free(buf);
            }
            struct Test_Event e = {
                .pid = pid,
                .pathhash = pathhash,
                .nr = nr,
                .cnt = cnt,
                .time = time,
                .ret = ret 
            };
            if (comm != nullptr) {
                strncpy(e.comm, comm, sizeof(e.comm) - 1);
                e.comm[sizeof(e.comm) - 1] = '\0';
            } else {
                 memset(e.comm, 0, sizeof(e.comm)); // 如果为空，设为空字符串
            }
            ASSERT_LT(g_test_event_count, (size_t)TEST_EVENT_MAX);
            g_test_events[g_test_event_count++] = e;
        }
        int runSyscallStat(const std::vector<std::string> &_args){
            std::vector<std::string> t;
            t.push_back("syscall_stat");
            t.insert(t.end(),_args.begin(), _args.end());
            std::vector<char *> argv;
            argv.reserve(t.size());
            for(const auto &arg : t){
                argv.push_back(const_cast<char *>(arg.c_str()));
            }
            argv.push_back(nullptr);
            FILE *log_file = fopen(TEST_LOG_FILE.c_str(),"w");
            if (!log_file) 
            {
                ADD_FAILURE() << "Failed to create log file";
                return -1;
            }
            runtime = syscall_stat_init(log_file);
            std::future<SyscallStatFds> fds_future = runtime->fds_promise.get_future();
            std::thread event_thread(
                event_worker,
                g_test_events,
                g_test_event_count,
                runtime,
                std::move(fds_future));
            int ret = syscall_stat_main((int)t.size(), argv.data());
            {
                std::lock_guard<std::mutex> lock(runtime->sync.m);
                runtime->sync.exit_requested = true;
            }
            runtime->sync.cv.notify_all();
            event_thread.join();
            syscall_stat_deinit();
            fclose(log_file);
            return ret;
        }
};
TEST_F(SyscallStatTest, SimpleTest1)
{
    runSyscallStat({"-h"});
    EXPECT_TRUE(existStr("Usage:"));
}
// 测试单一系统调用的统计输出
TEST_F(SyscallStatTest, SingleStatPrinted)
{
    addTestEvent(0, nullptr, nullptr, 0, 1, 1000000000, 2);
    runSyscallStat({"-i","1"});
    EXPECT_TRUE(existStr("read"));
    EXPECT_TRUE(existStr("total: 1"));
    EXPECT_TRUE(existStr("2"));
    EXPECT_TRUE(existStr("1.000000"));
}
// 测试多个系统调用的统计输出
TEST_F(SyscallStatTest, MultipleStatsPrinted)
{
    addTestEvent(0, nullptr, nullptr, 0, 1, 1000000000, 2);
    addTestEvent(0, nullptr, nullptr, 1, 2, 2000000000, 3);
    runSyscallStat({"-i","1"});
    EXPECT_TRUE(existStr("read"));
    EXPECT_TRUE(existStr("write"));
    EXPECT_TRUE(existStr("total: 3"));
    EXPECT_TRUE(existStr("2"));
    EXPECT_TRUE(existStr("3"));
    EXPECT_TRUE(existStr("1.000000"));
    EXPECT_TRUE(existStr("1.000000"));
}
//测试cnt=0能否被阻止输出
TEST_F(SyscallStatTest,ZeroCountStatNotPrinted)
{
    addTestEvent(158, nullptr, nullptr, 0, 0, 5000000000, 7);
    addTestEvent(175, nullptr, nullptr, 1, 8 , 8000000000, 19);
    runSyscallStat({"-i","1"});
    EXPECT_TRUE(!existStr("read"));
    EXPECT_TRUE(existStr("write"));
}

// 测试-p pid能否正确过滤
TEST_F(SyscallStatTest,PidFilterApplied)
{
    addTestEvent(121, nullptr, nullptr, 3, 10, 3000000000, 0);
    addTestEvent(122, nullptr, nullptr, 0, 1 , 2000000000, 3);
    runSyscallStat({"-p","121"});
    EXPECT_TRUE(existStr("close"));
    EXPECT_TRUE(!existStr("read"));
}
// 测试-f path能否正确过滤
TEST_F(SyscallStatTest,PathFilterApplied)
{
    addTestEvent(12, "/usr/bin/ls", nullptr, 4, 3, 3000000000, 0);
    addTestEvent(15, "/usr/bin/cat", nullptr, 5, 2 , 2000000000, 3);
    runSyscallStat({"-f", "/usr/bin/ls"});
    EXPECT_TRUE(existStr("newstat"));
    EXPECT_TRUE(!existStr("newfstat"));
}
// 测试-c comm能否正确过滤
TEST_F(SyscallStatTest,CommFilterApplied)
{
    addTestEvent(12, nullptr, "ls", 8, 3, 3000000000, 0);
    addTestEvent(15, nullptr, "cat", 9, 2 , 2000000000, 3);
    runSyscallStat({"-c", "ls"});
    EXPECT_TRUE(existStr("lseek"));
    EXPECT_TRUE(!existStr("mmap"));
}
// 测试-t 能否实现滚动刷新输出
TEST_F(SyscallStatTest,TopModePrintsClearScreenEscape)
{
    addTestEvent(152, nullptr, nullptr, 3, 7, 4000000000, 5);
    addTestEvent(155, nullptr, nullptr, 2, 18 , 6000000000, 10);
    addTestEvent(0, nullptr, nullptr, 0, 5, 1000000000, 7);
    addTestEvent(56, nullptr, nullptr, 15, 56, 8000000000, 12);
    addTestEvent(65, nullptr, nullptr, 25, 10, 7000000000, 8);
    runSyscallStat({"-t"});
    EXPECT_TRUE(existStr("mremap"));
    EXPECT_TRUE(existStr("close"));
    EXPECT_TRUE(existStr("open"));
    EXPECT_TRUE(existStr("read"));
    EXPECT_TRUE(existStr("rt_sigreturn"));
    EXPECT_TRUE(existStr("\33[H\33[2J\33[3J"));
}
// 测试-i 能否实现定时输出
TEST_F(SyscallStatTest, IntervalControlsPeriodicOutput)
{
    addTestEvent(0, nullptr, nullptr, 0, 5, 1000000000, 7);
    auto start = std::chrono::steady_clock::now();
    runSyscallStat({"-i", "2"});
    auto end = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    EXPECT_GE(ms, 1900);
    EXPECT_LT(ms, 2100);
}
// 测试 -i 0 应返回错误，且输出错误提示。
TEST_F(SyscallStatTest, InvalidIntervalZero)
{
   addTestEvent(0, nullptr, nullptr, 32, 5, 8000000000, 7);
   runSyscallStat({"-i", "0"});
   EXPECT_TRUE(existStr("wrong interval value: 0, must be >0 integer"));
   EXPECT_TRUE(!existStr("dup"));
}
// 测试 -i -2 应返回错误，且输出错误提示。
TEST_F(SyscallStatTest, InvalidIntervalNegative)
{
   addTestEvent(0, nullptr, nullptr, 32, 5, 8000000000, 7);
   runSyscallStat({"-i", "-2"});
   EXPECT_TRUE(existStr("wrong interval value: -2, must be >0 integer"));
   EXPECT_TRUE(!existStr("dup"));
}
// 测试 -i a 应返回错误，且输出错误提示。
TEST_F(SyscallStatTest, InvalidIntervalChar)
{
   addTestEvent(0, nullptr, nullptr, 32, 5, 8000000000, 7);
   runSyscallStat({"-i", "a"});
   EXPECT_TRUE(existStr("wrong interval value: a, must be >0 integer"));
   EXPECT_TRUE(!existStr("dup"));
}
// 测试当传入的comm字节数大于16时，不触发崩溃而是正常截断
TEST_F(SyscallStatTest, LongCommIsTruncatedSafely)
{
   addTestEvent(0, nullptr, "tpm2_getcommandauditdigest", 28, 5, 8000000000, 7);
   runSyscallStat({"-c", "tpm2_getcommandauditdigest"});
   EXPECT_TRUE(existStr("madvise"));
}
// 测试1s内，对同一nr号进行多次统计，最后一次会将前面的统计进行覆盖
TEST_F(SyscallStatTest, SameSyscallLastWriteWins)
{
    addTestEvent(0, nullptr, nullptr, 0, 60, 8000000000, 7);
    addTestEvent(0, nullptr, nullptr, 0, 15, 16000000000, 17);
    runSyscallStat({"-i", "1"});
    EXPECT_TRUE(!existStr("60"));
    EXPECT_TRUE(existStr("15"));
}
// 测试是否按照cnt进行降序输出
TEST_F(SyscallStatTest, MultipleStatsSortedByCountDesc)
{
    addTestEvent(0, nullptr, nullptr, 1, 5, 1000000000, 1);    // write
    addTestEvent(0, nullptr, nullptr, 3, 7, 1000000000, 1);    // close
    addTestEvent(0, nullptr, nullptr, 25, 10, 1000000000, 1);  // mremap
    addTestEvent(0, nullptr, nullptr, 2, 18, 1000000000, 1);   // open

    runSyscallStat({"-i", "1"});

    std::string log = readLog();

    size_t pos_open = log.find("open");
    size_t pos_mremap = log.find("mremap");
    size_t pos_close = log.find("close");
    size_t pos_write = log.find("write");

    ASSERT_NE(pos_open, std::string::npos);
    ASSERT_NE(pos_mremap, std::string::npos);
    ASSERT_NE(pos_close, std::string::npos);
    ASSERT_NE(pos_write, std::string::npos);

    EXPECT_LT(pos_open, pos_mremap);
    EXPECT_LT(pos_mremap, pos_close);
    EXPECT_LT(pos_close, pos_write);
}
