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

// flag bits
#define FD_READ 1  // Flag for read operation
#define FD_WRITE 2 // Flag for write operation

// Structure to define a rule for filtering
struct Rule
{
	pid_t pid; // Process ID
	int fd;	   // File descriptor
	int rw;	   // Read/Write flag
};
enum EventType
{
    EVENT_READ,
    EVENT_WRITE,
    EVENT_RECVFROM,
    EVENT_SENDTO,
};
// Structure to log data
struct Test_Event
{
    pid_t pid; // Process ID
	int fd;	   // File descriptor
	int rw;	   // Read/Write flag
	size_t sz;
	char buf[1024];
    enum EventType type; // Event type
};
struct BpfData
{
	size_t sz;
	char buf[1024];
};
struct PeekFdSync
{
    std::mutex m;
    std::condition_variable cv;
    bool init_done = false;
    bool exit_requested = false;
};

struct PeekFds
{
    int filter_fd;
    int logs_fd;
};

struct PeekFdRuntime
{
    PeekFdSync sync;
    std::promise<PeekFds> fds_promise;
    std::atomic<bool> *exit_flag = nullptr;
};
extern std::shared_ptr<PeekFdRuntime> peek_fd_init(FILE *output);
extern void peek_fd_deinit();
extern int peek_fd_main(int argc, char *args[]);
extern long bpf_for_each_map_elem(int fd, void *callback_fn, void *callback_ctx, unsigned long long flags);

#define TEST_EVENT_MAX 32
static Test_Event g_test_events[TEST_EVENT_MAX] = {};
static size_t g_test_event_count = 0;

extern int ring_buffer__push(int fd, void *data, size_t sz);
extern bool peek_fd_is_event_enabled(EventType type);


static long match_call(struct bpf_map *map, const void *key, void *value, void *ctx)
{
    struct Test_Event *test_event = (struct Test_Event *)ctx;
    struct Rule *rule = (struct Rule *)value;
    if (rule->pid > 0 &&  rule->pid!= test_event->pid)
    {
        return 0;
    }
    
    if (rule->fd >= 0 && rule->fd != test_event->fd)
    {
        return 0;
    }
    if (!(rule->rw & test_event->rw))
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
    std::shared_ptr<PeekFdRuntime> runtime,
    std::future<PeekFds> fds_future
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
    PeekFds fds;
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
        if(rules_filter(filter_fd, e) && peek_fd_is_event_enabled(e.type)){
           struct BpfData log = {};
           size_t len = e.sz;
            if (len > sizeof(log.buf) - 1)
            {
                len = sizeof(log.buf) - 1; // Limit to buffer size
            }
            memcpy(log.buf, e.buf, len);
            log.buf[len] = '\0'; // Null-terminate the string
            log.sz = len;
            size_t send_sz = sizeof(log.sz) + len;
            ring_buffer__push(logs_fd, &log, send_sz);
        }    
    }
    request_exit();
}
class PeekFdTest : public ::testing::Test
{
    protected:
        const std::string TEST_ROOT = "/tmp/peek_fd_test_dir";
        const std::string TEST_LOG_FILE = TEST_ROOT + "/log.txt";
        std::shared_ptr<PeekFdRuntime> runtime;

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
        void addTestEvent(pid_t pid, int fd, int rw, const char *buf, enum EventType type){
            struct Test_Event e = {
                .pid = pid,
                .fd = fd,
                .rw = rw,
                .sz = buf ? strlen(buf) : 0,
                .type = type
            };
            if (buf != nullptr) {
                strncpy(e.buf, buf, sizeof(e.buf) - 1);
                e.buf[sizeof(e.buf) - 1] = '\0';
            } else {
                e.buf[0] = '\0'; // 如果为空，设为空字符串
            }
            ASSERT_LT(g_test_event_count, (size_t)TEST_EVENT_MAX);
            g_test_events[g_test_event_count++] = e;
        }
        int runPeekFd(const std::vector<std::string> &_args){
            std::vector<std::string> t;
            t.push_back("peek_fd");
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
            runtime = peek_fd_init(log_file);
            std::future<PeekFds> fds_future = runtime->fds_promise.get_future();
            std::thread event_thread(
                event_worker,
                g_test_events,
                g_test_event_count,
                runtime,
                std::move(fds_future));
        int ret = peek_fd_main(argv.size(), argv.data());
            {
                std::lock_guard<std::mutex> lock(runtime->sync.m);
                runtime->sync.exit_requested = true;
            }
            runtime->sync.cv.notify_all();
            event_thread.join();
            peek_fd_deinit();
            fclose(log_file);
            return ret;
        }
};
//
TEST_F(PeekFdTest, SimpleTest1)
{
    runPeekFd({"-h"});
    EXPECT_TRUE(existStr("Usage:"));
}
TEST_F(PeekFdTest, SimpleTest2)
{
    runPeekFd({""});
    EXPECT_TRUE(existStr("You need to specify which process and which fd to"));
    EXPECT_TRUE(existStr("watch on by the options -pid(-p) and -fd(-f)"));
}
// 测试-r能否正确过滤
TEST_F(PeekFdTest, RwFilterApplied)
{
    addTestEvent(1, 2, FD_READ, "test-read-1", EVENT_READ);
    addTestEvent(1, 2, FD_WRITE, "test-write-1", EVENT_WRITE);
    runPeekFd({"-p", "1", "-f", "2", "-r"});
    EXPECT_TRUE(existStr("start peeking"));
    EXPECT_TRUE(existStr("test-read-1"));
    EXPECT_TRUE(!existStr("test-write-1"));
}
// 测试-p pid能否正确过滤
TEST_F(PeekFdTest, PidFilterApplied)
{
    addTestEvent(3, 2, FD_READ, "test-read-1", EVENT_READ);
    addTestEvent(1, 2, FD_READ, "test-read-2", EVENT_READ);
    runPeekFd({"-p", "3", "-f", "2", "-r"});
    EXPECT_TRUE(existStr("start peeking"));
    EXPECT_TRUE(existStr("test-read-1"));
    EXPECT_TRUE(!existStr("test-read-2"));
}
// 测试-f fd能否正确过滤
TEST_F(PeekFdTest, FdFilterApplied)
{
    addTestEvent(1, 1, FD_WRITE, "test-write-1", EVENT_WRITE);
    addTestEvent(1, 4, FD_WRITE, "test-write-2", EVENT_WRITE);
    runPeekFd({"-p", "1", "-f", "1", "-w"});
    EXPECT_TRUE(existStr("start peeking"));
    EXPECT_TRUE(existStr("test-write-1"));
    EXPECT_TRUE(!existStr("test-write-2"));
}
// 测试-r -p pid能否组合 正确过滤
TEST_F(PeekFdTest, ReadAndPidFilterApplied)
{
    addTestEvent(3, 2, FD_READ, "matched-read", EVENT_READ);
    addTestEvent(3, 2, FD_WRITE, "pid-only", EVENT_WRITE);
    addTestEvent(1, 2, FD_READ, "read-only", EVENT_READ);
    runPeekFd({"-p", "3", "-f", "2", "-r"});
    EXPECT_TRUE(existStr("start peeking"));
    EXPECT_TRUE(existStr("matched-read"));
    EXPECT_TRUE(!existStr("pid-only"));
    EXPECT_TRUE(!existStr("read-only"));
}
// 测试-r -f fd能否组合 正确过滤
TEST_F(PeekFdTest, ReadAndFdFilterApplied)
{
    addTestEvent(1, 2, FD_READ, "matched-read", EVENT_READ);
    addTestEvent(1, 2, FD_WRITE, "fd-only", EVENT_WRITE);
    addTestEvent(1, 3, FD_READ, "read-only", EVENT_READ);
    runPeekFd({"-p", "1", "-f", "2", "-r"});
    EXPECT_TRUE(existStr("start peeking"));
    EXPECT_TRUE(existStr("matched-read"));
    EXPECT_TRUE(!existStr("fd-only"));
    EXPECT_TRUE(!existStr("read-only"));
}
// 测试-p pid -f fd能否组合 正确过滤
TEST_F(PeekFdTest, PidAndFdFilterApplied)
{
    addTestEvent(3, 2, FD_READ, "matched-event", EVENT_READ);
    addTestEvent(3, 4, FD_READ, "pid-only", EVENT_READ);
    addTestEvent(1, 2, FD_READ, "fd-only", EVENT_READ);
    runPeekFd({"-p", "3", "-f", "2", "-r"});
    EXPECT_TRUE(existStr("start peeking"));
    EXPECT_TRUE(existStr("matched-event"));
    EXPECT_TRUE(!existStr("pid-only"));
    EXPECT_TRUE(!existStr("fd-only"));
}
// 测试 -o 是否能将输出重定向到指定文件
  TEST_F(PeekFdTest, OutfileApplied)
  {
      const std::string custom_out = TEST_ROOT + "/custom_out.txt";
      addTestEvent(1, 2, FD_READ, "test-read-1", EVENT_READ);
      runPeekFd({"-p", "1", "-f", "2", "-r", "-o", custom_out});

      std::ifstream file(custom_out, std::ios::binary | std::ios::ate);
      ASSERT_TRUE(file.is_open());
      std::streamsize size = file.tellg();
      file.seekg(0, std::ios::beg);

      std::string content(size, '\0');
      ASSERT_TRUE(file.read(&content[0], size));

      EXPECT_TRUE(content.find("start peeking") != std::string::npos);
      EXPECT_TRUE(content.find("test-read-1") != std::string::npos);
      EXPECT_TRUE(!existStr("test-read-1"));
  }
// 测试未指定 -s 时，socket 读事件不会被输出
TEST_F(PeekFdTest, SocketReadDisabledByDefault)
{
    addTestEvent(1, 2, FD_READ, "normal-read", EVENT_READ);
    addTestEvent(1, 2, FD_READ, "socket-read", EVENT_RECVFROM);
    runPeekFd({"-p", "1", "-f", "2", "-r"});
    EXPECT_TRUE(existStr("start peeking"));
    EXPECT_TRUE(existStr("normal-read"));
    EXPECT_TRUE(!existStr("socket-read"));
}
// 测试指定 -s 时，socket 读事件能够被输出
TEST_F(PeekFdTest, SocketReadEnabledWithOptionS)
{
    addTestEvent(1, 2, FD_READ, "normal-read", EVENT_READ);
    addTestEvent(1, 2, FD_READ, "socket-read", EVENT_RECVFROM);
    runPeekFd({"-p", "1", "-f", "2", "-r", "-s"});
    EXPECT_TRUE(existStr("start peeking"));
    EXPECT_TRUE(existStr("normal-read"));
    EXPECT_TRUE(existStr("socket-read"));
}
// 测试指定 -s 时，socket 写事件能够被输出
TEST_F(PeekFdTest, SocketWriteEnabledWithOptionS)
{
    addTestEvent(1, 2, FD_WRITE, "normal-write", EVENT_WRITE);
    addTestEvent(1, 2, FD_WRITE, "socket-write", EVENT_SENDTO);
    runPeekFd({"-p", "1", "-f", "2", "-w", "-s"});
    EXPECT_TRUE(existStr("start peeking"));
    EXPECT_TRUE(existStr("normal-write"));
    EXPECT_TRUE(existStr("socket-write"));
}
// 测试未指定 -s 时，socket 写事件不会被输出
TEST_F(PeekFdTest, SocketWriteDisabledByDefault)
{
    addTestEvent(1, 2, FD_WRITE, "normal-write", EVENT_WRITE);
    addTestEvent(1, 2, FD_WRITE, "socket-write", EVENT_SENDTO);
    runPeekFd({"-p", "1", "-f", "2", "-w"});
    EXPECT_TRUE(existStr("start peeking"));
    EXPECT_TRUE(existStr("normal-write"));
    EXPECT_TRUE(!existStr("socket-write"));
}
// 测试 -p 传入负数时返回错误并输出提示
TEST_F(PeekFdTest, InvalidPidNegativeRejected)
{
    runPeekFd({"-p", "-1", "-f", "2", "-r"});
    EXPECT_TRUE(existStr("wrong pid value: -1, must be a positive integer"));
    EXPECT_TRUE(!existStr("start peeking"));
}

// 测试 -p 传入 0 时返回错误并输出提示
TEST_F(PeekFdTest, InvalidPidZeroRejected)
{
    runPeekFd({"-p", "0", "-f", "2", "-r"});
    EXPECT_TRUE(existStr("wrong pid value: 0, must be a positive integer"));
    EXPECT_TRUE(!existStr("start peeking"));
}

// 测试 -p 传入字母时返回错误并输出提示
TEST_F(PeekFdTest, InvalidPidAlphaRejected)
{
    runPeekFd({"-p", "abc", "-f", "2", "-r"});

    EXPECT_TRUE(existStr("wrong pid value: abc, must be a positive integer"));
    EXPECT_TRUE(!existStr("start peeking"));
}

// 测试 -p 传入带脏字符的数字时返回错误并输出提示
TEST_F(PeekFdTest, InvalidPidMixedRejected)
{
    runPeekFd({"-p", "12aa", "-f", "2", "-r"});

    EXPECT_TRUE(existStr("wrong pid value: 12aa, must be a positive integer"));
    EXPECT_TRUE(!existStr("start peeking"));
}

// 测试 -f 传入负数时返回错误并输出提示
TEST_F(PeekFdTest, InvalidFdNegativeRejected)
{
    runPeekFd({"-p", "1", "-f", "-1", "-r"});

    EXPECT_TRUE(existStr("wrong fd value: -1, must be a non-negative integer"));
    EXPECT_TRUE(!existStr("start peeking"));
}

// 测试 -f 传入字母时返回错误并输出提示
TEST_F(PeekFdTest, InvalidFdAlphaRejected)
{
    runPeekFd({"-p", "1", "-f", "abc", "-r"});

    EXPECT_TRUE(existStr("wrong fd value: abc, must be a non-negative integer"));
    EXPECT_TRUE(!existStr("start peeking"));
}

// 测试 -f 传入带脏字符的数字时返回错误并输出提示
TEST_F(PeekFdTest, InvalidFdMixedRejected)
{
    runPeekFd({"-p", "1", "-f", "2xx", "-r"});

    EXPECT_TRUE(existStr("wrong fd value: 2xx, must be a non-negative integer"));
    EXPECT_TRUE(!existStr("start peeking"));
}

// 测试缺少 -p 参数时返回错误并输出提示
TEST_F(PeekFdTest, MissingPidRejected)
{
    runPeekFd({"-f", "2", "-r"});

    EXPECT_TRUE(existStr("You need to specify which process and which fd to"));
    EXPECT_TRUE(existStr("watch on by the options -pid(-p) and -fd(-f)"));
    EXPECT_TRUE(!existStr("start peeking"));
}

// 测试缺少 -f 参数时返回错误并输出提示
TEST_F(PeekFdTest, MissingFdRejected)
{
    runPeekFd({"-p", "1", "-r"});

    EXPECT_TRUE(existStr("You need to specify which process and which fd to"));
    EXPECT_TRUE(existStr("watch on by the options -pid(-p) and -fd(-f)"));
    EXPECT_TRUE(!existStr("start peeking"));
}

// 测试未指定 -r/-w 时返回错误并输出提示
TEST_F(PeekFdTest, MissingRwOptionRejected)
{
    runPeekFd({"-p", "1", "-f", "2"});

    EXPECT_TRUE(existStr("You need to specify at least one of option -r/-w"));
    EXPECT_TRUE(!existStr("start peeking"));
}
