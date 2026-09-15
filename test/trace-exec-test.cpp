// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

// This file uses/derives from googletest
// Copyright 2008, Google Inc.
// Licensed under the BSD 3-Clause License
// See NOTICE for full license text

#include "gtest/gtest.h"

#include <atomic>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include "com.h"
#include <bpf/bpf.h>

#define PATH_MAX 4096 
#define COMM_MAX_LEN 16
#define CHAIN_MAX_DEPTH 128
#define TEST_EVENT_MAX 32

struct Rule
{
	char target_path[4096];
	uint32_t depth;
	uint32_t uid;
};

struct Test_Event
{
	uint32_t uid;
	char path[PATH_MAX];
	uint32_t depth;
	uint32_t chain_len;
	char comm[CHAIN_MAX_DEPTH][COMM_MAX_LEN];
	pid_t pid[CHAIN_MAX_DEPTH];
};
struct Buf
{
	char path[PATH_MAX]; // Path of the file
	char log[PATH_MAX];	 // Log information
};

static const std::string TEST_ROOT = "/tmp/trace_exec_test_dir";
static const std::string TEST_LOG_FILE = TEST_ROOT + "/log.txt";
static Test_Event g_test_events[TEST_EVENT_MAX] = {};
static size_t g_test_event_count = 0;
static std::atomic<int> g_condition = 0;
static std::atomic<bool> *g_exit_flag = nullptr;

extern void trace_exec_init(
	FILE *output,
	std::atomic<int> *conditionp,
	std::atomic<bool> **exit_flagp,
	int *filter_fd,
	int *log_fd
);
extern int trace_exec_main(int argc, char *argv[]);
extern void trace_exec_deinit();
extern long bpf_for_each_map_elem(int fd, void *callback_fn, void *callback_ctx, unsigned long long flags);
extern int ring_buffer__push(int fd, void *data, size_t sz);

// Function to concatenate strings with a limit
static inline void strncat(void *dst, long dsz, const void *src, long ssz)
{
	char *d = (char *)(dst);
	const char *s = (const char *)src;
	// Copy until the source string ends or destination space runs out
	while (ssz > 0 && dsz > 0)
	{
		if (*s == 0)
		{
			return; // Stop if end of source string is reached
		}
		*d++ = *s++; // Copy character
		ssz--;
		dsz--; // Decrement sizes
	}
}
static long match_call(struct bpf_map *map, const void *key, void *value, void *ctx)
{
    struct Test_Event *test_event = (struct Test_Event *)ctx;
    struct Rule *rule = (struct Rule *)value;
    if(rule->uid > 0 && rule->uid != (uint32_t)-1 && test_event->uid != rule->uid){
        return 0;
    }
    if(rule->target_path[0] != '\0' &&
          strncmp(test_event->path, rule->target_path, sizeof(rule->target_path)) != 0)
    {
         return 0;
    }
	if (rule->depth > 128)
	{
		test_event->depth = 128; // Limit depth to 50
	}
    test_event->depth = rule->depth;
    return 1;
}
static bool rules_filter(int filter_fd, struct Test_Event &event)
{
    return bpf_for_each_map_elem(filter_fd, (void *)match_call, &event, 0) == 1;
}

static int add_buf_to_ringbuf(struct Test_Event &test_event, struct Buf &buf)
{
	char *pbuf = buf.path;	  // Buffer for path
	char *log = buf.log;	  // Buffer for log
	long log_left = PATH_MAX; // Remaining space in log

	if (test_event.chain_len == 0)
	{
		return 0;
	}
	int ret = snprintf(pbuf, 32, "%s(%d)", test_event.comm[0], (int)test_event.pid[0]);
	if (ret < 1)
	{
		printf("error: bpf_snprintf: %d", ret); // Log error
		return 0;
	}
	if (ret > 32)
	{
		return 0; // Overflow check
	}
	strncat(log, log_left, pbuf, 32); // Concatenate to log
	log_left -= ret;			  // Update remaining space
	log += ret;					  // Move log pointer

	int loop_limit = 0; // Limit for loops
	int key = 1; // index for comm and pid
	do
	{
        if (key >= (int)test_event.chain_len)
        {
            break;
        }
		int ret = snprintf(pbuf, 32, "<-%s(%d)", test_event.comm[key], (int)test_event.pid[key]);
		if (ret < 1)
		{
			printf("error: bpf_snprintf: %d", ret); // Log error
			break;
		}
		if (ret > 32)
		{
			printf("impossible code branch reached");// Overflow check
			break;
		}
		strncat(log, log_left, pbuf, 32); // Concatenate to log
		log_left -= ret;			  // Update remaining space
		log += ret;					  // Move log pointer
		if (test_event.pid[key] == 1 || loop_limit++ >= test_event.depth)
		{
			break; // Stop if reached root or limit
		}
		key++;
	} while (1);
	return 1;
}

static void event_worker(
    Test_Event *test_events,
    size_t test_event_count,
    std::atomic<int> &condition ,
    std::atomic<bool> *exit_flag,
    int *filter_fdp, 
    int *log_fdp
)
{
    while(condition <= 0)
    {
        std::this_thread::sleep_for(std::chrono::microseconds(5));
    }
    if(condition != 1)
    {
        *exit_flag = true;
        return;
    }
    auto filter_fd = *filter_fdp;
    auto log_fd = *log_fdp;
    for(size_t i = 0; i < test_event_count; ++i)
    {
        auto &e = test_events[i];
		struct Buf buf = {};
        if(rules_filter(filter_fd, e)){
			if(add_buf_to_ringbuf(e, buf))
			{
                size_t len = strlen(buf.log);
                if (len > 0)
                {
                    ring_buffer__push(log_fd, buf.log, len);
                }
			}
        }    
    }
    condition = 2;
	*exit_flag = true;
}
class TraceExecTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            createTestFiles();
            memset(g_test_events, 0, sizeof(g_test_events));
            g_test_event_count = 0;
            g_condition = 0;
            g_exit_flag = nullptr;
        }
        void TearDown() override
        {
            cleanTestFiles();
        }
        void createTestFiles()
        {
            system(("mkdir -p " + TEST_ROOT).c_str());
        }
        void cleanTestFiles()
        {
            system(("rm -rf " + TEST_ROOT).c_str());
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
                return false;
            }
            std::streamsize size = file.tellg();
            file.seekg(0, std::ios::beg);
            std::string content(size, '\0');
            if(!file.read(&content[0],size)){
                return false;
            }
            int count = 0;
            size_t pos = 0;
            while((pos = content.find(str, pos)) != std::string::npos) {
                ++count;
                pos += str.length();
            }
            return count;
        }
        // comm 和 pid 的数组顺序是，索引越大越靠近父节点
        void addTestEvent(uint32_t uid, const char *path, const std::vector<std::string> &comm,const std::vector<pid_t> &pid){
            ASSERT_LT(g_test_event_count, (size_t)TEST_EVENT_MAX);
            auto &e = g_test_events[g_test_event_count++];
            memset(&e, 0, sizeof(e));
            e.uid = uid;
            e.chain_len = std::min(comm.size(), pid.size());
            if (e.chain_len > CHAIN_MAX_DEPTH)
            {
                e.chain_len = CHAIN_MAX_DEPTH;
            }
            if (path != nullptr) {
                strncpy(e.path, path, sizeof(e.path) - 1);
                e.path[sizeof(e.path) - 1] = '\0';
            } else {
                e.path[0] = '\0'; // 如果为空，设为空字符串
            }
            for (uint32_t i = 0; i < e.chain_len; ++i)
            {
                strncpy(e.comm[i], comm[i].c_str(), COMM_MAX_LEN - 1);
                e.comm[i][COMM_MAX_LEN - 1] = '\0';
                e.pid[i] = pid[i];
            }
        }
        int runTraceExec(const std::vector<std::string> &_args){
            g_condition = 0;
            g_exit_flag = nullptr;
            std::vector<std::string> t;
            t.push_back("trace-exec");
            t.insert(t.end(),_args.begin(), _args.end());
            std::vector<char *> argv;
            argv.reserve(t.size());
            for(const auto &arg : t){
                argv.push_back(const_cast<char *>(arg.c_str()));
            }
            argv.push_back(nullptr);
            FILE *log_file = fopen(TEST_LOG_FILE.c_str(),"w");
            int filter_fd, log_fd;
            trace_exec_init(log_file, &g_condition ,&g_exit_flag, &filter_fd, &log_fd);
            std::thread *event_theard = new std::thread(
                event_worker,
                g_test_events,
                g_test_event_count,
                std::ref(g_condition),
                g_exit_flag,
                &filter_fd,
                &log_fd
            );
            int ret = trace_exec_main((int)t.size(), argv.data());
            event_theard->join();
            delete event_theard;
            trace_exec_deinit();
            fclose(log_file);
            return ret;
        }
};
TEST_F(TraceExecTest, SimpleTest1)
{
    runTraceExec({"-h"});
    EXPECT_TRUE(existStr("Usage:"));
    EXPECT_TRUE(!existStr("Tracing exec events... Hit Ctrl-C to end."));
}
TEST_F(TraceExecTest, SimpleTest2)
{
    addTestEvent(1, "/usr/bin/ls", {"ls", "bash", "deepin-terminal", "systemd", "systemd"},{2776242, 2776221, 2726957, 5082, 1});
    runTraceExec({});
    EXPECT_TRUE(existStr("Tracing exec events... Hit Ctrl-C to end."));
    EXPECT_TRUE(existStr("ls(2776242)<-bash(2776221)<-deepin-terminal(2726957)<-systemd(5082)<-systemd(1)"));
}
//测试-u能否过滤成功
TEST_F(TraceExecTest, UidFilterApplied)
{
    addTestEvent(1, "/usr/bin/ls", {"ls", "bash", "deepin-terminal", "systemd", "systemd"},{2776242, 2776221, 2726957, 5082, 1});
    addTestEvent(2, "/usr/bin/tail", {"tail", "bash", "bash", "deepin-terminal", "systemd", "systemd"},{2881663, 2881661, 2881649, 2726957, 5082, 1});
    runTraceExec({"-u","1"});
    EXPECT_TRUE(existStr("Tracing exec events... Hit Ctrl-C to end."));
    EXPECT_TRUE(existStr("ls(2776242)<-bash(2776221)<-deepin-terminal(2726957)<-systemd(5082)<-systemd(1)"));
    EXPECT_TRUE(!existStr("tail(2881663)<-bash(2881661)<-bash(2881649)<-deepin-terminal(2726957)<-systemd(5082)<-systemd(1)")); 
}
//测试-t能否过滤成功
TEST_F(TraceExecTest, TargetPathFilterApplied)
{
    addTestEvent(1, "/usr/bin/ls", {"ls", "bash", "deepin-terminal", "systemd", "systemd"},{2776242, 2776221, 2726957, 5082, 1});
    addTestEvent(1, "/usr/bin/tail", {"tail", "bash", "bash", "deepin-terminal", "systemd", "systemd"},{2881663, 2881661, 2881649, 2726957, 5082, 1});
    runTraceExec({"-t","/usr/bin/tail"});
    EXPECT_TRUE(existStr("Tracing exec events... Hit Ctrl-C to end."));
    EXPECT_TRUE(existStr("tail(2881663)<-bash(2881661)<-bash(2881649)<-deepin-terminal(2726957)<-systemd(5082)<-systemd(1)"));
    EXPECT_TRUE(!existStr("ls(2776242)<-bash(2776221)<-deepin-terminal(2726957)<-systemd(5082)<-systemd(1)"));
}
//测试-d能否过滤成功
TEST_F(TraceExecTest, DepthFilterApplied)
{
    addTestEvent(1, "/usr/bin/ls", {"ls", "bash", "deepin-terminal", "systemd", "systemd"},{2776242, 2776221, 2726957, 5082, 1});
    addTestEvent(1, "/usr/bin/tail", {"tail", "bash", "bash", "deepin-terminal", "systemd", "systemd"},{2881663, 2881661, 2881649, 2726957, 5082, 1});
    runTraceExec({"-d","2"});
    EXPECT_TRUE(existStr("Tracing exec events... Hit Ctrl-C to end."));
    EXPECT_TRUE(existStr("tail(2881663)<-bash(2881661)<-bash(2881649)<-deepin-terminal(2726957)"));
    EXPECT_TRUE(existStr("ls(2776242)<-bash(2776221)<-deepin-terminal(2726957)<-systemd(5082)"));
}
//测试-d，-u能否组合过滤成功
TEST_F(TraceExecTest, UidAndTargetCombinedFilterApplied)
{
    addTestEvent(1, "/usr/bin/ls", {"ls", "bash", "deepin-terminal", "systemd", "systemd"},{2776242, 2776221, 2726957, 5082, 1});
    addTestEvent(2, "/usr/bin/tail", {"tail", "bash", "bash", "deepin-terminal", "systemd", "systemd"},{2881663, 2881661, 2881649, 2726957, 5082, 1});
    runTraceExec({"-d","2", "-u", "1"});
    EXPECT_TRUE(existStr("Tracing exec events... Hit Ctrl-C to end."));
    EXPECT_TRUE(existStr("ls(2776242)<-bash(2776221)<-deepin-terminal(2726957)"));
    EXPECT_TRUE(!existStr("tail(2881663)<-bash(2881661)<-bash(2881649)<-deepin-terminal(2726957)"));
    EXPECT_TRUE(!existStr("tail(2881663)<-bash(2881661)<-bash(2881649)"));
}
//测试-u -1 异常数值能否被正确阻止，正确的uid正常被过滤
TEST_F(TraceExecTest, InvalidUidRejectedtest1)
{
    addTestEvent(1, "/usr/bin/ls", {"ls", "bash", "deepin-terminal", "systemd", "systemd"},{2776242, 2776221, 2726957, 5082, 1});
    addTestEvent(2, "/usr/bin/tail", {"tail", "bash", "bash", "deepin-terminal", "systemd", "systemd"},{2881663, 2881661, 2881649, 2726957, 5082, 1});
    runTraceExec({"-u","1"});
    EXPECT_TRUE(existStr("Tracing exec events... Hit Ctrl-C to end."));
    EXPECT_TRUE(existStr("ls(2776242)<-bash(2776221)<-deepin-terminal(2726957)<-systemd(5082)<-systemd(1)"));
    EXPECT_TRUE(!existStr("tail(2881663)<-bash(2881661)<-bash(2881649)<-deepin-terminal(2726957)<-systemd(5082)<-systemd(1)")); 
    runTraceExec({"-u","-1"});
    EXPECT_TRUE(existStr("wrong uid value: -1, must be a non-negative integer"));
}
//测试-u 12abc 异常数值能否被正确阻止，正确的uid正常被过滤
TEST_F(TraceExecTest, InvalidUidRejectedtest2)
{
    addTestEvent(1, "/usr/bin/ls", {"ls", "bash", "deepin-terminal", "systemd", "systemd"},{2776242, 2776221, 2726957, 5082, 1});
    addTestEvent(2, "/usr/bin/tail", {"tail", "bash", "bash", "deepin-terminal", "systemd", "systemd"},{2881663, 2881661, 2881649, 2726957, 5082, 1});
    runTraceExec({"-u","1"});
    EXPECT_TRUE(existStr("Tracing exec events... Hit Ctrl-C to end."));
    EXPECT_TRUE(existStr("ls(2776242)<-bash(2776221)<-deepin-terminal(2726957)<-systemd(5082)<-systemd(1)"));
    EXPECT_TRUE(!existStr("tail(2881663)<-bash(2881661)<-bash(2881649)<-deepin-terminal(2726957)<-systemd(5082)<-systemd(1)")); 
    runTraceExec({"-u","12abc"});
    EXPECT_TRUE(existStr("wrong uid value: 12abc, must be a non-negative integer"));
}
//测试-d -1 异常数值能否被正确阻止，正确的depth正常起作用
TEST_F(TraceExecTest, InvalidDepthRejectedtest1)
{
    addTestEvent(1, "/usr/bin/ls", {"ls", "bash", "deepin-terminal", "systemd", "systemd"},{2776242, 2776221, 2726957, 5082, 1});
    addTestEvent(2, "/usr/bin/tail", {"tail", "bash", "bash", "deepin-terminal", "systemd", "systemd"},{2881663, 2881661, 2881649, 2726957, 5082, 1});
    runTraceExec({"-d","1"});
    EXPECT_TRUE(existStr("Tracing exec events... Hit Ctrl-C to end."));
    EXPECT_TRUE(existStr("ls(2776242)<-bash(2776221)<-deepin-terminal(2726957)"));
    EXPECT_TRUE(existStr("tail(2881663)<-bash(2881661)<-bash(2881649)")); 
    runTraceExec({"-d","-1"});
    EXPECT_TRUE(existStr("wrong depth value: -1, must be a positive integer"));
}
//测试-d 0 异常数值能否被正确阻止，正确的depth正常起作用
TEST_F(TraceExecTest, InvalidDepthRejectedtest2)
{
    addTestEvent(1, "/usr/bin/ls", {"ls", "bash", "deepin-terminal", "systemd", "systemd"},{2776242, 2776221, 2726957, 5082, 1});
    addTestEvent(2, "/usr/bin/tail", {"tail", "bash", "bash", "deepin-terminal", "systemd", "systemd"},{2881663, 2881661, 2881649, 2726957, 5082, 1});
    runTraceExec({"-d","1"});
    EXPECT_TRUE(existStr("Tracing exec events... Hit Ctrl-C to end."));
    EXPECT_TRUE(existStr("ls(2776242)<-bash(2776221)<-deepin-terminal(2726957)"));
    EXPECT_TRUE(existStr("tail(2881663)<-bash(2881661)<-bash(2881649)")); 
    runTraceExec({"-d","0"});
    EXPECT_TRUE(existStr("wrong depth value: 0, must be a positive integer"));
}
//测试-d 12a 异常数值能否被正确阻止，正确的depth正常起作用
TEST_F(TraceExecTest, InvalidDepthRejectedtest3)
{
    addTestEvent(1, "/usr/bin/ls", {"ls", "bash", "deepin-terminal", "systemd", "systemd"},{2776242, 2776221, 2726957, 5082, 1});
    addTestEvent(2, "/usr/bin/tail", {"tail", "bash", "bash", "deepin-terminal", "systemd", "systemd"},{2881663, 2881661, 2881649, 2726957, 5082, 1});
    runTraceExec({"-d","1"});
    EXPECT_TRUE(existStr("Tracing exec events... Hit Ctrl-C to end."));
    EXPECT_TRUE(existStr("ls(2776242)<-bash(2776221)<-deepin-terminal(2726957)"));
    EXPECT_TRUE(existStr("tail(2881663)<-bash(2881661)<-bash(2881649)")); 
    runTraceExec({"-d","12a"});
    EXPECT_TRUE(existStr("wrong depth value: 12a, must be a positive integer"));
}
//测试-u 超大数值能否被正确阻止，正确的uid正常起作用
TEST_F(TraceExecTest, InvalidUidOverflowRejected)
{
    addTestEvent(1, "/usr/bin/ls", {"ls", "bash", "deepin-terminal", "systemd", "systemd"},{2776242, 2776221, 2726957, 5082, 1});
    addTestEvent(2, "/usr/bin/tail", {"tail", "bash", "bash", "deepin-terminal", "systemd", "systemd"},{2881663, 2881661, 2881649, 2726957, 5082, 1});
    runTraceExec({"-u","1"});
    EXPECT_TRUE(existStr("Tracing exec events... Hit Ctrl-C to end."));
    EXPECT_TRUE(existStr("ls(2776242)<-bash(2776221)<-deepin-terminal(2726957)<-systemd(5082)<-systemd(1)"));
    EXPECT_TRUE(!existStr("tail(2881663)<-bash(2881661)<-bash(2881649)<-deepin-terminal(2726957)<-systemd(5082)<-systemd(1)")); 
    runTraceExec({"-u","7000000000000000000000"});
    EXPECT_TRUE(existStr("wrong uid value: 7000000000000000000000, must be a non-negative integer"));
}
