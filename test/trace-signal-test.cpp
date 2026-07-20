// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

// This file uses/derives from googletest
// Copyright 2008, Google Inc.
// Licensed under the BSD 3-Clause License
// See NOTICE for full license text

#include "gtest/gtest.h"
#include "jhash.h"

#include <atomic>
#include <bpf/bpf.h>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#define COMM_MAX_LEN 16
#define TEST_EVENT_MAX 32

struct Rule
{
	pid_t sender_pid;
	uint32_t sender_phash;
	pid_t recv_pid;
	uint32_t recv_phash;
	int sig;
	int res;
};

struct Test_Event
{
	pid_t sender_pid;
	char sender_comm[COMM_MAX_LEN];
	pid_t recv_pid;
	char recv_comm[COMM_MAX_LEN];
	int sig;
	int res;
	uint32_t sender_phash;
	uint32_t recv_phash;
};
struct BpfData
{
	pid_t sender_pid;
	char sender_comm[COMM_MAX_LEN];
	pid_t recv_pid;
	char recv_comm[COMM_MAX_LEN];
	int sig;
	int res;
};

static const std::string TEST_ROOT = "/tmp/trace_signal_test_dir";
static const std::string TEST_LOG_FILE = TEST_ROOT + "/log.txt";
static Test_Event g_test_events[TEST_EVENT_MAX] = {};
static size_t g_test_event_count = 0;
static std::atomic<int> g_condition = 0;
static std::atomic<bool> *g_exit_flag = nullptr;
void trace_signal_init(
	FILE *output,
	std::atomic<int> *conditionp,
	std::atomic<bool> **exit_flagp,
	int *filter_fd,
	int *log_fd
);
extern int trace_signal_main(int argc, char *argvp[]);
extern void trace_signal_deinit();
extern long bpf_for_each_map_elem(int fd, void *callback_fn, void *callback_ctx, unsigned long long flags);
extern int ring_buffer__push(int fd, void *data, size_t sz);

static long match_call(struct bpf_map *map, const void *key, void *value, void *ctx)
{
    struct Test_Event *test_event = (struct Test_Event *)ctx;
    struct Rule *rule = (struct Rule *)value;
    if(rule->sender_pid > 0 && rule->sender_pid != (pid_t)-1 && test_event->sender_pid != rule->sender_pid){
        return 0;
    }
	if(rule->recv_pid > 0 && rule->recv_pid != (pid_t)-1 && test_event->recv_pid != rule->recv_pid){
        return 0;
    }
	if(rule->sig > 0 && rule->sig != (int)-1 && test_event->sig != rule->sig){
        return 0;
    }
	if(rule->res > 0 && rule->res != (int)-1 && test_event->res != rule->res){
		return 0;
    }
	if(rule->sender_phash != 0 && test_event->sender_phash != rule->sender_phash){
		return 0;
	}
	if(rule->recv_phash != 0 && test_event->recv_phash != rule->recv_phash){
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
        if(rules_filter(filter_fd, e)){
			struct BpfData log_data = {}; 
			log_data.sender_pid = e.sender_pid;
			log_data.recv_pid = e.recv_pid;
			log_data.sig = e.sig;
			log_data.res = e.res;
			strcpy(log_data.sender_comm, e.sender_comm);
			strcpy(log_data.recv_comm, e.recv_comm);
			int ret = ring_buffer__push(log_fd, &log_data, sizeof(log_data));
        }    
    }
    condition = 2;
	*exit_flag = true;
}
class TraceSignalTest : public ::testing::Test
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
        void addTestEvent(uint32_t sender_pid, 
						  uint32_t recv_pid, 
						  const char *sender_comm, 
						  const char *recv_comm, 
						  const char *sender_path, 
						  const char *recv_path, 
						  int32_t sig, int32_t res){
            ASSERT_LT(g_test_event_count, (size_t)TEST_EVENT_MAX);
            auto &e = g_test_events[g_test_event_count++];
            memset(&e, 0, sizeof(e));
            e.sender_pid = sender_pid;
            e.recv_pid = recv_pid;
			e.sig = sig;
			e.res = res;
            if (sender_comm!= nullptr) {
                strncpy(e.sender_comm , sender_comm, sizeof(e.sender_comm ) - 1);
                e.sender_comm[sizeof(e.sender_comm) - 1] = '\0';
            } else {
                e.sender_comm[0] = '\0'; // 如果为空，设为空字符串
            }
            if (recv_comm!= nullptr) {
                strncpy(e.recv_comm , recv_comm, sizeof(e.recv_comm ) - 1);
                e.recv_comm[sizeof(e.recv_comm) - 1] = '\0';
            } else {
                e.recv_comm[0] = '\0'; // 如果为空，设为空字符串
            }
            uint32_t sender_phash = 0;
            if(sender_path != nullptr){
                char *buf = (char *)calloc(4096, sizeof(char)); // 从堆区申请内存
                if (!buf)
                {
                    perror("calloc");
                    exit(EXIT_FAILURE);
                }
                strncpy(buf, sender_path, 4096);
                buf[4095] = '\0';
                sender_phash =  jhash(buf, 4096, 0);
                free(buf);
            }
			uint32_t recv_phash = 0;
            if(recv_path != nullptr){
                char *buf = (char *)calloc(4096, sizeof(char)); // 从堆区申请内存
                if (!buf)
                {
                    perror("calloc");
                    exit(EXIT_FAILURE);
                }
                strncpy(buf, recv_path, 4096);
                buf[4095] = '\0';
                recv_phash =  jhash(buf, 4096, 0);
                free(buf);
            }
			e.sender_phash = sender_phash;
			e.recv_phash = recv_phash;
        }
        int runTraceSignal(const std::vector<std::string> &_args){
            g_condition = 0;
            g_exit_flag = nullptr;
            std::vector<std::string> t;
            t.push_back("trace-signal");
            t.insert(t.end(),_args.begin(), _args.end());
            std::vector<char *> argv;
            argv.reserve(t.size());
            for(const auto &arg : t){
                argv.push_back(const_cast<char *>(arg.c_str()));
            }
            argv.push_back(nullptr);
            FILE *log_file = fopen(TEST_LOG_FILE.c_str(),"w");
            int filter_fd, log_fd;
            trace_signal_init(log_file, &g_condition ,&g_exit_flag, &filter_fd, &log_fd);
            std::thread *event_theard = new std::thread(
                event_worker,
                g_test_events,
                g_test_event_count,
                std::ref(g_condition),
                g_exit_flag,
                &filter_fd,
                &log_fd
            );
            int ret = trace_signal_main((int)t.size(), argv.data());
            event_theard->join();
            delete event_theard;
            trace_signal_deinit();
            fclose(log_file);
            return ret;
        }
};
TEST_F(TraceSignalTest, SimpleTest1)
{
    runTraceSignal({"-h"});
    EXPECT_TRUE(existStr("Usage:"));
}
//测试能否正常输出数据
TEST_F(TraceSignalTest, SimpleTest2)
{
	addTestEvent(3027354, 2649772, "sender1", "receiver1", "/tmp/trace_signal_test_dir/sender1", "/tmp/trace_signal_test_dir/receiver1", 2, 0);
	addTestEvent(3070643, 2649682, "sender2", "receiver2", "/tmp/trace_signal_test_dir/sender2", "/tmp/trace_signal_test_dir/receiver2", 0, 0);
	addTestEvent(945692, 2649772, "sender3", "receiver3", "/tmp/trace_signal_test_dir/sender3", "/tmp/trace_signal_test_dir/receiver3", 4, 1);
    runTraceSignal({""});
    EXPECT_TRUE(existStr("=============== filter ================="));
	EXPECT_TRUE(existStr("sender_pid = 0"));
    EXPECT_TRUE(existStr("sender_phash = 0"));
    EXPECT_TRUE(existStr("recv_pid = 0"));
    EXPECT_TRUE(existStr("recv_phash = 0"));
    EXPECT_TRUE(existStr("signal = 0"));
    EXPECT_TRUE(existStr("return = 0"));
	EXPECT_TRUE(existStr("SENDER          S-COMM      RCVER          R-COMM       SIGNAL   RESULT"));
	EXPECT_TRUE(existStr("3027354         sender1    2649772       receiver1    Interrupt        0"));
    EXPECT_TRUE(existStr("3070643         sender2    2649682       receiver2            0        0"));
	EXPECT_TRUE(existStr("945692         sender3    2649772       receiver3 Illegal instruction        1"));
}
//测试能否正常根据 -P senderID过滤
TEST_F(TraceSignalTest, SenderPidFilterApplied)
{
	addTestEvent(3027354, 2649772, "sender1", "receiver1", "/tmp/trace_signal_test_dir/sender1", "/tmp/trace_signal_test_dir/receiver1", 2, 0);
	addTestEvent(3070643, 2649682, "sender2", "receiver2", "/tmp/trace_signal_test_dir/sender2", "/tmp/trace_signal_test_dir/receiver2", 0, 0);
	addTestEvent(945692, 2649772, "sender3", "receiver3", "/tmp/trace_signal_test_dir/sender3", "/tmp/trace_signal_test_dir/receiver3", 4, 1);
    runTraceSignal({"-P","945692"});
    EXPECT_TRUE(existStr("=============== filter ================="));
	EXPECT_TRUE(existStr("sender_pid = 945692"));
    EXPECT_TRUE(existStr("sender_phash = 0"));
    EXPECT_TRUE(existStr("recv_pid = 0"));
    EXPECT_TRUE(existStr("recv_phash = 0"));
    EXPECT_TRUE(existStr("signal = 0"));
    EXPECT_TRUE(existStr("return = 0"));
	EXPECT_TRUE(existStr("SENDER          S-COMM      RCVER          R-COMM       SIGNAL   RESULT"));
	EXPECT_TRUE(!existStr("3027354         sender1    2649772       receiver1    Interrupt        0"));
    EXPECT_TRUE(!existStr("3070643         sender2    2649682       receiver2            0        0"));
	EXPECT_TRUE(existStr("945692         sender3    2649772       receiver3 Illegal instruction        1"));
}
//测试能否正常根据 -P receiverID过滤
TEST_F(TraceSignalTest, ReceiverPidFilterApplied)
{
	addTestEvent(3027354, 2649772, "sender1", "receiver1", "/tmp/trace_signal_test_dir/sender1", "/tmp/trace_signal_test_dir/receiver1", 2, 0);
	addTestEvent(3070643, 2649682, "sender2", "receiver2", "/tmp/trace_signal_test_dir/sender2", "/tmp/trace_signal_test_dir/receiver2", 0, 0);
	addTestEvent(945692, 2649772, "sender3", "receiver3", "/tmp/trace_signal_test_dir/sender3", "/tmp/trace_signal_test_dir/receiver3", 4, 1);
    runTraceSignal({"-p","2649682"});
    EXPECT_TRUE(existStr("=============== filter ================="));
	EXPECT_TRUE(existStr("sender_pid = 0"));
    EXPECT_TRUE(existStr("sender_phash = 0"));
    EXPECT_TRUE(existStr("recv_pid = 2649682"));
    EXPECT_TRUE(existStr("recv_phash = 0"));
    EXPECT_TRUE(existStr("signal = 0"));
    EXPECT_TRUE(existStr("return = 0"));
	EXPECT_TRUE(existStr("SENDER          S-COMM      RCVER          R-COMM       SIGNAL   RESULT"));
	EXPECT_TRUE(!existStr("3027354         sender1    2649772       receiver1    Interrupt        0"));
    EXPECT_TRUE(existStr("3070643         sender2    2649682       receiver2            0        0"));
	EXPECT_TRUE(!existStr("945692         sender3    2649772       receiver3 Illegal instruction        1"));
}
//测试能否正常根据 -s senderProg过滤
TEST_F(TraceSignalTest, SenderProgramFilterApplied)
{
	addTestEvent(3027354, 2649772, "sender1", "receiver1", "/tmp/trace_signal_test_dir/sender1", "/tmp/trace_signal_test_dir/receiver1", 2, 0);
	addTestEvent(3070643, 2649682, "sender2", "receiver2", "/tmp/trace_signal_test_dir/sender2", "/tmp/trace_signal_test_dir/receiver2", 0, 0);
	addTestEvent(945692, 2649772, "sender3", "receiver3", "/tmp/trace_signal_test_dir/sender3", "/tmp/trace_signal_test_dir/receiver3", 4, 1);
    runTraceSignal({"-s","/tmp/trace_signal_test_dir/sender3"});
    char *buf = (char *)calloc(4096, 1);
    memset(buf, 0, 4096);
	strncpy(buf, "/tmp/trace_signal_test_dir/sender3", 4096);
	buf[4095] = 0;
	uint32_t sender_phash = jhash2((u32 *)buf, 4096 / 4, 0);
    free(buf);
    EXPECT_TRUE(existStr("=============== filter ================="));
	EXPECT_TRUE(existStr("sender_pid = 0"));
    EXPECT_TRUE(existStr("sender_phash = " + std::to_string(sender_phash)));
    EXPECT_TRUE(existStr("recv_pid = 0"));
    EXPECT_TRUE(existStr("recv_phash = 0"));
    EXPECT_TRUE(existStr("signal = 0"));
    EXPECT_TRUE(existStr("return = 0"));
	EXPECT_TRUE(existStr("SENDER          S-COMM      RCVER          R-COMM       SIGNAL   RESULT"));
	EXPECT_TRUE(!existStr("3027354         sender1    2649772       receiver1    Interrupt        0"));
    EXPECT_TRUE(!existStr("3070643         sender2    2649682       receiver2            0        0"));
	EXPECT_TRUE(existStr("945692         sender3    2649772       receiver3 Illegal instruction        1"));
}
//测试能否正常根据 -r receiverProg过滤
TEST_F(TraceSignalTest, ReceiverProgramFilterApplied)
{
	addTestEvent(3027354, 2649772, "sender1", "receiver1", "/tmp/trace_signal_test_dir/sender1", "/tmp/trace_signal_test_dir/receiver1", 2, 0);
	addTestEvent(3070643, 2649682, "sender2", "receiver2", "/tmp/trace_signal_test_dir/sender2", "/tmp/trace_signal_test_dir/receiver2", 0, 0);
	addTestEvent(945692, 2649772, "sender3", "receiver3", "/tmp/trace_signal_test_dir/sender3", "/tmp/trace_signal_test_dir/receiver3", 4, 1);
    runTraceSignal({"-r","/tmp/trace_signal_test_dir/receiver2"});
    char *buf = (char *)calloc(4096, 1);
    memset(buf, 0, 4096);
	strncpy(buf, "/tmp/trace_signal_test_dir/receiver2", 4096);
	buf[4095] = 0;
	uint32_t recv_phash = jhash2((u32 *)buf, 4096 / 4, 0);
    free(buf);
    EXPECT_TRUE(existStr("=============== filter ================="));
	EXPECT_TRUE(existStr("sender_pid = 0"));
    EXPECT_TRUE(existStr("sender_phash = 0" ));
    EXPECT_TRUE(existStr("recv_pid = 0"));
    EXPECT_TRUE(existStr("recv_phash = " + std::to_string(recv_phash)));
    EXPECT_TRUE(existStr("signal = 0"));
    EXPECT_TRUE(existStr("return = 0"));
	EXPECT_TRUE(existStr("SENDER          S-COMM      RCVER          R-COMM       SIGNAL   RESULT"));
	EXPECT_TRUE(!existStr("3027354         sender1    2649772       receiver1    Interrupt        0"));
    EXPECT_TRUE(existStr("3070643         sender2    2649682       receiver2            0        0"));
	EXPECT_TRUE(!existStr("945692         sender3    2649772       receiver3 Illegal instruction        1"));
}
//测试能否正常根据 -S signal过滤
TEST_F(TraceSignalTest, SignalFilterApplied)
{
	addTestEvent(3027354, 2649772, "sender1", "receiver1", "/tmp/trace_signal_test_dir/sender1", "/tmp/trace_signal_test_dir/receiver1", 2, 0);
	addTestEvent(3070643, 2649682, "sender2", "receiver2", "/tmp/trace_signal_test_dir/sender2", "/tmp/trace_signal_test_dir/receiver2", 0, 0);
	addTestEvent(945692, 2649772, "sender3", "receiver3", "/tmp/trace_signal_test_dir/sender3", "/tmp/trace_signal_test_dir/receiver3", 4, 1);
    runTraceSignal({"-S","4"});
    EXPECT_TRUE(existStr("=============== filter ================="));
	EXPECT_TRUE(existStr("sender_pid = 0"));
    EXPECT_TRUE(existStr("sender_phash = 0"));
    EXPECT_TRUE(existStr("recv_pid = 0"));
    EXPECT_TRUE(existStr("recv_phash = 0"));
    EXPECT_TRUE(existStr("signal = 4"));
    EXPECT_TRUE(existStr("return = 0"));
	EXPECT_TRUE(existStr("SENDER          S-COMM      RCVER          R-COMM       SIGNAL   RESULT"));
	EXPECT_TRUE(!existStr("3027354         sender1    2649772       receiver1    Interrupt        0"));
    EXPECT_TRUE(!existStr("3070643         sender2    2649682       receiver2            0        0"));
	EXPECT_TRUE(existStr("945692         sender3    2649772       receiver3 Illegal instruction        1"));
}
//测试能否正常根据 -S result过滤
TEST_F(TraceSignalTest, ResultFilterApplied)
{
	addTestEvent(3027354, 2649772, "sender1", "receiver1", "/tmp/trace_signal_test_dir/sender1", "/tmp/trace_signal_test_dir/receiver1", 2, 2);
	addTestEvent(3070643, 2649682, "sender2", "receiver2", "/tmp/trace_signal_test_dir/sender2", "/tmp/trace_signal_test_dir/receiver2", 0, 0);
	addTestEvent(945692, 2649772, "sender3", "receiver3", "/tmp/trace_signal_test_dir/sender3", "/tmp/trace_signal_test_dir/receiver3", 4, 1);
    runTraceSignal({"-R","2"});
    EXPECT_TRUE(existStr("=============== filter ================="));
	EXPECT_TRUE(existStr("sender_pid = 0"));
    EXPECT_TRUE(existStr("sender_phash = 0"));
    EXPECT_TRUE(existStr("recv_pid = 0"));
    EXPECT_TRUE(existStr("recv_phash = 0"));
    EXPECT_TRUE(existStr("signal = 0"));
    EXPECT_TRUE(existStr("return = 2"));
	EXPECT_TRUE(existStr("SENDER          S-COMM      RCVER          R-COMM       SIGNAL   RESULT"));
	EXPECT_TRUE(existStr("3027354         sender1    2649772       receiver1    Interrupt        2"));
    EXPECT_TRUE(!existStr("3070643         sender2    2649682       receiver2            0        0"));
	EXPECT_TRUE(!existStr("945692         sender3    2649772       receiver3 Illegal instruction        1"));
}
//测试组合过滤条件能否正常工作
TEST_F(TraceSignalTest, CombinedFiltersApplied)
{
	addTestEvent(3027354, 2649772, "sender1", "receiver1", "/tmp/trace_signal_test_dir/sender1", "/tmp/trace_signal_test_dir/receiver1", 2, 2);
	addTestEvent(3070643, 2649682, "sender2", "receiver2", "/tmp/trace_signal_test_dir/sender2", "/tmp/trace_signal_test_dir/receiver2", 0, 0);
	addTestEvent(945692, 2649772, "sender3", "receiver3", "/tmp/trace_signal_test_dir/sender3", "/tmp/trace_signal_test_dir/receiver3", 4, 1);
    runTraceSignal({"-P","3027354","-p","2649772","-s","/tmp/trace_signal_test_dir/sender1","-r","/tmp/trace_signal_test_dir/receiver1","-S","2","-R","2"});
    char *buf = (char *)calloc(4096, 1);
    char *buf1 = (char *)calloc(4096, 1);
    memset(buf, 0, 4096);
    memset(buf1, 0, 4096);
	strncpy(buf, "/tmp/trace_signal_test_dir/sender1", 4096);
    strncpy(buf1, "/tmp/trace_signal_test_dir/receiver1", 4096);
	buf[4095] = 0;
    buf1[4035] = 0;
	uint32_t sender_phash = jhash2((u32 *)buf, 4096 / 4, 0);
    uint32_t recv_phash = jhash2((u32 *)buf1, 4096 / 4, 0);
    free(buf);
    free(buf1);
    EXPECT_TRUE(existStr("=============== filter ================="));
	EXPECT_TRUE(existStr("sender_pid = 3027354"));
    EXPECT_TRUE(existStr("sender_phash = " + std::to_string(sender_phash)));
    EXPECT_TRUE(existStr("recv_pid = 2649772"));
    EXPECT_TRUE(existStr("recv_phash = " + std::to_string(recv_phash)));
    EXPECT_TRUE(existStr("signal = 2"));
    EXPECT_TRUE(existStr("return = 2"));
	EXPECT_TRUE(existStr("SENDER          S-COMM      RCVER          R-COMM       SIGNAL   RESULT"));
	EXPECT_TRUE(existStr("3027354         sender1    2649772       receiver1    Interrupt        2"));
    EXPECT_TRUE(!existStr("3070643         sender2    2649682       receiver2            0        0"));
	EXPECT_TRUE(!existStr("945692         sender3    2649772       receiver3 Illegal instruction        1"));
}
//测试能否正常根据 -P senderID过滤非法输入
TEST_F(TraceSignalTest, InvalidSenderPidRejected)
{
    addTestEvent(3027354, 2649772, "sender1", "receiver1", "/tmp/trace_signal_test_dir/sender1", "/tmp/trace_signal_test_dir/receiver1", 2, 2);
	addTestEvent(3070643, 2649682, "sender2", "receiver2", "/tmp/trace_signal_test_dir/sender2", "/tmp/trace_signal_test_dir/receiver2", 0, 0);
	addTestEvent(945692, 2649772, "sender3", "receiver3", "/tmp/trace_signal_test_dir/sender3", "/tmp/trace_signal_test_dir/receiver3", 4, 1);
    runTraceSignal({"-P","-1"});
    EXPECT_TRUE(existStr("wrong sender pid value: -1, must be a positive integer"));
    runTraceSignal({"-P","12abc"});
    EXPECT_TRUE(existStr("wrong sender pid value: 12abc, must be a positive integer"));
    runTraceSignal({"-P","1000000000000000"});
    EXPECT_TRUE(existStr("wrong sender pid value: 1000000000000000, must be a positive integer"));
    EXPECT_TRUE(!existStr("=============== filter ================="));
}
//测试能否正常根据 -p receiverID过滤非法输入
TEST_F(TraceSignalTest, InvalidReceiverPidRejected)
{
    addTestEvent(3027354, 2649772, "sender1", "receiver1", "/tmp/trace_signal_test_dir/sender1", "/tmp/trace_signal_test_dir/receiver1", 2, 2);
	addTestEvent(3070643, 2649682, "sender2", "receiver2", "/tmp/trace_signal_test_dir/sender2", "/tmp/trace_signal_test_dir/receiver2", 0, 0);
	addTestEvent(945692, 2649772, "sender3", "receiver3", "/tmp/trace_signal_test_dir/sender3", "/tmp/trace_signal_test_dir/receiver3", 4, 1);
    runTraceSignal({"-p","-1"});
    EXPECT_TRUE(existStr("wrong receiver pid value: -1, must be a positive integer"));
    runTraceSignal({"-p","12abc"});
    EXPECT_TRUE(existStr("wrong receiver pid value: 12abc, must be a positive integer"));
    runTraceSignal({"-p","1000000000000000"});
    EXPECT_TRUE(existStr("wrong receiver pid value: 1000000000000000, must be a positive integer"));
    EXPECT_TRUE(!existStr("=============== filter ================="));
}
//测试能否正常根据 -S signal过滤非法输入
TEST_F(TraceSignalTest, InvalidSignalRejected)
{
    addTestEvent(3027354, 2649772, "sender1", "receiver1", "/tmp/trace_signal_test_dir/sender1", "/tmp/trace_signal_test_dir/receiver1", 2, 2);
	addTestEvent(3070643, 2649682, "sender2", "receiver2", "/tmp/trace_signal_test_dir/sender2", "/tmp/trace_signal_test_dir/receiver2", 0, 0);
	addTestEvent(945692, 2649772, "sender3", "receiver3", "/tmp/trace_signal_test_dir/sender3", "/tmp/trace_signal_test_dir/receiver3", 4, 1);
    runTraceSignal({"-S","-1"});
    EXPECT_TRUE(existStr("wrong signal value: -1, must be a positive integer"));
    runTraceSignal({"-S","12abc"});
    EXPECT_TRUE(existStr("wrong signal value: 12abc, must be a positive integer"));
    runTraceSignal({"-S","1000000000000000"});
    EXPECT_TRUE(existStr("wrong signal value: 1000000000000000, must be a positive integer"));
    EXPECT_TRUE(!existStr("=============== filter ================="));
}
//测试能否正常根据 -R result过滤非法输入
TEST_F(TraceSignalTest, InvalidResultRejected)
{
    addTestEvent(3027354, 2649772, "sender1", "receiver1", "/tmp/trace_signal_test_dir/sender1", "/tmp/trace_signal_test_dir/receiver1", 2, 2);
	addTestEvent(3070643, 2649682, "sender2", "receiver2", "/tmp/trace_signal_test_dir/sender2", "/tmp/trace_signal_test_dir/receiver2", 0, 0);
	addTestEvent(945692, 2649772, "sender3", "receiver3", "/tmp/trace_signal_test_dir/sender3", "/tmp/trace_signal_test_dir/receiver3", 4, 1);
    runTraceSignal({"-R","-1"});
    EXPECT_TRUE(existStr("wrong result value: -1, must be an integer"));
    runTraceSignal({"-R","12abc"});
    EXPECT_TRUE(existStr("wrong result value: 12abc, must be an integer"));
    runTraceSignal({"-R","1000000000000000"});
    EXPECT_TRUE(existStr("wrong result value: 1000000000000000, must be an integer"));
    EXPECT_TRUE(!existStr("=============== filter ================="));
}
