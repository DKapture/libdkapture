// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

// This file uses/derives from googletest
// Copyright 2008, Google Inc.
// Licensed under the BSD 3-Clause License
// See NOTICE for full license text

#include "gtest/gtest.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

struct PeekFdRule
{
	int32_t pid;
	int32_t fd;
	int32_t rw;
};

struct PeekFdLog
{
	ssize_t sz;
	char buf[];
};

extern void peek_fd_init(
	FILE *output,
	std::atomic<int> *conditionp,
	std::atomic<bool> **exit_flagp,
	int *filter_fd_out,
	int *log_fd_out
);
extern void peek_fd_deinit();
extern void peek_fd_get_rule_copy(void *out, size_t out_sz);
extern bool peek_fd_get_sock_trace_enabled();
extern bool peek_fd_get_read_trace_selected();
extern bool peek_fd_get_write_trace_selected();
extern int peek_fd_submit_builtin_event(
	int32_t pid,
	int32_t fd,
	int32_t rw,
	bool is_socket,
	const char *payload
);
extern int peek_fd_main(int argc, char **argv);

namespace
{
constexpr int kFdRead = 1;
constexpr int kFdWrite = 2;

struct WorkerCapture
{
	PeekFdRule rule {};
	bool sock_trace_enabled = false;
	bool read_trace_selected = false;
	bool write_trace_selected = false;
};

struct SimulatedEvent
{
	int32_t pid;
	int32_t fd;
	int32_t rw;
	bool is_socket;
	std::string payload;
};
}

class PeekFdBuiltinTest : public ::testing::Test
{
  protected:
	const std::string test_root = "/tmp/peek_fd_test_dir";
	const std::string log_file_path = test_root + "/peek_fd.log";
	const std::string out_file_path = test_root + "/peek_fd.out";

	void SetUp() override
	{
		std::filesystem::create_directories(test_root);
	}

	void TearDown() override
	{
		std::error_code ec;
		std::filesystem::remove_all(test_root, ec);
	}

	std::string readFile(const std::string &path) const
	{
		std::ifstream file(path, std::ios::binary);
		if (!file.is_open())
		{
			return "";
		}
		return std::string(
			(std::istreambuf_iterator<char>(file)),
			std::istreambuf_iterator<char>()
		);
	}

	int runPeekFd(
		const std::vector<std::string> &tool_args,
		const std::vector<SimulatedEvent> &events,
		WorkerCapture *capture = nullptr
	)
	{
		std::vector<std::string> args;
		args.reserve(tool_args.size() + 1);
		args.push_back("peek-fd");
		args.insert(args.end(), tool_args.begin(), tool_args.end());

		std::vector<char *> argv;
		argv.reserve(args.size() + 1);
		for (const auto &arg : args)
		{
			argv.push_back(const_cast<char *>(arg.c_str()));
		}
		argv.push_back(nullptr);

		FILE *log_file = fopen(log_file_path.c_str(), "w");
		EXPECT_NE(log_file, nullptr);
		if (!log_file)
		{
			return -1;
		}

		std::atomic<int> condition = 0;
		std::atomic<bool> *exit_flag = nullptr;
		int worker_error = 0;
		peek_fd_init(log_file, &condition, &exit_flag, nullptr, nullptr);

		int ret = -999;
		std::thread tool_thread(
			[&]()
			{
				ret = peek_fd_main(static_cast<int>(argv.size() - 1), argv.data());
			}
		);

		while (condition <= 0)
		{
			std::this_thread::sleep_for(std::chrono::microseconds(5));
		}
		if (condition == 1)
		{
			if (capture)
			{
				peek_fd_get_rule_copy(&capture->rule, sizeof(capture->rule));
				capture->sock_trace_enabled = peek_fd_get_sock_trace_enabled();
				capture->read_trace_selected = peek_fd_get_read_trace_selected();
				capture->write_trace_selected = peek_fd_get_write_trace_selected();
			}

			for (const auto &event : events)
			{
				if (peek_fd_submit_builtin_event(
						event.pid,
						event.fd,
						event.rw,
						event.is_socket,
						event.payload.c_str()
					) != 0)
				{
					worker_error = -1;
					break;
				}
			}
			condition = 2;
			*exit_flag = true;
		}

		tool_thread.join();
		peek_fd_deinit();
		fclose(log_file);
		if (worker_error != 0)
		{
			return worker_error;
		}
		return ret;
	}
};

TEST_F(PeekFdBuiltinTest, HelpOptionPrintsUsage)
{
	EXPECT_EQ(runPeekFd({"-h"}, {}), 0);
	const std::string content = readFile(log_file_path);
	EXPECT_NE(content.find("Usage: peek-fd"), std::string::npos);
	EXPECT_NE(content.find("--pid"), std::string::npos);
	EXPECT_NE(content.find("--fd"), std::string::npos);
	EXPECT_NE(content.find("--outfile"), std::string::npos);
	EXPECT_NE(content.find("--sock"), std::string::npos);
}

TEST_F(PeekFdBuiltinTest, InvalidOptionReturnsError)
{
	EXPECT_LT(runPeekFd({"--bad-option"}, {}), 0);
	EXPECT_NE(readFile(log_file_path).find("Usage: peek-fd"), std::string::npos);
}

TEST_F(PeekFdBuiltinTest, MissingPidOrFdReturnsError)
{
	EXPECT_LT(runPeekFd({"--pid", "123", "--read"}, {}), 0);
	EXPECT_NE(
		readFile(log_file_path).find(
			"You need to specify which process and which fd"
		),
		std::string::npos
	);
}

TEST_F(PeekFdBuiltinTest, MissingReadWriteModeReturnsError)
{
	EXPECT_LT(runPeekFd({"--pid", "123", "--fd", "8"}, {}), 0);
	EXPECT_NE(
		readFile(log_file_path).find(
			"You need to specify at least one of option -r/-w"
		),
		std::string::npos
	);
}

TEST_F(PeekFdBuiltinTest, ReadModeLoadsRuleAndOnlyLogsMatchingReadEvents)
{
	WorkerCapture capture;
	ASSERT_EQ(
		runPeekFd(
			{"--pid", "321", "--fd", "9", "--read"},
			{
				{321, 9, kFdRead, false, "matched-read"},
				{321, 9, kFdWrite, false, "wrong-mode"},
				{999, 9, kFdRead, false, "wrong-pid"},
				{321, 10, kFdRead, false, "wrong-fd"},
			},
			&capture
		),
		0
	);

	EXPECT_EQ(capture.rule.pid, 321);
	EXPECT_EQ(capture.rule.fd, 9);
	EXPECT_EQ(capture.rule.rw, kFdRead);
	EXPECT_FALSE(capture.sock_trace_enabled);
	EXPECT_TRUE(capture.read_trace_selected);
	EXPECT_FALSE(capture.write_trace_selected);

	const std::string content = readFile(log_file_path);
	EXPECT_NE(content.find("matched-read"), std::string::npos);
	EXPECT_EQ(content.find("wrong-mode"), std::string::npos);
	EXPECT_EQ(content.find("wrong-pid"), std::string::npos);
	EXPECT_EQ(content.find("wrong-fd"), std::string::npos);
}

TEST_F(PeekFdBuiltinTest, WriteModeLoadsRuleAndOnlyLogsMatchingWriteEvents)
{
	WorkerCapture capture;
	ASSERT_EQ(
		runPeekFd(
			{"--pid", "456", "--fd", "10", "--write"},
			{
				{456, 10, kFdWrite, false, "matched-write"},
				{456, 10, kFdRead, false, "wrong-mode"},
				{456, 11, kFdWrite, false, "wrong-fd"},
			},
			&capture
		),
		0
	);

	EXPECT_EQ(capture.rule.pid, 456);
	EXPECT_EQ(capture.rule.fd, 10);
	EXPECT_EQ(capture.rule.rw, kFdWrite);
	EXPECT_FALSE(capture.sock_trace_enabled);
	EXPECT_FALSE(capture.read_trace_selected);
	EXPECT_TRUE(capture.write_trace_selected);

	const std::string content = readFile(log_file_path);
	EXPECT_NE(content.find("matched-write"), std::string::npos);
	EXPECT_EQ(content.find("wrong-mode"), std::string::npos);
	EXPECT_EQ(content.find("wrong-fd"), std::string::npos);
}

TEST_F(PeekFdBuiltinTest, ReadWriteAndSockModesLogAllSelectedEvents)
{
	WorkerCapture capture;
	ASSERT_EQ(
		runPeekFd(
			{"--pid", "789", "--fd", "11", "--read", "--write", "--sock"},
			{
				{789, 11, kFdRead, false, "plain-read"},
				{789, 11, kFdWrite, false, "plain-write"},
				{789, 11, kFdRead, true, "socket-read"},
				{789, 11, kFdWrite, true, "socket-write"},
				{789, 11, kFdRead | kFdWrite, false, "rw-combined"},
			},
			&capture
		),
		0
	);

	EXPECT_EQ(capture.rule.pid, 789);
	EXPECT_EQ(capture.rule.fd, 11);
	EXPECT_EQ(capture.rule.rw, kFdRead | kFdWrite);
	EXPECT_TRUE(capture.sock_trace_enabled);
	EXPECT_TRUE(capture.read_trace_selected);
	EXPECT_TRUE(capture.write_trace_selected);

	const std::string content = readFile(log_file_path);
	EXPECT_NE(content.find("plain-read"), std::string::npos);
	EXPECT_NE(content.find("plain-write"), std::string::npos);
	EXPECT_NE(content.find("socket-read"), std::string::npos);
	EXPECT_NE(content.find("socket-write"), std::string::npos);
	EXPECT_NE(content.find("rw-combined"), std::string::npos);
}

TEST_F(PeekFdBuiltinTest, SocketEventsRequireSockOption)
{
	ASSERT_EQ(
		runPeekFd(
			{"--pid", "901", "--fd", "7", "--read"},
			{
				{901, 7, kFdRead, true, "socket-read"},
				{901, 7, kFdRead, false, "plain-read"},
			}
		),
		0
	);

	const std::string content = readFile(log_file_path);
	EXPECT_NE(content.find("plain-read"), std::string::npos);
	EXPECT_EQ(content.find("socket-read"), std::string::npos);
}

TEST_F(PeekFdBuiltinTest, DefaultOutputPrintsMatchedLogsToCurrentStdout)
{
	ASSERT_EQ(
		runPeekFd(
			{"--pid", "100", "--fd", "12", "--read"},
			{{100, 12, kFdRead, false, "stdout-data"}}
		),
		0
	);
	EXPECT_NE(readFile(log_file_path).find("stdout-data"), std::string::npos);
}

TEST_F(PeekFdBuiltinTest, OutfileRedirectsMatchedLogsToFile)
{
	ASSERT_EQ(
		runPeekFd(
			{"--pid", "200", "--fd", "13", "--write", "--outfile", out_file_path},
			{
				{200, 13, kFdWrite, false, "outfile-data"},
				{200, 14, kFdWrite, false, "wrong-fd"},
			}
		),
		0
	);

	EXPECT_NE(readFile(out_file_path).find("outfile-data"), std::string::npos);
	EXPECT_EQ(readFile(out_file_path).find("wrong-fd"), std::string::npos);
	EXPECT_EQ(readFile(log_file_path).find("outfile-data"), std::string::npos);
}
