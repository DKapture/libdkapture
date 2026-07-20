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

struct TraceSignalRule
{
	int32_t sender_pid;
	uint32_t sender_phash;
	int32_t recv_pid;
	uint32_t recv_phash;
	int32_t sig;
	int32_t res;
};

struct TraceSignalLog
{
	int32_t sender_pid;
	char sender_comm[16];
	int32_t recv_pid;
	char recv_comm[16];
	int32_t sig;
	int32_t res;
};

extern void trace_signal_init(
	FILE *output,
	std::atomic<int> *conditionp,
	std::atomic<bool> **exit_flagp,
	int *filter_fd,
	int *log_fd
);
extern void trace_signal_deinit();
extern int trace_signal_emit_log(const void *log, size_t data_sz);
extern int trace_signal_submit_builtin_event(
	const void *log,
	size_t data_sz,
	uint32_t sender_phash,
	uint32_t recv_phash
);
extern void trace_signal_get_rule_copy(void *out, size_t out_sz);
extern int trace_signal_main(int argc, char **argv);

namespace
{
struct SimulatedEvent
{
	TraceSignalLog log {};
	uint32_t sender_phash = 0;
	uint32_t recv_phash = 0;
};

struct WorkerCapture
{
	TraceSignalRule rule {};
};

uint32_t programHash(const std::string &program)
{
	std::vector<u32> words(4096 / sizeof(u32), 0);
	char *buf = reinterpret_cast<char *>(words.data());
	strncpy(buf, program.c_str(), 4096 - 1);
	return jhash2(words.data(), words.size(), 0);
}

bool waitForSubstring(
	const std::string &path,
	const std::vector<std::string> &needles,
	int timeout_ms
)
{
	for (int waited = 0; waited < timeout_ms; waited += 10)
	{
		std::ifstream file(path, std::ios::binary);
		std::string content(
			(std::istreambuf_iterator<char>(file)),
			std::istreambuf_iterator<char>()
		);
		bool matched = true;
		for (const auto &needle : needles)
		{
			if (content.find(needle) == std::string::npos)
			{
				matched = false;
				break;
			}
		}
		if (matched)
		{
			return true;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	return false;
}
}

class TraceSignalBuiltinTest : public ::testing::Test
{
  protected:
	const std::string test_root = "/tmp/trace_signal_test_dir";
	const std::string log_file_path = test_root + "/trace_signal.log";

	void SetUp() override
	{
		std::filesystem::create_directories(test_root);
	}

	void TearDown() override
	{
		std::error_code ec;
		std::filesystem::remove_all(test_root, ec);
	}

	std::string readLog() const
	{
		std::ifstream file(log_file_path, std::ios::binary);
		if (!file.is_open())
		{
			return "";
		}
		return std::string(
			(std::istreambuf_iterator<char>(file)),
			std::istreambuf_iterator<char>()
		);
	}

	int runTraceSignal(
		const std::vector<std::string> &tool_args,
		const std::vector<SimulatedEvent> &events,
		WorkerCapture *capture = nullptr
	)
	{
		std::vector<std::string> args;
		args.reserve(tool_args.size() + 1);
		args.push_back("trace-signal");
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
		trace_signal_init(
			log_file,
			&condition,
			&exit_flag,
			nullptr,
			nullptr
		);
		int ret = -999;
		std::thread tool_thread(
			[&]()
			{
				ret =
					trace_signal_main(static_cast<int>(argv.size() - 1), argv.data());
			}
		);

		while (condition <= 0)
		{
			std::this_thread::sleep_for(std::chrono::microseconds(50));
		}
		if (condition == 1)
		{
			if (capture)
			{
				trace_signal_get_rule_copy(&capture->rule, sizeof(capture->rule));
			}

			for (const auto &event : events)
			{
				if (trace_signal_submit_builtin_event(
						&event.log,
						sizeof(event.log),
						event.sender_phash,
						event.recv_phash
					) != 0)
				{
					ret = -1;
				}
			}
			*exit_flag = true;
		}

		tool_thread.join();
		trace_signal_deinit();
		fclose(log_file);
		return ret;
	}
};

TEST_F(TraceSignalBuiltinTest, HelpOptionPrintsUsage)
{
	EXPECT_EQ(runTraceSignal({"-h"}, {}), 0);
	const std::string content = readLog();
	EXPECT_NE(content.find("Usage: trace-signal"), std::string::npos);
	EXPECT_NE(content.find("--sender-pid"), std::string::npos);
	EXPECT_NE(content.find("--recv-pid"), std::string::npos);
	EXPECT_NE(content.find("--sender-prog"), std::string::npos);
	EXPECT_NE(content.find("--recv-prog"), std::string::npos);
	EXPECT_NE(content.find("--sig"), std::string::npos);
	EXPECT_NE(content.find("--res"), std::string::npos);
}

TEST_F(TraceSignalBuiltinTest, InvalidOptionReturnsError)
{
	EXPECT_LT(runTraceSignal({"--bad-option"}, {}), 0);
	EXPECT_NE(readLog().find("Usage: trace-signal"), std::string::npos);
}

TEST_F(TraceSignalBuiltinTest, LoadsRuleAndPrintsLogs)
{
	WorkerCapture capture;
	SimulatedEvent matched = {};
	matched.log.sender_pid = 101;
	snprintf(matched.log.sender_comm, sizeof(matched.log.sender_comm), "bash");
	matched.log.recv_pid = 202;
	snprintf(matched.log.recv_comm, sizeof(matched.log.recv_comm), "sleep");
	matched.log.sig = 15;
	matched.log.res = 0;

	SimulatedEvent wrong_sender = matched;
	wrong_sender.log.sender_pid = 999;
	snprintf(wrong_sender.log.sender_comm, sizeof(wrong_sender.log.sender_comm), "other");

	SimulatedEvent wrong_recv = matched;
	wrong_recv.log.recv_pid = 303;
	snprintf(wrong_recv.log.recv_comm, sizeof(wrong_recv.log.recv_comm), "otherrecv");

	SimulatedEvent wrong_sig = matched;
	wrong_sig.log.sig = 9;

	SimulatedEvent wrong_res = matched;
	wrong_res.log.res = -1;

	ASSERT_EQ(
		runTraceSignal(
			{"--sender-pid", "101", "--recv-pid", "202", "--sig", "15", "--res", "0"},
			{matched, wrong_sender, wrong_recv, wrong_sig, wrong_res},
			&capture
		),
		0
	);

	EXPECT_EQ(capture.rule.sender_pid, 101);
	EXPECT_EQ(capture.rule.recv_pid, 202);
	EXPECT_EQ(capture.rule.sig, 15);
	EXPECT_EQ(capture.rule.res, 0);

	std::string output = readLog();
	EXPECT_NE(output.find("bash"), std::string::npos);
	EXPECT_NE(output.find("sleep"), std::string::npos);
	EXPECT_NE(output.find("Terminated"), std::string::npos);
	EXPECT_EQ(output.find("other"), std::string::npos);
	EXPECT_EQ(output.find("otherrecv"), std::string::npos);
}

TEST_F(TraceSignalBuiltinTest, DefaultRuleValuesAreApplied)
{
	WorkerCapture capture;
	ASSERT_EQ(runTraceSignal({}, {}, &capture), 0);

	EXPECT_EQ(capture.rule.sender_pid, 0);
	EXPECT_EQ(capture.rule.sender_phash, 0u);
	EXPECT_EQ(capture.rule.recv_pid, 0);
	EXPECT_EQ(capture.rule.recv_phash, 0u);
	EXPECT_EQ(capture.rule.sig, 0);
	EXPECT_EQ(capture.rule.res, 0);
}

TEST_F(TraceSignalBuiltinTest, SenderProgramFilterOnlyEmitsMatchingSenderProgram)
{
	WorkerCapture capture;
	SimulatedEvent matched = {};
	matched.log.sender_pid = 101;
	snprintf(matched.log.sender_comm, sizeof(matched.log.sender_comm), "bash");
	matched.log.recv_pid = 202;
	snprintf(matched.log.recv_comm, sizeof(matched.log.recv_comm), "sleep");
	matched.log.sig = 15;
	matched.sender_phash = programHash("/usr/bin/bash");

	SimulatedEvent wrong_sender_prog = matched;
	snprintf(
		wrong_sender_prog.log.sender_comm,
		sizeof(wrong_sender_prog.log.sender_comm),
		"python"
	);
	wrong_sender_prog.sender_phash = programHash("/usr/bin/python3");

	ASSERT_EQ(
		runTraceSignal(
			{
				"--sender-pid",
				"101",
				"--recv-pid",
				"202",
				"--sender-prog",
				"/usr/bin/bash"
			},
			{matched, wrong_sender_prog},
			&capture
		),
		0
	);

	EXPECT_EQ(capture.rule.sender_pid, 101);
	EXPECT_EQ(capture.rule.recv_pid, 202);
	EXPECT_EQ(capture.rule.sender_phash, programHash("/usr/bin/bash"));
	EXPECT_EQ(capture.rule.recv_phash, 0u);
	EXPECT_EQ(capture.rule.sig, 0);
	EXPECT_EQ(capture.rule.res, 0);

	const std::string output = readLog();
	EXPECT_NE(output.find("bash"), std::string::npos);
	EXPECT_EQ(output.find("python"), std::string::npos);
}

TEST_F(TraceSignalBuiltinTest, SenderAndReceiverProgramFiltersBothApply)
{
	WorkerCapture capture;
	SimulatedEvent matched = {};
	matched.log.sender_pid = 101;
	snprintf(matched.log.sender_comm, sizeof(matched.log.sender_comm), "bash");
	matched.log.recv_pid = 202;
	snprintf(matched.log.recv_comm, sizeof(matched.log.recv_comm), "sleep");
	matched.log.sig = 15;
	matched.sender_phash = programHash("/usr/bin/bash");
	matched.recv_phash = programHash("/usr/bin/sleep");

	SimulatedEvent wrong_recv_prog = matched;
	snprintf(
		wrong_recv_prog.log.recv_comm,
		sizeof(wrong_recv_prog.log.recv_comm),
		"cat"
	);
	wrong_recv_prog.recv_phash = programHash("/usr/bin/cat");

	SimulatedEvent wrong_sender_prog = matched;
	snprintf(
		wrong_sender_prog.log.sender_comm,
		sizeof(wrong_sender_prog.log.sender_comm),
		"python"
	);
	wrong_sender_prog.sender_phash = programHash("/usr/bin/python3");

	ASSERT_EQ(
		runTraceSignal(
			{
				"--sender-pid",
				"101",
				"--recv-pid",
				"202",
				"--sender-prog",
				"/usr/bin/bash",
				"--recv-prog",
				"/usr/bin/sleep",
				"--sig",
				"15"
			},
			{matched, wrong_recv_prog, wrong_sender_prog},
			&capture
		),
		0
	);

	EXPECT_EQ(capture.rule.sender_pid, 101);
	EXPECT_EQ(capture.rule.recv_pid, 202);
	EXPECT_EQ(capture.rule.sender_phash, programHash("/usr/bin/bash"));
	EXPECT_EQ(capture.rule.recv_phash, programHash("/usr/bin/sleep"));
	EXPECT_EQ(capture.rule.sig, 15);
	EXPECT_EQ(capture.rule.res, 0);

	const std::string output = readLog();
	EXPECT_NE(output.find("bash"), std::string::npos);
	EXPECT_NE(output.find("sleep"), std::string::npos);
	EXPECT_EQ(output.find("python"), std::string::npos);
	EXPECT_EQ(output.find("cat"), std::string::npos);
}

TEST_F(TraceSignalBuiltinTest, DefaultRuleValuesAllowMultipleEvents)
{
	WorkerCapture capture;
	SimulatedEvent first = {};
	first.log.sender_pid = 11;
	snprintf(first.log.sender_comm, sizeof(first.log.sender_comm), "bash");
	first.log.recv_pid = 22;
	snprintf(first.log.recv_comm, sizeof(first.log.recv_comm), "sleep");
	first.log.sig = 15;
	first.log.res = 0;

	SimulatedEvent second = {};
	second.log.sender_pid = 33;
	snprintf(second.log.sender_comm, sizeof(second.log.sender_comm), "python");
	second.log.recv_pid = 44;
	snprintf(second.log.recv_comm, sizeof(second.log.recv_comm), "cat");
	second.log.sig = 9;
	second.log.res = -1;

	ASSERT_EQ(runTraceSignal({}, {first, second}, &capture), 0);

	EXPECT_EQ(capture.rule.sender_pid, 0);
	EXPECT_EQ(capture.rule.sender_phash, 0u);
	EXPECT_EQ(capture.rule.recv_pid, 0);
	EXPECT_EQ(capture.rule.recv_phash, 0u);
	EXPECT_EQ(capture.rule.sig, 0);
	EXPECT_EQ(capture.rule.res, 0);

	EXPECT_TRUE(
		waitForSubstring(
			log_file_path,
			{"bash", "sleep", "python", "cat"},
			500
		)
	);
}
