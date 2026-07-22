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

namespace
{
constexpr size_t kPathMax = 4096;
}

union LsofRule
{
	char path[kPathMax];
	struct
	{
		uint64_t not_inode;
		uint64_t inode;
		uint64_t dev;
	};
};

struct LsofLog
{
	uint32_t uid;
	int32_t pid;
	int32_t fd;
	char comm[16];
};

struct SimulatedEvent
{
	LsofLog log {};
	std::string path;
	uint64_t dev = 0;
	uint64_t inode = 0;
};

extern void lsof_init(
	FILE *output,
	std::atomic<int> *conditionp,
	std::atomic<bool> **exit_flagp
);
extern void lsof_deinit();
extern void lsof_get_rule_copy(void *out, size_t out_sz);
extern int lsof_submit_builtin_event(
	const void *log,
	size_t data_sz,
	const char *path,
	dev_t dev,
	uint64_t inode
);
extern int lsof_main(int argc, char **argv);

namespace
{
struct WorkerCapture
{
	LsofRule rule {};
};

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

class LsofBuiltinTest : public ::testing::Test
{
  protected:
	const std::string test_root = "/tmp/lsof_test_dir";
	const std::string log_file_path = test_root + "/lsof.log";

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

	int runLsof(
		const std::vector<std::string> &tool_args,
		const std::vector<SimulatedEvent> &events,
		WorkerCapture *capture = nullptr
	)
	{
		std::vector<std::string> args;
		args.reserve(tool_args.size() + 1);
		args.push_back("lsof");
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
		lsof_init(log_file, &condition, &exit_flag);
		int ret = -999;
		std::thread tool_thread(
			[&]()
			{
				ret = lsof_main(static_cast<int>(argv.size() - 1), argv.data());
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
				lsof_get_rule_copy(&capture->rule, sizeof(capture->rule));
			}

			for (const auto &event : events)
			{
				if (lsof_submit_builtin_event(
						&event.log,
						sizeof(event.log),
						event.path.c_str(),
						static_cast<dev_t>(event.dev),
						event.inode
					) != 0)
				{
					ret = -1;
				}
			}
			*exit_flag = true;
		}

		tool_thread.join();
		lsof_deinit();
		fclose(log_file);
		return ret;
	}
};

TEST_F(LsofBuiltinTest, HelpOptionPrintsUsage)
{
	EXPECT_EQ(runLsof({"-h"}, {}), 0);
	const std::string content = readLog();
	EXPECT_NE(content.find("Usage: lsof"), std::string::npos);
	EXPECT_NE(content.find("--path"), std::string::npos);
	EXPECT_NE(content.find("--dev"), std::string::npos);
	EXPECT_NE(content.find("--inode"), std::string::npos);
	EXPECT_NE(content.find("--help"), std::string::npos);
}

TEST_F(LsofBuiltinTest, InvalidOptionReturnsError)
{
	EXPECT_LT(runLsof({"--bad-option"}, {}), 0);
	EXPECT_NE(readLog().find("Usage: lsof"), std::string::npos);
}

TEST_F(LsofBuiltinTest, PathAndInodeCannotBeUsedTogether)
{
	EXPECT_LT(
		runLsof({"--path", "/tmp/a", "--inode", "123", "--dev", "456"}, {}),
		0
	);
	EXPECT_NE(
		readLog().find("error: -p and -i can't be used together"),
		std::string::npos
	);
}

TEST_F(LsofBuiltinTest, DevAndInodeMustBeUsedTogether)
{
	EXPECT_LT(runLsof({"--dev", "123"}, {}), 0);
	EXPECT_NE(
		readLog().find("error: -d and -i must be used together"),
		std::string::npos
	);
}

TEST_F(LsofBuiltinTest, PathRuleAggregatesMatchedFileAndVmaEntries)
{
	WorkerCapture capture;
	SimulatedEvent fd3 = {};
	fd3.log.uid = 1000;
	fd3.log.pid = 321;
	fd3.log.fd = 3;
	snprintf(fd3.log.comm, sizeof(fd3.log.comm), "bash");
	fd3.path = "/tmp/target";

	SimulatedEvent fd5 = fd3;
	fd5.log.fd = 5;

	SimulatedEvent vma = fd3;
	vma.log.fd = -1;

	SimulatedEvent other = fd3;
	other.log.pid = 999;
	snprintf(other.log.comm, sizeof(other.log.comm), "other");
	other.path = "/tmp/other";

	ASSERT_EQ(
		runLsof({"--path", "/tmp/target"}, {fd3, fd5, vma, other}, &capture),
		0
	);

	EXPECT_STREQ(capture.rule.path, "/tmp/target");
	const std::string content = readLog();
	EXPECT_TRUE(
		waitForSubstring(
			log_file_path,
			{"COMM", "UID", "PID", "FD", "bash", "1000", "321", "3", "5", "vma(1)"},
			500
		)
	);
	EXPECT_EQ(content.find("other"), std::string::npos);
}

TEST_F(LsofBuiltinTest, DevAndInodeRuleOnlyEmitsMatchedEntries)
{
	WorkerCapture capture;
	SimulatedEvent matched = {};
	matched.log.uid = 2000;
	matched.log.pid = 456;
	matched.log.fd = 8;
	snprintf(matched.log.comm, sizeof(matched.log.comm), "python");
	matched.dev = 12345;
	matched.inode = 67890;

	SimulatedEvent wrong_dev = matched;
	wrong_dev.dev = 12346;

	SimulatedEvent wrong_inode = matched;
	wrong_inode.inode = 67891;

	ASSERT_EQ(
		runLsof(
			{"--dev", "12345", "--inode", "67890"},
			{matched, wrong_dev, wrong_inode},
			&capture
		),
		0
	);

	EXPECT_EQ(capture.rule.not_inode, 0u);
	EXPECT_EQ(capture.rule.dev, 12345u);
	EXPECT_EQ(capture.rule.inode, 67890u);
	const std::string content = readLog();
	EXPECT_TRUE(
		waitForSubstring(log_file_path, {"python", "2000", "456", "8"}, 500)
	);
}

TEST_F(LsofBuiltinTest, DefaultRuleValuesAreZeroed)
{
	WorkerCapture capture;
	ASSERT_EQ(runLsof({}, {}, &capture), 0);
	EXPECT_EQ(capture.rule.not_inode, 0u);
	EXPECT_EQ(capture.rule.dev, 0u);
	EXPECT_EQ(capture.rule.inode, 0u);
	EXPECT_EQ(capture.rule.path[0], '\0');
	EXPECT_TRUE(waitForSubstring(log_file_path, {"COMM", "UID", "PID", "FD"}, 500));
}
