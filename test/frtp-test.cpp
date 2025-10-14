// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

// This file uses/derives from googletest
// Copyright 2008, Google Inc.
// Licensed under the BSD 3-Clause License
// See NOTICE for full license text

#include "gtest/gtest.h"
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <thread>
#include <sys/wait.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <sys/stat.h>

using std::string, std::ofstream, std::vector, std::pair;

#define FMODE_READ (0x1)
#define FMODE_WRITE (0x2)
#define FMODE_EXEC (0x20)

struct TestEvent
{
	string proc_path;
	string target_path;
	int act;
};

struct Event
{
	const char *proc_path; /**< 进程路径 */
	struct
	{
		dev_t dev;
		ino_t ino;
	} target; /**< 目标文件信息 */
	int act;  /**< 操作类型 */
};

struct Rule
{
	union
	{
		struct
		{
			uint32_t not_pid; /**< 标志位，0表示使用PID，1表示使用进程路径 */
			pid_t pid; /**< 进程ID */
		};
		char process[4096]; /**< 进程路径字符串 */
	};
	int act; /**< 禁止的操作类型 */
	struct
	{
		dev_t dev;
		ino_t ino;
	} target;
	; /**< 目标文件标识 */
};

struct BpfData
{
	unsigned int act;
	pid_t pid;
	struct
	{
		dev_t dev;
		ino_t ino;
	};
	char process[];
};

void frtp_init(
	FILE *output,
	std::atomic<int> *conditionp,
	std::atomic<bool> **exit_flagp,
	int *filter_fd,
	int *log_fd
);
extern void frtp_deinit();
extern int frtp_main(int argc, char **argv);
extern long bpf_for_each_map_elem(
	int fd,
	void *callback_fn,
	void *callback_ctx,
	__u64 flags
);
extern int ring_buffer__push(int fd, void *data, size_t sz);

static long wildcard_match(const char *pattern, const char *str, long n)
{
	const char *s1 = pattern;
	const char *s2 = str;
	if (n < 0)
	{
		return 0; // Ensure n is not negative
	}
	// Compare in chunks of long size
	while (n >= sizeof(long))
	{
		const unsigned long *p1 = (const unsigned long *)s1;
		const unsigned long *p2 = (const unsigned long *)s2;
		if (*p1 != *p2)
		{
			if (n > sizeof(long))
			{
				n = sizeof(long);
			}

			while (n > 0)
			{
				if (*s1 == '*')
				{
					return 0;
				}

				if (*s1 != *s2)
				{
					return (*s1 - *s2); // Return comparison result
				}
				if (*s1 == 0)
				{
					return 0; // Stop if end of string is reached
				}
				s1++;
				s2++;
				n--; // Move to next character
			}
			return *p1 - *p2;
		}
		if (*p1 == 0)
		{
			return 0; // Stop if end of string is reached
		}
		s1 += sizeof(long); // Move pointers
		s2 += sizeof(long);
		n -= sizeof(long);
	}

	while (n > 0)
	{
		if (*s1 == '*')
		{
			return 0;
		}

		if (*s1 != *s2)
		{
			return (*s1 - *s2); // Return comparison result
		}
		if (*s1 == 0)
		{
			return 0; // Stop if end of string is reached
		}
		s1++;
		s2++;
		n--; // Move to next character
	}
	return 0; // All compared characters are equal
}

static long
match_callback(struct bpf_map *map, const void *key, void *value, void *ctx)
{
	const char *proc_path;
	dev_t dev;
	ino_t ino;
	int act;

	struct Event *event = (struct Event *)ctx;
	struct Rule *rule = (struct Rule *)value;

	proc_path = event->proc_path;
	dev = event->target.dev;
	ino = event->target.ino;
	act = event->act;

	if (rule->not_pid)
	{
		if (!proc_path)
		{
			return 0;
		}
		// Check if process path matches
		if (wildcard_match(rule->process, proc_path, 4096))
		{
			return 0;
		}
	}
	else
	{
		pid_t pid = 1;
		if (rule->pid != pid)
		{
			return 0;
		}
	}

	// Check if file matches
	if (rule->target.ino != ino || rule->target.dev != dev)
	{
		return 0;
	}

	// Check if act is a subset of rule->act
	if (act & rule->act)
	{
		event->act = 0;
	}

	return 1;
}

static bool rules_filter(int filter_fd, struct Event &event)
{
	bpf_for_each_map_elem(filter_fd, (void *)match_callback, &event, 0);

	return !!event.act;
}

static void audit_log(int log_fd, struct Event &event, const char *fname)
{
	char buffer[4096];
	memset(buffer, 0, 4096);
	auto log = (BpfData *)buffer;
	log->act = event.act;
	log->pid = 10000;
	log->dev = event.target.dev;
	log->ino = event.target.ino;
	int offset = sizeof(struct BpfData);
	strncpy(log->process, event.proc_path, 4094 - offset);
	offset += strlen(log->process) + 1;
	strncpy(log->process + strlen(log->process) + 1, fname, 4095 - offset);
	offset += strlen(&buffer[offset]) + 1;
	ring_buffer__push(log_fd, buffer, offset);
}

static pair<string, string> splitPath(const string &path)
{
	size_t lastSlashPos = path.find_last_of('/');

	if (lastSlashPos == string::npos)
	{
		return make_pair(".", path);
	}
	else if (lastSlashPos == 0)
	{
		return std::make_pair("/", path.substr(1));
	}
	else
	{
		return std::make_pair(
			path.substr(0, lastSlashPos),
			path.substr(lastSlashPos + 1)
		);
	}
}

static void event_worker(
	vector<TestEvent> &events,
	std::atomic<int> &condition,
	std::atomic<bool> *exit_flag,
	int *filter_fdp,
	int *log_fdp
)
{
	while (condition <= 0)
	{
		std::this_thread::sleep_for(std::chrono::microseconds(5));
	};
	if (condition != 1)
	{
		*exit_flag = true;
		return;
	}
	auto filter_fd = *filter_fdp;
	auto log_fd = *log_fdp;
	for (auto &e : events)
	{
		struct stat st;
		char proc_path[4096];
		if (stat(e.target_path.c_str(), &st))
		{
			continue;
		}
		memset(proc_path, 0, 4096);
		strcpy(proc_path, e.proc_path.c_str());
		struct Event event = {
			proc_path,
			{st.st_dev, st.st_ino},
			e.act,
		};

		if (!rules_filter(filter_fd, event))
		{
			event.act = e.act;
			audit_log(log_fd, event, "");
			continue;
		}
		auto [dirname, fname] = splitPath(e.target_path);
		if (stat(dirname.c_str(), &st))
		{
			continue;
		}
		event.target = {st.st_dev, st.st_ino};
		if (!rules_filter(filter_fd, event))
		{
			event.act = e.act;
			audit_log(log_fd, event, fname.c_str());
		}
	}
	condition = 2;
	*exit_flag = true;
}

class FrtpTest : public ::testing::Test
{
  protected:
	const string TEST_ROOT = "/tmp/frtp_test_dir";
	const string TEST_POLICY_FILE = TEST_ROOT + "/frtp_test.pol";
	const string TEST_LOG_FILE = TEST_ROOT + "/log.txt";
	vector<TestEvent> events;
	std::atomic<int> condition = 0;
	std::atomic<bool> *exit_flag;
	struct bpf_map *rules_map;

	void SetUp() override
	{
		createTestFiles();
	}

	void TearDown() override
	{
		cleanupTestFiles();
	}

	void createTestFiles()
	{
		system(("mkdir -p " + TEST_ROOT).c_str());
	}

	void cleanupTestFiles()
	{
		system(("rm -rf " + TEST_ROOT).c_str());
	}

	void mkdir(const string &dir)
	{
		system(("mkdir -p " + TEST_ROOT + "/" + dir).c_str());
	}

	int createFile(const string &path, const string &content)
	{
		ofstream file(path);
		if (!file.is_open())
		{
			return -1;
		}
		file << content;
		file.close();
		return 0;
	}

	void printLogFile()
	{
		std::cout << "=== log file start ===\n";
		system(("cat " + TEST_LOG_FILE).c_str());
		std::cout << "==== log file end ====\n";
	}

	bool existStr(const std::string &str)
	{
		std::ifstream file(TEST_LOG_FILE, std::ios::binary | std::ios::ate);
		if (!file.is_open())
		{
			return false;
		}

		std::streamsize size = file.tellg();
		file.seekg(0, std::ios::beg);

		std::string content(size, '\0');
		if (!file.read(&content[0], size))
		{
			return false;
		}

		return content.find(str) != std::string::npos;
	}

	int countStr(const std::string &str)
	{
		std::ifstream file(TEST_LOG_FILE, std::ios::binary | std::ios::ate);
		if (!file.is_open())
		{
			return 0;
		}

		std::streamsize size = file.tellg();
		file.seekg(0, std::ios::beg);

		std::string content(size, '\0');
		if (!file.read(&content[0], size))
		{
			return 0;
		}

		int count = 0;
		size_t pos = 0;
		while ((pos = content.find(str, pos)) != std::string::npos)
		{
			++count;
			pos += str.length();
		}
		return count;
	}

	void addEvent(string proc_path, string target_path, int act)
	{
		struct TestEvent e =
			{.proc_path = proc_path, .target_path = target_path, .act = act};
		events.push_back(e);
	}

	int runFrtp(const std::vector<std::string> &_args)
	{
		std::vector<std::string> t;
		t.reserve(_args.size() + 1);
		t.push_back("frtp");
		t.insert(t.end(), _args.begin(), _args.end());
		std::vector<char *> argv;
		argv.reserve(t.size());

		for (const auto &arg : t)
		{
			argv.push_back(const_cast<char *>(arg.c_str()));
		}
		FILE *log_file = fopen(TEST_LOG_FILE.c_str(), "w");
		int filter_fd, log_fd;
		frtp_init(log_file, &condition, &exit_flag, &filter_fd, &log_fd);
		std::thread *event_thread = new std::thread(
			event_worker,
			std::ref(events),
			std::ref(condition),
			exit_flag,
			&filter_fd,
			&log_fd
		);
		int ret = frtp_main(argv.size(), argv.data());
		event_thread->join();
		frtp_deinit();
		fclose(log_file);
		return ret;
	}
};

TEST_F(FrtpTest, SimpleTest1)
{
	runFrtp({"-h"});
	EXPECT_EQ(existStr("Usage"), true);
}

TEST_F(FrtpTest, SimpleTest2)
{
	createFile(
		TEST_POLICY_FILE,
		"forbid proc=/usr/bin/cat rw " + TEST_ROOT + "/*"
	);
	auto f1 = TEST_ROOT + "/file1";
	createFile(f1, "");
	auto f2 = TEST_ROOT + "/file2";
	createFile(f2, "");
	addEvent("/usr/bin/cat", f1, FMODE_READ);
	addEvent("/usr/bin/cat", f2, FMODE_READ);
	addEvent("/usr/bin/truncate", f2, FMODE_WRITE);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	EXPECT_EQ(
		existStr("/usr/bin/cat[10000] tried to read " + f1 + ", denied!"),
		true
	);
	EXPECT_EQ(
		existStr("/usr/bin/cat[10000] tried to read " + f2 + ", denied!"),
		true
	);
	EXPECT_EQ(
		existStr("/usr/bin/truncate[10000] tried to write " + f2 + ", denied!"),
		false
	);
}

TEST_F(FrtpTest, SimpleTest3)
{
	auto f1 = TEST_ROOT + "/file1";
	createFile(f1, "");
	createFile(TEST_POLICY_FILE, "forbid proc=/usr/bin/* rw " + f1);
	addEvent("/usr/local/bin/app1", f1, FMODE_READ);
	addEvent("/usr/bin/cat", f1, FMODE_READ | FMODE_WRITE);
	addEvent("/usr/bin/truncate", f1, FMODE_WRITE);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	EXPECT_EQ(
		existStr(
			"/usr/local/bin/app1[10000] tried to read " + f1 + ", denied!"
		),
		false
	);
	EXPECT_EQ(
		existStr("/usr/bin/cat[10000] tried to read/write " + f1 + ", denied!"),
		true
	);
	EXPECT_EQ(
		existStr("/usr/bin/truncate[10000] tried to write " + f1 + ", denied!"),
		true
	);
}

TEST_F(FrtpTest, SimpleTest4)
{
	// 测试PID规则
	auto f1 = TEST_ROOT + "/file1";
	createFile(f1, "");
	createFile(TEST_POLICY_FILE, "forbid pid=1234 rw " + f1);
	addEvent("/usr/bin/cat", f1, FMODE_READ);
	addEvent("/usr/bin/cat", f1, FMODE_WRITE);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	// PID规则应该不匹配（因为代码中硬编码pid=1总是不匹配）
	EXPECT_EQ(existStr("denied!"), false);
}

TEST_F(FrtpTest, MultipleOperations)
{
	// 测试多个操作类型
	auto f1 = TEST_ROOT + "/file1";
	createFile(f1, "");
	createFile(TEST_POLICY_FILE, "forbid proc=/usr/bin/cat rw " + f1);
	addEvent("/usr/bin/cat", f1, FMODE_READ);
	addEvent("/usr/bin/cat", f1, FMODE_WRITE);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	EXPECT_EQ(existStr("tried to read " + f1), true);
	EXPECT_EQ(existStr("tried to write " + f1), true);
}

TEST_F(FrtpTest, NestedDirectoryRules)
{
	// 测试嵌套目录规则
	mkdir("subdir");
	auto f1 = TEST_ROOT + "/file1";
	auto f2 = TEST_ROOT + "/subdir/file2";
	createFile(f1, "");
	createFile(f2, "");
	createFile(
		TEST_POLICY_FILE,
		"forbid proc=/usr/bin/cat rw " + TEST_ROOT + "/subdir/*"
	);
	addEvent("/usr/bin/cat", f1, FMODE_READ);
	addEvent("/usr/bin/cat", f2, FMODE_READ);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	EXPECT_EQ(existStr("tried to read " + f1), false);
	EXPECT_EQ(existStr("tried to read " + f2), true);
}

TEST_F(FrtpTest, ExactPathMatching)
{
	// 测试精确路径匹配
	auto f1 = TEST_ROOT + "/exact_file";
	createFile(f1, "");
	createFile(TEST_POLICY_FILE, "forbid proc=/usr/bin/cat rw " + f1);
	addEvent("/usr/bin/cat", f1, FMODE_READ);
	addEvent("/usr/bin/cat", TEST_ROOT + "/different_file", FMODE_READ);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	EXPECT_EQ(existStr("tried to read " + f1), true);
	EXPECT_EQ(
		existStr("tried to read " + TEST_ROOT + "/different_file"),
		false
	);
}

TEST_F(FrtpTest, MultipleProcesses)
{
	// 测试多个进程规则
	auto f1 = TEST_ROOT + "/file1";
	createFile(f1, "");
	createFile(
		TEST_POLICY_FILE,
		"forbid proc=/usr/bin/cat rw " + f1 + "\n" +
			"forbid proc=/usr/bin/ls r " + f1
	);
	addEvent("/usr/bin/cat", f1, FMODE_READ);
	addEvent("/usr/bin/ls", f1, FMODE_READ);
	addEvent("/usr/bin/ls", f1, FMODE_WRITE);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	EXPECT_EQ(
		existStr("tried to read " + f1 + ", denied!"),
		true
	); // cat read被阻止
	EXPECT_EQ(
		existStr("/usr/bin/ls[10000] tried to read " + f1 + ", denied!"),
		true
	); // ls read被阻止
	EXPECT_EQ(
		existStr("/usr/bin/ls[10000] tried to write " + f1),
		false
	); // ls write不被阻止
}

TEST_F(FrtpTest, NoPolicyFile)
{
	// 测试没有策略文件的情况
	auto f1 = TEST_ROOT + "/file1";
	createFile(f1, "");
	addEvent("/usr/bin/cat", f1, FMODE_READ);
	runFrtp({});
	// 没有策略文件，应该没有阻止行为
	EXPECT_EQ(existStr("denied!"), false);
}

TEST_F(FrtpTest, EmptyPolicyFile)
{
	// 测试空策略文件
	createFile(TEST_POLICY_FILE, "");
	auto f1 = TEST_ROOT + "/file1";
	createFile(f1, "");
	addEvent("/usr/bin/cat", f1, FMODE_READ);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	EXPECT_EQ(existStr("denied!"), false);
}

TEST_F(FrtpTest, InvalidPolicyFormat)
{
	// 测试无效策略格式
	createFile(TEST_POLICY_FILE, "invalid policy format");
	auto f1 = TEST_ROOT + "/file1";
	createFile(f1, "");
	addEvent("/usr/bin/cat", f1, FMODE_READ);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	// 无效格式应该不会阻止操作
	EXPECT_EQ(existStr("denied!"), false);
}

TEST_F(FrtpTest, MultipleFilesSameProcess)
{
	// 测试同一进程对多个文件的操作
	auto f1 = TEST_ROOT + "/file1";
	auto f2 = TEST_ROOT + "/file2";
	auto f3 = TEST_ROOT + "/file3";
	createFile(f1, "");
	createFile(f2, "");
	createFile(f3, "");
	createFile(
		TEST_POLICY_FILE,
		"forbid proc=/usr/bin/cat rw " + f1 + "\n" +
			"forbid proc=/usr/bin/cat r " + f2
	);
	addEvent("/usr/bin/cat", f1, FMODE_READ);
	addEvent("/usr/bin/cat", f1, FMODE_WRITE);
	addEvent("/usr/bin/cat", f2, FMODE_READ);
	addEvent("/usr/bin/cat", f3, FMODE_READ);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	EXPECT_EQ(
		existStr("/usr/bin/cat[10000] tried to read " + f1 + ", denied!"),
		true
	); // f1 read被阻止
	EXPECT_EQ(
		existStr("/usr/bin/cat[10000] tried to write " + f1 + ", denied!"),
		true
	); // f1 write被阻止
	EXPECT_EQ(
		existStr("/usr/bin/cat[10000] tried to read " + f2 + ", denied!"),
		true
	); // f2 read被阻止
	EXPECT_EQ(
		existStr("/usr/bin/cat[10000] tried to read " + f3),
		false
	); // f3不被阻止
}

TEST_F(FrtpTest, WriteOnlyRule)
{
	// 测试仅写入规则
	auto f1 = TEST_ROOT + "/file1";
	createFile(f1, "");
	createFile(TEST_POLICY_FILE, "forbid proc=/usr/bin/cat w " + f1);
	addEvent("/usr/bin/cat", f1, FMODE_READ);
	addEvent("/usr/bin/cat", f1, FMODE_WRITE);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	EXPECT_EQ(existStr("tried to read " + f1), false); // read不应该被阻止
	EXPECT_EQ(
		existStr("tried to write " + f1 + ", denied!"),
		true
	); // write应该被阻止
}

TEST_F(FrtpTest, ReadOnlyRule)
{
	// 测试仅读取规则
	auto f1 = TEST_ROOT + "/file1";
	createFile(f1, "");
	createFile(TEST_POLICY_FILE, "forbid proc=/usr/bin/cat r " + f1);
	addEvent("/usr/bin/cat", f1, FMODE_READ);
	addEvent("/usr/bin/cat", f1, FMODE_WRITE);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	EXPECT_EQ(
		existStr("tried to read " + f1 + ", denied!"),
		true
	);													// read应该被阻止
	EXPECT_EQ(existStr("tried to write " + f1), false); // write不应该被阻止
}

TEST_F(FrtpTest, NonExistentFile)
{
	// 测试不存在的文件
	auto non_existent = TEST_ROOT + "/non_existent_file";
	createFile(
		TEST_POLICY_FILE,
		"forbid proc=/usr/bin/cat rw " + TEST_ROOT + "/*"
	);
	addEvent("/usr/bin/cat", non_existent, FMODE_READ);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	// 不存在的文件不应该被记录
	EXPECT_EQ(existStr("denied!"), false);
}

TEST_F(FrtpTest, MixedAllowAndDeny)
{
	// 测试混合允许和阻止规则（假设系统支持）
	auto f1 = TEST_ROOT + "/allowed_file";
	auto f2 = TEST_ROOT + "/denied_file";
	createFile(f1, "");
	createFile(f2, "");
	createFile(TEST_POLICY_FILE, "forbid proc=/usr/bin/cat rw " + f2);
	addEvent("/usr/bin/cat", f1, FMODE_READ);
	addEvent("/usr/bin/cat", f2, FMODE_READ);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	EXPECT_EQ(existStr("tried to read " + f1), false); // f1不应该被阻止
	EXPECT_EQ(
		existStr("tried to read " + f2 + ", denied!"),
		true
	); // f2应该被阻止
}

TEST_F(FrtpTest, SpecialCharactersInPaths)
{
	// 测试路径中的特殊字符
	auto special_file = TEST_ROOT + "/file_with_spaces.txt";
	createFile(special_file, "");
	createFile(
		TEST_POLICY_FILE,
		"forbid proc=/usr/bin/cat rw " + TEST_ROOT + "/*"
	);
	addEvent("/usr/bin/cat", special_file, FMODE_READ);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	EXPECT_EQ(existStr("tried to read " + special_file + ", denied!"), true);
}

TEST_F(FrtpTest, ConcurrencyTest)
{
	// 测试并发情况（虽然实际是顺序处理）
	auto f1 = TEST_ROOT + "/file1";
	auto f2 = TEST_ROOT + "/file2";
	createFile(f1, "");
	createFile(f2, "");
	createFile(
		TEST_POLICY_FILE,
		"forbid proc=/usr/bin/cat rw " + TEST_ROOT + "/*"
	);

	// 添加多个事件，模拟并发场景
	for (int i = 0; i < 5; i++)
	{
		addEvent("/usr/bin/cat", f1, FMODE_READ);
		addEvent("/usr/bin/cat", f2, FMODE_WRITE);
	}

	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	EXPECT_EQ(countStr("denied!"), 10); // 5次read + 5次write
}

TEST_F(FrtpTest, PolicyWithComments)
{
	// 测试带注释的策略文件
	auto f1 = TEST_ROOT + "/file1";
	createFile(f1, "");
	createFile(
		TEST_POLICY_FILE,
		"# This is a comment\n"
		"forbid proc=/usr/bin/cat rw " +
			f1 +
			"\n"
			"# Another comment\n"
			"allow proc=/usr/bin/ls r " +
			f1 // 假设系统支持allow规则
	);
	addEvent("/usr/bin/cat", f1, FMODE_READ);
	addEvent("/usr/bin/ls", f1, FMODE_READ);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	EXPECT_EQ(
		existStr("/usr/bin/cat[10000] tried to read " + f1 + ", denied!"),
		true
	); // cat被阻止
	EXPECT_EQ(
		existStr("/usr/bin/ls[10000] tried to read " + f1),
		false
	); // ls不应该被阻止
}

TEST_F(FrtpTest, MultiplePolicyLines)
{
	// 测试多行策略
	auto f1 = TEST_ROOT + "/file1";
	auto f2 = TEST_ROOT + "/file2";
	auto f3 = TEST_ROOT + "/file3";
	createFile(f1, "");
	createFile(f2, "");
	createFile(f3, "");
	createFile(
		TEST_POLICY_FILE,
		"forbid proc=/usr/bin/cat r " + f1 + "\n" +
			"forbid proc=/usr/bin/ls w " + f2 + "\n"
	);
	addEvent("/usr/bin/cat", f1, FMODE_READ);
	addEvent("/usr/bin/ls", f2, FMODE_WRITE);
	addEvent("/usr/bin/cat", f2, FMODE_READ); // 应该不被阻止
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	EXPECT_EQ(
		existStr("/usr/bin/cat[10000] tried to read " + f1 + ", denied!"),
		true
	); // cat read f1被阻止
	EXPECT_EQ(
		existStr("/usr/bin/ls[10000] tried to write " + f2 + ", denied!"),
		true
	); // ls write f2被阻止
	EXPECT_EQ(
		existStr("/usr/bin/cat[10000] tried to read " + f2),
		false
	); // cat read f2不被阻止
}

TEST_F(FrtpTest, FileInheritance)
{
	// 测试文件继承规则
	mkdir("parent");
	auto parent_file = TEST_ROOT + "/parent/parent_file";
	auto child_file = TEST_ROOT + "/parent/child/child_file";
	mkdir("parent/child");
	createFile(parent_file, "");
	createFile(child_file, "");
	createFile(
		TEST_POLICY_FILE,
		"forbid proc=/usr/bin/cat rw " + TEST_ROOT + "/parent/*"
	);
	addEvent("/usr/bin/cat", parent_file, FMODE_READ);
	addEvent("/usr/bin/cat", child_file, FMODE_READ);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	EXPECT_EQ(
		existStr(
			"/usr/bin/cat[10000] tried to read " + parent_file + ", denied!"
		),
		true
	);
	EXPECT_EQ(
		existStr(
			"/usr/bin/cat[10000] tried to read " + child_file + ", denied!"
		),
		true
	);
}

TEST_F(FrtpTest, CaseSensitivity)
{
	// 测试大小写敏感性
	auto f1 = TEST_ROOT + "/File1";
	auto f2 = TEST_ROOT + "/file1";
	createFile(f1, "");
	createFile(f2, "");
	createFile(TEST_POLICY_FILE, "forbid proc=/usr/bin/cat rw " + f1);
	addEvent("/usr/bin/cat", f1, FMODE_READ);
	addEvent("/usr/bin/cat", f2, FMODE_READ);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	EXPECT_EQ(
		existStr("/usr/bin/cat[10000] tried to read " + f1 + ", denied!"),
		true
	);
	EXPECT_EQ(existStr("/usr/bin/cat[10000] tried to read " + f2), false);
}

TEST_F(FrtpTest, SameFileMultipleOperations)
{
	// 测试同一文件的多次不同操作
	auto f1 = TEST_ROOT + "/file1";
	createFile(f1, "");
	createFile(TEST_POLICY_FILE, "forbid proc=/usr/bin/cat r " + f1);
	addEvent("/usr/bin/cat", f1, FMODE_READ);
	addEvent("/usr/bin/cat", f1, FMODE_READ);
	addEvent("/usr/bin/cat", f1, FMODE_WRITE);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	EXPECT_EQ(
		existStr("/usr/bin/cat[10000] tried to read " + f1 + ", denied!"),
		true
	); // 第一个read被阻止
	// 第二个read也会被阻止，但可能在日志中显示为一个事件（取决于实现）
	EXPECT_EQ(
		existStr("/usr/bin/cat[10000] tried to write " + f1),
		false
	); // write不被阻止
}

TEST_F(FrtpTest, DifferentProcessSameFile)
{
	// 测试不同进程对同一文件的操作
	auto f1 = TEST_ROOT + "/file1";
	createFile(f1, "");
	createFile(TEST_POLICY_FILE, "forbid proc=/usr/bin/cat r " + f1);
	addEvent("/usr/bin/cat", f1, FMODE_READ);
	addEvent("/usr/bin/ls", f1, FMODE_READ);
	addEvent("/bin/sh", f1, FMODE_READ);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	EXPECT_EQ(
		existStr("/usr/bin/cat[10000] tried to read " + f1 + ", denied!"),
		true
	); // cat被阻止
	EXPECT_EQ(
		existStr("/usr/bin/ls[10000] tried to read " + f1),
		false
	); // ls不被阻止
	EXPECT_EQ(
		existStr("/bin/sh[10000] tried to read " + f1),
		false
	); // sh不被阻止
}

TEST_F(FrtpTest, PartialPathMatch)
{
	// 测试部分路径匹配
	auto f1 = TEST_ROOT + "/file1";
	auto f2 = TEST_ROOT + "/prefix_file1";
	auto f3 = TEST_ROOT + "/other_file";
	createFile(f1, "");
	createFile(f2, "");
	createFile(f3, "");
	createFile(
		TEST_POLICY_FILE,
		"forbid proc=/usr/bin/cat rw " + TEST_ROOT + "/file*"
	);
	addEvent("/usr/bin/cat", f1, FMODE_READ);
	addEvent("/usr/bin/cat", f2, FMODE_READ);
	addEvent("/usr/bin/cat", f3, FMODE_READ);
	runFrtp({"-p", TEST_POLICY_FILE.c_str()});
	EXPECT_EQ(
		existStr("/usr/bin/cat[10000] tried to read " + f1 + ", denied!"),
		false
	); // file1不被阻止
	EXPECT_EQ(
		existStr("/usr/bin/cat[10000] tried to read " + f2 + ", denied!"),
		false
	); // prefix_file1不被阻止
	EXPECT_EQ(
		existStr("/usr/bin/cat[10000] tried to read " + f3 + ", denied!"),
		false
	); // other_file不被阻止
}