// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
#include <limits.h>
#include <getopt.h>
#include <string>
#include <signal.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <algorithm>
#include <pthread.h>
#include <map>
#include <sys/sysmacros.h> // 添加这个头文件用于设备号操作
#ifdef BUILTIN
#include <deque>
#include <mutex>
#endif

#include "lsof.skel.h"
#include "com.h"
#include "jhash.h"

#define PATH_MAX 4096

#ifdef BUILTIN
#define BUILTIN_LOCAL static
#define BUILTIN_FLUSH_STDOUT() fflush(stdout)
#else
#define BUILTIN_LOCAL
#define BUILTIN_FLUSH_STDOUT() do {} while (0)
#endif

// 添加设备号转换函数，参考frtp
static inline uint32_t dev_old2new(dev_t old)
{
	uint32_t major = gnu_dev_major(old);
	uint32_t minor = gnu_dev_minor(old);
	return ((major & 0xfff) << 20) | (minor & 0xfffff);
}

union Rule
{
	char path[PATH_MAX];
	struct
	{
		u64 not_inode; // used for judging whether it's inode filter
		u64 inode;
		dev_t dev; // 设备号
	};
};
static union Rule rule;

struct BpfData
{
	uid_t uid;
	pid_t pid;
	int fd;
	char comm[16];
};

static lsof_bpf *obj;
static int log_map_fd;
BUILTIN_LOCAL struct ring_buffer *rb = NULL;
static int filter_fd;
static pthread_t t1;
static int iter_fd;
static std::atomic<bool> exit_flag(false);
static std::map<pid_t, std::vector<struct BpfData>> log_stat;

#ifdef BUILTIN
struct LsofBuiltinEvent
{
	struct BpfData log;
	char path[PATH_MAX];
	dev_t dev;
	u64 inode;
};
static FILE *stdout_bak;
static std::atomic<int> *condition;
static std::mutex builtin_event_mu;
static std::deque<LsofBuiltinEvent> builtin_events;
static std::map<std::string, std::tuple<int, int, int, bpf_map_type>>
	local_map_info = {
		{"filter", {sizeof(uint32_t), sizeof(rule), 1, BPF_MAP_TYPE_HASH}},
		{"logs", {0, 1, 256 * 1024, BPF_MAP_TYPE_RINGBUF}},
	};
extern std::string test_name;
extern std::map<std::string, std::tuple<int, int, int, bpf_map_type>> *map_info;
#endif

static struct option lopts[] = {
	{"path",	 required_argument, 0, 'p'},
	{"dev",	required_argument, 0, 'd'},
	{"inode", required_argument, 0, 'i'},
	{"help",	 no_argument,		  0, 'h'},
	{0,		0,				 0, 0  }
};

struct HelpMsg
{
	const char *argparam;
	const char *msg;
};

static HelpMsg help_msg[] = {
	{"[path]",  "path of the file to watch on\n"					   },
	{"[dev]",
	 "the device number of filesystem to which the inode belong.\n"
	 "\tyou can get the dev by running command 'stat -c %d <file>'\n"
	}, // 更新帮助信息
	{"[inode]", "inode of the file to watch on\n"					 },
	{"",		 "print this help message\n"							},
};

BUILTIN_LOCAL void Usage(const char *arg0)
{
	printf("Usage: %s [option]\n", arg0);
	printf("  To query who are occupying the specified file.\n\n");
	printf("Options:\n");
	for (int i = 0; lopts[i].name; i++)
	{
		printf(
			"  -%c, --%s %s\n\t%s\n",
			lopts[i].val,
			lopts[i].name,
			help_msg[i].argparam,
			help_msg[i].msg
		);
	}
	BUILTIN_FLUSH_STDOUT();
}

BUILTIN_LOCAL std::string long_opt2short_opt(const option lopts[])
{
	std::string sopts = "";
	for (int i = 0; lopts[i].name; i++)
	{
		sopts += lopts[i].val;
		switch (lopts[i].has_arg)
		{
		case no_argument:
			break;
		case required_argument:
			sopts += ":";
			break;
		case optional_argument:
			sopts += "::";
			break;
		default:
			DIE("Code internal bug!!!\n");
			abort();
		}
	}
	return sopts;
}

BUILTIN_LOCAL int parse_args(int argc, char *args[])
{
	int opt, opt_idx;
	int optbits = 0;
#ifdef BUILTIN
	optind = 0;
	opterr = 0;
#else
	optind = 1;
#endif
	std::string sopts = long_opt2short_opt(lopts);
	while ((opt = getopt_long(argc, args, sopts.c_str(), lopts, &opt_idx)) > 0)
	{
		switch (opt)
		{
		case 'p':
			strncpy(rule.path, optarg, sizeof(rule.path));
			rule.path[sizeof(rule.path) - 1] = 0;
			optbits |= 1;
			break;
		case 'd':
			rule.dev = strtoul(optarg, NULL, 10); // 直接解析设备号
			rule.not_inode = 0;
			optbits |= 1 << 1;
			break;
		case 'i':
			rule.inode = atoi(optarg);
			rule.not_inode = 0;
			optbits |= 1 << 2;
			break;
		case 'h':
			Usage(args[0]);
			return 1;
		default:
			Usage(args[0]);
			return -1;
		}
	}

	if ((optbits & 1) && (optbits & 4))
	{
		printf("error: -p and -i can't be used together\n");
		BUILTIN_FLUSH_STDOUT();
		return -1;
	}

	if (!!(optbits & 2) ^ !!(optbits & 4))
	{
		printf("error: -d and -i must be used together\n"); // 更新错误信息
		BUILTIN_FLUSH_STDOUT();
		return -1;
	}
	return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct BpfData *log = (const struct BpfData *)data;
	u64 key = log->pid;
	log_stat[key].push_back(*log);
	return 0;
}

static void summary_print(void)
{
	printf("%16s %6s %8s   %s\n", "COMM", "UID", "PID", "FD");
	printf("--------------------------------------------\n");
	for (auto &it : log_stat)
	{
		std::vector<struct BpfData> &logs = it.second;
		pid_t pid = it.first;
		uid_t uid = logs[0].uid;
		char *comm = logs[0].comm;
		printf("%16s %6d %8d   ", comm, uid, pid);
		size_t vma_cnt = 0;
		for (auto &log : logs)
		{
			if (log.fd == -1)
			{
				vma_cnt++;
			}
			else
			{
				printf("%d ", log.fd);
			}
		}
		if (vma_cnt)
		{
			printf("vma(%ld)\n", vma_cnt);
		}
		else
		{
			printf("\n");
		}
	}
	printf("\n");
	BUILTIN_FLUSH_STDOUT();
}

BUILTIN_LOCAL void *ringbuf_worker(void *)
{
	while (!exit_flag)
	{
		int err = ring_buffer__poll(rb, 100 /* timeout in ms */);

		if (err < 0 && err != -EINTR)
		{
			pr_error("Error polling ring buffer: %d\n", err);
			sleep(5);
		}

		if (err == 0 && iter_fd == -1)
		{
			break;
		}
	}
	stop_trace();
	kill(getpid(), SIGINT);
	return NULL;
}

BUILTIN_LOCAL void register_signal()
{
	struct sigaction sa;
	sa.sa_handler = [](int) { exit_flag = true; };
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		perror("sigaction");
		exit(EXIT_FAILURE);
	}
}

#ifdef BUILTIN
void lsof_init(FILE *output, std::atomic<int> *conditionp, std::atomic<bool> **exit_flagp)
{
	test_name = "lsof";
	map_info = &local_map_info;
	condition = conditionp;
	*exit_flagp = &exit_flag;
	obj = nullptr;
	rb = nullptr;
	filter_fd = -1;
	log_map_fd = -1;
	iter_fd = -1;
	exit_flag = false;
	memset(&rule, 0, sizeof(rule));
	log_stat.clear();
	{
		std::lock_guard<std::mutex> lock(builtin_event_mu);
		builtin_events.clear();
	}
	stdout_bak = stdout;
	fflush(stdout);
	stdout = output;
	Log::set_file(output);
}

static void lsof_builtin_cleanup()
{
	if (rb)
	{
		ring_buffer__free(rb);
		rb = nullptr;
	}
	if (obj)
	{
		lsof_bpf::detach(obj);
		lsof_bpf::destroy(obj);
		obj = nullptr;
	}
}

void lsof_deinit()
{
	exit_flag = true;
	lsof_builtin_cleanup();
	filter_fd = -1;
	log_map_fd = -1;
	iter_fd = -1;
	log_stat.clear();
	{
		std::lock_guard<std::mutex> lock(builtin_event_mu);
		builtin_events.clear();
	}
	test_name = "";
	map_info = nullptr;
	fflush(stdout);
	stdout = stdout_bak;
	Log::set_file(stderr);
}

void lsof_get_rule_copy(void *out, size_t out_sz)
{
	if (out && out_sz >= sizeof(rule))
	{
		memcpy(out, &rule, sizeof(rule));
	}
}

int lsof_submit_builtin_event(
	const void *log,
	size_t data_sz,
	const char *path,
	dev_t dev,
	uint64_t inode
)
{
	if (!log || data_sz != sizeof(struct BpfData))
	{
		return -1;
	}

	LsofBuiltinEvent event = {};
	memcpy(&event.log, log, sizeof(event.log));
	if (path)
	{
		strncpy(event.path, path, sizeof(event.path) - 1);
		event.path[sizeof(event.path) - 1] = '\0';
	}
	event.dev = dev;
	event.inode = inode;

	std::lock_guard<std::mutex> lock(builtin_event_mu);
	builtin_events.push_back(event);
	return 0;
}

// Mirror the BPF-side file_filter() logic for BUILTIN tests.
static bool should_emit_builtin_event(const LsofBuiltinEvent &event)
{
	if (rule.not_inode)
	{
		return strncmp(event.path, rule.path, PATH_MAX) == 0;
	}
	if (rule.dev || rule.inode)
	{
		return rule.dev == event.dev && rule.inode == event.inode;
	}
	return true;
}

// Process queued synthetic events on the owning thread before summary output.
static int drain_builtin_events()
{
	std::deque<LsofBuiltinEvent> pending;
	{
		std::lock_guard<std::mutex> lock(builtin_event_mu);
		pending.swap(builtin_events);
	}

	for (const auto &event : pending)
	{
		if (!should_emit_builtin_event(event))
		{
			continue;
		}
		handle_event(nullptr, (void *)&event.log, sizeof(event.log));
	}
	return 0;
}

static bool builtin_events_empty()
{
	std::lock_guard<std::mutex> lock(builtin_event_mu);
	return builtin_events.empty();
}
#endif

#ifdef BUILTIN
int lsof_main(int argc, char *args[])
#else
int main(int argc, char *args[])
#endif
{
	ssize_t rd_sz = 0;
	char buf[PATH_MAX] = {0};
	int ret = parse_args(argc, args);

	if (ret != 0)
	{
#ifdef BUILTIN
		*condition = 2;
#endif
		return ret > 0 ? 0 : ret;
	}
#ifndef BUILTIN
	register_signal();
#endif

	int key = 0;
	obj = lsof_bpf::open_and_load();
	if (!obj)
	{
		ret = -1;
		goto err_out;
	}

	if (0 != lsof_bpf::attach(obj))
	{
		ret = -1;
		goto err_out;
	}

	filter_fd = bpf_get_map_fd(obj->obj, "filter", goto err_out);

	if (0 != bpf_map_update_elem(filter_fd, &key, &rule, BPF_ANY))
	{
		printf("Error: bpf_map_update_elem");
		ret = -1;
		goto err_out;
	}

	log_map_fd = bpf_get_map_fd(obj->obj, "logs", goto err_out);
	rb = ring_buffer__new(log_map_fd, handle_event, NULL, NULL);
	if (!rb)
	{
		ret = -1;
		goto err_out;
	}

#ifndef BUILTIN
	iter_fd = bpf_iter_create(bpf_link__fd(obj->links.file_iterator));
	if (iter_fd < 0)
	{
		fprintf(stderr, "Error creating BPF iterator\n");
		ret = -1;
		goto err_out;
	}

	while ((rd_sz = read(iter_fd, buf, sizeof(buf))) > 0)
	{
	}

	close(iter_fd);
	iter_fd = bpf_iter_create(bpf_link__fd(obj->links.vma_iterator));
	if (iter_fd < 0)
	{
		fprintf(stderr, "Error creating BPF iterator\n");
		ret = -1;
		goto err_out;
	}

	while ((rd_sz = read(iter_fd, buf, sizeof(buf))) > 0)
	{
	}

	close(iter_fd);
	iter_fd = -1;
#endif

#ifdef BUILTIN
	*condition = 1;
	while (!exit_flag || !builtin_events_empty())
	{
		if (drain_builtin_events() != 0)
		{
			ret = -1;
			break;
		}
		std::this_thread::sleep_for(std::chrono::microseconds(100));
	}
	summary_print();
	goto err_out;
#else
	printf("Scanning for file %s...\n", rule.path);
	//! TODO ringbuffer消耗不及时, 后续修复
	pthread_create(&t1, NULL, ringbuf_worker, NULL);
	follow_trace_pipe();
	pthread_join(t1, NULL);
	summary_print();
#endif

err_out:
#ifdef BUILTIN
	if (ret != 0)
	{
		*condition = 2;
	}
	lsof_builtin_cleanup();
	return ret;
#else
	if (rb)
	{
		ring_buffer__free(rb);
	}
	lsof_bpf::detach(obj);
	lsof_bpf::destroy(obj);
	return ret;
#endif
}
