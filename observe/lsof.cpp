// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <stdio.h>
#include <assert.h>
#include <errno.h>
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
#include <memory>
#include <future>
#include <mutex>
#include <condition_variable>
#include <pthread.h>
#include <map>
#include <sys/sysmacros.h> // 添加这个头文件用于设备号操作

#include "lsof.skel.h"
#include "com.h"
#include "jhash.h"

#define PATH_MAX 4096

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
static ring_buffer *rb = NULL;
static int filter_fd;
static pthread_t t1;
static int iter_fd;
static std::atomic<bool> exit_flag(false);
static std::map<pid_t, std::vector<struct BpfData>> log_stat;
#ifdef BUILTIN
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
static FILE *stdout_bak;
static std::map<std::string, std::tuple<int, int, int, bpf_map_type>> 
local_map_info = {
	{"filter", {sizeof(unsigned int), sizeof(union Rule), 1, BPF_MAP_TYPE_HASH}},
	{"logs", {0, 1, 256 * 1024, BPF_MAP_TYPE_RINGBUF}},
};
static std::shared_ptr<LsofRuntime> runtime_state;
extern std::string test_name;
extern std::map<std::string,std::tuple<int, int, int, bpf_map_type>> *map_info;
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

static void Usage(const char *arg0)
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
}

static std::string long_opt2short_opt(const option lopts[])
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

static int parse_args(int argc, char *args[])
{
	int opt, opt_idx;
	int optbits = 0;
	optind = 0;
	opterr = 0;
	std::string sopts = long_opt2short_opt(lopts);
	while ((opt = getopt_long(argc, args, sopts.c_str(), lopts, &opt_idx)) > 0)
	{
		switch (opt)
		{
		case 'p':
			if (!optarg || optarg[0] == '\0')
			{
				printf("error: -p requires a non-empty path\n");
#ifndef BUILTIN
				exit(-1);
#else
				return -1;
#endif
			}
			strncpy(rule.path, optarg, sizeof(rule.path));
			rule.path[sizeof(rule.path) - 1] = 0;
			optbits |= 1;
			break;
		case 'd':
		{
			char *end = NULL;
			unsigned long long val;
			errno = 0;
			val = strtoull(optarg, &end, 10);
			if (!optarg || end == optarg || *end != '\0' || errno == ERANGE)
			{
				printf("error: invalid dev value: %s\n", optarg ? optarg : "(null)");
#ifndef BUILTIN
				exit(-1);
#else
				return -1;
#endif
			}
			rule.dev = (dev_t)val; // 直接解析设备号
			rule.not_inode = 0;
			optbits |= 1 << 1;
			break;
		}
		case 'i':
		{
			char *end = NULL;
			unsigned long long val;
			errno = 0;
			val = strtoull(optarg, &end, 10);
			if (!optarg || end == optarg || *end != '\0' || errno == ERANGE)
			{
				printf("error: invalid inode value: %s\n", optarg ? optarg : "(null)");
#ifndef BUILTIN
				exit(-1);
#else
				return -1;
#endif
			}
			rule.inode = val;
			rule.not_inode = 0;
			optbits |= 1 << 2;
			break;
		}
		case 'h':
			Usage(args[0]);
#ifndef BUILTIN
			exit(0);
#else
			return 0;
#endif
			break;
		default:
			Usage(args[0]);
#ifndef BUILTIN
			exit(-1);
#else
			return -1;
#endif
			break;
		}
	}

	if ((optbits & 1) && (optbits & ((1 << 1) | (1 << 2))))
	{
		printf("error: -p can't be used together with -d/-i\n");
#ifndef BUILTIN
			exit(-1);
#else
			return -1;
#endif
	}

	if (!!(optbits & 2) ^ !!(optbits & 4))
	{
		printf("error: -d and -i must be used together\n"); // 更新错误信息
#ifndef BUILTIN
			exit(-1);
#else
			return -1;
#endif
	}
	return 0; 
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	if (data_sz < sizeof(struct BpfData)) 
	{
		return 0;
	}
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
		if (logs.empty())
		{
			continue;
		}
		
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
}

static void *ringbuf_worker(void *)
{
	while (!exit_flag)
	{
#ifdef BUILTIN
		int err = ring_buffer__poll(rb, 50 /* timeout in ms */);
#else
		int err = ring_buffer__poll(rb, 100 /* timeout in ms */);
#endif

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

static int register_signal()
{
	struct sigaction sa;
	sa.sa_handler = [](int) { exit_flag = true; };
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		perror("sigaction");
#ifndef BUILTIN
		exit(EXIT_FAILURE);
#else
		return -1;
#endif
	}
	return 0;
}
#ifdef BUILTIN
std::shared_ptr<LsofRuntime> lsof_init(FILE *output)
{
	test_name = "lsof";           // Register tool name
  	map_info = &local_map_info;      // Register map definitions
	runtime_state = std::make_shared<LsofRuntime>();
	runtime_state->exit_flag = &exit_flag;
  	exit_flag = false;               // Reset exit state
  	rb = NULL;                       // Reset ring buffer
	iter_fd = -1;                    // Reset iterator fd
  	memset(&rule, 0, sizeof(rule));  // Reset rule filter
	log_stat.clear();                // Reset collected logs
  	stdout_bak = stdout;             // Backup stdout
  	fflush(stdout);                  // Flush stdout
  	stdout = output;                 // Redirect stdout
  	Log::set_file(output);           // Redirect logs
	{
		std::lock_guard<std::mutex> lock(runtime_state->sync.m);
		runtime_state->sync.init_done = false;
		runtime_state->sync.exit_requested = false;
	}
	return runtime_state;
}
void lsof_deinit()
{
	test_name = "";
	map_info = NULL;
	runtime_state.reset();
	fflush(stdout);
	stdout = stdout_bak;
	Log::set_file(stderr);
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

	int ret = parse_args(argc, args); // Parse command line arguments
	if (ret != 0)
	{
#ifdef BUILTIN
		{
			std::lock_guard<std::mutex> lock(runtime_state->sync.m);
			runtime_state->sync.exit_requested = true;
		}
		runtime_state->sync.cv.notify_all();
#endif
		return ret;
	}
	ret = register_signal(); // Register signal handler
	if(ret < 0){
		return ret;
	}

	int key = 0;
	obj = lsof_bpf::open_and_load();
	if (!obj)
	{
#ifndef BUILTIN
		exit(-1); // Exit if opening failed
#else
		ret = -1;
		goto err_out;
#endif
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
#ifdef BUILTIN
	runtime_state->fds_promise.set_value(LsofFds{filter_fd, log_map_fd});
#endif
	rb = ring_buffer__new(log_map_fd, handle_event, NULL, NULL);
	if (!rb)
	{
		ret = -1;
		goto err_out;
	}

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

	printf("Scanning for file %s...\n", rule.path);
	pthread_create(&t1, NULL, ringbuf_worker, NULL);
#ifndef BUILTIN
	follow_trace_pipe();
#else
	{
		std::lock_guard<std::mutex> lock(runtime_state->sync.m);
		runtime_state->sync.init_done = true;
	}
	runtime_state->sync.cv.notify_all();
	{
		std::unique_lock<std::mutex> lock(runtime_state->sync.m);
		runtime_state->sync.cv.wait(lock, [&] { return runtime_state->sync.exit_requested; });
	}
#endif
	pthread_join(t1, NULL);
	summary_print();
err_out:
	if (rb)
	{
		ring_buffer__free(rb);
	}
	lsof_bpf::detach(obj);
	lsof_bpf::destroy(obj);
	return ret;
}
