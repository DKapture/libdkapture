// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <string>
#include <memory>
#include <future>
#include <mutex>
#include <condition_variable>
#include <map>
#include <climits>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "pagefault.skel.h"
#include "com.h"

static volatile bool exiting = false;
static pagefault_bpf *obj = NULL;
static struct ring_buffer *rb = NULL;
#define PAGEFAULT_STACK_DEPTH 127

#ifdef BUILTIN
#define PAGEFAULT_STACK_MAX_ENTRIES 1000
struct PagefaultFds
{
	int filter_fd;
	int events_fd;
	int stack_traces_fd;
};
struct PagefaultSync
{
	std::mutex m;
	std::condition_variable cv;
	bool init_done = false;
	bool exit_requested = false;
};
struct PagefaultRuntime
{
	PagefaultSync sync;
	std::promise<PagefaultFds> fds_promise;
	volatile bool *exit_flag = nullptr;
	std::mutex consume_m;
	std::condition_variable consume_cv;
	size_t consumed = 0;
};
static FILE *stdout_bak;
static std::map<std::string, std::tuple<int, int, int, bpf_map_type>>
local_map_info = {
	{"events", {0, 1, 1024 * 256, BPF_MAP_TYPE_RINGBUF}},
	{"filter", {sizeof(int), sizeof(pid_t), 1, BPF_MAP_TYPE_ARRAY}},
	{"stack_traces",
	 {sizeof(__u32),
	  PAGEFAULT_STACK_DEPTH * (int)sizeof(__u64),
	  PAGEFAULT_STACK_MAX_ENTRIES,
	  BPF_MAP_TYPE_STACK_TRACE}},
};
static std::shared_ptr<PagefaultRuntime> runtime_state;
extern std::string test_name;
extern std::map<std::string, std::tuple<int, int, int, bpf_map_type>> *map_info;
#endif

struct page_fault_t
{
	pid_t pid;
	pid_t tid;
	char comm[16];
	int stack_id;
	__u64 timestamp;
	unsigned long address;
	unsigned long ip;
	unsigned long error_code;
};

static void sig_handler(int signo)
{
	exiting = true;
}

static void usage(const char *prog)
{
	printf("Usage: %s [OPTIONS]\n", prog);
	printf("Options:\n");
	printf("  -p, --pid <pid>         只跟踪指定进程的pagefault\n");
	printf("  -u, --user              只跟踪用户态pagefault\n");
	printf("  -k, --kernel            只跟踪内核态pagefault\n");
	printf("  -s, --stack             显示用户态堆栈信息\n");
	printf("  -t, --timestamp         显示时间戳\n");
	printf("  -h, --help              显示帮助信息\n");
}

struct env_t
{
	pid_t pid;
	bool user;
	bool kernel;
	bool show_stack;
	bool show_ts;
}; 
static struct env_t env = {};

static int print_stack(struct pagefault_bpf *skel, int stack_id)
{
	if (stack_id < 0)
	{
		return 0;
	}
	int n = 0;
	char sym[256];
	__u64 ips[PAGEFAULT_STACK_DEPTH] = {};
	int fd = bpf_map__fd(skel->maps.stack_traces);
	n = bpf_map_lookup_elem(fd, &stack_id, ips);
	if (n < 0)
	{
		printf("    [Failed to get stack trace]\n");
		return 0;
	}
	printf("    User stack:\n");
	for (int i = 0; i < PAGEFAULT_STACK_DEPTH && ips[i]; i++)
	{
		snprintf(
			sym,
			sizeof(sym),
			"        0x%llx",
			(unsigned long long)ips[i]
		);
		printf("%s\n", sym);
	}
	return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	if (data_sz < sizeof(struct page_fault_t))
	{
		return 0;
	}
	const struct page_fault_t *e = (const struct page_fault_t *)data;
	if (env.pid && e->pid != env.pid)
	{
		return 0;
	}
	printf(
		"PID:%d TID:%d COMM:%s ADDR:0x%lx IP:0x%lx ERR:0x%lx",
		e->pid,
		e->tid,
		e->comm,
		e->address,
		e->ip,
		e->error_code
	);
	if (env.show_ts)
	{
		printf(" TS:%llu", e->timestamp);
	}
	printf("\n");
	if (env.show_stack)
	{
		print_stack((struct pagefault_bpf *)ctx, e->stack_id);
	}
#ifdef BUILTIN
	if (runtime_state)
	{
		std::lock_guard<std::mutex> lock(runtime_state->consume_m);
		runtime_state->consumed++;
		runtime_state->consume_cv.notify_all();
	}
#endif
	return 0;
}

#ifdef BUILTIN
std::shared_ptr<PagefaultRuntime> pagefault_init(FILE *output)
{
	test_name = "pagefault";
	map_info = &local_map_info;
	runtime_state = std::make_shared<PagefaultRuntime>();
	runtime_state->exit_flag = &exiting;
	runtime_state->consumed = 0;
	exiting = false;
	obj = NULL;
	rb = NULL;
	env = {};
	stdout_bak = stdout;
	fflush(stdout);
	stdout = output;
	Log::set_file(output);
	{
		std::lock_guard<std::mutex> lock(runtime_state->sync.m);
		runtime_state->sync.init_done = false;
		runtime_state->sync.exit_requested = false;
	}
	return runtime_state;
}

void pagefault_deinit()
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
int pagefault_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
{
	struct pagefault_bpf *skel = NULL;
	int err = 0, opt;
	int filter_fd, events_fd, stack_traces_fd;
	static const struct option long_options[] = {
		{"pid",		required_argument, 0, 'p'},
		{"user",		 no_argument,		  0, 'u'},
		{"kernel",	   no_argument,		0, 'k'},
		{"stack",	  no_argument,	   0, 's'},
		{"timestamp", no_argument,	   0, 't'},
		{"help",		 no_argument,		  0, 'h'},
		{0,			0,				 0, 0  }
	};

	optind = 0;
	opterr = 0;
	while ((opt = getopt_long(argc, argv, "p:uksth", long_options, NULL)) != -1)
	{
		switch (opt)
		{
		case 'p':
		{
			char *end = nullptr;
			errno = 0;
			long val = strtol(optarg, &end, 10);
			if (end == optarg || *end != '\0' || errno == ERANGE || val <= 0 || val > INT_MAX)
			{
				printf("wrong pid value: %s, must be a positive integer\n", optarg);
#ifndef BUILTIN
				exit(-1);
#else
				return -1;
#endif
			}
			env.pid = (pid_t)val;
			break;
		}
		case 'u':
			env.user = true;
			break;
		case 'k':
			env.kernel = true;
			break;
		case 's':
			env.show_stack = true;
			break;
		case 't':
			env.show_ts = true;
			break;
		case 'h':
		default:
			usage(argv[0]);
#ifdef BUILTIN
			if (runtime_state)
			{
				{
					std::lock_guard<std::mutex> lock(runtime_state->sync.m);
					runtime_state->sync.exit_requested = true;
				}
				runtime_state->sync.cv.notify_all();
			}
#endif
			return -1;
		}
	}

	if (!env.user && !env.kernel)
	{
		env.user = env.kernel = true;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
	setrlimit(RLIMIT_MEMLOCK, &rlim);

	skel = pagefault_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return -1;
	}
	obj = skel;

	int key = 0;
	// 过滤pid
	filter_fd = bpf_map__fd(skel->maps.filter);
	if (filter_fd < 0)
	{
		fprintf(stderr, "Failed to get filter map fd: %d\n", filter_fd);
		err = filter_fd;
		goto cleanup;
	}

	if (env.pid)
	{
		err = bpf_map_update_elem(filter_fd, &key, &env.pid, BPF_ANY);
        if (err)
        {
			fprintf(stderr, "Failed to update filter map: %d\n", err);
			goto cleanup;
        }
	}

	if (!env.user)
	{
		skel->links.page_fault_user = NULL;
	}
	if (!env.kernel)
	{
		skel->links.page_fault_kernel = NULL;
	}

	err = pagefault_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}
	err = pagefault_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	events_fd = bpf_map__fd(skel->maps.events);
	stack_traces_fd = bpf_map__fd(skel->maps.stack_traces);
#ifdef BUILTIN
	runtime_state->fds_promise.set_value(
		PagefaultFds{filter_fd, events_fd, stack_traces_fd}
	);
#endif
	rb = ring_buffer__new(
		events_fd,
		handle_event,
		skel,
		NULL
	);
	if (!rb)
	{
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

#ifdef BUILTIN
	{
		std::lock_guard<std::mutex> lock(runtime_state->sync.m);
		runtime_state->sync.init_done = true;
	}
	runtime_state->sync.cv.notify_all();
	{
		std::unique_lock<std::mutex> lock(runtime_state->sync.m);
		while (!runtime_state->sync.exit_requested && !exiting)
		{
			lock.unlock();
			err = ring_buffer__poll(rb, 100);
			if (err == -EINTR)
			{
				break;
			}
			if (err < 0)
			{
				fprintf(stderr, "Error polling ring buffer: %d\n", err);
				break;
			}
			lock.lock();
		}
	}
#else
	printf("Tracing page faults... Hit Ctrl-C to exit.\n");
	while (!exiting)
	{
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR)
		{
			break;
		}
		if (err < 0)
		{
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}
#endif

cleanup:
	if (rb)
	{
		ring_buffer__free(rb);
	}
	pagefault_bpf__destroy(skel);
	return err < 0 ? 1 : 0;
}
