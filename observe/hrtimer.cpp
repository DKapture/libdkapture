// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1-only

/**
 * ebpf 用户空间程序(loader、read ringbuffer)
 */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "hrtimer.skel.h"

struct env
{
	pid_t pid;
	bool relative_time;
	bool milliseconds;
	int targ_time;
	bool per_process;
	bool verbose;
	char *cgroupspath;
	bool cg;
} env = {};

const char *argp_program_version = "hrtimer 0.1";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/"
									   "master/libbpf-tools";
const char argp_program_doc[] =
	"modify hrtimer_nanosleep args.\n"
	"\n"
	"USAGE: hrtimer [--help] [-T] [-m] [--pidnss] [-L] [-P] [-p PID] "
	"[interval] [count] [-c CG]\n"
	"\n"
	"EXAMPLES:\n"
	"    hrtimer 1        # modify all process hrtimer_nanosleep arg timespec "
	"to 1 second\n"
	"    hrtimer -m 1     # modify all process hrtimer_nanosleep arg timespec "
	"to 1 millisecond\n"
	"    hrtimer -rm 10   # modify all process hrtimer_nanosleep args timespec "
	"add 10 milliseconds\n"
	"    hrtimer -p 185 1 # modify PID 185 hrtimer_nanosleep arg timespec to 1 "
	"second only\n"
	"    hrtimer -p 185 -rm 123 # modify PID 185 hrtimer_nanosleep arg "
	"timespec add 123 milliseconds only\n"
	"    hrtimer -c CG  1  # modify process under cgroupsPath CG "
	"hrtimer_nanosleep args timespec to 1 second only\n";

#define OPT_PIDNSS 1 /* --pidnss */

static const struct argp_option opts[] = {
	{"relative", 'r', NULL, 0, "modify timespec time relatively", 0},
	{"milliseconds", 'm', NULL, 0, "unit is millisecond ", 0},
	{"pid", 'p', "PID", 0, "modify this PID only", 0},
	{"verbose", 'v', NULL, 0, "Verbose debug output", 0},
	{"cgroup",
	 'c', "/sys/fs/cgroup/unified",
	 0, "modify process in cgroup path",
	 0},
	{NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key)
	{
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'm':
		env.milliseconds = true;
		break;
	case 'r':
		env.relative_time = true;
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		printf("env pid: %d\n", env.pid);
		if (errno)
		{
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		env.targ_time = strtol(arg, NULL, 10);
		printf("env targ_time: %d\n", env.targ_time);
		if (errno)
		{
			fprintf(stderr, "invalid internal\n");
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;
static void sig_int(int signo)
{
	stop = 1;
}

// ring buffer data process
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	printf("\n");

	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct hrtimer_bpf *skel;
	int err;
	int idx, cg_map_fd;
	int cgfd = -1;
	struct ring_buffer *rb = NULL;

	// 检查是否缺少必要参数
	if (argc < 2)
	{
		// 当不带参数运行时，输出帮助信息
		argp_help(&argp, stderr, ARGP_HELP_STD_HELP, argv[0]);
		return 1;
	}

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
	{
		return err;
	}

	/* 设置libbpf错误和调试信息回调 */
	libbpf_set_print(libbpf_print_fn);

	/* 加载并验证 hrtimer.bpf.c 应用程序 */
	skel = hrtimer_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	skel->rodata->targ_unit_ms = env.milliseconds;
	skel->rodata->targ_relative_time = env.relative_time;
	skel->rodata->targ_tgid = env.pid;
	skel->rodata->filter_cg = env.cg;
	skel->rodata->targ_time = env.targ_time;

	printf("targ_unit_ms: %d\n", skel->rodata->targ_unit_ms);
	printf("targ_time: %d\n", skel->rodata->targ_time);
	printf("targ_relative_time: %d\n", skel->rodata->targ_relative_time);

	/* 加载并验证 hrtimer.bpf.c 应用程序 */
	err = hrtimer_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}

	/* update cgroup path fd to map */
	if (env.cg)
	{
		idx = 0;
		cg_map_fd = bpf_map__fd(skel->maps.cgroup_map);
		cgfd = open(env.cgroupspath, O_RDONLY);
		if (cgfd < 0)
		{
			fprintf(stderr, "Failed opening Cgroup path: %s", env.cgroupspath);
			goto cleanup;
		}
		if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY))
		{
			fprintf(stderr, "Failed adding target cgroup to map");
			goto cleanup;
		}
	}

	/* 附加 hrtimer.bpf.c 程序到跟踪点 */
	err = hrtimer_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Control-C 停止信号 */
	if (signal(SIGINT, sig_int) == SIG_ERR)
	{
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat "
		   "/sys/kernel/debug/tracing/trace_pipe` "
		   "to see output of the BPF programs.\n");

	/* 设置环形缓冲区轮询 */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* 处理收到的内核数据 */
	while (!stop)
	{
		// 轮询内核数据
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		if (err == -EINTR)
		{ /* Ctrl-C will cause -EINTR */
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	if (rb)
	{
		ring_buffer__free(rb);
	}
	/* 销毁挂载的ebpf程序 */
	hrtimer_bpf__destroy(skel);
	return -err;
}