// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

/**
 * ebpf 用户空间程序(loader、read ringbuffer)
 */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "wakeup_count.h"
#include "wakeup_count.skel.h"

#define min(x, y)                                                              \
	({                                                                         \
		typeof(x) _min1 = (x);                                                 \
		typeof(y) _min2 = (y);                                                 \
		(void)(&_min1 == &_min2);                                              \
		_min1 < _min2 ? _min1 : _min2;                                         \
	})

struct env
{
	time_t interval;
	pid_t pid;
	bool verbose;
	char *cgroupspath;
	bool cg;
} env = {
	.interval = 99999999,
};

const char *argp_program_version = "wakeup 0.1";
const char argp_program_doc[] = "Summarize wakeup times as a histogram.\n"
								"\n"
								"USAGE: wakeup [--help] [-p PID] [-c CG]\n"
								"\n"
								"EXAMPLES:\n"
								"    wakeup         # summarize  wakeup times "
								"as a histogram\n"
								"    wakeup -p 185  # trace PID 185 only\n"
								"    wakeup -c CG   # Trace process under "
								"cgroupsPath CG\n";

static const struct argp_option opts[] = {
	{"pid", 'p', "PID", 0, "Trace this PID only", 0},
	{"verbose", 'v', NULL, 0, "Verbose debug output", 0},
	{"cgroup",
	 'c', "/sys/fs/cgroup/unified",
	 0, "Trace process in cgroup path",
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
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
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

static void print_stars(unsigned int val, unsigned int val_max, int width)
{
	int num_stars, num_spaces, i;
	bool need_plus;

	num_stars = min(val, val_max) * width / val_max;
	num_spaces = width - num_stars;
	need_plus = val > val_max;

	for (i = 0; i < num_stars; i++)
	{
		printf("*");
	}
	for (i = 0; i < num_spaces; i++)
	{
		printf(" ");
	}
	if (need_plus)
	{
		printf("+");
	}
}

static int print_log2_hists(struct bpf_map *hists)
{
	int err, fd = bpf_map__fd(hists);
	struct hkey lookup_key = {}, next_key;
	struct hist hist;
	int stars_max = 40;
	unsigned long long max_wakeup_count = 0;

	/*calc max_wakeup_count*/
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key))
	{
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0)
		{
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			return -1;
		}
		if (hist.wakeup_count > max_wakeup_count)
		{
			max_wakeup_count = hist.wakeup_count;
		}
		lookup_key = next_key;
	}
	printf("max_wakeup_count = %llu\n", max_wakeup_count);

	printf("%-8s  %-20s  %-10s\n", "pid", "comm", "count");
	/*printf task wakeup_count*/
	memset(&lookup_key, 0, sizeof(lookup_key));
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key))
	{
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0)
		{
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			return -1;
		}

		lookup_key = next_key;

		printf(
			"%-8d  %-20s  %-10llu |",
			lookup_key.pid,
			hist.comm,
			hist.wakeup_count
		);
		/*print stars*/
		print_stars(hist.wakeup_count, max_wakeup_count, stars_max);
		printf("|\n");
	}

	memset(&lookup_key, 0, sizeof(lookup_key));
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key))
	{
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0)
		{
			fprintf(stderr, "failed to cleanup hist : %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}

	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct wakeup_count_bpf *skel;
	int err;
	int idx, cg_map_fd;
	int cgfd = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
	{
		return err;
	}

	/* 设置libbpf错误和调试信息回调 */
	libbpf_set_print(libbpf_print_fn);

	/* 加载并验证 wakeup.bpf.c 应用程序 */
	skel = wakeup_count_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	skel->rodata->targ_tgid = env.pid;
	skel->rodata->filter_cg = env.cg;

	err = wakeup_count_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "failed to load BPF object: %d\n", err);
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

	/* 附加 wakeup.bpf.c 程序到跟踪点 */
	err = wakeup_count_bpf__attach(skel);
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
	printf("Tracing wakeup count... Hit Ctrl-C to end.\n");

	/* 处理收到的内核数据 */
	while (!stop)
	{
		sleep(env.interval);
		printf("\n");

		print_log2_hists(skel->maps.hists);
		if (err < 0)
		{
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* 销毁挂载的ebpf程序 */
	wakeup_count_bpf__destroy(skel);
	return -err;
}