// SPDX-License-Identifier: GPL-2.0
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "rcu-insight.skel.h"

// RCU事件数据结构（与BPF程序中的结构一致）
struct rcu_event
{
	uint64_t timestamp;
	uint32_t pid;
	uint32_t cpu;
	uint8_t event_type; // 0: utilization, 1: stall_warning
	union
	{
		struct
		{
			char s[16]; // rcu_utilization的s字段
		} util;
		struct
		{
			char rcuname[16]; // rcu_stall_warning的rcuname字段
			char msg[64];	  // rcu_stall_warning的msg字段
		} stall;
	};
};

// 过滤规则结构
struct rcu_filter
{
	bool enabled;
	uint32_t target_pid;
	uint32_t target_cpu;
	bool monitor_utilization;
	bool monitor_stall;
};

// 统计信息结构
struct rcu_stats
{
	uint64_t total_events;
	uint64_t utilization_events;
	uint64_t stall_events;
	uint64_t start_time;
};

// 全局变量
static struct rcu_stats stats = {0};
static volatile bool exiting = false;

// 程序参数结构
struct env
{
	bool verbose;
	long interval;
	int times;
	bool timestamp;
	pid_t pid;
	int cpu;
	bool utilization_only;
	bool stall_only;
} env = {
	.interval = 1,
	.times = 99999999,
	.pid = 0,
	.cpu = -1,
};

// 命令行参数定义
const char *argp_program_version = "rcu-insight 0.1";
const char *argp_program_bug_address = "https://github.com/example/dkapture";
const char argp_program_doc[] =
	"Monitor RCU (Read-Copy-Update) subsystem activity.\n"
	"\n"
	"USAGE: rcu-insight [--help] [-v] [-i INTERVAL] [-d DURATION] [-p PID] [-c "
	"CPU] [--utilization-only] [--stall-only]\n"
	"\n"
	"EXAMPLES:\n"
	"    rcu-insight                     # Monitor all RCU events\n"
	"    rcu-insight -p 1234             # Monitor RCU events for PID 1234\n"
	"    rcu-insight -c 2                # Monitor RCU events for CPU 2\n"
	"    rcu-insight --utilization-only  # Monitor only utilization events\n"
	"    rcu-insight --stall-only        # Monitor only stall warning events\n";

static const struct argp_option opts[] = {
	{"verbose", 'v', NULL, 0, "Verbose debug output"},
	{"interval", 'i', "INTERVAL", 0, "Summary interval (seconds)"},
	{"duration", 'd', "DURATION", 0, "Duration of trace (seconds)"},
	{"timestamp", 'T', NULL, 0, "Include timestamp on output"},
	{"pid", 'p', "PID", 0, "Process ID to trace"},
	{"cpu", 'c', "CPU", 0, "CPU to trace"},
	{"utilization-only", 'u', NULL, 0, "Monitor only utilization events"},
	{"stall-only", 's', NULL, 0, "Monitor only stall warning events"},
	{},
};

// 命令行参数解析函数
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	switch (key)
	{
	case 'v':
		env.verbose = true;
		break;
	case 'i':
		env.interval = strtol(arg, NULL, 10);
		break;
	case 'd':
		env.times = strtol(arg, NULL, 10);
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'p':
		env.pid = strtol(arg, NULL, 10);
		break;
	case 'c':
		env.cpu = strtol(arg, NULL, 10);
		break;
	case 'u':
		env.utilization_only = true;
		break;
	case 's':
		env.stall_only = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_opt,
	.doc = argp_program_doc,
};

// 信号处理函数
static void sig_handler(int sig)
{
	exiting = true;
}

// 时间戳转换函数
static void print_timestamp(char *buf, size_t buf_size, uint64_t ns)
{
	struct tm *tm;
	time_t t;
	int ms;

	t = ns / 1000000000;
	ms = (ns % 1000000000) / 1000000;
	tm = localtime(&t);
	strftime(buf, buf_size, "%H:%M:%S", tm);
	snprintf(buf + strlen(buf), buf_size - strlen(buf), ".%03d", ms);
}

// 事件处理函数
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct rcu_event *e = (const struct rcu_event *)data;
	char timestamp_buf[32];

	stats.total_events++;

	if (env.timestamp)
	{
		print_timestamp(timestamp_buf, sizeof(timestamp_buf), e->timestamp);
		printf("%-12s ", timestamp_buf);
	}

	printf("%-8u %-4u ", e->pid, e->cpu);

	if (e->event_type == 0)
	{
		// rcu_utilization event
		stats.utilization_events++;
		printf("%-13s %s\n", "UTILIZATION", e->util.s);
	}
	else if (e->event_type == 1)
	{
		// rcu_stall_warning event
		stats.stall_events++;
		printf(
			"%-13s rcuname=%s msg=%s\n",
			"STALL_WARNING",
			e->stall.rcuname,
			e->stall.msg
		);
	}

	return 0;
}

// 打印统计信息
static void print_stats(void)
{
	uint64_t current_time = time(NULL);
	uint64_t duration = current_time - stats.start_time;

	if (duration == 0)
	{
		duration = 1;
	}

	printf("\n=== RCU Monitoring Statistics ===\n");
	printf("Total events: %lu\n", stats.total_events);
	printf("Utilization events: %lu\n", stats.utilization_events);
	printf("Stall warning events: %lu\n", stats.stall_events);
	printf("Duration: %lu seconds\n", duration);
	printf(
		"Event rate: %.2f events/second\n",
		(double)stats.total_events / duration
	);
}

// 打印表头
static void print_header(void)
{
	if (env.timestamp)
	{
		printf("%-12s ", "TIME");
	}
	printf("%-8s %-4s %-13s %s\n", "PID", "CPU", "EVENT_TYPE", "DETAILS");
}

// libbpf打印回调
static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
	{
		return 0;
	}
	return vfprintf(stderr, format, args);
}

// 主函数
int main(int argc, char **argv)
{
	struct rcu_insight_bpf *skel;
	struct ring_buffer *rb = NULL;
	struct rcu_filter filter;
	uint32_t key = 0;
	int err;

	// 解析命令行参数
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
	{
		return err;
	}

	// 参数验证
	if (env.utilization_only && env.stall_only)
	{
		fprintf(
			stderr,
			"Error: --utilization-only and --stall-only are mutually "
			"exclusive\n"
		);
		return 1;
	}

	// 设置libbpf打印函数
	libbpf_set_print(libbpf_print_fn);

	// 设置信号处理
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 打开BPF程序
	skel = rcu_insight_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open BPF program\n");
		return 1;
	}

	// 加载BPF程序
	err = rcu_insight_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load BPF program: %d\n", err);
		goto cleanup;
	}

	// 挂载BPF程序
	err = rcu_insight_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF program: %d\n", err);
		goto cleanup;
	}

	// 设置过滤规则
	filter.enabled =
		(env.pid || env.cpu != -1 || env.utilization_only || env.stall_only);
	filter.target_pid = (uint32_t)env.pid;
	filter.target_cpu = (uint32_t)env.cpu;
	filter.monitor_utilization = !env.stall_only;
	filter.monitor_stall = !env.utilization_only;
	err = bpf_map_update_elem(
		bpf_map__fd(skel->maps.filter_map),
		&key,
		&filter,
		0
	);
	if (err)
	{
		fprintf(stderr, "Failed to update filter map: %d\n", err);
		goto cleanup;
	}

	// 设置环形缓冲区
	rb = ring_buffer__new(
		bpf_map__fd(skel->maps.events),
		handle_event,
		NULL,
		NULL
	);
	if (!rb)
	{
		fprintf(stderr, "Failed to create ring buffer\n");
		err = -1;
		goto cleanup;
	}

	// 初始化统计信息
	stats.start_time = time(NULL);

	// 打印表头
	print_header();

	// 主循环
	while (!exiting)
	{
		err = ring_buffer__poll(rb, 100); // 100ms timeout
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}

		// 检查是否到达运行时间限制
		if (env.times != 99999999 &&
			(long)(time(NULL) - stats.start_time) >= env.times)
		{
			break;
		}
	}

	// 打印统计信息
	if (env.verbose || stats.total_events > 0)
	{
		print_stats();
	}

cleanup:
	ring_buffer__free(rb);
	rcu_insight_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}