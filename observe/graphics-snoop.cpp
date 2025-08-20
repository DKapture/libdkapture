/**
 * graphics-snoop - Graphics system events monitoring
 * Monitor DRM and DMA fence events in the graphics subsystem
 */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "graphics-snoop.skel.h"
#include "dkapture.h"
#include "graphics-snoop.h"

/* 全局变量和环境结构 */
static struct ring_buffer *rb = NULL;
static struct graphics_snoop_bpf *obj = NULL;
static volatile bool exiting = false;

struct env
{
	__u32 pid;		   /* 进程过滤 */
	__u32 cpu;		   /* CPU过滤 */
	char comm[16];	   /* 命令名过滤 */
	__u32 event_mask;  /* 事件类型掩码 */
	__u32 crtc_filter; /* CRTC过滤 */
	bool verbose;	   /* 详细输出 */
	bool timestamp;	   /* 显示时间戳 */
	bool stats;		   /* 显示统计 */
	bool errors_only;  /* 仅显示错误 */
	time_t interval;   /* 输出间隔 */
	int times;		   /* 运行次数 */
} env = {
	.pid = 0,
	.cpu = (__u32)-1,
	.comm = "",
	.event_mask = GRAPHICS_EVENT_ALL_MASK,
	.crtc_filter = 0,
	.verbose = false,
	.timestamp = false,
	.stats = false,
	.errors_only = false,
	.interval = 1,
	.times = 0,
};

/* 统计数据 */
static struct graphics_stats stats = {};

/* 命令行参数定义 */
static const struct argp_option opts[] = {
	{"pid", 'p', "PID", 0, "Trace process with this PID only"},
	{"cpu", 'c', "CPU", 0, "Trace events on this CPU only"},
	{"comm", 'C', "COMM", 0, "Trace process with this command name only"},
	{"events", 'e', "MASK", 0, "Event type mask (1=vblank, 2=fence)"},
	{"crtc", 'r', "CRTC", 0, "Trace specific CRTC only"},
	{"verbose", 'v', NULL, 0, "Verbose output"},
	{"timestamp", 't', NULL, 0, "Print timestamp"},
	{"stats", 's', NULL, 0, "Print statistics"},
	{"errors-only", 'E', NULL, 0, "Show error events only"},
	{"interval", 'i', "INTERVAL", 0, "Summary interval in seconds"},
	{"times", 'T', "TIMES", 0, "Number of intervals to run"},
	{},
};

static const char args_doc[] = "";
static const char program_doc[] =
	"graphics-snoop - Monitor graphics system events\n"
	"\n"
	"USAGE: graphics-snoop [OPTIONS]\n"
	"\n"
	"EXAMPLES:\n"
	"    graphics-snoop                    # Monitor all graphics events\n"
	"    graphics-snoop -p 1234            # Monitor process 1234 only\n"
	"    graphics-snoop -e 1               # Monitor VBlank events only\n"
	"    graphics-snoop -E                 # Show error events only\n"
	"    graphics-snoop -v -t              # Verbose output with timestamps\n"
	"    graphics-snoop -s -i 5            # Print statistics every 5 "
	"seconds\n";

/* 事件类型转换函数 */
static const char *event_type_str(__u32 event_type)
{
	switch (event_type)
	{
	case GRAPHICS_VBLANK_EVENT:
		return "VBLANK";
	case GRAPHICS_VBLANK_QUEUED:
		return "VBLANK_Q";
	case GRAPHICS_FENCE_INIT:
		return "FENCE_INIT";
	case GRAPHICS_FENCE_DESTROY:
		return "FENCE_DEST";
	case GRAPHICS_FENCE_ENABLE:
		return "FENCE_EN";
	case GRAPHICS_FENCE_SIGNALED:
		return "FENCE_SIG";
	default:
		return "UNKNOWN";
	}
}

/* 事件输出函数 */
static void print_vblank_event(const struct graphics_event *e)
{
	if (env.verbose)
	{
		printf(
			"[%d] %s[%d]: %s crtc=%d seq=%d timestamp=%llu device=%s\n",
			e->header.cpu,
			e->header.comm,
			e->header.pid,
			event_type_str(e->header.event_type),
			e->data.vblank.crtc_id,
			e->data.vblank.sequence,
			e->data.vblank.timestamp_ns,
			e->data.vblank.device_name
		);
	}
	else
	{
		printf(
			"[%d] %s[%d]: %s crtc=%d seq=%d\n",
			e->header.cpu,
			e->header.comm,
			e->header.pid,
			event_type_str(e->header.event_type),
			e->data.vblank.crtc_id,
			e->data.vblank.sequence
		);
	}
}

static void print_fence_event(const struct graphics_event *e)
{
	if (env.verbose)
	{
		printf(
			"[%d] %s[%d]: %s fence=0x%llx ctx=%llu seq=%d err=%d driver=%s "
			"timeline=%s\n",
			e->header.cpu,
			e->header.comm,
			e->header.pid,
			event_type_str(e->header.event_type),
			e->data.fence.fence_ptr,
			e->data.fence.context,
			e->data.fence.seqno,
			e->data.fence.error,
			e->data.fence.driver_name,
			e->data.fence.timeline_name
		);
	}
	else
	{
		printf(
			"[%d] %s[%d]: %s fence=0x%llx seq=%d%s\n",
			e->header.cpu,
			e->header.comm,
			e->header.pid,
			event_type_str(e->header.event_type),
			e->data.fence.fence_ptr,
			e->data.fence.seqno,
			e->data.fence.error ? " (ERROR)" : ""
		);
	}
}

/* 更新统计信息 */
static void update_stats(const struct graphics_event *e)
{
	stats.total_events++;

	switch (e->header.event_type)
	{
	case GRAPHICS_VBLANK_EVENT:
	case GRAPHICS_VBLANK_QUEUED:
		stats.vblank_events++;
		stats.total_vblanks++;
		break;
	case GRAPHICS_FENCE_INIT:
		stats.fence_events++;
		stats.fence_created++;
		break;
	case GRAPHICS_FENCE_DESTROY:
		stats.fence_events++;
		stats.fence_destroyed++;
		break;
	case GRAPHICS_FENCE_SIGNALED:
		stats.fence_events++;
		stats.fence_signaled++;
		break;
	default:
		stats.fence_events++;
		break;
	}

	if (e->header.event_type >= GRAPHICS_FENCE_INIT &&
		e->header.event_type <= GRAPHICS_FENCE_SIGNALED)
	{
		if (e->data.fence.error != 0)
		{
			stats.error_events++;
		}
	}
}

/* 打印统计信息 */
static void print_stats(void)
{
	printf("\nGraphics Events Statistics:\n");
	printf("==========================\n");
	printf("Total Events:      %llu\n", stats.total_events);
	printf(
		"VBlank Events:     %llu (%.1f%%)\n",
		stats.vblank_events,
		stats.total_events ? 100.0 * stats.vblank_events / stats.total_events
						   : 0
	);
	printf(
		"Fence Events:      %llu (%.1f%%)\n",
		stats.fence_events,
		stats.total_events ? 100.0 * stats.fence_events / stats.total_events : 0
	);
	printf(
		"Error Events:      %llu (%.1f%%)\n",
		stats.error_events,
		stats.total_events ? 100.0 * stats.error_events / stats.total_events : 0
	);
	printf("\nDRM Statistics:\n");
	printf("Total VBlanks:     %llu\n", stats.total_vblanks);
	printf("Active CRTCs:      %u\n", stats.active_crtcs);
	printf("\nDMA Fence Statistics:\n");
	printf("Fences Created:    %llu\n", stats.fence_created);
	printf("Fences Destroyed:  %llu\n", stats.fence_destroyed);
	printf("Fences Signaled:   %llu\n", stats.fence_signaled);
	printf("Fence Timeouts:    %llu\n", stats.fence_timeouts);
	printf("\n");
}

/* 事件处理函数 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct graphics_event *e = (const struct graphics_event *)data;
	struct tm *tm;
	char ts[32];
	time_t t;

	/* 更新统计 */
	update_stats(e);

	if (env.timestamp)
	{
		t = time(NULL);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%s ", ts);
	}

	switch (e->header.event_type)
	{
	case GRAPHICS_VBLANK_EVENT:
	case GRAPHICS_VBLANK_QUEUED:
		print_vblank_event(e);
		break;
	case GRAPHICS_FENCE_INIT:
	case GRAPHICS_FENCE_DESTROY:
	case GRAPHICS_FENCE_ENABLE:
	case GRAPHICS_FENCE_SIGNALED:
		print_fence_event(e);
		break;
	default:
		printf("Unknown event type: %d\n", e->header.event_type);
		break;
	}

	return 0;
}

/* 信号处理 */
static void sig_handler(int sig)
{
	exiting = true;
}

/* 命令行参数解析 */
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key)
	{
	case 'p':
		env.pid = strtoul(arg, NULL, 10);
		break;
	case 'c':
		env.cpu = strtoul(arg, NULL, 10);
		break;
	case 'C':
		strncpy(env.comm, arg, sizeof(env.comm) - 1);
		env.comm[sizeof(env.comm) - 1] = '\0';
		break;
	case 'e':
		env.event_mask = strtoul(arg, NULL, 0);
		break;
	case 'r':
		env.crtc_filter = strtoul(arg, NULL, 10);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 't':
		env.timestamp = true;
		break;
	case 's':
		env.stats = true;
		break;
	case 'E':
		env.errors_only = true;
		break;
	case 'i':
		env.interval = strtol(arg, NULL, 10);
		break;
	case 'T':
		env.times = strtol(arg, NULL, 10);
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.args_doc = args_doc,
	.doc = program_doc,
};

/* 主函数 */
int main(int argc, char **argv)
{
	int err;
	int filter_key = 0;
	int filter_fd;
	struct graphics_filter filter = {};

	/* 信号处理设置 */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* 命令行参数解析 */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
	{
		return err;
	}

	printf("Filter settings:\n");
	printf("  PID: %d, CPU: %d, COMM: %s\n", env.pid, env.cpu, env.comm);
	printf(
		"  Event mask: 0x%x, CRTC: %d, Errors only: %s\n\n",
		env.event_mask,
		env.crtc_filter,
		env.errors_only ? "yes" : "no"
	);

	/* BPF对象操作 */
	obj = graphics_snoop_bpf__open();
	if (!obj)
	{
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* 设置BPF程序配置 */
	obj->rodata->targ_verbose = env.verbose;
	obj->rodata->targ_errors_only = env.errors_only;

	/* 设置过滤规则 */
	filter.target_pid = env.pid;
	filter.target_cpu = env.cpu;
	strcpy(filter.target_comm, env.comm);
	filter.event_mask = env.event_mask;
	filter.crtc_filter = env.crtc_filter;
	filter.filter_errors_only = env.errors_only;

	err = graphics_snoop_bpf__load(obj);
	if (err)
	{
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/* 更新过滤规则 */
	filter_fd = bpf_map__fd(obj->maps.filter_map);
	err = bpf_map_update_elem(filter_fd, &filter_key, &filter, BPF_ANY);
	if (err)
	{
		fprintf(stderr, "failed to update filter map: %d\n", err);
		goto cleanup;
	}

	err = graphics_snoop_bpf__attach(obj);
	if (err)
	{
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	/* Ring buffer设置 */
	rb = ring_buffer__new(
		bpf_map__fd(obj->maps.graphics_events),
		handle_event,
		NULL,
		NULL
	);
	if (!rb)
	{
		err = -1;
		fprintf(stderr, "failed to create ring buffer\n");
		goto cleanup;
	}

	printf("Tracing graphics events... Hit Ctrl-C to end.\n");

	/* 主循环 */
	while (!exiting)
	{
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

	/* 显示最终统计 */
	if (env.stats)
	{
		print_stats();
	}

cleanup:
	if (rb)
	{
		ring_buffer__free(rb);
	}
	graphics_snoop_bpf__destroy(obj);
	return err != 0;
}