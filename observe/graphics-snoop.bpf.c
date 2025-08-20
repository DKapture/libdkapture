/**
 * graphics-snoop - Graphics system events monitoring
 * Monitor DRM and DMA fence events in the graphics subsystem
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "dkapture.h"
#include "Kcom.h"
#include "Kstr-utils.h"
#include "graphics-snoop.h"

char LICENSE[] SEC("license") = "GPL";

/* 可配置选项 */
const volatile bool targ_verbose = false;
const volatile bool targ_errors_only = false;

/* BPF Maps定义 */

/* 事件输出ring buffer */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} graphics_events SEC(".maps");

/* 过滤规则配置 */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct graphics_filter);
	__uint(max_entries, 1);
} filter_map SEC(".maps");

/* CRTC状态跟踪 */
struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);	  /* crtc_id */
	__type(value, __u64); /* last_vblank_time */
	__uint(max_entries, 32);
} crtc_state SEC(".maps");

/* DMA围栏跟踪 */
struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);	  /* fence_ptr */
	__type(value, __u64); /* creation_time */
	__uint(max_entries, 1024);
} fence_tracker SEC(".maps");

/* 辅助函数 */

/* 获取过滤规则 */
static __always_inline struct graphics_filter *get_filter(void)
{
	__u32 key = 0;
	return bpf_map_lookup_elem(&filter_map, &key);
}

/* 过滤检查函数 */
static __always_inline bool should_trace_pid(__u32 pid)
{
	struct graphics_filter *filter = get_filter();
	if (!filter)
	{
		return true;
	}
	return filter->target_pid == 0 || filter->target_pid == pid;
}

static __always_inline bool should_trace_cpu(__u32 cpu)
{
	struct graphics_filter *filter = get_filter();
	if (!filter)
	{
		return true;
	}
	return filter->target_cpu == (__u32)-1 || filter->target_cpu == cpu;
}

static __always_inline bool should_trace_event(__u32 event_type)
{
	struct graphics_filter *filter = get_filter();
	if (!filter)
	{
		return true;
	}
	if (filter->event_mask == 0)
	{
		return true;
	}
	return filter->event_mask & (1 << (event_type - 1));
}

static __always_inline bool should_trace_crtc(__u32 crtc_id)
{
	struct graphics_filter *filter = get_filter();
	if (!filter)
	{
		return true;
	}
	return filter->crtc_filter == 0 || filter->crtc_filter == crtc_id;
}

static __always_inline bool should_trace_comm(const char *comm)
{
	struct graphics_filter *filter = get_filter();
	if (!filter)
	{
		return true;
	}
	if (filter->target_comm[0] == '\0')
	{
		return true;
	}
	return strncmp(comm, filter->target_comm, TASK_COMM_LEN) == 0;
}

/* 公共头部填充函数 */
static __always_inline void
fill_common_header(struct graphics_event_header *header, __u32 event_type)
{
	header->timestamp = bpf_ktime_get_ns();
	header->event_type = event_type;
	header->cpu = bpf_get_smp_processor_id();
	header->pid = bpf_get_current_pid_tgid() >> 32;
	header->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	bpf_get_current_comm(header->comm, sizeof(header->comm));
}

/* 事件提交函数 */
static __always_inline int submit_graphics_event(struct graphics_event *event)
{
	/* 基础过滤检查 */
	if (!should_trace_pid(event->header.pid))
	{
		return 0;
	}
	if (!should_trace_cpu(event->header.cpu))
	{
		return 0;
	}
	if (!should_trace_event(event->header.event_type))
	{
		return 0;
	}
	if (!should_trace_comm(event->header.comm))
	{
		return 0;
	}

	/* 错误过滤检查 */
	if (targ_errors_only)
	{
		if (event->header.event_type == GRAPHICS_FENCE_INIT ||
			event->header.event_type == GRAPHICS_FENCE_DESTROY ||
			event->header.event_type == GRAPHICS_FENCE_ENABLE ||
			event->header.event_type == GRAPHICS_FENCE_SIGNALED)
		{
			if (event->data.fence.error == 0)
			{
				return 0;
			}
		}
	}

	return bpf_ringbuf_output(&graphics_events, event, sizeof(*event), 0);
}

/* Tracepoint处理函数 */

/* 由于实际的DRM
 * tracepoint可能不存在或结构不同，我们使用通用的系统调用监控来模拟 */
/* 这里提供一个框架，实际部署时需要根据系统的tracepoint情况调整 */

/* 自定义tracepoint结构体 */
struct drm_vblank_event_ctx
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int crtc;
	unsigned int seq;
	__s64 time;
	bool high_prec;
};

/* 真实的DRM垂直同步事件处理 */
SEC("tracepoint/drm/drm_vblank_event")
int handle_drm_vblank_event(struct drm_vblank_event_ctx *ctx)
{
	struct graphics_event event = {};

	if (!should_trace_event(GRAPHICS_VBLANK_EVENT))
	{
		return 0;
	}

	fill_common_header(&event.header, GRAPHICS_VBLANK_EVENT);

	/* 读取真实的vblank数据 */
	event.data.vblank.crtc_id = ctx->crtc;
	event.data.vblank.sequence = ctx->seq;
	event.data.vblank.timestamp_ns = ctx->time;
	__builtin_memcpy(event.data.vblank.device_name, "drm", 4);

	if (!should_trace_crtc(event.data.vblank.crtc_id))
	{
		return 0;
	}

	/* 更新CRTC状态 */
	__u32 crtc_id = event.data.vblank.crtc_id;
	__u64 now = event.header.timestamp;
	bpf_map_update_elem(&crtc_state, &crtc_id, &now, BPF_ANY);

	return submit_graphics_event(&event);
}

struct dma_fence_init_ctx
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	__u32 __data_loc_driver;
	__u32 __data_loc_timeline;
	unsigned int context;
	unsigned int seqno;
};

/* 真实的DMA围栏初始化事件处理 */
SEC("tracepoint/dma_fence/dma_fence_init")
int handle_dma_fence_init(struct dma_fence_init_ctx *ctx)
{
	struct graphics_event event = {};
	__u64 now = bpf_ktime_get_ns();

	if (!should_trace_event(GRAPHICS_FENCE_INIT))
	{
		return 0;
	}

	fill_common_header(&event.header, GRAPHICS_FENCE_INIT);

	event.data.fence.fence_ptr = now; /* 使用时间戳标识围栏 */
	event.data.fence.context = ctx->context;
	event.data.fence.seqno = ctx->seqno;
	event.data.fence.error = GRAPHICS_NO_ERROR;

	/* 获取driver和timeline字符串 */
	char *driver_str =
		(char *)((void *)ctx + (ctx->__data_loc_driver & 0xffff));
	char *timeline_str =
		(char *)((void *)ctx + (ctx->__data_loc_timeline & 0xffff));
	bpf_probe_read_kernel_str(
		event.data.fence.driver_name,
		sizeof(event.data.fence.driver_name),
		driver_str
	);
	bpf_probe_read_kernel_str(
		event.data.fence.timeline_name,
		sizeof(event.data.fence.timeline_name),
		timeline_str
	);

	/* 记录围栏创建 */
	bpf_map_update_elem(
		&fence_tracker,
		&event.data.fence.fence_ptr,
		&now,
		BPF_ANY
	);

	return submit_graphics_event(&event);
}

struct dma_fence_signaled_ctx
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	__u32 __data_loc_driver;
	__u32 __data_loc_timeline;
	unsigned int context;
	unsigned int seqno;
};

/* 真实的DMA围栏信号完成事件处理 */
SEC("tracepoint/dma_fence/dma_fence_signaled")
int handle_dma_fence_signaled(struct dma_fence_signaled_ctx *ctx)
{
	struct graphics_event event = {};
	__u64 now = bpf_ktime_get_ns();

	if (!should_trace_event(GRAPHICS_FENCE_SIGNALED))
	{
		return 0;
	}

	fill_common_header(&event.header, GRAPHICS_FENCE_SIGNALED);

	event.data.fence.fence_ptr = now; /* 使用时间戳标识围栏 */
	event.data.fence.context = ctx->context;
	event.data.fence.seqno = ctx->seqno;
	event.data.fence.error = GRAPHICS_NO_ERROR;

	/* 获取driver和timeline字符串 */
	char *driver_str =
		(char *)((void *)ctx + (ctx->__data_loc_driver & 0xffff));
	char *timeline_str =
		(char *)((void *)ctx + (ctx->__data_loc_timeline & 0xffff));
	bpf_probe_read_kernel_str(
		event.data.fence.driver_name,
		sizeof(event.data.fence.driver_name),
		driver_str
	);
	bpf_probe_read_kernel_str(
		event.data.fence.timeline_name,
		sizeof(event.data.fence.timeline_name),
		timeline_str
	);

	return submit_graphics_event(&event);
}

struct drm_vblank_event_queued_ctx
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int crtc;
	unsigned int seq;
	__s64 time;
	bool high_prec;
};

/* 真实的DRM垂直同步队列事件处理 */
SEC("tracepoint/drm/drm_vblank_event_queued")
int handle_drm_vblank_queued(struct drm_vblank_event_queued_ctx *ctx)
{
	struct graphics_event event = {};

	if (!should_trace_event(GRAPHICS_VBLANK_QUEUED))
	{
		return 0;
	}

	fill_common_header(&event.header, GRAPHICS_VBLANK_QUEUED);

	/* 读取真实的vblank队列数据 */
	event.data.vblank.crtc_id = ctx->crtc;
	event.data.vblank.sequence = ctx->seq;
	event.data.vblank.timestamp_ns = ctx->time;
	__builtin_memcpy(event.data.vblank.device_name, "drm", 4);

	if (!should_trace_crtc(event.data.vblank.crtc_id))
	{
		return 0;
	}

	return submit_graphics_event(&event);
}