#ifndef __GRAPHICS_SNOOP_H
#define __GRAPHICS_SNOOP_H

#define TASK_COMM_LEN 16
#define DRM_DEVICE_NAME_LEN 32
#define FENCE_CONTEXT_NAME_LEN 32

/* 图形事件类型枚举 */
enum graphics_event_type
{
	GRAPHICS_VBLANK_EVENT = 1,	 /* DRM垂直同步事件 */
	GRAPHICS_VBLANK_QUEUED = 2,	 /* DRM垂直同步队列事件 */
	GRAPHICS_FENCE_INIT = 3,	 /* DMA围栏初始化 */
	GRAPHICS_FENCE_DESTROY = 4,	 /* DMA围栏销毁 */
	GRAPHICS_FENCE_ENABLE = 5,	 /* DMA围栏信号启用 */
	GRAPHICS_FENCE_SIGNALED = 6, /* DMA围栏信号完成 */
};

/* 通用事件头部（参考sched-snoop设计） */
struct graphics_event_header
{
	__u64 timestamp;
	__u32 event_type;
	__u32 cpu;
	__u32 pid;
	__u32 tid;
	char comm[TASK_COMM_LEN];
};

/* DRM垂直同步事件数据 */
struct drm_vblank_data
{
	__u32 crtc_id;		/* CRTC ID */
	__u32 sequence;		/* 序列号 */
	__u64 timestamp_ns; /* 硬件时间戳 */
	char device_name[DRM_DEVICE_NAME_LEN];
};

/* DMA围栏事件数据 */
struct dma_fence_data
{
	__u64 fence_ptr; /* 围栏对象指针 */
	__u64 context;	 /* 围栏上下文 */
	__u32 seqno;	 /* 序列号 */
	__s32 error;	 /* 错误代码 */
	char driver_name[DRM_DEVICE_NAME_LEN];
	char timeline_name[FENCE_CONTEXT_NAME_LEN];
};

/* 主事件结构体（使用union优化内存，参考sched-snoop） */
struct graphics_event
{
	struct graphics_event_header header;
	union
	{
		struct drm_vblank_data vblank;
		struct dma_fence_data fence;
	} data;
};

/* 过滤规则结构体（参考irqsnoop设计） */
struct graphics_filter
{
	__u32 target_pid;				 /* 0表示无过滤 */
	__u32 target_cpu;				 /* -1表示无过滤 */
	char target_comm[TASK_COMM_LEN]; /* 空表示无过滤 */
	__u32 event_mask;				 /* 事件类型位掩码 */
	__u32 crtc_filter;				 /* CRTC过滤 */
	__u64 fence_context_filter;		 /* 围栏上下文过滤 */
	bool filter_errors_only;		 /* 仅显示错误事件 */
};

/* 统计信息结构体（参考bio-stat设计） */
struct graphics_stats
{
	__u64 total_events;
	__u64 vblank_events;
	__u64 fence_events;
	__u64 error_events;

	/* DRM统计 */
	__u64 total_vblanks;
	__u64 missed_vblanks;
	__u32 active_crtcs;

	/* DMA围栏统计 */
	__u64 fence_created;
	__u64 fence_destroyed;
	__u64 fence_signaled;
	__u64 fence_timeouts;

	/* 性能统计 */
	__u64 min_vblank_interval;
	__u64 max_vblank_interval;
	__u64 avg_fence_latency;
};

/* 事件类型掩码定义 */
#define GRAPHICS_EVENT_VBLANK_MASK (1 << (GRAPHICS_VBLANK_EVENT - 1))
#define GRAPHICS_EVENT_VBLANK_Q_MASK (1 << (GRAPHICS_VBLANK_QUEUED - 1))
#define GRAPHICS_EVENT_FENCE_INIT_MASK (1 << (GRAPHICS_FENCE_INIT - 1))
#define GRAPHICS_EVENT_FENCE_DEST_MASK (1 << (GRAPHICS_FENCE_DESTROY - 1))
#define GRAPHICS_EVENT_FENCE_EN_MASK (1 << (GRAPHICS_FENCE_ENABLE - 1))
#define GRAPHICS_EVENT_FENCE_SIG_MASK (1 << (GRAPHICS_FENCE_SIGNALED - 1))
#define GRAPHICS_EVENT_ALL_MASK 0x3F

/* 错误代码定义 */
#define GRAPHICS_NO_ERROR 0
#define GRAPHICS_FENCE_TIMEOUT -ETIMEDOUT
#define GRAPHICS_FENCE_CANCELLED -ECANCELED

#endif /* __GRAPHICS_SNOOP_H */