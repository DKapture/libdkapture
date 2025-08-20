// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

// RCU事件数据结构
struct rcu_event
{
	u64 timestamp;
	u32 pid;
	u32 cpu;
	u8 event_type; // 0: utilization, 1: stall_warning
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
	u32 target_pid;
	u32 target_cpu;
	bool monitor_utilization;
	bool monitor_stall;
};

// 过滤规则映射
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct rcu_filter);
} filter_map SEC(".maps");

// 事件输出映射
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// tracepoint结构定义已在vmlinux.h中定义，无需重复定义

// 获取过滤规则
static struct rcu_filter *get_filter(void)
{
	u32 key = 0;
	return bpf_map_lookup_elem(&filter_map, &key);
}

// 检查过滤条件
static bool should_trace(struct rcu_filter *filter, u32 pid, u32 cpu)
{
	if (!filter || !filter->enabled)
	{
		return true;
	}

	if (filter->target_pid && filter->target_pid != pid)
	{
		return false;
	}

	if (filter->target_cpu && filter->target_cpu != cpu)
	{
		return false;
	}

	return true;
}

// rcu_utilization tracepoint处理函数
SEC("tracepoint/rcu/rcu_utilization")
int trace_rcu_utilization(struct trace_event_raw_rcu_utilization *ctx)
{
	struct rcu_filter *filter = get_filter();
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 cpu = bpf_get_smp_processor_id();

	if (!should_trace(filter, pid, cpu))
	{
		return 0;
	}

	if (filter && !filter->monitor_utilization)
	{
		return 0;
	}

	struct rcu_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
	{
		return 0;
	}

	event->timestamp = bpf_ktime_get_ns();
	event->pid = pid;
	event->cpu = cpu;
	event->event_type = 0; // utilization

	// 从tracepoint中提取s字段
	bpf_probe_read_str(event->util.s, sizeof(event->util.s), ctx->s);

	bpf_ringbuf_submit(event, 0);
	return 0;
}

// rcu_stall_warning tracepoint处理函数
SEC("tracepoint/rcu/rcu_stall_warning")
int trace_rcu_stall_warning(struct trace_event_raw_rcu_stall_warning *ctx)
{
	struct rcu_filter *filter = get_filter();
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 cpu = bpf_get_smp_processor_id();

	if (!should_trace(filter, pid, cpu))
	{
		return 0;
	}

	if (filter && !filter->monitor_stall)
	{
		return 0;
	}

	struct rcu_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
	{
		return 0;
	}

	event->timestamp = bpf_ktime_get_ns();
	event->pid = pid;
	event->cpu = cpu;
	event->event_type = 1; // stall_warning

	// 从tracepoint中提取rcuname和msg字段
	bpf_probe_read_str(
		event->stall.rcuname,
		sizeof(event->stall.rcuname),
		ctx->rcuname
	);
	bpf_probe_read_str(event->stall.msg, sizeof(event->stall.msg), ctx->msg);

	bpf_ringbuf_submit(event, 0);
	return 0;
}