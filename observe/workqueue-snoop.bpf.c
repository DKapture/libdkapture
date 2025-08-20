#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define WORKQUEUE_NAME_LEN 32
#define MAX_ENTRIES 10240

// Event types
#define WQ_EVENT_QUEUE 0
#define WQ_EVENT_ACTIVATE 1
#define WQ_EVENT_START 2
#define WQ_EVENT_END 3

// Structures are already defined in vmlinux.h

// Filter configuration
struct filter_config
{
	u32 target_pid;
	u32 target_cpu;
	char target_workqueue[WORKQUEUE_NAME_LEN];
	char target_function[64];
	u8 filter_pid;
	u8 filter_cpu;
	u8 filter_workqueue;
	u8 filter_function;
};

// Event structure sent to userspace
struct workqueue_event
{
	u64 timestamp;
	u32 pid;
	u32 cpu;
	u64 work_ptr;
	u64 function_ptr;
	char workqueue_name[WORKQUEUE_NAME_LEN];
	char comm[TASK_COMM_LEN];
	u8 event_type;
	s32 req_cpu;
	u64 delay_ns; // For timing analysis
};

// Work timing tracking
struct work_timing
{
	u64 queue_time;
	u64 start_time;
	u32 pid;
	char comm[TASK_COMM_LEN];
	char workqueue_name[WORKQUEUE_NAME_LEN];
};

// Ring buffer for events
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Hash map for work timing tracking
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); // work pointer
	__type(value, struct work_timing);
	__uint(max_entries, MAX_ENTRIES);
} work_timings SEC(".maps");

// Configuration map
struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct filter_config);
	__uint(max_entries, 1);
} filter_config_map SEC(".maps");

// Helper function removed - using direct field access

// Helper function to check if event should be filtered
static __always_inline bool should_filter_event(
	struct filter_config *cfg,
	u32 pid,
	u32 cpu,
	char *workqueue_name,
	u64 function_ptr
)
{
	if (cfg->filter_pid && cfg->target_pid != pid)
	{
		return true;
	}

	if (cfg->filter_cpu && cfg->target_cpu != cpu)
	{
		return true;
	}

	if (cfg->filter_workqueue && workqueue_name)
	{
		bool match = false;
		for (int i = 0; i < WORKQUEUE_NAME_LEN - 1; i++)
		{
			if (cfg->target_workqueue[i] == 0)
			{
				break;
			}
			if (workqueue_name[i] != cfg->target_workqueue[i])
			{
				return true;
			}
			if (workqueue_name[i] == 0)
			{
				match = true;
				break;
			}
		}
		if (!match)
		{
			return true;
		}
	}

	return false;
}

// Helper function to send event to userspace
static __always_inline void send_event(
	u8 event_type,
	u64 work_ptr,
	u64 function_ptr,
	char *workqueue_name,
	s32 req_cpu,
	u64 delay_ns
)
{
	u32 key = 0;
	struct filter_config *cfg = bpf_map_lookup_elem(&filter_config_map, &key);
	if (!cfg)
	{
		return;
	}

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	u32 cpu = bpf_get_smp_processor_id();

	if (should_filter_event(cfg, pid, cpu, workqueue_name, function_ptr))
	{
		return;
	}

	struct workqueue_event *event =
		bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
	{
		return;
	}

	event->timestamp = bpf_ktime_get_ns();
	event->pid = pid;
	event->cpu = cpu;
	event->work_ptr = work_ptr;
	event->function_ptr = function_ptr;
	event->event_type = event_type;
	event->req_cpu = req_cpu;
	event->delay_ns = delay_ns;

	bpf_get_current_comm(event->comm, sizeof(event->comm));

	if (workqueue_name)
	{
		bpf_probe_read_str(
			event->workqueue_name,
			sizeof(event->workqueue_name),
			workqueue_name
		);
	}
	else
	{
		event->workqueue_name[0] = 0;
	}

	bpf_ringbuf_submit(event, 0);
}

SEC("tp/workqueue/workqueue_queue_work")
int tp_workqueue_queue_work(struct trace_event_raw_workqueue_queue_work *ctx)
{
	u64 work_ptr = (u64)ctx->work;
	u64 function_ptr = (u64)ctx->function;
	// Get workqueue name from __data_loc field
	char *workqueue_name = (char *)ctx + (ctx->__data_loc_workqueue & 0xFFFF);
	s32 req_cpu = ctx->req_cpu;

	// Store timing info for delay calculation
	struct work_timing timing = {0};
	timing.queue_time = bpf_ktime_get_ns();
	timing.start_time = 0;
	timing.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(timing.comm, sizeof(timing.comm));
	if (workqueue_name)
	{
		bpf_probe_read_str(
			timing.workqueue_name,
			sizeof(timing.workqueue_name),
			workqueue_name
		);
	}

	bpf_map_update_elem(&work_timings, &work_ptr, &timing, BPF_ANY);

	send_event(
		WQ_EVENT_QUEUE,
		work_ptr,
		function_ptr,
		workqueue_name,
		req_cpu,
		0
	);
	return 0;
}

SEC("tp/workqueue/workqueue_activate_work")
int tp_workqueue_activate_work(
	struct trace_event_raw_workqueue_activate_work *ctx
)
{
	u64 work_ptr = (u64)ctx->work;

	send_event(WQ_EVENT_ACTIVATE, work_ptr, 0, NULL, -1, 0);
	return 0;
}

SEC("tp/workqueue/workqueue_execute_start")
int tp_workqueue_execute_start(
	struct trace_event_raw_workqueue_execute_start *ctx
)
{
	u64 work_ptr = (u64)ctx->work;
	u64 function_ptr = (u64)ctx->function;
	u64 now = bpf_ktime_get_ns();
	u64 delay_ns = 0;

	// Calculate queue delay
	struct work_timing *timing = bpf_map_lookup_elem(&work_timings, &work_ptr);
	if (timing && timing->queue_time > 0)
	{
		delay_ns = now - timing->queue_time;
		timing->start_time = now;
		bpf_map_update_elem(&work_timings, &work_ptr, timing, BPF_EXIST);
	}

	send_event(WQ_EVENT_START, work_ptr, function_ptr, NULL, -1, delay_ns);
	return 0;
}

SEC("tp/workqueue/workqueue_execute_end")
int tp_workqueue_execute_end(struct trace_event_raw_workqueue_execute_end *ctx)
{
	u64 work_ptr = (u64)ctx->work;
	u64 function_ptr = (u64)ctx->function;
	u64 now = bpf_ktime_get_ns();
	u64 exec_time = 0;

	// Calculate execution time
	struct work_timing *timing = bpf_map_lookup_elem(&work_timings, &work_ptr);
	if (timing && timing->start_time > 0)
	{
		exec_time = now - timing->start_time;
	}

	send_event(WQ_EVENT_END, work_ptr, function_ptr, NULL, -1, exec_time);

	// Clean up timing entry
	bpf_map_delete_elem(&work_timings, &work_ptr);
	return 0;
}