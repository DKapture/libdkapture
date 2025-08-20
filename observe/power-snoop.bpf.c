// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 DKapture Project
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "dkapture.h"
#include "Kcom.h"

/* Power Event Types - Based on available power tracepoints */
enum power_event_type
{
	POWER_CPU_FREQ = 1,		   /* cpu_frequency */
	POWER_CPU_IDLE = 2,		   /* cpu_idle */
	POWER_DEVICE_PM_START = 3, /* device_pm_callback_start */
	POWER_DEVICE_PM_END = 4,   /* device_pm_callback_end */
	POWER_PM_QOS_ADD = 5,	   /* pm_qos_add_request */
	POWER_PM_QOS_UPDATE = 6,   /* pm_qos_update_request */
	POWER_CLOCK_ENABLE = 7,	   /* clock_enable */
	POWER_CLOCK_DISABLE = 8,   /* clock_disable */
	POWER_RPM_SUSPEND = 9,	   /* rpm_suspend */
	POWER_RPM_RESUME = 10,	   /* rpm_resume */
};

/* Common power event header */
struct power_event_header
{
	__u64 timestamp;
	__u32 event_type;
	__u32 cpu;
	char comm[16]; /* TASK_COMM_LEN */
	__u32 pid;
	__u32 tid;
};

/* Power event structure with union for different event types */
struct power_event_t
{
	struct power_event_header header;

	/* Event-specific data (union to save space) */
	union
	{
		/* CPU frequency event */
		struct
		{
			__u32 cpu_id;
			__u32 old_freq;
			__u32 new_freq;
			__u32 policy;
		} cpu_freq;

		/* CPU idle event */
		struct
		{
			__u32 cpu_id;
			__u32 state;
			__u64 duration_ns;
			__u32 exit_reason;
		} cpu_idle;

		/* Device power management event */
		struct
		{
			char device_name[64];
			__u32 pm_event;
			__u32 pm_state;
			__u64 duration_ns;
			__s32 ret;
		} device_pm;

		/* PM QoS event */
		struct
		{
			__u32 qos_type;
			__u32 qos_value;
			__u32 qos_flags;
			char requestor[32];
		} pm_qos;

		/* Clock event */
		struct
		{
			char clock_name[32];
			__u64 rate;
			__u32 prepare_count;
			__u32 enable_count;
		} clock;

		/* Runtime PM event */
		struct
		{
			char device_name[64];
			__u32 usage_count;
			__u32 disable_depth;
			__u32 runtime_error;
			__u64 active_time;
			__u64 suspended_time;
		} rpm;
	} data;
};

/* Filter configuration */
struct power_filter
{
	__u32 target_pid;		 /* 0 means no filter */
	__u32 target_cpu;		 /* -1 means no filter */
	char target_comm[16];	 /* Empty means no filter */
	__u32 event_mask;		 /* Bitmask of events to trace */
	__u32 min_freq;			 /* Minimum CPU frequency to trace */
	__u32 max_freq;			 /* Maximum CPU frequency to trace */
	__u64 min_idle_duration; /* Minimum idle duration to trace */
	__u64 max_idle_duration; /* Maximum idle duration to trace */
};

/* Map sizes */
#define MAX_POWER_EVENTS 262144 /* Ring buffer size */
#define MAX_FILTER_RULES 1		/* Filter rules map size */
#define MAX_CPU_HISTORY 256		/* CPU frequency history */
#define MAX_DEVICE_TRACK 1000	/* Device PM tracking */

/* Configuration from user space */
const volatile bool targ_verbose = false;
const volatile bool targ_timestamp = false;

/* BPF Maps */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_POWER_EVENTS);
} power_events SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct power_filter);
	__uint(max_entries, MAX_FILTER_RULES);
} filter_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);	  /* cpu_id */
	__type(value, __u32); /* last_freq */
	__uint(max_entries, MAX_CPU_HISTORY);
} cpu_freq_history SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);	  /* device_id hash */
	__type(value, __u64); /* start_time */
	__uint(max_entries, MAX_DEVICE_TRACK);
} device_pm_tracking SEC(".maps");

/* Helper functions */
static __always_inline bool should_trace_pid(__u32 pid)
{
	struct power_filter *filter;
	__u32 key = 0;

	filter = bpf_map_lookup_elem(&filter_map, &key);
	if (!filter)
	{
		return true;
	}

	return filter->target_pid == 0 || filter->target_pid == pid;
}

static __always_inline bool should_trace_cpu(__u32 cpu)
{
	struct power_filter *filter;
	__u32 key = 0;

	filter = bpf_map_lookup_elem(&filter_map, &key);
	if (!filter)
	{
		return true;
	}

	return filter->target_cpu == (__u32)-1 || filter->target_cpu == cpu;
}

static __always_inline bool should_trace_event(__u32 event_type)
{
	struct power_filter *filter;
	__u32 key = 0;

	filter = bpf_map_lookup_elem(&filter_map, &key);
	if (!filter)
	{
		return true;
	}

	return filter->event_mask & (1 << event_type);
}

static __always_inline bool should_trace_freq_range(__u32 freq)
{
	struct power_filter *filter;
	__u32 key = 0;

	filter = bpf_map_lookup_elem(&filter_map, &key);
	if (!filter)
	{
		return true;
	}

	if (filter->min_freq > 0 && freq < filter->min_freq)
	{
		return false;
	}
	if (filter->max_freq > 0 && freq > filter->max_freq)
	{
		return false;
	}

	return true;
}

static __always_inline void
fill_common_header(struct power_event_header *header, __u32 event_type)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	header->timestamp = bpf_ktime_get_ns();
	header->event_type = event_type;
	header->cpu = bpf_get_smp_processor_id();
	header->pid = pid_tgid >> 32;
	header->tid = pid_tgid;
	bpf_get_current_comm(header->comm, sizeof(header->comm));
}

static __always_inline void submit_event(struct power_event_t *event)
{
	long ret = bpf_ringbuf_output(&power_events, event, sizeof(*event), 0);
	if (ret)
	{
		bpf_err("bpf_ringbuf_output err: %ld", ret);
	}
}

/* CPU frequency tracepoint */
SEC("tracepoint/power/cpu_frequency")
int handle_cpu_frequency(void *ctx)
{
	struct power_event_t event = {};
	__u32 cpu = bpf_get_smp_processor_id();
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Apply filters */
	if (!should_trace_pid(pid) || !should_trace_cpu(cpu) ||
		!should_trace_event(POWER_CPU_FREQ))
	{
		return 0;
	}

	/* Fill common header */
	fill_common_header(&event.header, POWER_CPU_FREQ);

	/* Fill CPU frequency specific data - simplified for now */
	event.data.cpu_freq.cpu_id = cpu;
	event.data.cpu_freq.new_freq = 0; /* Will be filled by real tracepoint data
									   */
	event.data.cpu_freq.old_freq = 0;

	/* Submit event */
	submit_event(&event);

	return 0;
}

/* CPU idle tracepoint */
SEC("tracepoint/power/cpu_idle")
int handle_cpu_idle(void *ctx)
{
	struct power_event_t event = {};
	__u32 cpu = bpf_get_smp_processor_id();
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Apply filters */
	if (!should_trace_pid(pid) || !should_trace_cpu(cpu) ||
		!should_trace_event(POWER_CPU_IDLE))
	{
		return 0;
	}

	/* Fill common header */
	fill_common_header(&event.header, POWER_CPU_IDLE);

	/* Fill CPU idle specific data - simplified */
	event.data.cpu_idle.cpu_id = cpu;
	event.data.cpu_idle.state = 0; /* Will be filled by real tracepoint data */
	event.data.cpu_idle.duration_ns = 0;
	event.data.cpu_idle.exit_reason = 0;

	/* Submit event */
	submit_event(&event);

	return 0;
}

/* Device PM callback start tracepoint */
SEC("tracepoint/power/device_pm_callback_start")
int handle_device_pm_start(void *ctx)
{
	struct power_event_t event = {};
	__u32 cpu = bpf_get_smp_processor_id();
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Apply filters */
	if (!should_trace_pid(pid) || !should_trace_cpu(cpu) ||
		!should_trace_event(POWER_DEVICE_PM_START))
	{
		return 0;
	}

	/* Fill common header */
	fill_common_header(&event.header, POWER_DEVICE_PM_START);

	/* Fill device PM specific data - simplified */
	event.data.device_pm.device_name[0] = '\0'; /* Empty for now */
	event.data.device_pm.pm_event = 0;
	event.data.device_pm.pm_state = 0;
	event.data.device_pm.duration_ns = 0;
	event.data.device_pm.ret = 0;

	/* Submit event */
	submit_event(&event);

	return 0;
}

/* Simple demonstration tracepoint - using available syscall entry */
SEC("tracepoint/syscalls/sys_enter_nanosleep")
int handle_demo_power_event(void *ctx)
{
	struct power_event_t event = {};
	__u32 cpu = bpf_get_smp_processor_id();
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Apply filters */
	if (!should_trace_pid(pid) || !should_trace_cpu(cpu) ||
		!should_trace_event(POWER_CPU_FREQ))
	{
		return 0;
	}

	/* Fill common header */
	fill_common_header(&event.header, POWER_CPU_FREQ);

	/* Fill demo data */
	event.data.cpu_freq.cpu_id = cpu;
	event.data.cpu_freq.new_freq = 1000000; /* Demo: 1GHz */
	event.data.cpu_freq.old_freq = 800000;	/* Demo: 800MHz */

	/* Submit event */
	submit_event(&event);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";