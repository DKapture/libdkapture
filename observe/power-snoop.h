#ifndef __POWER_SNOOP_H
#define __POWER_SNOOP_H

#ifdef __KERNEL__
/* BPF program - use kernel types */
#include <linux/types.h>
#else
/* User space program - use standard types */
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#endif

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

/* Power management states */
#define POWER_CPU_IDLE_EXIT_LATENCY 0
#define POWER_CPU_IDLE_TARGET_RESIDENCY 1

/* PM QoS types */
#define PM_QOS_CPU_DMA_LATENCY 1
#define PM_QOS_NETWORK_LATENCY 2
#define PM_QOS_NETWORK_THROUGHPUT 3

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
struct power_event
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

/* Power statistics */
struct power_stats
{
	__u64 total_events;
	__u64 cpu_freq_events;
	__u64 cpu_idle_events;
	__u64 device_pm_events;
	__u64 pm_qos_events;
	__u64 clock_events;
	__u64 rpm_events;

	/* CPU frequency statistics */
	__u32 min_freq_seen;
	__u32 max_freq_seen;
	__u64 freq_changes;

	/* CPU idle statistics */
	__u64 total_idle_time;
	__u64 idle_entries;
	__u64 idle_exits;

	/* Device PM statistics */
	__u64 device_suspends;
	__u64 device_resumes;
	__u64 pm_failures;
};

/* Command line argument constants */
#define ARG_MIN_FREQ 1001
#define ARG_MAX_FREQ 1002
#define ARG_MIN_IDLE 1003
#define ARG_MAX_IDLE 1004

/* Event Masks for filtering */
#define POWER_EVENT_MASK_ALL 0xFFFF
#define POWER_EVENT_MASK_CPU_FREQ (1 << POWER_CPU_FREQ)
#define POWER_EVENT_MASK_CPU_IDLE (1 << POWER_CPU_IDLE)
#define POWER_EVENT_MASK_DEVICE_PM                                             \
	((1 << POWER_DEVICE_PM_START) | (1 << POWER_DEVICE_PM_END))
#define POWER_EVENT_MASK_PM_QOS                                                \
	((1 << POWER_PM_QOS_ADD) | (1 << POWER_PM_QOS_UPDATE))
#define POWER_EVENT_MASK_CLOCK                                                 \
	((1 << POWER_CLOCK_ENABLE) | (1 << POWER_CLOCK_DISABLE))
#define POWER_EVENT_MASK_RPM                                                   \
	((1 << POWER_RPM_SUSPEND) | (1 << POWER_RPM_RESUME))

/* Map sizes */
#define MAX_POWER_EVENTS 262144 /* Ring buffer size */
#define MAX_FILTER_RULES 1		/* Filter rules map size */
#define MAX_CPU_HISTORY 256		/* CPU frequency history */
#define MAX_DEVICE_TRACK 1000	/* Device PM tracking */

#endif /* __POWER_SNOOP_H */