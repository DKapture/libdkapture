// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 DKapture Project
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "dkapture.h"
#include "Kcom.h"

/* Thermal Event Types - Based on available thermal tracepoints */
enum thermal_event_type
{
	THERMAL_TEMP_UPDATE = 1,	/* thermal_temperature */
	THERMAL_TRIP_TRIGGERED = 2, /* thermal_zone_trip */
	THERMAL_CDEV_UPDATE = 3,	/* cdev_update */
	THERMAL_POWER_ALLOC = 4,	/* thermal_power_allocator */
	THERMAL_POWER_PID = 5,		/* thermal_power_allocator_pid */
};

/* Common thermal event header */
struct thermal_event_header
{
	__u64 timestamp;
	__u32 event_type;
	__u32 cpu;
	char comm[16]; /* TASK_COMM_LEN */
	__u32 pid;
	__u32 tid;
};

/* Thermal event structure with union for different event types */
struct thermal_event
{
	struct thermal_event_header header;

	/* Event-specific data (union to save space) */
	union
	{
		/* Temperature update event */
		struct
		{
			__u32 thermal_zone_id;
			__s32 temperature;	/* Temperature value (millicelsius) */
			char zone_type[32]; /* Thermal zone type name */
			__u32 zone_temp;	/* Current temperature */
			__u32 prev_temp;	/* Previous temperature */
		} temp_update;

		/* Trip point triggered event */
		struct
		{
			__u32 thermal_zone_id;
			__u32 trip_id;
			char trip_type[16]; /* passive, active, hot, critical */
			__s32 trip_temp;	/* Trip point temperature */
			__s32 current_temp; /* Current temperature */
			__u32 trip_hyst;	/* Hysteresis value */
		} trip_event;

		/* Cooling device update event */
		struct
		{
			__u32 cdev_id;
			char cdev_type[32]; /* Cooling device type */
			__u32 old_state;	/* Previous state */
			__u32 new_state;	/* New state */
			__u32 max_state;	/* Maximum state */
			__u64 power;		/* Power information */
		} cdev_update;

		/* Power allocator event */
		struct
		{
			__u32 thermal_zone_id;
			__u32 total_req_power;	 /* Total requested power */
			__u32 granted_power;	 /* Actually allocated power */
			__u32 extra_actor_power; /* Extra actor power */
			__s32 delta_temp;		 /* Temperature delta */
			__s32 switch_on_temp;	 /* Switch on temperature */
		} power_alloc;

		/* PID power control event */
		struct
		{
			__u32 thermal_zone_id;
			__s32 err;	  /* PID error value */
			__s32 p_term; /* Proportional term */
			__s32 i_term; /* Integral term */
			__s32 d_term; /* Derivative term */
			__s32 output; /* PID output */
		} power_pid;
	} data;
};

/* Filter configuration */
struct thermal_filter
{
	__u32 target_pid;		 /* 0 means no filter */
	__u32 target_cpu;		 /* -1 means no filter */
	char target_comm[16];	 /* Empty means no filter */
	__u32 event_mask;		 /* Bitmask of events to trace */
	__s32 min_temp;			 /* Minimum temperature threshold */
	__s32 max_temp;			 /* Maximum temperature threshold */
	__u32 thermal_zone_mask; /* Thermal zone ID bitmask */
	__u32 cdev_type_mask;	 /* Cooling device type mask */
};

/* Map sizes */
#define MAX_THERMAL_EVENTS 262144 /* Ring buffer size */
#define MAX_FILTER_RULES 1		  /* Filter rules map size */
#define MAX_ZONE_HISTORY 128	  /* Thermal zone history */
#define MAX_CDEV_TRACK 64		  /* Cooling device tracking */

/* Configuration from user space */
const volatile bool targ_verbose = false;
const volatile bool targ_timestamp = false;

/* BPF Maps */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_THERMAL_EVENTS);
} thermal_events SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct thermal_filter);
	__uint(max_entries, MAX_FILTER_RULES);
} filter_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);	  /* thermal_zone_id */
	__type(value, __s32); /* last_temperature */
	__uint(max_entries, MAX_ZONE_HISTORY);
} zone_temp_history SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);	  /* cdev_id */
	__type(value, __u32); /* last_state */
	__uint(max_entries, MAX_CDEV_TRACK);
} cdev_state_history SEC(".maps");

/* Helper functions */
static __always_inline bool should_trace_pid(__u32 pid)
{
	struct thermal_filter *filter;
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
	struct thermal_filter *filter;
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
	struct thermal_filter *filter;
	__u32 key = 0;

	filter = bpf_map_lookup_elem(&filter_map, &key);
	if (!filter)
	{
		return true;
	}

	return filter->event_mask & (1 << event_type);
}

static __always_inline bool should_trace_temp_range(__s32 temp)
{
	struct thermal_filter *filter;
	__u32 key = 0;

	filter = bpf_map_lookup_elem(&filter_map, &key);
	if (!filter)
	{
		return true;
	}

	if (filter->min_temp != 0 && temp < filter->min_temp)
	{
		return false;
	}
	if (filter->max_temp != 0 && temp > filter->max_temp)
	{
		return false;
	}

	return true;
}

static __always_inline bool should_trace_thermal_zone(__u32 zone_id)
{
	struct thermal_filter *filter;
	__u32 key = 0;

	filter = bpf_map_lookup_elem(&filter_map, &key);
	if (!filter)
	{
		return true;
	}

	if (filter->thermal_zone_mask == 0)
	{
		return true;
	}

	return filter->thermal_zone_mask & (1 << zone_id);
}

static __always_inline void
fill_common_header(struct thermal_event_header *header, __u32 event_type)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	header->timestamp = bpf_ktime_get_ns();
	header->event_type = event_type;
	header->cpu = bpf_get_smp_processor_id();
	header->pid = pid_tgid >> 32;
	header->tid = pid_tgid;
	bpf_get_current_comm(header->comm, sizeof(header->comm));
}

static __always_inline void submit_event(struct thermal_event *event)
{
	long ret = bpf_ringbuf_output(&thermal_events, event, sizeof(*event), 0);
	if (ret)
	{
		bpf_err("bpf_ringbuf_output err: %ld", ret);
	}
}

static __always_inline bool
is_significant_temp_change(__u32 zone_id, __s32 new_temp)
{
	__s32 *last_temp = bpf_map_lookup_elem(&zone_temp_history, &zone_id);

	if (!last_temp)
	{
		/* First reading for this zone */
		bpf_map_update_elem(&zone_temp_history, &zone_id, &new_temp, BPF_ANY);
		return true;
	}

	/* Check for significant change (>= 1000 millicelsius = 1°C) */
	__s32 diff = new_temp - *last_temp;
	if (diff < 0)
	{
		diff = -diff;
	}

	if (diff >= 1000)
	{
		bpf_map_update_elem(&zone_temp_history, &zone_id, &new_temp, BPF_ANY);
		return true;
	}

	return false;
}

/* Temperature reading tracepoint - thermal_temperature */
SEC("tracepoint/thermal/thermal_temperature")
int handle_thermal_temperature(void *ctx)
{
	struct thermal_event event = {};
	__u32 cpu = bpf_get_smp_processor_id();
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Apply filters */
	if (!should_trace_pid(pid) || !should_trace_cpu(cpu) ||
		!should_trace_event(THERMAL_TEMP_UPDATE))
	{
		return 0;
	}

	/* Fill common header */
	fill_common_header(&event.header, THERMAL_TEMP_UPDATE);

	/* Extract real thermal data from tracepoint context */
	/* Note: This requires proper tracepoint context structure */
	event.data.temp_update.thermal_zone_id = 0; /* Extract from ctx */
	event.data.temp_update.temperature = 0;		/* Extract from ctx */
	event.data.temp_update.zone_temp = event.data.temp_update.temperature;
	event.data.temp_update.prev_temp = 0; /* From history map */
	__builtin_memcpy(event.data.temp_update.zone_type, "thermal", 8);

	/* Apply temperature range filter */
	if (!should_trace_temp_range(event.data.temp_update.temperature))
	{
		return 0;
	}

	/* Check if this is a significant temperature change */
	if (!is_significant_temp_change(
			event.data.temp_update.thermal_zone_id,
			event.data.temp_update.temperature
		))
	{
		return 0;
	}

	/* Submit event */
	submit_event(&event);

	return 0;
}

/* Trip point trigger - thermal_zone_trip */
SEC("tracepoint/thermal/thermal_zone_trip")
int handle_thermal_zone_trip(void *ctx)
{
	struct thermal_event event = {};
	__u32 cpu = bpf_get_smp_processor_id();
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Apply filters */
	if (!should_trace_pid(pid) || !should_trace_cpu(cpu) ||
		!should_trace_event(THERMAL_TRIP_TRIGGERED))
	{
		return 0;
	}

	/* Fill common header */
	fill_common_header(&event.header, THERMAL_TRIP_TRIGGERED);

	/* Extract real trip data from tracepoint context */
	/* Note: This requires proper tracepoint context structure */
	event.data.trip_event.thermal_zone_id = 0; /* Extract from ctx */
	event.data.trip_event.trip_id = 0;		   /* Extract from ctx */
	event.data.trip_event.trip_temp = 0;	   /* Extract from ctx */
	event.data.trip_event.current_temp = 0;	   /* Extract from ctx */
	event.data.trip_event.trip_hyst = 0;	   /* Extract from ctx */
	__builtin_memcpy(event.data.trip_event.trip_type, "unknown", 8); /* Extract
																		from ctx
																	  */

	/* Apply thermal zone filter */
	if (!should_trace_thermal_zone(event.data.trip_event.thermal_zone_id))
	{
		return 0;
	}

	/* Apply temperature range filter */
	if (!should_trace_temp_range(event.data.trip_event.current_temp))
	{
		return 0;
	}

	/* Submit event */
	submit_event(&event);

	return 0;
}

/* Cooling device update - cdev_update */
SEC("tracepoint/thermal/cdev_update")
int handle_cdev_update(void *ctx)
{
	struct thermal_event event = {};
	__u32 cpu = bpf_get_smp_processor_id();
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Apply filters */
	if (!should_trace_pid(pid) || !should_trace_cpu(cpu) ||
		!should_trace_event(THERMAL_CDEV_UPDATE))
	{
		return 0;
	}

	/* Fill common header */
	fill_common_header(&event.header, THERMAL_CDEV_UPDATE);

	/* Extract real cooling device data from tracepoint context */
	/* Note: This requires proper tracepoint context structure */
	event.data.cdev_update.cdev_id = 0;	  /* Extract from ctx */
	event.data.cdev_update.old_state = 0; /* From history map */
	event.data.cdev_update.new_state = 0; /* Extract from ctx */
	event.data.cdev_update.max_state = 0; /* Extract from ctx */
	event.data.cdev_update.power = 0;	  /* Extract from ctx */
	__builtin_memcpy(event.data.cdev_update.cdev_type, "unknown", 8); /* Extract
																		 from
																		 ctx */

	/* Update cooling device state history */
	__u32 cdev_id = event.data.cdev_update.cdev_id;
	__u32 *last_state = bpf_map_lookup_elem(&cdev_state_history, &cdev_id);
	if (last_state)
	{
		event.data.cdev_update.old_state = *last_state;
	}
	bpf_map_update_elem(
		&cdev_state_history,
		&cdev_id,
		&event.data.cdev_update.new_state,
		BPF_ANY
	);

	/* Submit event */
	submit_event(&event);

	return 0;
}

/* Power devfreq get power - thermal_power_devfreq_get_power */
SEC("tracepoint/thermal/thermal_power_devfreq_get_power")
int handle_thermal_power_devfreq_get_power(void *ctx)
{
	struct thermal_event event = {};
	__u32 cpu = bpf_get_smp_processor_id();
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Apply filters */
	if (!should_trace_pid(pid) || !should_trace_cpu(cpu) ||
		!should_trace_event(THERMAL_POWER_ALLOC))
	{
		return 0;
	}

	/* Fill common header */
	fill_common_header(&event.header, THERMAL_POWER_ALLOC);

	/* Extract real power allocator data from tracepoint context */
	/* Note: This requires proper tracepoint context structure */
	event.data.power_alloc.thermal_zone_id = 0;	  /* Extract from ctx */
	event.data.power_alloc.total_req_power = 0;	  /* Extract from ctx */
	event.data.power_alloc.granted_power = 0;	  /* Extract from ctx */
	event.data.power_alloc.extra_actor_power = 0; /* Extract from ctx */
	event.data.power_alloc.delta_temp = 0;		  /* Extract from ctx */
	event.data.power_alloc.switch_on_temp = 0;	  /* Extract from ctx */

	/* Apply thermal zone filter */
	if (!should_trace_thermal_zone(event.data.power_alloc.thermal_zone_id))
	{
		return 0;
	}

	/* Apply temperature range filter for delta_temp */
	if (!should_trace_temp_range(event.data.power_alloc.switch_on_temp))
	{
		return 0;
	}

	/* Submit event */
	submit_event(&event);

	return 0;
}

/* Power devfreq limit - thermal_power_devfreq_limit */
SEC("tracepoint/thermal/thermal_power_devfreq_limit")
int handle_thermal_power_devfreq_limit(void *ctx)
{
	struct thermal_event event = {};
	__u32 cpu = bpf_get_smp_processor_id();
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	/* Apply filters */
	if (!should_trace_pid(pid) || !should_trace_cpu(cpu) ||
		!should_trace_event(THERMAL_POWER_PID))
	{
		return 0;
	}

	/* Fill common header */
	fill_common_header(&event.header, THERMAL_POWER_PID);

	/* Extract real PID control data from tracepoint context */
	/* Note: This requires proper tracepoint context structure */
	event.data.power_pid.thermal_zone_id = 0; /* Extract from ctx */
	event.data.power_pid.err = 0;			  /* Extract from ctx */
	event.data.power_pid.p_term = 0;		  /* Extract from ctx */
	event.data.power_pid.i_term = 0;		  /* Extract from ctx */
	event.data.power_pid.d_term = 0;		  /* Extract from ctx */
	event.data.power_pid.output = 0;		  /* Extract from ctx */

	/* Apply thermal zone filter */
	if (!should_trace_thermal_zone(event.data.power_pid.thermal_zone_id))
	{
		return 0;
	}

	/* Submit event */
	submit_event(&event);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";