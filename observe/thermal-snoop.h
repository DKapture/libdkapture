#ifndef __THERMAL_SNOOP_H
#define __THERMAL_SNOOP_H

#ifdef __KERNEL__
/* BPF program - use kernel types */
#include <linux/types.h>
#else
/* User space program - use standard types */
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#endif

#ifndef __BPF__
/* This is for user space program only */
#else
/* This is for BPF program - only use kernel types */
#ifndef __KERNEL__
#define __KERNEL__
#endif
#endif

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

/* Thermal statistics */
struct thermal_stats
{
	__u64 total_events;
	__u64 temp_update_events;
	__u64 trip_events;
	__u64 cdev_update_events;
	__u64 power_alloc_events;
	__u64 power_pid_events;

	/* Temperature statistics */
	__s32 min_temp_seen;
	__s32 max_temp_seen;
	__u64 temp_readings;

	/* Trip point statistics */
	__u64 critical_trips;
	__u64 hot_trips;
	__u64 passive_trips;
	__u64 active_trips;

	/* Cooling device statistics */
	__u64 cdev_activations;
	__u64 throttling_events;
};

/* Command line argument constants */
#define ARG_MIN_TEMP 1001
#define ARG_MAX_TEMP 1002
#define ARG_ZONE_FILTER 1003
#define ARG_CELSIUS 1004

/* Event Masks for filtering */
#define THERMAL_EVENT_MASK_ALL 0xFFFF
#define THERMAL_EVENT_MASK_TEMP_UPDATE (1 << THERMAL_TEMP_UPDATE)
#define THERMAL_EVENT_MASK_TRIP (1 << THERMAL_TRIP_TRIGGERED)
#define THERMAL_EVENT_MASK_CDEV_UPDATE (1 << THERMAL_CDEV_UPDATE)
#define THERMAL_EVENT_MASK_POWER_ALLOC (1 << THERMAL_POWER_ALLOC)
#define THERMAL_EVENT_MASK_POWER_PID (1 << THERMAL_POWER_PID)

/* Map sizes */
#define MAX_THERMAL_EVENTS 262144 /* Ring buffer size */
#define MAX_FILTER_RULES 1		  /* Filter rules map size */
#define MAX_ZONE_HISTORY 128	  /* Thermal zone history */
#define MAX_CDEV_TRACK 64		  /* Cooling device tracking */

/* Trip type definitions */
#define TRIP_TYPE_ACTIVE "active"
#define TRIP_TYPE_PASSIVE "passive"
#define TRIP_TYPE_HOT "hot"
#define TRIP_TYPE_CRITICAL "critical"

/* Temperature conversion helpers */
#define MILLICELSIUS_TO_CELSIUS(temp) ((double)(temp) / 1000.0)
#define MILLICELSIUS_TO_FAHRENHEIT(temp)                                       \
	(((double)(temp) / 1000.0) * 9.0 / 5.0 + 32.0)

#endif /* __THERMAL_SNOOP_H */