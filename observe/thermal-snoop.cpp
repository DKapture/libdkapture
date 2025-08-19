// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 DKapture Project
//
// Based on dkapture framework thermal management observation tool.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <thread>

#include "thermal-snoop.skel.h"
#include "dkapture.h"
#include "thermal-snoop.h"

static struct ring_buffer *rb = NULL;
static struct thermal_snoop_bpf *obj = NULL;
static volatile bool exiting = false;

#ifdef BUILTIN
static std::thread *rb_thread = nullptr;
#endif

/* Environment structure for command line arguments */
struct env
{
	__u32 pid;
	__u32 cpu;
	char comm[16];
	__u32 event_mask;
	__s32 min_temp;
	__s32 max_temp;
	__u32 zone_filter;
	bool verbose;
	bool timestamp;
	bool stats;
	bool celsius;
	time_t interval;
	int times;
} env = {
	.pid = 0,
	.cpu = (__u32)-1,
	.comm = "",
	.event_mask = THERMAL_EVENT_MASK_ALL,
	.min_temp = 0,
	.max_temp = 0,
	.zone_filter = 0,
	.verbose = false,
	.timestamp = false,
	.stats = false,
	.celsius = true,
	.interval = 99999999,
	.times = 99999999,
};

static struct thermal_stats global_stats = {};

const char argp_program_doc[] =
	"thermal-snoop - Thermal management subsystem observation tool\n"
	"\n"
	"USAGE: thermal-snoop [OPTIONS]\n"
	"\n"
	"EXAMPLES:\n"
	"    thermal-snoop                           # Trace all thermal events\n"
	"    thermal-snoop -p 1234                   # Trace specific process\n"
	"    thermal-snoop -c 0                      # Trace specific CPU\n"
	"    thermal-snoop -e 0x03                   # Trace temp updates and trips\n"
	"    thermal-snoop --min-temp 50000          # Trace temperatures >= 50°C\n"
	"    thermal-snoop -z 1                      # Trace specific thermal zone\n"
	"    thermal-snoop -v -t                     # Verbose output with timestamps\n"
	"    thermal-snoop -s                        # Show statistics\n"
	"\n"
	"Event types (for -e bitmask):\n"
	"    1   TEMP_UPDATE     Temperature updates\n"
	"    2   TRIP_TRIGGER    Trip point triggers\n"
	"    4   CDEV_UPDATE     Cooling device updates\n"
	"    8   POWER_ALLOC     Power allocator events\n"
	"    16  POWER_PID       PID power control events\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "cpu", 'c', "CPU", 0, "CPU ID to trace", 0 },
	{ "comm", 'C', "COMM", 0, "Process name to trace", 0 },
	{ "events", 'e', "MASK", 0, "Event types to trace (bitmask)", 0 },
	{ "zone", 'z', "ZONE", 0, "Thermal zone ID to trace", 0 },
	{ "min-temp", ARG_MIN_TEMP, "TEMP", 0,
	  "Minimum temperature to trace (millicelsius)", 0 },
	{ "max-temp", ARG_MAX_TEMP, "TEMP", 0,
	  "Maximum temperature to trace (millicelsius)", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose output", 0 },
	{ "timestamp", 't', NULL, 0, "Show timestamps", 0 },
	{ "stats", 's', NULL, 0, "Show statistics", 0 },
	{ "celsius", ARG_CELSIUS, NULL, 0,
	  "Display temperatures in Celsius (default)", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key)
	{
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno)
		{
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		errno = 0;
		env.cpu = strtol(arg, NULL, 10);
		if (errno)
		{
			fprintf(stderr, "invalid CPU: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'C':
		strncpy(env.comm, arg, sizeof(env.comm) - 1);
		env.comm[sizeof(env.comm) - 1] = '\0';
		break;
	case 'e':
		errno = 0;
		env.event_mask = strtol(arg, NULL, 0);
		if (errno)
		{
			fprintf(stderr, "invalid event mask: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'z':
		errno = 0;
		env.zone_filter = strtol(arg, NULL, 10);
		if (errno)
		{
			fprintf(stderr, "invalid zone filter: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARG_MIN_TEMP:
		errno = 0;
		env.min_temp = strtol(arg, NULL, 10);
		if (errno)
		{
			fprintf(stderr, "invalid min temperature: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARG_MAX_TEMP:
		errno = 0;
		env.max_temp = strtol(arg, NULL, 10);
		if (errno)
		{
			fprintf(stderr, "invalid max temperature: %s\n", arg);
			argp_usage(state);
		}
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
	case ARG_CELSIUS:
		env.celsius = true;
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0)
		{
			env.interval = strtol(arg, NULL, 10);
			if (errno)
			{
				fprintf(stderr, "invalid interval\n");
				argp_usage(state);
			}
		}
		else if (pos_args == 1)
		{
			env.times = strtol(arg, NULL, 10);
			if (errno)
			{
				fprintf(stderr, "invalid times\n");
				argp_usage(state);
			}
		}
		else
		{
			fprintf(stderr,
				"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

static const char *thermal_event_type_str(__u32 event_type)
{
	switch (event_type)
	{
	case THERMAL_TEMP_UPDATE:
		return "TEMP_UPDATE";
	case THERMAL_TRIP_TRIGGERED:
		return "TRIP_TRIGGER";
	case THERMAL_CDEV_UPDATE:
		return "CDEV_UPDATE";
	case THERMAL_POWER_ALLOC:
		return "POWER_ALLOC";
	case THERMAL_POWER_PID:
		return "POWER_PID";
	default:
		return "UNKNOWN";
	}
}

static const char *format_temperature(__s32 milli_temp)
{
	static char temp_str[64];

	if (env.celsius)
	{
		snprintf(temp_str, sizeof(temp_str), "%.1f°C",
			 (double)milli_temp / 1000.0);
	}
	else
	{
		snprintf(temp_str, sizeof(temp_str), "%.1f°F",
			 ((double)milli_temp / 1000.0) * 9.0 / 5.0 + 32.0);
	}

	return temp_str;
}

static const char *trip_type_description(const char *trip_type)
{
	if (strstr(trip_type, "critical"))
		return "CRITICAL";
	else if (strstr(trip_type, "hot"))
		return "HOT";
	else if (strstr(trip_type, "passive"))
		return "PASSIVE";
	else if (strstr(trip_type, "active"))
		return "ACTIVE";
	else
		return "UNKNOWN";
}

static const char *cdev_type_description(const char *cdev_type)
{
	if (strstr(cdev_type, "cpufreq"))
		return "CPU-FREQ";
	else if (strstr(cdev_type, "fan"))
		return "FAN";
	else if (strstr(cdev_type, "thermal"))
		return "THERMAL";
	else
		return cdev_type;
}

static void print_timestamp()
{
	if (env.timestamp)
	{
		struct timespec ts;
		struct tm *tm;
		char time_str[64];

		clock_gettime(CLOCK_REALTIME, &ts);
		tm = localtime(&ts.tv_sec);
		strftime(time_str, sizeof(time_str), "%H:%M:%S", tm);
		printf("[%s.%06ld] ", time_str, ts.tv_nsec / 1000);
	}
}

#ifndef BUILTIN
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct thermal_event *e = (const struct thermal_event *)data;

	/* Update global statistics */
	global_stats.total_events++;

	switch (e->header.event_type)
	{
	case THERMAL_TEMP_UPDATE:
		global_stats.temp_update_events++;
		global_stats.temp_readings++;

		if (global_stats.min_temp_seen == 0 ||
		    e->data.temp_update.temperature <
			    global_stats.min_temp_seen)
			global_stats.min_temp_seen =
				e->data.temp_update.temperature;
		if (e->data.temp_update.temperature >
		    global_stats.max_temp_seen)
			global_stats.max_temp_seen =
				e->data.temp_update.temperature;

		print_timestamp();
		if (env.verbose)
		{
			printf("CPU[%u] PID:%u %s\n", e->header.cpu,
			       e->header.pid, e->header.comm);
			printf("  Event: TEMP_UPDATE\n");
			printf("  Zone: zone%u (%s)\n",
			       e->data.temp_update.thermal_zone_id,
			       e->data.temp_update.zone_type);
			printf("  Temperature: %s -> %s\n",
			       format_temperature(
				       e->data.temp_update.prev_temp),
			       format_temperature(
				       e->data.temp_update.temperature));
			printf("  Change: %+.1f°C\n",
			       (double)(e->data.temp_update.temperature -
					e->data.temp_update.prev_temp) /
				       1000.0);
			printf("\n");
		}
		else
		{
			printf("[%u] %-12s zone%u (%s): %s -> %s\n",
			       e->header.cpu, "TEMP_UPDATE",
			       e->data.temp_update.thermal_zone_id,
			       e->data.temp_update.zone_type,
			       format_temperature(
				       e->data.temp_update.prev_temp),
			       format_temperature(
				       e->data.temp_update.temperature));
		}
		break;

	case THERMAL_TRIP_TRIGGERED:
		global_stats.trip_events++;

		if (strstr(e->data.trip_event.trip_type, "critical"))
			global_stats.critical_trips++;
		else if (strstr(e->data.trip_event.trip_type, "hot"))
			global_stats.hot_trips++;
		else if (strstr(e->data.trip_event.trip_type, "passive"))
			global_stats.passive_trips++;
		else if (strstr(e->data.trip_event.trip_type, "active"))
			global_stats.active_trips++;

		print_timestamp();
		if (env.verbose)
		{
			printf("CPU[%u] PID:%u %s\n", e->header.cpu,
			       e->header.pid, e->header.comm);
			printf("  Event: TRIP_TRIGGER\n");
			printf("  Zone: zone%u (ID: %u)\n",
			       e->data.trip_event.thermal_zone_id,
			       e->data.trip_event.trip_id);
			printf("  Trip: %s\n",
			       trip_type_description(
				       e->data.trip_event.trip_type));
			printf("  Trip Temperature: %s\n",
			       format_temperature(
				       e->data.trip_event.trip_temp));
			printf("  Current Temperature: %s\n",
			       format_temperature(
				       e->data.trip_event.current_temp));
			printf("  Hysteresis: %s\n",
			       format_temperature(
				       e->data.trip_event.trip_hyst));
			printf("\n");
		}
		else
		{
			printf("[%u] %-12s zone%u: %s trip at %s (current: %s)\n",
			       e->header.cpu, "TRIP_TRIGGER",
			       e->data.trip_event.thermal_zone_id,
			       trip_type_description(
				       e->data.trip_event.trip_type),
			       format_temperature(e->data.trip_event.trip_temp),
			       format_temperature(
				       e->data.trip_event.current_temp));
		}
		break;

	case THERMAL_CDEV_UPDATE:
		global_stats.cdev_update_events++;
		global_stats.cdev_activations++;

		if (e->data.cdev_update.new_state >
		    e->data.cdev_update.old_state)
			global_stats.throttling_events++;

		print_timestamp();
		if (env.verbose)
		{
			printf("CPU[%u] PID:%u %s\n", e->header.cpu,
			       e->header.pid, e->header.comm);
			printf("  Event: CDEV_UPDATE\n");
			printf("  Device: %s (ID: %u)\n",
			       e->data.cdev_update.cdev_type,
			       e->data.cdev_update.cdev_id);
			printf("  State: %u -> %u (max: %u)\n",
			       e->data.cdev_update.old_state,
			       e->data.cdev_update.new_state,
			       e->data.cdev_update.max_state);
			printf("  Power: %llu mW\n", e->data.cdev_update.power);
			printf("\n");
		}
		else
		{
			printf("[%u] %-12s %s: state %u -> %u (max: %u)\n",
			       e->header.cpu, "CDEV_UPDATE",
			       cdev_type_description(
				       e->data.cdev_update.cdev_type),
			       e->data.cdev_update.old_state,
			       e->data.cdev_update.new_state,
			       e->data.cdev_update.max_state);
		}
		break;

	case THERMAL_POWER_ALLOC:
		global_stats.power_alloc_events++;

		print_timestamp();
		if (env.verbose)
		{
			printf("CPU[%u] PID:%u %s\n", e->header.cpu,
			       e->header.pid, e->header.comm);
			printf("  Event: POWER_ALLOC\n");
			printf("  Zone: zone%u\n",
			       e->data.power_alloc.thermal_zone_id);
			printf("  Requested: %u mW\n",
			       e->data.power_alloc.total_req_power);
			printf("  Granted: %u mW\n",
			       e->data.power_alloc.granted_power);
			printf("  Delta Temp: %s\n",
			       format_temperature(
				       e->data.power_alloc.delta_temp));
			printf("  Switch On: %s\n",
			       format_temperature(
				       e->data.power_alloc.switch_on_temp));
			printf("\n");
		}
		else
		{
			printf("[%u] %-12s zone%u: req=%umW granted=%umW delta=%s\n",
			       e->header.cpu, "POWER_ALLOC",
			       e->data.power_alloc.thermal_zone_id,
			       e->data.power_alloc.total_req_power,
			       e->data.power_alloc.granted_power,
			       format_temperature(
				       e->data.power_alloc.delta_temp));
		}
		break;

	case THERMAL_POWER_PID:
		global_stats.power_pid_events++;

		print_timestamp();
		if (env.verbose)
		{
			printf("CPU[%u] PID:%u %s\n", e->header.cpu,
			       e->header.pid, e->header.comm);
			printf("  Event: POWER_PID\n");
			printf("  Zone: zone%u\n",
			       e->data.power_pid.thermal_zone_id);
			printf("  Error: %s\n",
			       format_temperature(e->data.power_pid.err));
			printf("  P Term: %d\n", e->data.power_pid.p_term);
			printf("  I Term: %d\n", e->data.power_pid.i_term);
			printf("  D Term: %d\n", e->data.power_pid.d_term);
			printf("  Output: %d\n", e->data.power_pid.output);
			printf("\n");
		}
		else
		{
			printf("[%u] %-12s zone%u: err=%s P=%d I=%d D=%d out=%d\n",
			       e->header.cpu, "POWER_PID",
			       e->data.power_pid.thermal_zone_id,
			       format_temperature(e->data.power_pid.err),
			       e->data.power_pid.p_term,
			       e->data.power_pid.i_term,
			       e->data.power_pid.d_term,
			       e->data.power_pid.output);
		}
		break;

	default:
		printf("Unknown event type: %u\n", e->header.event_type);
		break;
	}

	return 0;
}
#endif

static void print_stats()
{
	if (!env.stats)
		return;

	printf("\nThermal Monitoring Statistics:\n");
	printf("==============================\n");
	printf("Total Events:           %llu\n", global_stats.total_events);
	printf("├─ Temperature Updates: %llu (%.1f%%)\n",
	       global_stats.temp_update_events,
	       global_stats.total_events ?
		       (double)global_stats.temp_update_events * 100.0 /
			       global_stats.total_events :
		       0.0);
	printf("├─ Trip Triggers:       %llu (%.1f%%)\n",
	       global_stats.trip_events,
	       global_stats.total_events ?
		       (double)global_stats.trip_events * 100.0 /
			       global_stats.total_events :
		       0.0);
	printf("├─ Cooling Dev Updates: %llu (%.1f%%)\n",
	       global_stats.cdev_update_events,
	       global_stats.total_events ?
		       (double)global_stats.cdev_update_events * 100.0 /
			       global_stats.total_events :
		       0.0);
	printf("├─ Power Allocator:     %llu (%.1f%%)\n",
	       global_stats.power_alloc_events,
	       global_stats.total_events ?
		       (double)global_stats.power_alloc_events * 100.0 /
			       global_stats.total_events :
		       0.0);
	printf("└─ Power PID Control:   %llu (%.1f%%)\n",
	       global_stats.power_pid_events,
	       global_stats.total_events ?
		       (double)global_stats.power_pid_events * 100.0 /
			       global_stats.total_events :
		       0.0);
	printf("\n");

	if (global_stats.temp_readings > 0)
	{
		printf("Temperature Range:\n");
		printf("├─ Minimum: %s\n",
		       format_temperature(global_stats.min_temp_seen));
		printf("├─ Maximum: %s\n",
		       format_temperature(global_stats.max_temp_seen));
		printf("└─ Readings: %llu\n", global_stats.temp_readings);
		printf("\n");
	}

	if (global_stats.trip_events > 0)
	{
		printf("Trip Point Events:\n");
		printf("├─ Critical: %llu\n", global_stats.critical_trips);
		printf("├─ Hot: %llu\n", global_stats.hot_trips);
		printf("├─ Passive: %llu\n", global_stats.passive_trips);
		printf("└─ Active: %llu\n", global_stats.active_trips);
		printf("\n");
	}

	if (global_stats.cdev_update_events > 0)
	{
		printf("Cooling Device Activity:\n");
		printf("├─ Activations: %llu\n", global_stats.cdev_activations);
		printf("└─ Throttling Events: %llu\n",
		       global_stats.throttling_events);
		printf("\n");
	}
}

#ifdef BUILTIN
static void ringbuffer_worker()
{
	while (!exiting)
	{
		ring_buffer__poll(rb, 500 /* timeout, ms */);
	}
}
#endif

static void thermal_snoop_deinit()
{
#ifdef BUILTIN
	if (rb_thread)
	{
		rb_thread->join();
		delete rb_thread;
		rb_thread = nullptr;
	}
#endif

	if (rb)
		ring_buffer__free(rb);
	thermal_snoop_bpf__destroy(obj);
}

#ifdef BUILTIN
int thermal_snoop_init(callback_func_t callback)
#else
int main(int argc, char **argv)
#endif
{
	int err;

#ifndef BUILTIN
	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
#endif

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	/* Setup signal handlers */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Open BPF application */
	obj = thermal_snoop_bpf__open();
	if (!obj)
	{
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* Initialize rodata */
	obj->rodata->targ_verbose = env.verbose;
	obj->rodata->targ_timestamp = env.timestamp;

	/* Load & verify BPF programs */
	err = thermal_snoop_bpf__load(obj);
	if (err)
	{
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/* Attach BPF programs */
	err = thermal_snoop_bpf__attach(obj);
	if (err)
	{
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	/* Setup filter if needed */
	{
		struct thermal_filter filter = {};
		__u32 key = 0;

		filter.target_pid = env.pid;
		filter.target_cpu = env.cpu;
		strncpy(filter.target_comm, env.comm,
			sizeof(filter.target_comm) - 1);
		filter.event_mask = env.event_mask;
		filter.min_temp = env.min_temp;
		filter.max_temp = env.max_temp;
		filter.thermal_zone_mask =
			env.zone_filter ? (1 << env.zone_filter) : 0;

		bpf_map__update_elem(obj->maps.filter_map, &key, sizeof(key),
				     &filter, sizeof(filter), BPF_ANY);
	}

	/* Setup ring buffer polling */
#ifdef BUILTIN
	rb = ring_buffer__new(bpf_map__fd(obj->maps.thermal_events), callback,
			      NULL, NULL);
#else
	rb = ring_buffer__new(bpf_map__fd(obj->maps.thermal_events),
			      handle_event, NULL, NULL);
#endif
	if (!rb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

#ifndef BUILTIN
	if (env.verbose)
		printf("thermal-snoop: Tracing thermal management events... Ctrl-C to end.\n");

	/* Main event loop */
	while (!exiting)
	{
		err = ring_buffer__poll(rb, 500 /* timeout, ms */);
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

	print_stats();
#else
	/* BUILTIN mode - start background thread */
	rb_thread = new std::thread(ringbuffer_worker);
#endif

cleanup:
#ifndef BUILTIN
	thermal_snoop_deinit();
	return err != 0;
#else
	if (err != 0)
		thermal_snoop_deinit();
	return err;
#endif
}