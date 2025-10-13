// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
#include <limits.h>
#include <getopt.h>
#include <string>
#include <signal.h>
#include <pthread.h>
#include <stdint.h>

#include "sched-snoop.skel.h"
#include "com.h"

#define TASK_COMM_LEN 16

// Event types (matching kernel side)
enum sched_event_type
{
	SCHED_SWITCH = 1,
	SCHED_WAKEUP = 2,
	SCHED_MIGRATE = 3,
	SCHED_FORK = 4,
	SCHED_EXIT = 5,
	SCHED_EXEC = 6,
	SCHED_STAT_RUNTIME = 7,
	SCHED_STAT_WAIT = 8,
	SCHED_STAT_SLEEP = 9,
	SCHED_STAT_BLOCKED = 10,
	SCHED_STAT_IOWAIT = 11,
	SCHED_WAKEUP_NEW = 12,
};

// Filter configuration
struct Rule
{
	uint32_t target_pid; // 0 means no filter
	int target_cpu;		 // -1 means no filter
	char target_comm[TASK_COMM_LEN];
	uint32_t event_mask; // Bitmask of events to trace
};

// Common event data structure (matching kernel side)
struct BpfData
{
	uint64_t timestamp;
	uint32_t cpu;
	uint32_t event_type;

	// Common fields for all events
	char comm[TASK_COMM_LEN];
	uint32_t pid;
	uint32_t prio;

	// Event-specific data (union to save space)
	union
	{
		// For SCHED_SWITCH
		struct
		{
			char prev_comm[TASK_COMM_LEN];
			uint32_t prev_pid;
			uint32_t prev_prio;
			uint64_t prev_state;
			char next_comm[TASK_COMM_LEN];
			uint32_t next_pid;
			uint32_t next_prio;
		} switch_data;

		// For SCHED_WAKEUP
		struct
		{
			uint32_t target_cpu;
		} wakeup_data;

		// For SCHED_MIGRATE
		struct
		{
			uint32_t orig_cpu;
			uint32_t dest_cpu;
		} migrate_data;

		// For SCHED_FORK
		struct
		{
			char parent_comm[TASK_COMM_LEN];
			uint32_t parent_pid;
			char child_comm[TASK_COMM_LEN];
			uint32_t child_pid;
		} fork_data;

		// For SCHED_STAT_* events
		struct
		{
			uint64_t delay;	  // delay time in nanoseconds
			uint64_t runtime; // runtime in nanoseconds
		} stat_data;

		// For SCHED_EXIT and SCHED_EXEC - use common fields only
	};
};

static struct sched_snoop_bpf *skel;
static struct Rule rule = {0, -1, "", 0x3F}; // Default: trace all events

static const char *event_type_str(uint32_t event_type)
{
	switch (event_type)
	{
	case SCHED_SWITCH:
		return "SWITCH";
	case SCHED_WAKEUP:
		return "WAKEUP";
	case SCHED_WAKEUP_NEW:
		return "WAKEUP_NEW";
	case SCHED_MIGRATE:
		return "MIGRATE";
	case SCHED_FORK:
		return "FORK";
	case SCHED_EXIT:
		return "EXIT";
	case SCHED_EXEC:
		return "EXEC";
	case SCHED_STAT_RUNTIME:
		return "STAT_RT";
	case SCHED_STAT_WAIT:
		return "STAT_WAIT";
	case SCHED_STAT_SLEEP:
		return "STAT_SLEEP";
	case SCHED_STAT_BLOCKED:
		return "STAT_BLOCK";
	case SCHED_STAT_IOWAIT:
		return "STAT_IOWAIT";
	default:
		return "UNKNOWN";
	}
}

static const char *state_to_str(uint64_t state)
{
	switch (state)
	{
	case 0x0000:
		return "R"; // Running
	case 0x0001:
		return "S"; // Interruptible sleep
	case 0x0002:
		return "D"; // Uninterruptible sleep
	case 0x0004:
		return "T"; // Stopped
	case 0x0008:
		return "t"; // Tracing stop
	case 0x0010:
		return "X"; // Dead
	case 0x0020:
		return "Z"; // Zombie
	case 0x0040:
		return "P"; // Parked
	case 0x0080:
		return "I"; // Idle
	default:
		return "?";
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct BpfData *log = (const struct BpfData *)data;
	struct tm *tm;
	char ts[32];
	time_t t;

	// Apply comm filter in userspace if specified
	if (rule.target_comm[0] != '\0')
	{
		bool match_found = false;

		// Check main comm field
		if (strstr(log->comm, rule.target_comm) != nullptr)
		{
			match_found = true;
		}

		// For switch events, also check prev/next comm
		if (!match_found && log->event_type == SCHED_SWITCH)
		{
			if (strstr(log->switch_data.prev_comm, rule.target_comm) !=
					nullptr ||
				strstr(log->switch_data.next_comm, rule.target_comm) != nullptr)
			{
				match_found = true;
			}
		}

		// For fork events, check parent/child comm
		if (!match_found && log->event_type == SCHED_FORK)
		{
			if (strstr(log->fork_data.parent_comm, rule.target_comm) !=
					nullptr ||
				strstr(log->fork_data.child_comm, rule.target_comm) != nullptr)
			{
				match_found = true;
			}
		}

		if (!match_found)
		{
			return 0;
		}
	}

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s [%03d] %-7s ", ts, log->cpu, event_type_str(log->event_type));

	switch (log->event_type)
	{
	case SCHED_SWITCH:
		printf(
			"%16s:%-7d [%3d] %s ==> %16s:%-7d [%3d]\n",
			log->switch_data.prev_comm,
			log->switch_data.prev_pid,
			log->switch_data.prev_prio,
			state_to_str(log->switch_data.prev_state),
			log->switch_data.next_comm,
			log->switch_data.next_pid,
			log->switch_data.next_prio
		);
		break;

	case SCHED_WAKEUP:
		printf(
			"%16s:%-7d [%3d] target_cpu=%d\n",
			log->comm,
			log->pid,
			log->prio,
			log->wakeup_data.target_cpu
		);
		break;

	case SCHED_WAKEUP_NEW:
		printf(
			"%16s:%-7d [%3d] target_cpu=%d (new)\n",
			log->comm,
			log->pid,
			log->prio,
			log->wakeup_data.target_cpu
		);
		break;

	case SCHED_MIGRATE:
		printf(
			"%16s:%-7d [%3d] %d => %d\n",
			log->comm,
			log->pid,
			log->prio,
			log->migrate_data.orig_cpu,
			log->migrate_data.dest_cpu
		);
		break;

	case SCHED_FORK:
		printf(
			"%16s:%-7d => %16s:%-7d\n",
			log->fork_data.parent_comm,
			log->fork_data.parent_pid,
			log->fork_data.child_comm,
			log->fork_data.child_pid
		);
		break;

	case SCHED_EXIT:
		printf("%16s:%-7d [%3d] exited\n", log->comm, log->pid, log->prio);
		break;

	case SCHED_EXEC:
		printf(
			"%16s:%-7d [%3d] exec: %s\n",
			log->comm,
			log->pid,
			log->prio,
			log->comm
		);
		break;

	case SCHED_STAT_RUNTIME:
		printf(
			"%16s:%-7d [%3d] runtime=%lu ns\n",
			log->comm,
			log->pid,
			log->prio,
			log->stat_data.runtime
		);
		break;

	case SCHED_STAT_WAIT:
		printf(
			"%16s:%-7d [%3d] wait_delay=%lu ns\n",
			log->comm,
			log->pid,
			log->prio,
			log->stat_data.delay
		);
		break;

	case SCHED_STAT_SLEEP:
		printf(
			"%16s:%-7d [%3d] sleep_delay=%lu ns\n",
			log->comm,
			log->pid,
			log->prio,
			log->stat_data.delay
		);
		break;

	case SCHED_STAT_BLOCKED:
		printf(
			"%16s:%-7d [%3d] blocked_delay=%lu ns\n",
			log->comm,
			log->pid,
			log->prio,
			log->stat_data.delay
		);
		break;

	case SCHED_STAT_IOWAIT:
		printf(
			"%16s:%-7d [%3d] iowait_delay=%lu ns\n",
			log->comm,
			log->pid,
			log->prio,
			log->stat_data.delay
		);
		break;

	default:
		printf(
			"%16s:%-7d [%3d] unknown event\n",
			log->comm,
			log->pid,
			log->prio
		);
		break;
	}

	return 0;
}

static void cleanup()
{
	if (skel)
	{
		sched_snoop_bpf__destroy(skel);
		skel = nullptr;
	}
}

static void sig_handler(int sig)
{
	cleanup();
	exit(0);
}

static void print_usage(const char *prog_name)
{
	printf("Usage: %s [OPTIONS]\n", prog_name);
	printf("Trace scheduler events\n\n");
	printf("Options:\n");
	printf("  -p PID        Trace specific process ID\n");
	printf("  -c CPU        Trace specific CPU core\n");
	printf("  -C COMM       Filter by command name (substring match)\n");
	printf("  -e EVENTS     Event types to trace (comma-separated):\n");
	printf("                  switch        - Context switches\n");
	printf("                  wakeup        - Process wakeups\n");
	printf("                  wakeup_new    - New process wakeups\n");
	printf("                  migrate       - Process migrations\n");
	printf("                  fork          - Process forks\n");
	printf("                  exit          - Process exits\n");
	printf("                  exec          - Process execs\n");
	printf("                  stat_runtime  - Runtime statistics\n");
	printf("                  stat_wait     - Wait time statistics\n");
	printf("                  stat_sleep    - Sleep time statistics\n");
	printf("                  stat_blocked  - Blocked time statistics\n");
	printf("                  stat_iowait   - IO wait statistics\n");
	printf("                  all           - All event types\n");
	printf("                Default: switch,wakeup,migrate,fork,exit,exec\n");
	printf("  -h            Show this help\n");
	printf("\nExamples:\n");
	printf(
		"  %s                    # Trace basic scheduler events\n",
		prog_name
	);
	printf("  %s -p 1234            # Trace events for PID 1234\n", prog_name);
	printf("  %s -c 0               # Trace events on CPU 0\n", prog_name);
	printf(
		"  %s -C ssh             # Trace events for processes containing "
		"'ssh'\n",
		prog_name
	);
	printf(
		"  %s -e switch,fork     # Trace only switch and fork events\n",
		prog_name
	);
	printf("  %s -e all             # Trace all available events\n", prog_name);
	printf(
		"  %s -e stat_runtime    # Trace only runtime statistics\n",
		prog_name
	);
}

static uint32_t parse_events(const char *events_str)
{
	uint32_t mask = 0;
	char *events_copy = strdup(events_str);
	char *token = strtok(events_copy, ",");

	while (token != nullptr)
	{
		if (strcmp(token, "switch") == 0)
		{
			mask |= (1 << SCHED_SWITCH);
		}
		else if (strcmp(token, "wakeup") == 0)
		{
			mask |= (1 << SCHED_WAKEUP);
		}
		else if (strcmp(token, "wakeup_new") == 0)
		{
			mask |= (1 << SCHED_WAKEUP_NEW);
		}
		else if (strcmp(token, "migrate") == 0)
		{
			mask |= (1 << SCHED_MIGRATE);
		}
		else if (strcmp(token, "fork") == 0)
		{
			mask |= (1 << SCHED_FORK);
		}
		else if (strcmp(token, "exit") == 0)
		{
			mask |= (1 << SCHED_EXIT);
		}
		else if (strcmp(token, "exec") == 0)
		{
			mask |= (1 << SCHED_EXEC);
		}
		else if (strcmp(token, "stat_runtime") == 0)
		{
			mask |= (1 << SCHED_STAT_RUNTIME);
		}
		else if (strcmp(token, "stat_wait") == 0)
		{
			mask |= (1 << SCHED_STAT_WAIT);
		}
		else if (strcmp(token, "stat_sleep") == 0)
		{
			mask |= (1 << SCHED_STAT_SLEEP);
		}
		else if (strcmp(token, "stat_blocked") == 0)
		{
			mask |= (1 << SCHED_STAT_BLOCKED);
		}
		else if (strcmp(token, "stat_iowait") == 0)
		{
			mask |= (1 << SCHED_STAT_IOWAIT);
		}
		else if (strcmp(token, "all") == 0)
		{
			mask = 0xFFFF; // Enable all events
		}
		else
		{
			fprintf(stderr, "Unknown event type: %s\n", token);
			free(events_copy);
			return 0;
		}
		token = strtok(nullptr, ",");
	}

	free(events_copy);
	return mask;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = nullptr;
	int opt;

	while ((opt = getopt(argc, argv, "p:c:C:e:h")) != -1)
	{
		switch (opt)
		{
		case 'p':
			rule.target_pid = atoi(optarg);
			break;
		case 'c':
			rule.target_cpu = atoi(optarg);
			break;
		case 'C':
			strncpy(rule.target_comm, optarg, TASK_COMM_LEN - 1);
			rule.target_comm[TASK_COMM_LEN - 1] = '\0';
			break;
		case 'e':
			rule.event_mask = parse_events(optarg);
			if (rule.event_mask == 0)
			{
				fprintf(stderr, "Invalid event specification\n");
				return 1;
			}
			break;
		case 'h':
			print_usage(argv[0]);
			return 0;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = sched_snoop_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	int err = sched_snoop_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		cleanup();
		return 1;
	}

	err = sched_snoop_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		cleanup();
		return 1;
	}

	// Set filter rules
	uint32_t key = 0;
	err = bpf_map_update_elem(
		bpf_map__fd(skel->maps.filter),
		&key,
		&rule,
		BPF_ANY
	);
	if (err)
	{
		fprintf(stderr, "Failed to set filter rules: %d\n", err);
		cleanup();
		return 1;
	}

	rb = ring_buffer__new(
		bpf_map__fd(skel->maps.logs),
		handle_event,
		nullptr,
		nullptr
	);
	if (!rb)
	{
		fprintf(stderr, "Failed to create ring buffer\n");
		cleanup();
		return 1;
	}

	printf("Tracing scheduler events... Hit Ctrl-C to end.\n");

	// Print header
	printf("%-8s %-5s %-7s %s\n", "TIME", "CPU", "EVENT", "DETAILS");
	printf("%-8s %-5s %-7s %s\n", "--------", "-----", "-------", "-------");

	while (true)
	{
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR)
		{
			break;
		}
		if (err < 0)
		{
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

	ring_buffer__free(rb);
	cleanup();
	return 0;
}