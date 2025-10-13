// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <inttypes.h>

#include "workqueue-snoop.skel.h"

#define TASK_COMM_LEN 16
#define WORKQUEUE_NAME_LEN 32

// Event types (must match kernel definitions)
#define WQ_EVENT_QUEUE 0
#define WQ_EVENT_ACTIVATE 1
#define WQ_EVENT_START 2
#define WQ_EVENT_END 3

// Event structure (must match kernel definition)
struct workqueue_event
{
	uint64_t timestamp;
	uint32_t pid;
	uint32_t cpu;
	uint64_t work_ptr;
	uint64_t function_ptr;
	char workqueue_name[WORKQUEUE_NAME_LEN];
	char comm[TASK_COMM_LEN];
	uint8_t event_type;
	int32_t req_cpu;
	uint64_t delay_ns;
};

// Filter configuration (must match kernel definition)
struct filter_config
{
	uint32_t target_pid;
	uint32_t target_cpu;
	char target_workqueue[WORKQUEUE_NAME_LEN];
	char target_function[64];
	uint8_t filter_pid;
	uint8_t filter_cpu;
	uint8_t filter_workqueue;
	uint8_t filter_function;
};

// Global variables
static struct workqueue_snoop_bpf *obj;
static struct ring_buffer *rb;
static volatile bool exiting = false;

// Signal handling pipe
static int signal_pipe[2];

// Current process info for filtering self-generated events
static pid_t self_pid;
static time_t program_start_time;

// Command line options
static struct
{
	int target_pid;
	int target_cpu;
	char *target_workqueue;
	char *target_function;
	int duration;
	bool statistics_mode;
	bool timestamp;
	bool verbose;
	bool json_output;
} env = {
	.target_pid = 0,
	.target_cpu = -1,
	.target_workqueue = NULL,
	.target_function = NULL,
	.duration = 0,
	.statistics_mode = false,
	.timestamp = false,
	.verbose = false,
	.json_output = false,
};

// Statistics tracking
struct work_stats
{
	uint64_t count;
	uint64_t total_delay;
	uint64_t total_exec_time;
	uint64_t min_delay;
	uint64_t max_delay;
	uint64_t min_exec_time;
	uint64_t max_exec_time;
};

static struct
{
	struct work_stats queue_stats;
	struct work_stats activate_stats;
	struct work_stats execute_stats;
	uint64_t total_events;
	time_t start_time;
} stats;

static const char *event_names[] = {"QUEUE", "ACTIVATE", "START", "END"};

// Function to resolve kernel symbol
static char *resolve_kernel_symbol(uint64_t addr)
{
	static char symbol[256];
	FILE *fp;
	char line[512];
	uint64_t sym_addr;
	char sym_name[256];
	char *best_match = NULL;
	uint64_t best_addr = 0;

	// Try to read from /proc/kallsyms
	fp = fopen("/proc/kallsyms", "r");
	if (!fp)
	{
		snprintf(symbol, sizeof(symbol), "0x%" PRIx64, (uint64_t)addr);
		return symbol;
	}

	while (fgets(line, sizeof(line), fp))
	{
		if (sscanf(line, "%" PRIx64 " %*c %255s", &sym_addr, sym_name) == 2)
		{
			if (sym_addr <= addr && sym_addr > best_addr)
			{
				best_addr = sym_addr;
				best_match = strdup(sym_name);
			}
		}
	}
	fclose(fp);

	if (best_match)
	{
		if (best_addr == addr)
		{
			snprintf(symbol, sizeof(symbol), "%s", best_match);
		}
		else
		{
			snprintf(
				symbol,
				sizeof(symbol),
				"%s+0x%" PRIx64,
				best_match,
				(uint64_t)(addr - best_addr)
			);
		}
		free(best_match);
	}
	else
	{
		snprintf(symbol, sizeof(symbol), "0x%" PRIx64, (uint64_t)addr);
	}

	return symbol;
}

// Format timestamp
static char *format_timestamp(uint64_t ns)
{
	static char ts_str[32];
	time_t sec = ns / 1000000000ULL;
	uint64_t nsec = ns % 1000000000ULL;

	if (env.timestamp)
	{
		struct tm *tm = localtime(&sec);
		snprintf(
			ts_str,
			sizeof(ts_str),
			"%02d:%02d:%02d.%06" PRIu64,
			tm->tm_hour,
			tm->tm_min,
			tm->tm_sec,
			(uint64_t)(nsec / 1000)
		);
	}
	else
	{
		snprintf(
			ts_str,
			sizeof(ts_str),
			"%ld.%06" PRIu64,
			(long)sec,
			(uint64_t)(nsec / 1000)
		);
	}

	return ts_str;
}

// Format delay/duration in human readable format
static char *format_duration(uint64_t ns)
{
	static char dur_str[32];

	if (ns < 1000)
	{
		snprintf(dur_str, sizeof(dur_str), "%" PRIu64 "ns", (uint64_t)ns);
	}
	else if (ns < 1000000)
	{
		snprintf(dur_str, sizeof(dur_str), "%.2fus", ns / 1000.0);
	}
	else if (ns < 1000000000ULL)
	{
		snprintf(dur_str, sizeof(dur_str), "%.2fms", ns / 1000000.0);
	}
	else
	{
		snprintf(dur_str, sizeof(dur_str), "%.2fs", ns / 1000000000.0);
	}

	return dur_str;
}

// Update statistics
static void update_stats(const struct workqueue_event *e)
{
	stats.total_events++;

	switch (e->event_type)
	{
	case WQ_EVENT_QUEUE:
		stats.queue_stats.count++;
		break;
	case WQ_EVENT_ACTIVATE:
		stats.activate_stats.count++;
		break;
	case WQ_EVENT_START:
		stats.execute_stats.count++;
		if (e->delay_ns > 0)
		{
			stats.queue_stats.total_delay += e->delay_ns;
			if (stats.queue_stats.min_delay == 0 ||
				e->delay_ns < stats.queue_stats.min_delay)
			{
				stats.queue_stats.min_delay = e->delay_ns;
			}
			if (e->delay_ns > stats.queue_stats.max_delay)
			{
				stats.queue_stats.max_delay = e->delay_ns;
			}
		}
		break;
	case WQ_EVENT_END:
		if (e->delay_ns > 0)
		{ // execution time
			stats.execute_stats.total_exec_time += e->delay_ns;
			if (stats.execute_stats.min_exec_time == 0 ||
				e->delay_ns < stats.execute_stats.min_exec_time)
			{
				stats.execute_stats.min_exec_time = e->delay_ns;
			}
			if (e->delay_ns > stats.execute_stats.max_exec_time)
			{
				stats.execute_stats.max_exec_time = e->delay_ns;
			}
		}
		break;
	}
}

// Print statistics summary
static void print_statistics()
{
	time_t now = time(NULL);
	double elapsed = difftime(now, stats.start_time);

	printf("\n=== Workqueue Statistics Summary ===\n");
	printf("Duration: %.1f seconds\n", elapsed);
	printf("Total Events: %" PRIu64 "\n", (uint64_t)stats.total_events);
	printf("\nEvent Counts:\n");
	printf("  QUEUE:    %8" PRIu64 "\n", (uint64_t)stats.queue_stats.count);
	printf("  ACTIVATE: %8" PRIu64 "\n", (uint64_t)stats.activate_stats.count);
	printf("  START:    %8" PRIu64 "\n", (uint64_t)stats.execute_stats.count);

	if (stats.queue_stats.total_delay > 0)
	{
		printf("\nQueue Delays:\n");
		printf(
			"  Average: %s\n",
			format_duration(
				stats.queue_stats.total_delay / stats.execute_stats.count
			)
		);
		printf("  Minimum: %s\n", format_duration(stats.queue_stats.min_delay));
		printf("  Maximum: %s\n", format_duration(stats.queue_stats.max_delay));
	}

	if (stats.execute_stats.total_exec_time > 0)
	{
		printf("\nExecution Times:\n");
		printf(
			"  Average: %s\n",
			format_duration(
				stats.execute_stats.total_exec_time / stats.execute_stats.count
			)
		);
		printf(
			"  Minimum: %s\n",
			format_duration(stats.execute_stats.min_exec_time)
		);
		printf(
			"  Maximum: %s\n",
			format_duration(stats.execute_stats.max_exec_time)
		);
	}

	printf("\nEvent Rate: %.1f events/sec\n", stats.total_events / elapsed);
}

// Ring buffer callback function
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct workqueue_event *e = (const struct workqueue_event *)data;
	char *function_name = NULL;

	// Check for forced exit even in event handler
	if (env.duration > 0)
	{
		time_t now = time(NULL);
		if (difftime(now, program_start_time) >= env.duration)
		{
			kill(getpid(), SIGKILL); // Force exit immediately
		}
	}

	if (data_sz < sizeof(*e))
	{
		fprintf(stderr, "Error: invalid data size\n");
		return 0;
	}

	// Filter out events from our own process to prevent event storm
	if (e->pid == (uint32_t)self_pid)
	{
		return 0;
	}

	// Update statistics
	update_stats(e);

	// Skip output in statistics mode
	if (env.statistics_mode)
	{
		return 0;
	}

	// Resolve function symbol
	if (e->function_ptr)
	{
		function_name = resolve_kernel_symbol(e->function_ptr);
	}

	if (env.json_output)
	{
		// JSON output format
		printf(
			"{\"timestamp\":\"%s\",\"pid\":%u,\"cpu\":%u,\"comm\":\"%s\","
			"\"event\":\"%s\",\"work\":\"0x%" PRIx64 "\"",
			format_timestamp(e->timestamp),
			e->pid,
			e->cpu,
			e->comm,
			event_names[e->event_type],
			e->work_ptr
		);

		if (function_name)
		{
			printf(",\"function\":\"%s\"", function_name);
		}

		if (e->workqueue_name[0])
		{
			printf(",\"workqueue\":\"%s\"", e->workqueue_name);
		}

		if (e->req_cpu >= 0)
		{
			printf(",\"req_cpu\":%d", e->req_cpu);
		}

		if (e->delay_ns > 0)
		{
			if (e->event_type == WQ_EVENT_START)
			{
				printf(",\"queue_delay_ns\":%" PRIu64, e->delay_ns);
			}
			else if (e->event_type == WQ_EVENT_END)
			{
				printf(",\"exec_time_ns\":%" PRIu64, e->delay_ns);
			}
		}

		printf("}\n");
	}
	else
	{
		// Human readable output
		printf(
			"%-18s %-6u %-3u %-16s %-8s 0x%-12" PRIx64,
			format_timestamp(e->timestamp),
			e->pid,
			e->cpu,
			e->comm,
			event_names[e->event_type],
			e->work_ptr
		);

		if (function_name)
		{
			printf(" %-30s", function_name);
		}
		else
		{
			printf(" %-30s", "-");
		}

		if (e->workqueue_name[0])
		{
			printf(" %-20s", e->workqueue_name);
		}
		else
		{
			printf(" %-20s", "-");
		}

		if (e->req_cpu >= 0)
		{
			printf(" %3d", e->req_cpu);
		}
		else
		{
			printf(" %3s", "-");
		}

		if (e->delay_ns > 0)
		{
			if (e->event_type == WQ_EVENT_START)
			{
				printf(" %12s", format_duration(e->delay_ns));
			}
			else if (e->event_type == WQ_EVENT_END)
			{
				printf(" %12s", format_duration(e->delay_ns));
			}
			else
			{
				printf(" %12s", "-");
			}
		}
		else
		{
			printf(" %12s", "-");
		}

		printf("\n");
	}

	return 0;
}

// Signal handler for forced exit
static void sig_force_exit(int signo)
{
	// Force immediate termination - no cleanup
	kill(getpid(), SIGKILL);
}

// Signal handler
static void sig_int(int signo)
{
	char byte = 1;
	exiting = true;

	// Write to signal pipe to wake up epoll - don't print in signal handler
	if (write(signal_pipe[1], &byte, 1) == -1)
	{
		// If pipe write fails, force terminate immediately
		kill(getpid(), SIGKILL);
	}

	// Set a backup timer for forced exit after 1 second if graceful exit fails
	signal(SIGALRM, sig_force_exit);
	alarm(1);
}

// Print usage information
static void usage(const char *prog)
{
	printf("USAGE: %s [OPTIONS]\n", prog);
	printf("Trace workqueue events\n\n");
	printf("OPTIONS:\n");
	printf("    -p, --pid PID           Trace this PID only\n");
	printf("    -c, --cpu CPU           Trace this CPU only\n");
	printf("    -w, --workqueue NAME    Trace this workqueue only\n");
	printf("    -f, --function FUNC     Trace functions containing this "
		   "string\n");
	printf("    -d, --duration SECONDS  Duration to trace\n");
	printf("        --timeout SECONDS   Same as --duration\n");
	printf("    -s, --statistics        Show statistics summary only\n");
	printf("    -t, --timestamp         Include timestamp in output\n");
	printf("    -j, --json              Output in JSON format\n");
	printf("    -v, --verbose           Verbose debug output\n");
	printf("    -h, --help              Show this help message\n");
	printf("\nEXAMPLES:\n");
	printf("    %s                      # Trace all workqueue events\n", prog);
	printf("    %s -p 1234              # Trace PID 1234 only\n", prog);
	printf("    %s -c 0                 # Trace CPU 0 only\n", prog);
	printf(
		"    %s -w events            # Trace 'events' workqueue only\n",
		prog
	);
	printf("    %s -s -d 10             # Show 10 second statistics\n", prog);
	printf("    %s -j                   # JSON output\n", prog);
}

// Setup filters
static int setup_filters()
{
	struct filter_config cfg = {0};
	int map_fd, key = 0;

	// Configure filters based on command line options
	if (env.target_pid > 0)
	{
		cfg.filter_pid = 1;
		cfg.target_pid = env.target_pid;
	}

	if (env.target_cpu >= 0)
	{
		cfg.filter_cpu = 1;
		cfg.target_cpu = env.target_cpu;
	}

	if (env.target_workqueue)
	{
		cfg.filter_workqueue = 1;
		strncpy(
			cfg.target_workqueue,
			env.target_workqueue,
			WORKQUEUE_NAME_LEN - 1
		);
	}

	if (env.target_function)
	{
		cfg.filter_function = 1;
		strncpy(
			cfg.target_function,
			env.target_function,
			sizeof(cfg.target_function) - 1
		);
	}

	// Update the config map
	map_fd = bpf_map__fd(obj->maps.filter_config_map);
	if (map_fd < 0)
	{
		fprintf(stderr, "Failed to get config map fd: %d\n", map_fd);
		return -1;
	}

	if (bpf_map_update_elem(map_fd, &key, &cfg, BPF_ANY))
	{
		fprintf(stderr, "Failed to update config map: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

// Parse command line arguments
static int parse_args(int argc, char **argv)
{
	static const struct option long_options[] = {
		{"pid",		required_argument, NULL, 'p'},
		{"cpu",		required_argument, NULL, 'c'},
		{"workqueue",  required_argument, NULL, 'w'},
		{"function",	 required_argument, NULL, 'f'},
		{"duration",	 required_argument, NULL, 'd'},
		{"timeout",	required_argument, NULL, 'd'}, // alias for duration
		{"statistics", no_argument,		NULL, 's'},
		{"timestamp",  no_argument,	   NULL, 't'},
		{"json",		 no_argument,		  NULL, 'j'},
		{"verbose",	no_argument,		 NULL, 'v'},
		{"help",		 no_argument,		  NULL, 'h'},
		{NULL,		   0,				  NULL, 0	 }
	};
	int opt;

	while ((opt = getopt_long(argc, argv, "p:c:w:f:d:stjvh", long_options, NULL)
		   ) != -1)
	{
		switch (opt)
		{
		case 'p':
			env.target_pid = atoi(optarg);
			if (env.target_pid <= 0)
			{
				fprintf(stderr, "Invalid PID: %s\n", optarg);
				return -1;
			}
			break;
		case 'c':
			env.target_cpu = atoi(optarg);
			if (env.target_cpu < 0)
			{
				fprintf(stderr, "Invalid CPU: %s\n", optarg);
				return -1;
			}
			break;
		case 'w':
			env.target_workqueue = optarg;
			break;
		case 'f':
			env.target_function = optarg;
			break;
		case 'd':
			env.duration = atoi(optarg);
			if (env.duration <= 0)
			{
				fprintf(stderr, "Invalid duration: %s\n", optarg);
				return -1;
			}
			break;
		case 's':
			env.statistics_mode = true;
			break;
		case 't':
			env.timestamp = true;
			break;
		case 'j':
			env.json_output = true;
			break;
		case 'v':
			env.verbose = true;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			usage(argv[0]);
			return -1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	int err;

	// Initialize process info for self-filtering
	self_pid = getpid();
	program_start_time = time(NULL);

	// Parse command line arguments
	if (parse_args(argc, argv))
	{
		return 1;
	}

	// Check if running as root
	if (geteuid() != 0)
	{
		fprintf(stderr, "This program requires root privileges\n");
		return 1;
	}

	// Setup libbpf errors and debug info callback
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	if (env.verbose)
	{
		libbpf_set_print(NULL);
	}

	// Initialize and configure BPF object
	obj = workqueue_snoop_bpf__open();
	if (!obj)
	{
		fprintf(stderr, "Failed to open BPF object\n");
		return 1;
	}

	// Load BPF program
	err = workqueue_snoop_bpf__load(obj);
	if (err)
	{
		fprintf(stderr, "Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	// Attach BPF program
	err = workqueue_snoop_bpf__attach(obj);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	// Setup filters
	if (setup_filters())
	{
		goto cleanup;
	}

	// Setup ring buffer
	rb = ring_buffer__new(
		bpf_map__fd(obj->maps.events),
		handle_event,
		NULL,
		NULL
	);
	if (!rb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	// Create a pipe for signal handling BEFORE setting up signal handlers
	if (pipe(signal_pipe) == -1)
	{
		perror("pipe");
		err = -1;
		goto cleanup;
	}

	// Setup signal handler with sigaction for more reliable handling
	struct sigaction sa;
	sa.sa_handler = sig_int;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0; // Don't restart system calls on signal
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	// Note: Removed SIGALRM handler and alarm() call
	// Duration checking is now handled in the main loop for better reliability

	// Print header for human readable output
	if (!env.json_output && !env.statistics_mode)
	{
		printf(
			"%-18s %-6s %-3s %-16s %-8s %-14s %-30s %-20s %-3s %12s\n",
			"TIME",
			"PID",
			"CPU",
			"COMM",
			"EVENT",
			"WORK",
			"FUNCTION",
			"WORKQUEUE",
			"REQ",
			"DELAY/EXEC"
		);
	}

	// Initialize statistics
	stats.start_time = time(NULL);

	if (env.verbose)
	{
		printf("Starting workqueue tracing...\n");
		printf(
			"Self PID: %d (events from this process will be filtered)\n",
			self_pid
		);
		if (env.target_pid > 0)
		{
			printf("Filtering PID: %d\n", env.target_pid);
		}
		if (env.target_cpu >= 0)
		{
			printf("Filtering CPU: %d\n", env.target_cpu);
		}
		if (env.target_workqueue)
		{
			printf("Filtering workqueue: %s\n", env.target_workqueue);
		}
		if (env.target_function)
		{
			printf("Filtering function: %s\n", env.target_function);
		}
		if (env.duration > 0)
		{
			printf("Duration: %d seconds\n", env.duration);
		}
	}

	// Create epoll instance for monitoring both ring buffer and signal pipe
	int epoll_fd, ring_fd;
	struct epoll_event ev;
	struct epoll_event events[2];

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd == -1)
	{
		perror("epoll_create1");
		err = -1;
		goto cleanup;
	}

	// Add ring buffer fd to epoll
	ring_fd = ring_buffer__epoll_fd(rb);
	if (ring_fd < 0)
	{
		fprintf(stderr, "Failed to get ring buffer epoll fd: %d\n", ring_fd);
		err = -1;
		close(epoll_fd);
		goto cleanup;
	}

	ev.events = EPOLLIN;
	ev.data.fd = ring_fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ring_fd, &ev) == -1)
	{
		perror("epoll_ctl: ring_fd");
		err = -1;
		close(epoll_fd);
		goto cleanup;
	}

	// Add signal pipe read end to epoll
	ev.events = EPOLLIN;
	ev.data.fd = signal_pipe[0];
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, signal_pipe[0], &ev) == -1)
	{
		perror("epoll_ctl: signal_pipe");
		err = -1;
		close(epoll_fd);
		goto cleanup;
	}

	// Main event loop using epoll
	while (!exiting)
	{
		// Check for timeout exit condition - FORCE EXIT if time exceeded
		if (env.duration > 0)
		{
			time_t now = time(NULL);
			if (difftime(now, program_start_time) >= env.duration)
			{
				if (env.verbose)
				{
					printf("\nDuration limit reached, forcing exit...\n");
				}
				// Force immediate exit without cleanup
				kill(getpid(), SIGKILL);
			}
		}

		int nfds = epoll_wait(
			epoll_fd,
			events,
			2,
			10
		); // 10ms timeout for faster response

		if (nfds == -1)
		{
			if (errno == EINTR)
			{
				// Signal received, check exiting flag
				break;
			}
			perror("epoll_wait");
			err = -1;
			break;
		}

		// Check exiting flag first
		if (exiting)
		{
			err = 0;
			break;
		}

		// Process events
		for (int i = 0; i < nfds; i++)
		{
			// Double check exiting flag before processing each event
			if (exiting)
			{
				break;
			}

			if (events[i].data.fd == ring_fd)
			{
				// Ring buffer has data - limit processing to prevent blocking
				int consume_count = 0;
				const int MAX_CONSUME_PER_LOOP = 10; // Reduced to exit faster

				while (consume_count < MAX_CONSUME_PER_LOOP && !exiting)
				{
					err = ring_buffer__consume(rb);
					if (err <= 0)
					{
						if (err < 0)
						{
							printf("Error consuming ring buffer: %d\n", err);
						}
						break; // No more events or error
					}
					consume_count++;

					// Check exit condition more frequently during heavy
					// processing
					if (consume_count % 5 == 0 && exiting)
					{
						break;
					}
				}

				if (err < 0)
				{
					goto loop_exit;
				}
			}
			else if (events[i].data.fd == signal_pipe[0])
			{
				// Signal received
				char buf[256];
				read(signal_pipe[0], buf,
					 sizeof(buf)); // Drain the pipe
				printf("\nSignal received, exiting gracefully...\n");
				exiting = true;
				break;
			}
		}
	}

loop_exit:
	close(epoll_fd);

	// Print statistics if requested
	if (env.statistics_mode || env.verbose)
	{
		print_statistics();
	}

cleanup:
	// Close signal pipe
	if (signal_pipe[0] != -1)
	{
		close(signal_pipe[0]);
	}
	if (signal_pipe[1] != -1)
	{
		close(signal_pipe[1]);
	}

	ring_buffer__free(rb);
	workqueue_snoop_bpf__destroy(obj);
	return err != 0 ? 1 : 0;
}