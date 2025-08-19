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
#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <algorithm>
#include <pthread.h>

#include "syscall-stat.skel.h"
#include "Ucom.h"
#include "jhash.h"

#ifdef __SYSCALL
#undef __SYSCALL
#endif
#define __SYSCALL(nr, str) [nr] = #str,

const char *sys_tbl[] = {
#include "syscall-tbl.h"
};

struct info
{
	u64 cnt;
	u64 time;
	long ret;
};
// Structure to hold the rule for filtering

struct Rule
{
	pid_t pid;
	uint32_t pathhash;
	char comm[16];
} rule = {
	.pid = -1,
	.pathhash = 0,
};

// Structure to hold log data
struct BpfData
{
	ssize_t sz; // Size of the log
	char buf[]; // Buffer for the log data
};

// Global variables
static syscall_stat_bpf *obj; // BPF program object
static int log_map_fd; // File descriptor for log map
struct ring_buffer *rb = NULL; // Ring buffer for log events
static int filter_fd; // File descriptor for filter map
static int stats_fd; // File descriptor for stats map
static pthread_t t1; // Thread for processing ring buffer
static pthread_t t2;
static int interval = 1;
static bool top = false;
static std::atomic<bool> exit_flag(false); // Flag to signal exit
// Command line options
static struct option lopts[] = { { "pid", required_argument, 0, 'p' },
				 { "file", required_argument, 0, 'f' },
				 { "comm", required_argument, 0, 'c' },
				 { "interval", required_argument, 0, 'i' },
				 { "top", no_argument, 0, 't' },
				 { "help", no_argument, 0, 'h' },
				 { 0, 0, 0, 0 } };

// Structure for help messages
struct HelpMsg
{
	const char *argparam; // Argument parameter
	const char *msg; // Help message
};

// Help messages
static HelpMsg help_msg[] = {
	{ "[pid]", "stat the syscalls of process of [pid]\n" },
	{ "[file]", "stat syscalls of process whose filepath is [file]\n" },
	{ "[comm]", "stat syscalls of process whose name is [comm]\n" },
	{ "[interval]", "the interval to stat syscalls\n" },
	{ "[top]", "output information in top way\n" },
	{ "", "print this help message\n" },
};

// Function to print usage information
void Usage(const char *arg0)
{
	printf("Usage: %s [option]\n", arg0);
	printf("  statistic the frequency of syscall calling of a specific process.\n"
	       "the process can be specified by pid, filepath or comm.\n"
	       "if more than one option is specified, the priority is pid > filepath > comm.\n\n");
	printf("Options:\n");
	for (int i = 0; lopts[i].name; i++)
	{
		printf("  -%c, --%s %s\n\t%s\n", lopts[i].val, lopts[i].name,
		       help_msg[i].argparam, help_msg[i].msg);
	}
}

// Convert long options to short options string
std::string long_opt2short_opt(const option lopts[])
{
	std::string sopts = "";
	for (int i = 0; lopts[i].name; i++)
	{
		sopts += lopts[i].val; // Add short option character
		switch (lopts[i].has_arg)
		{
		case no_argument:
			break;
		case required_argument:
			sopts += ":"; // Required argument
			break;
		case optional_argument:
			sopts += "::"; // Optional argument
			break;
		default:
			DIE("Code internal bug!!!\n");
			abort();
		}
	}
	return sopts;
}

// Parse command line arguments
void parse_args(int argc, char **argv)
{
	int opt, opt_idx;
	char *buf = (char *)calloc(4096, sizeof(char)); // 从堆区申请内存
	if (!buf)
	{
		perror("calloc");
		exit(EXIT_FAILURE);
	}
	optind = 1;
	std::string sopts = long_opt2short_opt(
		lopts); // Convert long options to short options
	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) >
	       0)
	{
		switch (opt)
		{
		case 'p': // Process ID
			rule.pid = strtol(optarg, NULL, 10);
			break;
		case 'f':
			strncpy(buf, optarg, 4096);
			buf[4095] = '\0';
			rule.pathhash = jhash(buf, 4096, 0);
			break;
		case 'c':
			strncpy(rule.comm, optarg, sizeof(rule.comm));
			rule.comm[sizeof(rule.comm) - 1] = '\0';
			break;
		case 'i':
			interval = strtol(optarg, NULL, 10);
			if (interval <= 0)
			{
				printf("wrong interval value: %s, must be >0 interger",
				       optarg);
				free(buf);
				exit(-1);
			}
			break;
		case 'h': // Help
			Usage(argv[0]);
			free(buf);
			exit(0);
			break;
		default: // Invalid option
			Usage(argv[0]);
			free(buf);
			exit(-1);
			break;
		}
	}
	free(buf); // 释放堆区内存
}

// Handle events from the ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct BpfData *log =
		(const struct BpfData *)data; // Cast data to BpfData structure
	fwrite(log->buf, 1, log->sz, stdout); // Write log buffer to stdout
	return 0;
}

// Worker thread for processing ring buffer
void *ringbuf_worker(void *)
{
	while (!exit_flag)
	{
		int err = ring_buffer__poll(rb, 1000 /* timeout in ms */);
		// Check for errors during polling
		if (err < 0 && err != -EINTR)
		{
			pr_error("Error polling ring buffer: %d\n", err);
			sleep(5); // Sleep before retrying
		}
	}
	return NULL;
}

// Register signal handler for graceful exit
void register_signal()
{
	struct sigaction sa;
	sa.sa_handler = [](int) {
		exit_flag = true;
		stop_trace();
	}; // Set exit flag on signal
	sa.sa_flags = 0; // No special flags
	sigemptyset(&sa.sa_mask); // No additional signals to block
	// Register the signal handler for SIGINT
	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		perror("sigaction");
		exit(EXIT_FAILURE);
	}
}

static void print_title(int max_name_len)
{
	printf("Syscall stats in %d second:\n\n", interval);

	printf("%-*s %-10s %-10s %-10s\n", max_name_len, "SYSCALL", "CALL-CNT",
	       "ERROR", "SECONDS");
	printf("%-.*s %-10s %-10s %-10s", max_name_len,
	       "----------------------------------------", "----------",
	       "----------", "----------\n");
}

// Function for the timer task
void *timer_task(void *)
{
	int max_name_len = 0;
	size_t sys_cnt = sizeof(sys_tbl) / sizeof(sys_tbl[0]);
	for (size_t i = 0; i < sys_cnt; i++)
	{
		int slen = strlen(sys_tbl[i]);
		if (max_name_len < slen)
			max_name_len = slen;
	}
	print_title(max_name_len);
	sleep(interval);
	while (!exit_flag)
	{
		u32 key = 0, nxt_key;
		u32 total = 0;
		std::vector<std::pair<u32, info> >
			stats; // Vector to store syscall stats

		while (0 == bpf_map_get_next_key(stats_fd, &key, &nxt_key))
		{
			info sys_stat;
			bpf_map_lookup_elem(stats_fd, &nxt_key, &sys_stat);
			if (nxt_key >= sizeof(sys_tbl) / sizeof(sys_tbl[0]))
			{
				key = nxt_key;
				continue;
			}
			if (sys_stat.cnt == 0)
			{
				key = nxt_key;
				continue;
			}
			stats.push_back({ nxt_key, sys_stat });
			total += sys_stat.cnt;
			memset(&sys_stat, 0, sizeof(sys_stat));
			bpf_map_update_elem(stats_fd, &nxt_key, &sys_stat,
					    BPF_ANY);
			key = nxt_key;
		}

		// Sort stats by sys_stat in descending order
		std::sort(stats.begin(), stats.end(),
			  [](const std::pair<u32, info> &a,
			     const std::pair<u32, info> &b) {
				  return b.second.cnt < a.second.cnt;
			  });

		if (top) // clear the screen
		{
			printf("\33[H\33[2J\33[3J");
			print_title(max_name_len);
		}

		// Print sorted stats
		for (const auto &stat : stats)
		{
			const info &info = stat.second;
			printf("%-*s %-10llu %-10ld %-f\n", max_name_len,
			       sys_tbl[stat.first], info.cnt, info.ret,
			       info.time / info.cnt / 1000000000.0f);
		}

		if (total)
			printf("\ntotal: %d\n", total);

		sleep(interval);
	}
	return NULL;
}

// Main function
int main(int argc, char *args[])
{
	parse_args(argc, args); // Parse command line arguments
	printf("filter: \n");
	printf("\tpid: %d, pathhash: %d, comm: %s\n\n", rule.pid, rule.pathhash,
	       rule.comm);
	register_signal(); // Register signal handler

	int key = 0; // Key for BPF map
	obj = syscall_stat_bpf::open_and_load(); // Load BPF program
	if (!obj)
		exit(-1); // Exit if loading failed

	if (0 != syscall_stat_bpf::attach(obj))
		exit(-1); // Attach BPF program

	// Get file descriptor for filter map and update it with the rule
	filter_fd = bpf_get_map_fd(obj->obj, "filter", goto err_out);
	stats_fd = bpf_get_map_fd(obj->obj, "syscall_stat", goto err_out);

	if (0 != bpf_map_update_elem(filter_fd, &key, &rule, BPF_ANY))
	{
		printf("Error: bpf_map_update_elem");
		goto err_out; // Handle error
	}

	// Create a ring buffer for logs
	log_map_fd = bpf_get_map_fd(obj->obj, "logs", goto err_out);
	rb = ring_buffer__new(log_map_fd, handle_event, NULL, NULL);
	if (!rb)
		goto err_out; // Handle error

	// Create a thread for processing the ring buffer
	pthread_create(&t1, NULL, ringbuf_worker, NULL);
	pthread_create(&t2, NULL, timer_task, NULL);
	follow_trace_pipe(); // Read trace pipe
	pthread_kill(t1, SIGINT);
	pthread_join(t1, NULL);
	pthread_kill(t2, SIGINT);
	pthread_join(t2, NULL);

err_out:
	if (rb)
		ring_buffer__free(rb); // Free ring buffer if allocated
	syscall_stat_bpf::detach(obj); // Detach BPF program
	syscall_stat_bpf::destroy(obj); // Clean up BPF program
	return 0; // Exit successfully
}