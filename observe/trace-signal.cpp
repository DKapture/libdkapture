// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

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
#include <atomic>
#include <limits>
#ifdef BUILTIN
#include <map>
#include <tuple>
#include <thread>
#include <chrono>
#endif

#include "trace-signal.skel.h"
#include "com.h"
#include "jhash.h"

struct Rule
{
	pid_t sender_pid; // Process ID
	u32 sender_phash;
	pid_t recv_pid;
	u32 recv_phash;
	int sig;
	int res; // Result of the signal sending
};

// Structure to log data
struct BpfData
{
	pid_t sender_pid;
	char sender_comm[16];
	pid_t recv_pid;
	char recv_comm[16];
	int sig;
	int res; // Result of the signal sending
};

static trace_signal_bpf *obj;
static int log_map_fd;
static struct ring_buffer *rb = NULL;
static int filter_fd;
static pthread_t t1;
static std::atomic<bool> exit_flag(false);
static struct Rule rule = {};

#ifdef BUILTIN
static FILE *stdout_bak;
static std::map<std::string, std::tuple<int, int, int, bpf_map_type>>
	local_map_info = {
		{"filter",       {sizeof(uint32_t), sizeof(Rule), 1, BPF_MAP_TYPE_HASH}},
		{"logs",         {0, 1, 1024 * 1024, BPF_MAP_TYPE_RINGBUF}                                              },
		{"pid2pathhash", {sizeof(pid_t), sizeof(u32), 10000, BPF_MAP_TYPE_LRU_HASH}                             },
};
static std::atomic<int> *condition;
static int *filter_fdp;
static int *log_map_fdp;
extern std::string test_name;
extern std::map<std::string, std::tuple<int, int, int, bpf_map_type>> *map_info;
#endif

static struct option lopts[] = {
	{"sender-pid",  required_argument, 0, 'P'},
	{"recv-pid",	 required_argument, 0, 'p'},
	{"sender-prog", required_argument, 0, 's'},
	{"recv-prog",	  required_argument, 0, 'r'},
	{"sig",			required_argument, 0, 'S'},
	{"res",			required_argument, 0, 'R'},
	{"help",		 no_argument,		  0, 'h'},
	{0,			 0,				 0, 0  }
};

// Structure for help messages
struct HelpMsg
{
	const char *argparam; // Argument parameter
	const char *msg;	  // Help message
};

// Help messages
static HelpMsg help_msg[] = {
	{"<sender-pid>",	 "Sender process ID to filter\n"	},
	{"<recv-pid>",	   "Receiver process ID to filter\n"},
	{"<sender-prog>", "Filter by sender program\n"	  },
	{"<recv-prog>",	"Filter by receiver program\n"	  },
	{"<sig>",		  "Signal number to filter\n"		 },
	{"<res>",		  "Signal number to filter\n"		 },
	{"",			  "print this help message\n"		},
};

// Function to print usage information
static void Usage(const char *arg0)
{
	printf("Usage: %s [option]\n", arg0);
	printf("  Trace signal communication between processes.\n\n");
	printf("Options:\n");
	for (int i = 0; lopts[i].name; i++)
	{
		printf(
			"  -%c, --%s %s\n\t%s\n",
			lopts[i].val,
			lopts[i].name,
			help_msg[i].argparam,
			help_msg[i].msg
		);
	}
}

// Convert long options to short options string
static std::string long_opt2short_opt(const option lopts[])
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
static int parse_args(int argc, char **argv)
{
	int opt, opt_idx;
	char *buf = (char *)calloc(4096, 1);
	if (!buf)
	{
		fprintf(stderr, "Failed to allocate buffer from heap\n");
		return -1;
	}

#ifdef BUILTIN
	optind = 0;
	opterr = 0;
#else
	optind = 1;
#endif
	std::string sopts = long_opt2short_opt(lopts); // Convert long options to
												   // short options
	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0)
	{
		switch (opt)
		{
		case 'P': // Sender PID
		{
			char *end = nullptr;
			errno = 0;
			long val = strtol(optarg, &end, 10);
			if (end == optarg || *end != '\0' || errno == ERANGE || val <= 0 || val > std::numeric_limits<pid_t>::max())
			{
				printf("wrong sender pid value: %s, must be a positive integer\n", optarg);
				free(buf);
				return -1;
			}
			rule.sender_pid = (pid_t)val;
			break;
		}
		case 'p': // Receiver PID
		{
			char *end = nullptr;
			errno = 0;
			long val = strtol(optarg, &end, 10);
			if (end == optarg || *end != '\0' || errno == ERANGE || val <= 0 || val > std::numeric_limits<pid_t>::max())
			{
				printf("wrong receiver pid value: %s, must be a positive integer\n", optarg);
				free(buf);
				return -1;
			}
			rule.recv_pid = (pid_t)val;
			break;
		}
		case 's': // Sender program
			memset(buf, 0, 4096);
			strncpy(buf, optarg, 4096);
			buf[4095] = 0;
			rule.sender_phash = jhash2((u32 *)buf, 4096 / 4, 0);
			break;
		case 'r': // Receiver program
			memset(buf, 0, 4096);
			strncpy(buf, optarg, 4096);
			buf[4095] = 0;
			rule.recv_phash = jhash2((u32 *)buf, 4096 / 4, 0);
			break;
		case 'S': // Signal
		{
			char *end = nullptr;
			errno = 0;
			long val = strtol(optarg, &end, 10);
			if (end == optarg || *end != '\0' || errno == ERANGE || val <= 0 || val > std::numeric_limits<int>::max())
			{
				printf("wrong signal value: %s, must be a positive integer\n", optarg);
				free(buf);
				return -1;
			}
			rule.sig = (int)val;
			break;
		}
		case 'R': // Result
		{
			char *end = nullptr;
			errno = 0;
			long val = strtol(optarg, &end, 10);
			if (end == optarg || *end != '\0' || errno == ERANGE || val < 0 || val > std::numeric_limits<int>::max())
			{
				printf("wrong result value: %s, must be an integer\n", optarg);
				free(buf);
				return -1;
			}
			rule.res = (int)val;
			break;
		}
		case 'h': // Help
			free(buf);
			Usage(argv[0]);
			return 1;
		default: // Invalid option
			free(buf);
			Usage(argv[0]);
			return -1;
		}
	}
	printf("\n=============== filter =================\n\n");
	printf(
		"\tsender_pid = %u\n"
		"\tsender_phash = %u\n"
		"\trecv_pid = %u\n"
		"\trecv_phash = %u\n"
		"\tsignal = %u\n"
		"\treturn = %u\n",
		rule.sender_pid,
		rule.sender_phash,
		rule.recv_pid,
		rule.recv_phash,
		rule.sig,
		rule.res
	);
	printf("\n========================================\n\n");

	free(buf);
	return 0;
}

// Handle events from the ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct BpfData *log = (const struct BpfData *)data; // Cast data to
															  // BpfData
															  // structure
	printf(
		"%10d %15s %10d %15s %12s %8d\n",
		log->sender_pid,
		log->sender_comm,
		log->recv_pid,
		log->recv_comm,
		log->sig ? strsignal(log->sig) : "0",
		log->res
	);
	return 0;
}

// Worker thread for processing ring buffer
static void *ringbuf_worker(void *)
{
	while (!exit_flag)
	{
		int err = ring_buffer__poll(
			rb,
#ifdef BUILTIN
			50 /* timeout in ms */
#else
			1000 /* timeout in ms */
#endif
		);
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
static int register_signal(void)
{
	struct sigaction sa;
	sa.sa_handler = [](int) { exit_flag = true; }; // Set exit flag on signal
	sa.sa_flags = 0;							   // No special flags
	sigemptyset(&sa.sa_mask); // No additional signals to block
	// Register the signal handler for SIGINT
	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		perror("sigaction");
		exit(EXIT_FAILURE);
		return -1;
	}
	return 0;
}

#ifdef BUILTIN
void trace_signal_init(
	FILE *output,
	std::atomic<int> *conditionp,
	std::atomic<bool> **exit_flagp,
	int *filter_fd,
	int *log_fd
)
{
	test_name = "trace-signal";
	map_info = &local_map_info;
	condition = conditionp;
	*exit_flagp = &exit_flag;
	rb = nullptr;
	filter_fdp = filter_fd;
	log_map_fdp = log_fd;
	memset(&rule, 0, sizeof(rule));
	exit_flag = false;
	stdout_bak = stdout;
	fflush(stdout);
	stdout = output;
	Log::set_file(output);
}
void trace_signal_deinit()
{
	test_name = "";
	map_info = nullptr;
	fflush(stdout);
	stdout = stdout_bak;
	Log::set_file(stderr);
}
#endif

// Main function
#ifdef BUILTIN
int trace_signal_main(int argc, char *args[])
#else
int main(int argc, char *args[])
#endif
{
	int iter_fd;
	ssize_t rd_sz;
	int ret = 0;
	char *buf = (char *)calloc(4096, 1);
	if (!buf)
	{
		fprintf(stderr, "Failed to allocate buffer from heap\n");
		return -1;
	}

	ret = parse_args(argc, args); // Parse command line arguments
	if (ret != 0)
	{
#ifdef BUILTIN
		*condition = 2;
#endif
		free(buf);
		return ret > 0 ? 0 : ret;
	}
#ifndef BUILTIN
	ret = register_signal();
	if (ret < 0)
	{
		return ret;
	}
#endif

	int key = 0;							 // Key for BPF map
	obj = trace_signal_bpf::open_and_load(); // Load BPF program
	if (!obj)
	{
		ret = -1;
		goto cleanup; // Exit if loading failed
	}

	if (0 != trace_signal_bpf::attach(obj))
	{
		ret = -1;
		goto cleanup; // Attach BPF program
	}

	// Get file descriptor for filter map and update it with the rule
	filter_fd = bpf_get_map_fd(obj->obj, "filter", goto cleanup);
#ifdef BUILTIN
	*filter_fdp = filter_fd;
#endif
	if (0 != bpf_map_update_elem(filter_fd, &key, &rule, BPF_ANY))
	{
		printf("Error: bpf_map_update_elem");
		ret = -1;
		goto cleanup; // Handle error
	}

	// Create a ring buffer for logs
	log_map_fd = bpf_get_map_fd(obj->obj, "logs", goto cleanup);
#ifdef BUILTIN
	*log_map_fdp = log_map_fd;
#endif
	rb = ring_buffer__new(log_map_fd, handle_event, NULL, NULL);
	if (!rb)
	{
		ret = -1;
		goto cleanup; // Handle error
	}

#ifndef BUILTIN
	iter_fd = bpf_iter_create(bpf_link__fd(obj->links.dump_task));
	if (iter_fd < 0)
	{
		fprintf(stderr, "Error creating BPF iterator\n");
		ret = -1;
		goto cleanup;
	}

	while ((rd_sz = read(iter_fd, buf, sizeof(buf))) > 0)
	{
	}

	close(iter_fd);
#endif

	printf(
		"%10s %15s %10s %15s %12s %8s\n",
		"SENDER",
		"S-COMM",
		"RCVER",
		"R-COMM",
		"SIGNAL",
		"RESULT"
	);

	// Create a thread for processing the ring buffer
	pthread_create(&t1, NULL, ringbuf_worker, NULL);
#ifndef BUILTIN
	follow_trace_pipe();	// Read trace pipe
#else
	*condition = 1;
	while (!exit_flag)
	{
		std::this_thread::sleep_for(std::chrono::microseconds(5));
	}
#endif
#ifndef BUILTIN
	pthread_kill(t1, SIGINT);
#endif
	pthread_join(t1, NULL);
	 // Wait for the worker thread to finish
cleanup:
	free(buf);						// Free allocated buffer
	if (rb)
	{
		ring_buffer__free(rb); // Free ring buffer if allocated
		rb = nullptr;
	}
	if (obj)
	{
		trace_signal_bpf::detach(obj);	// Detach BPF program
		trace_signal_bpf::destroy(obj); // Clean up BPF program
		obj = nullptr;
	}
	return 0; // Exit successfully
}
