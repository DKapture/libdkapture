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
#include <signal.h>
#include <string>
#include <atomic>
#ifdef BUILTIN
#include <map>
#include <tuple>
#include <thread>
#include <chrono>
#endif
#include <pthread.h>
#include "trace-exec.skel.h"
#include "com.h"

// BPF object for tracing execution
static trace_exec_bpf *obj;
static int filter_fd;
static struct ring_buffer *rb = NULL;
static int log_map_fd;
static pthread_t t1;
static std::atomic<bool> exit_flag(false);

// Structure to hold filtering rules
struct Rule
{
	char target_path[PATH_MAX]; // Path to filter on
	uint32_t depth;				// Depth of the printed task chain
	uint32_t uid;				// User ID to filter on
};
static struct Rule rule = {
	.depth = 50,		// Default depth
	.uid = (uint32_t)-1 // Default UID (no filtering)
};

#ifdef BUILTIN
static FILE *stdout_bak;
static std::map<std::string, std::tuple<int, int, int, bpf_map_type>>
	local_map_info = {
		{"filter", {sizeof(uint32_t), sizeof(struct Rule), 1, BPF_MAP_TYPE_HASH}},
		{"logs",   {0, 1, 1024 * 1024, BPF_MAP_TYPE_RINGBUF}                  },
	};
static std::atomic<int> *condition;
static int *filter_fdp;
static int *log_fdp;
extern std::string test_name;
extern std::map<std::string, std::tuple<int, int, int, bpf_map_type>> *map_info;
#endif

// Long options for command line arguments
static struct option lopts[] = {
	{"uid",	required_argument, 0, 'u'},
	{"depth",  required_argument, 0, 'd'},
	{"target", required_argument, 0, 't'},
	{"help",	 no_argument,		  0, 'h'},
	{0,		0,				 0, 0  }
};

// Help message structure
struct HelpMsg
{
	const char *argparam; // Argument parameter
	const char *msg;	  // Help message
};

// Help messages for each option
static HelpMsg help_msg[] = {
	{"<uid>",	  "filter with uid\n"					 },
	{"<depth>",	"set the printed task chain length\n"},
	{"[target]", "filter with process file path\n"	  },
	{"",		 "print this help message\n"			},
};

// Function to display usage information
static void Usage(const char *arg0)
{
	printf("Usage: %s [option]\n", arg0);
	printf("  trace exec event on the system, support filter with process "
		   "image file name and uid.\n"
		   "  This tool is useful for tracing processes that run and exit "
		   "fast, traditional methods, "
		   "like traversing through the proc dir, cannot catch such events in "
		   "time.\n\n");
	printf("options:\n");
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

// Convert long options to short options for getopt
static std::string long_opt2short_opt(const option lopts[])
{
	std::string sopts = "";
	for (int i = 0; lopts[i].name; i++)
	{
		sopts += lopts[i].val; // Append the short option character
		switch (lopts[i].has_arg)
		{
		case no_argument:
			break; // No argument required
		case required_argument:
			sopts += ":"; // Argument required
			break;
		case optional_argument:
			sopts += "::"; // Argument optional
			break;
		default:
			DIE("code internal bug!!!\n"); // Handle unexpected case
			abort();
			break;
		}
	}
	return sopts; // Return the constructed short options string
}

// Parse command line arguments
static int parse_args(int argc, char **argv)
{
	int opt, opt_idx;
	optind = 0;
	opterr = 0;
	std::string sopts = long_opt2short_opt(lopts); // Convert long options to
												   // short options
	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0)
	{
		switch (opt)
		{
		case 'u': // UID option
		{
			char *end = nullptr;
			errno = 0;
			long val = strtol(optarg, &end, 10);
			if (end == optarg || *end != '\0' ||  errno == ERANGE || val < 0 || (unsigned long)val > UINT32_MAX)
			{
				printf("wrong uid value: %s, must be a non-negative integer\n", optarg);
				return -1;
			}
			rule.uid = (uint32_t)val;
			break;
		}
		case 'd': // Depth option
		{
			char *end = nullptr;
			long val = strtol(optarg, &end, 10);
			if (end == optarg || *end != '\0' || val <= 0)
			{
				printf("wrong depth value: %s, must be a positive integer\n", optarg);
				return -1;
			}
			rule.depth = (uint32_t)val;
			break;
		}
		case 'h': // Help option
			Usage(argv[0]);
			return 1;
		case 't': // Target path option
			strncpy(rule.target_path, optarg, PATH_MAX);
			rule.target_path[PATH_MAX - 1] = 0;
			break;
		default: // Invalid option
			Usage(argv[0]);
			return -1;
		}
	}
	return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const char *log = (const char *)data;
	printf("%.*s\n", (int)data_sz, log);
	return 0;
}

void *ringbuf_worker(void *)
{
	while (!exit_flag)
	{
#ifdef BUILTIN
		int err = ring_buffer__poll(rb, 50 /* timeout in ms */);
#else
		int err = ring_buffer__poll(rb, 1000 /* timeout in ms */);
#endif
		if (err < 0 && err != -EINTR)
		{
			pr_error("Error polling ring buffer: %d\n", err);
			sleep(5);
		}
	}
	return NULL;
}

#ifdef BUILTIN
void trace_exec_init(
	FILE *output,
	std::atomic<int> *conditionp,
	std::atomic<bool> **exit_flagp,
	int *filter_fd,
	int *log_fd
)
{
	test_name = "trace-exec";
	map_info = &local_map_info;
	condition = conditionp;
	*exit_flagp = &exit_flag;
	filter_fdp = filter_fd;
	log_fdp = log_fd;
	rb = NULL;
	memset(&rule, 0, sizeof(rule));
	rule.depth = 50;
	rule.uid = (uint32_t)-1;
	exit_flag = false;
	stdout_bak = stdout;
	fflush(stdout);
	stdout = output;
	Log::set_file(output);
}
void trace_exec_deinit()
{
	test_name = "";
	map_info = NULL;
	fflush(stdout);
	stdout = stdout_bak;
	Log::set_file(stderr);
}
#endif

static int register_signal()
{
	struct sigaction sa;
	sa.sa_handler = [](int)
	{
		exit_flag = true;
		stop_trace();
	};						  // Set exit flag on signal
	sa.sa_flags = 0;		  // No special flags
	sigemptyset(&sa.sa_mask); // No additional signals to block
	// Register the signal handler for SIGINT
	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		perror("sigaction");
		return -1;
	}
	return 0;
}

// Main function
#ifdef BUILTIN
int trace_exec_main(int argc, char *args[])
#else
int main(int argc, char *args[])
#endif
{
	int ret = parse_args(argc, args); // Parse command line arguments
	if (ret != 0)
	{
#ifdef BUILTIN
		*condition = 2;
#endif
		return ret;
	}
#ifndef BUILTIN
	ret = register_signal();
	if (ret < 0)
	{
		return ret;
	}
#endif
	int key = 0;						   // Key for BPF map
	obj = trace_exec_bpf::open_and_load(); // Load BPF program
	if (!obj)
	{
		return -1; // Exit if loading failed
	}

	if (0 != trace_exec_bpf::attach(obj))
	{
		return -1; // Attach BPF program failed
	}

	// Get the file descriptor for the BPF map
	filter_fd = bpf_get_map_fd(obj->obj, "filter", goto err_out);
#ifdef BUILTIN
	*filter_fdp = filter_fd;
#endif
	if (0 != bpf_map_update_elem(filter_fd, &key, &rule, BPF_ANY))
	{
		printf("error: bpf_map_update_elem\n"); // Print error if updating fails
		ret = -1;
		goto err_out;							// Go to error handling
	}
	log_map_fd = bpf_get_map_fd(obj->obj, "logs", goto err_out);
#ifdef BUILTIN
	*log_fdp = log_map_fd;
#endif
	rb = ring_buffer__new(log_map_fd, handle_event, NULL, NULL);
	if (!rb)
	{
		goto err_out; // Handle error
	}
	pthread_create(&t1, NULL, ringbuf_worker, NULL);
	printf("Tracing exec events... Hit Ctrl-C to end.\n");
#ifndef BUILTIN
	follow_trace_pipe(); // Start reading from the trace pipe
#else
	*condition = 1;
	while(!exit_flag)
	{
		std::this_thread::sleep_for(std::chrono::microseconds(5));
	}
#endif
#ifndef BUILTIN
	pthread_kill(t1, SIGINT);
#endif
	pthread_join(t1, NULL);

err_out:
	if (rb)
	{
		ring_buffer__free(rb); // Free ring buffer if allocated
	}
	trace_exec_bpf::detach(obj);  // Detach BPF program
	trace_exec_bpf::destroy(obj); // Clean up BPF object
	return 0; // Exit successfully
}
