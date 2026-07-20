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
#ifdef BUILTIN
#include <deque>
#include <map>
#include <mutex>
#include <tuple>
#endif

#include "trace-signal.skel.h"
#include "com.h"
#include "jhash.h"

#ifdef BUILTIN
#define BUILTIN_LOCAL static
#define BUILTIN_FLUSH_STDOUT() fflush(stdout)
#else
#define BUILTIN_LOCAL
#define BUILTIN_FLUSH_STDOUT() do {} while (0)
#endif

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
BUILTIN_LOCAL struct ring_buffer *rb = NULL;
static int filter_fd;
static pthread_t t1;
static bool worker_started = false;
static std::atomic<bool> exit_flag(false);
static struct Rule rule = {};

#ifdef BUILTIN
struct TraceSignalBuiltinEvent
{
	struct BpfData log;
	u32 sender_phash;
	u32 recv_phash;
};
static FILE *stdout_bak;
static std::map<std::string, std::tuple<int, int, int, bpf_map_type>>
	local_map_info = {
		{"filter",       {sizeof(uint32_t), sizeof(pid_t) + sizeof(u32) * 3 + sizeof(int), 1, BPF_MAP_TYPE_HASH}},
		{"logs",         {0, 1, 1024 * 1024, BPF_MAP_TYPE_RINGBUF}                                              },
		{"pid2pathhash", {sizeof(pid_t), sizeof(u32), 10000, BPF_MAP_TYPE_LRU_HASH}                             },
};
static std::atomic<int> *condition;
static std::mutex builtin_event_mu;
static std::deque<TraceSignalBuiltinEvent> builtin_events;
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
BUILTIN_LOCAL void Usage(const char *arg0)
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
	BUILTIN_FLUSH_STDOUT();
}

// Convert long options to short options string
BUILTIN_LOCAL std::string long_opt2short_opt(const option lopts[])
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
BUILTIN_LOCAL int parse_args(int argc, char **argv)
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
			rule.sender_pid = atoi(optarg);
			break;
		case 'p': // Receiver PID
			rule.recv_pid = atoi(optarg);
			break;
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
			rule.sig = atoi(optarg);
			break;
		case 'R': // Signal
			rule.res = atoi(optarg);
			break;
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
	BUILTIN_FLUSH_STDOUT();

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
	BUILTIN_FLUSH_STDOUT();
	return 0;
}

// Worker thread for processing ring buffer
BUILTIN_LOCAL void *ringbuf_worker(void *)
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
BUILTIN_LOCAL void register_signal(void)
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
	}
}

#ifdef BUILTIN
void trace_signal_init(
	FILE *output,
	std::atomic<int> *conditionp,
	std::atomic<bool> **exit_flagp,
	int *filter_fd_out,
	int *log_fd_out
)
{
	test_name = "trace-signal";
	map_info = &local_map_info;
	condition = conditionp;
	*exit_flagp = &exit_flag;
	obj = nullptr;
	rb = nullptr;
	filter_fd = -1;
	log_map_fd = -1;
	worker_started = false;
	memset(&rule, 0, sizeof(rule));
	exit_flag = false;
	{
		std::lock_guard<std::mutex> lock(builtin_event_mu);
		builtin_events.clear();
	}
	stdout_bak = stdout;
	fflush(stdout);
	stdout = output;
	Log::set_file(output);
}

int trace_signal_poll_once(int timeout_ms)
{
	if (!rb)
	{
		return -1;
	}
	return ring_buffer__poll(rb, timeout_ms);
}

int trace_signal_emit_log(const void *log, size_t data_sz)
{
	return handle_event(nullptr, (void *)log, data_sz);
}

int trace_signal_submit_builtin_event(
	const void *log,
	size_t data_sz,
	u32 sender_phash,
	u32 recv_phash
)
{
	if (!log || data_sz != sizeof(struct BpfData))
	{
		return -1;
	}

	TraceSignalBuiltinEvent event = {};
	memcpy(&event.log, log, sizeof(event.log));
	event.sender_phash = sender_phash;
	event.recv_phash = recv_phash;

	std::lock_guard<std::mutex> lock(builtin_event_mu);
	builtin_events.push_back(event);
	return 0;
}

void trace_signal_get_rule_copy(void *out, size_t out_sz)
{
	if (out && out_sz >= sizeof(rule))
	{
		memcpy(out, &rule, sizeof(rule));
	}
}

static void trace_signal_builtin_cleanup()
{
	if (rb)
	{
		ring_buffer__free(rb);
		rb = nullptr;
	}
	if (obj)
	{
		trace_signal_bpf::detach(obj);
		trace_signal_bpf::destroy(obj);
		obj = nullptr;
	}
}

void trace_signal_deinit()
{
	exit_flag = true;
	trace_signal_builtin_cleanup();
	worker_started = false;
	filter_fd = -1;
	log_map_fd = -1;
	{
		std::lock_guard<std::mutex> lock(builtin_event_mu);
		builtin_events.clear();
	}
	test_name = "";
	map_info = nullptr;
	fflush(stdout);
	stdout = stdout_bak;
	Log::set_file(stderr);
}

static bool should_emit_builtin_event(const TraceSignalBuiltinEvent &event)
{
	if (rule.sender_pid > 0 && rule.sender_pid != event.log.sender_pid)
	{
		return false;
	}
	if (rule.recv_pid > 0 && rule.recv_pid != event.log.recv_pid)
	{
		return false;
	}
	if (rule.sender_phash && rule.sender_phash != event.sender_phash)
	{
		return false;
	}
	if (rule.recv_phash && rule.recv_phash != event.recv_phash)
	{
		return false;
	}
	if (rule.sig && rule.sig != event.log.sig)
	{
		return false;
	}
	if (rule.res && rule.res != event.log.res)
	{
		return false;
	}
	return true;
}

static int drain_builtin_events()
{
	std::deque<TraceSignalBuiltinEvent> pending;
	{
		std::lock_guard<std::mutex> lock(builtin_event_mu);
		pending.swap(builtin_events);
	}

	for (const auto &event : pending)
	{
		if (!should_emit_builtin_event(event))
		{
			continue;
		}
		if (handle_event(nullptr, (void *)&event.log, sizeof(event.log)) != 0)
		{
			return -1;
		}
	}
	return 0;
}

static bool builtin_events_empty()
{
	std::lock_guard<std::mutex> lock(builtin_event_mu);
	return builtin_events.empty();
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
	register_signal(); // Register signal handler
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
	if (0 != bpf_map_update_elem(filter_fd, &key, &rule, BPF_ANY))
	{
		printf("Error: bpf_map_update_elem");
		ret = -1;
		goto cleanup; // Handle error
	}

	// Create a ring buffer for logs
	log_map_fd = bpf_get_map_fd(obj->obj, "logs", goto cleanup);
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
	BUILTIN_FLUSH_STDOUT();

	// Create a thread for processing the ring buffer
#ifndef BUILTIN
	pthread_create(&t1, NULL, ringbuf_worker, NULL);
	worker_started = true;
#endif
#ifndef BUILTIN
	follow_trace_pipe();	// Read trace pipe
	pthread_join(t1, NULL); // Wait for the worker thread to finish
	worker_started = false;
#else
	*condition = 1;
	while (!exit_flag || !builtin_events_empty())
	{
		if (drain_builtin_events() != 0)
		{
			ret = -1;
			break;
		}
		usleep(100);
	}
	goto cleanup;
#endif

cleanup:
	free(buf);						// Free allocated buffer
#ifdef BUILTIN
	if (ret != 0)
	{
		*condition = 2;
	}
	trace_signal_builtin_cleanup();
	return ret;
#else
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
	return ret; // Exit successfully
#endif
}
