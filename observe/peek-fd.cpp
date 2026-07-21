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
#include <bpf/libbpf.h>
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
#include <vector>
#endif

#include "peek-fd.skel.h"
#include "com.h"

#ifdef BUILTIN
extern int ring_buffer__push(int fd, void *data, size_t sz);
#endif

#ifdef BUILTIN
#define BUILTIN_LOCAL static
#define BUILTIN_FLUSH_STDOUT() fflush(stdout)
#else
#define BUILTIN_LOCAL
#define BUILTIN_FLUSH_STDOUT() do {} while (0)
#endif

// Constants for read and write flags
#define FD_READ 1
#define FD_WRITE 2

// Structure to hold the rule for filtering
struct Rule
{
	pid_t pid; // Process ID to filter
	int fd;	   // File descriptor to watch
	int rw;	   // Read/Write flags
};

static struct Rule rule = {
	.pid = -1,
	.fd = -1,
	.rw = 0 // Default to watch both read and write
};

// Structure to hold log data
struct BpfData
{
	ssize_t sz; // Size of the log
	char buf[]; // Buffer for the log data
};

// Global variables
static peek_fd_bpf *obj;	   // BPF program object
static int log_map_fd;		   // File descriptor for log map
BUILTIN_LOCAL struct ring_buffer *rb = NULL; // Ring buffer for log events
static int filter_fd;		   // File descriptor for filter map
static pthread_t t1;		   // Thread for processing ring buffer
static bool worker_started = false;
static std::atomic<bool> exit_flag(false); // Flag to signal exit
static bool enable_sock_trace;
static bool read_trace_selected;
static bool write_trace_selected;
#ifdef BUILTIN
struct BuiltinEvent
{
	int32_t pid;
	int32_t fd;
	int32_t rw;
	bool is_socket;
	std::string payload;
};
static FILE *stdout_bak;
static std::map<std::string, std::tuple<int, int, int, bpf_map_type>>
	local_map_info = {
		{"filter", {sizeof(uint32_t), sizeof(struct Rule), 1, BPF_MAP_TYPE_HASH}},
		{"logs", {0, 1, 10 * 1024 * 1024, BPF_MAP_TYPE_RINGBUF}},
		{"args_map", {sizeof(pid_t), 64, 100, BPF_MAP_TYPE_HASH}},
		{"log_buf_4K", {sizeof(uint32_t), 4096 + sizeof(size_t), 1000, BPF_MAP_TYPE_HASH}},
		{"log_buf_1M", {sizeof(uint32_t), 1048576 + sizeof(size_t), 10, BPF_MAP_TYPE_HASH}},
	};
static std::atomic<int> *condition;
static std::mutex builtin_event_mu;
static std::deque<BuiltinEvent> builtin_events;
extern std::string test_name;
extern std::map<std::string, std::tuple<int, int, int, bpf_map_type>> *map_info;
#endif
// Command line options
static struct option lopts[] = {
	{"pid",		required_argument, 0, 'p'},
	{"fd",	   required_argument, 0, 'f'},
	{"read",	 no_argument,		  0, 'r'},
	{"write",	  no_argument,	   0, 'w'},
	{"outfile", required_argument, 0, 'o'},
	{"sock",	 no_argument,		  0, 's'},
	{"help",	 no_argument,		  0, 'h'},
	{0,		 0,				 0, 0  }
};

// Structure for help messages
struct HelpMsg
{
	const char *argparam; // Argument parameter
	const char *msg;	  // Help message
};

// Help messages
static HelpMsg help_msg[] = {
	{"<pid>",	  "filter with pid\n"							 },
	{"<fd>",		 "watch the specific fd in the process of pid\n"},
	{"[read]",	   "watch read data\n"							  },
	{"[write]",	"watch write data\n"							},
	{"[outfile]", "write data to a file\n"						  },
	{"[sock]",	   "output include fd of sockect type\n"			},
	{"",		  "print this help message\n"					},
};

// Function to print usage information
BUILTIN_LOCAL void Usage(const char *arg0)
{
	printf("Usage: %s [option]\n", arg0);
	printf("  Trace file descriptor IO data of a specific process on the "
		   "system. "
		   "Supports filtering by PID and FD.\n\n");
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
		case 'p': // Process ID
			rule.pid = strtol(optarg, NULL, 10);
			break;
		case 'f': // File descriptor
			rule.fd = strtol(optarg, NULL, 10);
			break;
		case 'h': // Help
			Usage(argv[0]);
			return 1;
		case 'r': // Read flag
			rule.rw |= FD_READ;
			break;
		case 'w': // Write flag
			rule.rw |= FD_WRITE;
			break;
		case 'o': // output file
			if (!freopen(optarg, "w+", stdout))
			{
				fprintf(stderr, "failed to open outfile: %s\n", optarg);
				return -1;
			}
			break;
		case 's':
			enable_sock_trace = true;
			break;
		default: // Invalid option
			Usage(argv[0]);
			return -1;
		}
	}
	// Ensure both PID and FD are specified
	if (rule.fd == -1 || rule.pid == -1)
	{
		printf("\nYou need to specify which process and which fd to \n"
			   "watch on by the options -pid(-p) and -fd(-f)\n\n");
		BUILTIN_FLUSH_STDOUT();
		return -1;
	}
	if (rule.rw == 0)
	{
		printf("\nYou need to specify at least one of option -r/-w\n\n");
		BUILTIN_FLUSH_STDOUT();
		return -1;
	}
	return 0;
}

// Handle events from the ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct BpfData *log = (const struct BpfData *)data; // Cast data to
															  // BpfData
															  // structure
	fwrite(log->buf, 1, log->sz, stdout); // Write log buffer to stdout
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
		exit_flag = true;
	}
}

#ifdef BUILTIN
void peek_fd_init(
	FILE *output,
	std::atomic<int> *conditionp,
	std::atomic<bool> **exit_flagp,
	int *,
	int *
)
{
	test_name = "peek-fd";
	map_info = &local_map_info;
	condition = conditionp;
	*exit_flagp = &exit_flag;
	obj = nullptr;
	rb = nullptr;
	filter_fd = -1;
	log_map_fd = -1;
	worker_started = false;
	exit_flag = false;
	enable_sock_trace = false;
	read_trace_selected = false;
	write_trace_selected = false;
	rule.pid = -1;
	rule.fd = -1;
	rule.rw = 0;
	{
		std::lock_guard<std::mutex> lock(builtin_event_mu);
		builtin_events.clear();
	}
	stdout_bak = stdout;
	fflush(stdout);
	stdout = output;
	Log::set_file(output);
}

static void peek_fd_builtin_cleanup()
{
	if (rb)
	{
		ring_buffer__free(rb);
		rb = nullptr;
	}
	if (obj)
	{
		peek_fd_bpf::detach(obj);
		peek_fd_bpf::destroy(obj);
		obj = nullptr;
	}
}

void peek_fd_deinit()
{
	exit_flag = true;
	peek_fd_builtin_cleanup();
	filter_fd = -1;
	log_map_fd = -1;
	enable_sock_trace = false;
	read_trace_selected = false;
	write_trace_selected = false;
	rule.pid = -1;
	rule.fd = -1;
	rule.rw = 0;
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

void peek_fd_get_rule_copy(void *out, size_t out_sz)
{
	if (out && out_sz >= sizeof(rule))
	{
		memcpy(out, &rule, sizeof(rule));
	}
}

bool peek_fd_get_sock_trace_enabled()
{
	return enable_sock_trace;
}

bool peek_fd_get_read_trace_selected()
{
	return (rule.rw & FD_READ) != 0;
}

bool peek_fd_get_write_trace_selected()
{
	return (rule.rw & FD_WRITE) != 0;
}

int peek_fd_emit_log(const void *log, size_t data_sz)
{
	return handle_event(nullptr, (void *)log, data_sz);
}

int peek_fd_submit_builtin_event(
	int32_t pid,
	int32_t fd,
	int32_t rw,
	bool is_socket,
	const char *payload
)
{
	if (!payload)
	{
		return -1;
	}
	std::lock_guard<std::mutex> lock(builtin_event_mu);
	builtin_events.push_back({pid, fd, rw, is_socket, payload});
	return 0;
}
#endif

static bool should_emit_builtin_event(
	int filter_fd,
	int32_t pid,
	int32_t fd,
	int32_t rw,
	bool is_socket
)
{
#ifdef BUILTIN
	int key = 0;
	struct Rule loaded_rule = {};
	if (bpf_map_lookup_elem(filter_fd, &key, &loaded_rule) != 0)
	{
		return false;
	}
	if (loaded_rule.pid && loaded_rule.pid != pid)
	{
		return false;
	}
	if (rw && !(rw & loaded_rule.rw))
	{
		return false;
	}
	if (loaded_rule.fd != -1 && loaded_rule.fd != fd)
	{
		return false;
	}
	if (is_socket && !enable_sock_trace)
	{
		return false;
	}
	return true;
#else
	(void)filter_fd;
	(void)pid;
	(void)fd;
	(void)rw;
	(void)is_socket;
	return false;
#endif
}

#ifdef BUILTIN
static int drain_builtin_events()
{
	std::deque<BuiltinEvent> pending;
	{
		std::lock_guard<std::mutex> lock(builtin_event_mu);
		pending.swap(builtin_events);
	}

	int processed = 0;
	for (const auto &event : pending)
	{
		if (!should_emit_builtin_event(
				filter_fd,
				event.pid,
				event.fd,
				event.rw,
				event.is_socket
			))
		{
			continue;
		}

		std::vector<char> buf(sizeof(ssize_t) + event.payload.size());
		auto *log = reinterpret_cast<BpfData *>(buf.data());
		log->sz = static_cast<ssize_t>(event.payload.size());
		memcpy(log->buf, event.payload.data(), event.payload.size());
		if (handle_event(nullptr, buf.data(), buf.size()) != 0)
		{
			return -1;
		}
		processed += 1;
	}
	return processed;
}

static bool builtin_events_empty()
{
	std::lock_guard<std::mutex> lock(builtin_event_mu);
	return builtin_events.empty();
}
#endif

static void enable_read_trace(void)
{
	if (!(rule.rw & FD_READ))
	{
		return;
	}
	read_trace_selected = true;

#ifdef BUILTIN
	return;
#endif

	bpf_program__set_autoload(obj->progs.trace_sys_enter_read, true);
	bpf_program__set_autoload(obj->progs.trace_sys_enter_readv, true);
	bpf_program__set_autoload(obj->progs.trace_sys_enter_preadv, true);
	bpf_program__set_autoload(obj->progs.trace_sys_enter_preadv2, true);
	bpf_program__set_autoload(obj->progs.trace_sys_exit_read, true);
	bpf_program__set_autoload(obj->progs.trace_sys_exit_readv, true);
	bpf_program__set_autoload(obj->progs.trace_sys_exit_preadv, true);
	bpf_program__set_autoload(obj->progs.trace_sys_exit_preadv2, true);

	if (!enable_sock_trace)
	{
		return;
	}

	bpf_program__set_autoload(obj->progs.trace_sys_enter_recvfrom, true);
	bpf_program__set_autoload(obj->progs.trace_sys_enter_recvmsg, true);
	bpf_program__set_autoload(obj->progs.trace_sys_enter_recvmmsg, true);
	bpf_program__set_autoload(obj->progs.trace_sys_exit_recvfrom, true);
	bpf_program__set_autoload(obj->progs.trace_sys_exit_recvmsg, true);
	bpf_program__set_autoload(obj->progs.trace_sys_exit_recvmmsg, true);
}

static void enable_write_trace(void)
{
	if (!(rule.rw & FD_WRITE))
	{
		return;
	}
	write_trace_selected = true;

#ifdef BUILTIN
	return;
#endif

	bpf_program__set_autoload(obj->progs.trace_sys_enter_write, true);
	bpf_program__set_autoload(obj->progs.trace_sys_enter_writev, true);
	bpf_program__set_autoload(obj->progs.trace_sys_enter_pwritev, true);
	bpf_program__set_autoload(obj->progs.trace_sys_enter_pwritev2, true);
	bpf_program__set_autoload(obj->progs.trace_sys_exit_write, true);
	bpf_program__set_autoload(obj->progs.trace_sys_exit_writev, true);
	bpf_program__set_autoload(obj->progs.trace_sys_exit_pwritev, true);
	bpf_program__set_autoload(obj->progs.trace_sys_exit_pwritev2, true);

	if (!enable_sock_trace)
	{
		return;
	}

	bpf_program__set_autoload(obj->progs.trace_sys_enter_sendto, true);
	bpf_program__set_autoload(obj->progs.trace_sys_enter_sendmsg, true);
	bpf_program__set_autoload(obj->progs.trace_sys_enter_sendmmsg, true);
	bpf_program__set_autoload(obj->progs.trace_sys_exit_sendto, true);
	bpf_program__set_autoload(obj->progs.trace_sys_exit_sendmsg, true);
	bpf_program__set_autoload(obj->progs.trace_sys_exit_sendmmsg, true);
}

// Main function
#ifdef BUILTIN
int peek_fd_main(int argc, char *args[])
#else
int main(int argc, char *args[])
#endif
{
	int ret = parse_args(argc, args); // Parse command line arguments
	int key = 0;			   // Key for BPF map
	if (ret != 0)
	{
#ifdef BUILTIN
		*condition = 2;
		return ret > 0 ? 0 : ret;
#else
		return ret > 0 ? 0 : ret;
#endif
	}
#ifndef BUILTIN
	register_signal();		// Register signal handler
#endif
	obj = peek_fd_bpf::open(); // Load BPF program
	if (!obj)
	{
		ret = -1;
		goto err_out; // Exit if loading failed
	}

	enable_read_trace();
	enable_write_trace();

	; // Load BPF program
	if (peek_fd_bpf::load(obj))
	{
		ret = -1;
		goto err_out; // Exit if loading failed
	}

	if (0 != peek_fd_bpf::attach(obj))
	{
		ret = -1;
		goto err_out; // Attach BPF program
	}

	// Get file descriptor for filter map and update it with the rule
	filter_fd = bpf_get_map_fd(obj->obj, "filter", goto err_out);
	if (0 != bpf_map_update_elem(filter_fd, &key, &rule, BPF_ANY))
	{
		printf("Error: bpf_map_update_elem");
		ret = -1;
		goto err_out; // Handle error
	}

	// Create a ring buffer for logs
	log_map_fd = bpf_get_map_fd(obj->obj, "logs", goto err_out);
	rb = ring_buffer__new(log_map_fd, handle_event, NULL, NULL);
	if (!rb)
	{
		ret = -1;
		goto err_out; // Handle error
	}

	printf("start peeking\n");
	BUILTIN_FLUSH_STDOUT();
#ifdef BUILTIN
	*condition = 1;
	while (!exit_flag || !builtin_events_empty())
	{
		int drained = drain_builtin_events();
		if (drained < 0)
		{
			ret = -1;
			break;
		}
		usleep(100);
	}
	goto err_out;
#else
	// Create a thread for processing the ring buffer
	pthread_create(&t1, NULL, ringbuf_worker, NULL);
	worker_started = true;
	follow_trace_pipe();	// Read trace pipe
	printf("normally exit\n");
	BUILTIN_FLUSH_STDOUT();
#endif

err_out:
	exit_flag = true;
#ifdef BUILTIN
	peek_fd_builtin_cleanup();
#else
	if (worker_started)
	{
		pthread_join(t1, NULL);
		worker_started = false;
	}
	if (rb)
	{
#ifdef BUILTIN
		fprintf(stderr, "peek-fd: before ring_buffer__free\n");
		fflush(stderr);
#endif
		ring_buffer__free(rb); // Free ring buffer if allocated
		rb = nullptr;
	}
	if (obj)
	{
#ifdef BUILTIN
		fprintf(stderr, "peek-fd: before detach/destroy\n");
		fflush(stderr);
#endif
		peek_fd_bpf::detach(obj);  // Detach BPF program
		peek_fd_bpf::destroy(obj); // Clean up BPF program
		obj = nullptr;
	}
#endif
#ifdef BUILTIN
	if (*condition <= 0)
	{
		*condition = 2;
	}
#endif
	return ret;				   // Exit successfully
}
