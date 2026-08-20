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

#include "peek-fd.skel.h"
#include <mutex>
#include <condition_variable>
#include <future>
#include <map>
#include <memory>
#include "com.h"

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
static struct Rule rule= {
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
static struct ring_buffer *rb = NULL; // Ring buffer for log events
static int filter_fd;		   // File descriptor for filter map
static pthread_t t1;		   // Thread for processing ring buffer
static std::atomic<bool> exit_flag(false); // Flag to signal exit
static bool enable_sock_trace;
#ifdef BUILTIN
struct PeekFds
{
	int filter_fd;
	int logs_fd;

};
struct PeekFdSync
{
	std::mutex m;
	std::condition_variable cv;
	bool init_done = false;
	bool exit_requested = false;
};
struct PeekFdRuntime
{
	PeekFdSync sync;
	std::promise<PeekFds> fds_promise;
	std::atomic<bool> *exit_flag = nullptr;
};
enum EventType
{
	EVENT_READ,
	EVENT_WRITE,
	EVENT_RECVFROM,
	EVENT_SENDTO,
};
static FILE *stdout_bak;
static std::map<std::string, std::tuple<int, int, int, bpf_map_type>> 
local_map_info = {
	{"filter", {sizeof(unsigned int), sizeof(struct Rule), 1, BPF_MAP_TYPE_HASH}},
	{"logs", {0, 1, 10* 1024 * 1024, BPF_MAP_TYPE_RINGBUF}},
};
static std::shared_ptr<PeekFdRuntime> runtime_state;
extern std::string test_name;
extern std::map<std::string,std::tuple<int, int, int, bpf_map_type>> *map_info;
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
static void Usage(const char *arg0)
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
	optind = 0;
	opterr = 0;
	std::string sopts = long_opt2short_opt(lopts); // Convert long options to
												   // short options
	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0)
	{
		switch (opt)
		{
		case 'p': // Process ID
		{
			char *end = nullptr;
			errno = 0;
			long val = strtol(optarg, &end, 10);
			if (end == optarg || *end != '\0' || errno == ERANGE || val <= 0 || val > INT_MAX)
			{
				printf("wrong pid value: %s, must be a positive integer\n", optarg);
#ifndef BUILTIN
				exit(-1);
#else
				return -1;
#endif
			}
			rule.pid = (int)val;
			break;
		}
		case 'f': // File descriptor
		{
			char *end = nullptr;
			errno = 0;
			long val = strtol(optarg, &end, 10);
			if (end == optarg || *end != '\0' || errno == ERANGE || val < 0 || val > INT_MAX)
			{
				printf("wrong fd value: %s, must be a non-negative integer\n", optarg);
#ifndef BUILTIN
				exit(-1);
#else
				return -1;
#endif
			}
			rule.fd = (int)val;
			break;
		}
		case 'h': // Help
			Usage(argv[0]);
#ifndef BUILTIN
			exit(0);
#else
			return 1;
#endif
			break;
		case 'r': // Read flag
			rule.rw |= FD_READ;
			break;
		case 'w': // Write flag
			rule.rw |= FD_WRITE;
			break;
		case 'o': // output file
			freopen(optarg, "w+", stdout);
			break;
		case 's':
			enable_sock_trace = true;
			break;
		default: // Invalid option
			Usage(argv[0]);
#ifndef BUILTIN
			exit(-1);
#else
			return -1;
#endif
			break;
		}
	}
	// Ensure both PID and FD are specified
	if (rule.fd == -1 || rule.pid == -1)
	{
		printf("\nYou need to specify which process and which fd to \n"
			   "watch on by the options -pid(-p) and -fd(-f)\n\n");
#ifndef BUILTIN
		exit(-1);
#else
		return -1;
#endif
	}
	if (rule.rw == 0)
	{
		printf("\nYou need to specify at least one of option -r/-w\n\n");
#ifndef BUILTIN
		exit(-1);
#else
		return -1;
#endif
	}
	return 0;
}

// Handle events from the ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	if (data_sz < sizeof(ssize_t)) 
	{
		return 0;
	}
	const struct BpfData *log = (const struct BpfData *)data; // Cast data to
															  // BpfData
															  // structure
	if (log->sz < 0) 
	{
		return 0;
	}
	size_t payload_sz = data_sz - sizeof(ssize_t);
	if ((size_t)log->sz > payload_sz) 
	{
		return 0;
	}
	fwrite(log->buf, 1, log->sz, stdout); // Write log buffer to stdout
	fflush(stdout);
	return 0;
}

// Worker thread for processing ring buffer
static void *ringbuf_worker(void *)
{
	while (!exit_flag)
	{
#ifdef BUILTIN
		int err = ring_buffer__poll(rb, 50 /* timeout in ms */);
#else
		int err = ring_buffer__poll(rb, 1000 /* timeout in ms */);
#endif
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
#ifndef BUILTIN
		exit(EXIT_FAILURE);
#else
		return -1;
#endif
	}
	return 0;
}

#ifdef BUILTIN
std::shared_ptr<PeekFdRuntime> peek_fd_init(FILE *output)
{
	test_name = "peek-fd";           // Register tool name
  	map_info = &local_map_info;      // Register map definitions
	runtime_state = std::make_shared<PeekFdRuntime>();
	runtime_state->exit_flag = &exit_flag;
  	exit_flag = false;               // Reset exit state
  	rb = NULL;                       // Reset ring buffer
  	rule.pid = -1;                   // Reset pid filter
  	rule.fd = -1;                    // Reset fd filter
  	rule.rw = 0;             		 // Reset rw filter
	enable_sock_trace = false;
  	stdout_bak = stdout;             // Backup stdout
  	fflush(stdout);                  // Flush stdout
  	stdout = output;                 // Redirect stdout
  	Log::set_file(output);           // Redirect logs
	{
		std::lock_guard<std::mutex> lock(runtime_state->sync.m);
		runtime_state->sync.init_done = false;
		runtime_state->sync.exit_requested = false;
	}
	return runtime_state;
}
void peek_fd_deinit()
{
	test_name = "";
	map_info = NULL;
	runtime_state.reset();
	fflush(stdout);
	stdout = stdout_bak;
	Log::set_file(stderr);
}
static void disable_all_trace_autoload(bool autoload)
  {
      bpf_program *programs[] = {
          obj->progs.trace_sys_enter_read,
          obj->progs.trace_sys_exit_read,
          obj->progs.trace_sys_enter_write,
          obj->progs.trace_sys_exit_write,

          obj->progs.trace_sys_enter_readv,
          obj->progs.trace_sys_exit_readv,
          obj->progs.trace_sys_enter_writev,
          obj->progs.trace_sys_exit_writev,

          obj->progs.trace_sys_enter_preadv,
          obj->progs.trace_sys_exit_preadv,
          obj->progs.trace_sys_enter_pwritev,
          obj->progs.trace_sys_exit_pwritev,

          obj->progs.trace_sys_enter_preadv2,
          obj->progs.trace_sys_exit_preadv2,
          obj->progs.trace_sys_enter_pwritev2,
          obj->progs.trace_sys_exit_pwritev2,

          obj->progs.trace_sys_enter_sendto,
          obj->progs.trace_sys_exit_sendto,
          obj->progs.trace_sys_enter_recvfrom,
          obj->progs.trace_sys_exit_recvfrom,

          obj->progs.trace_sys_enter_sendmsg,
          obj->progs.trace_sys_exit_sendmsg,
          obj->progs.trace_sys_enter_recvmsg,
          obj->progs.trace_sys_exit_recvmsg,

          obj->progs.trace_sys_enter_sendmmsg,
          obj->progs.trace_sys_exit_sendmmsg,
          obj->progs.trace_sys_enter_recvmmsg,
          obj->progs.trace_sys_exit_recvmmsg,
      };

      for (auto *prog : programs)
      {
          bpf_program__set_autoload(prog, false);
      }
  }
  bool peek_fd_is_event_enabled(EventType event_type)
  {
      switch (event_type)
      {
      case EVENT_READ:
          return bpf_program__autoload(obj->progs.trace_sys_enter_read);
      case EVENT_WRITE:
          return bpf_program__autoload(obj->progs.trace_sys_enter_write);
      case EVENT_RECVFROM:
          return bpf_program__autoload(obj->progs.trace_sys_enter_recvfrom);
      case EVENT_SENDTO:
          return bpf_program__autoload(obj->progs.trace_sys_enter_sendto);
      default:
          return false;
      }
  }
#endif
static int enable_read_trace(void)
{
	if (!(rule.rw & FD_READ))
	{
		return -1;
	}

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
		return -1;
	}

	bpf_program__set_autoload(obj->progs.trace_sys_enter_recvfrom, true);
	bpf_program__set_autoload(obj->progs.trace_sys_enter_recvmsg, true);
	bpf_program__set_autoload(obj->progs.trace_sys_enter_recvmmsg, true);
	bpf_program__set_autoload(obj->progs.trace_sys_exit_recvfrom, true);
	bpf_program__set_autoload(obj->progs.trace_sys_exit_recvmsg, true);
	bpf_program__set_autoload(obj->progs.trace_sys_exit_recvmmsg, true);

	return 0;
}
static int enable_write_trace(void)
{
	if (!(rule.rw & FD_WRITE))
	{
		return -1;
	}

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
		return -1;
	}

	bpf_program__set_autoload(obj->progs.trace_sys_enter_sendto, true);
	bpf_program__set_autoload(obj->progs.trace_sys_enter_sendmsg, true);
	bpf_program__set_autoload(obj->progs.trace_sys_enter_sendmmsg, true);
	bpf_program__set_autoload(obj->progs.trace_sys_exit_sendto, true);
	bpf_program__set_autoload(obj->progs.trace_sys_exit_sendmsg, true);
	bpf_program__set_autoload(obj->progs.trace_sys_exit_sendmmsg, true);

	return 0;
}

// Main function
#ifdef BUILTIN
int peek_fd_main(int argc, char *args[])
#else
int main(int argc, char *args[])
#endif
{
	int ret = parse_args(argc, args); // Parse command line arguments
	if (ret != 0)
	{
#ifdef BUILTIN
		{
			std::lock_guard<std::mutex> lock(runtime_state->sync.m);
			runtime_state->sync.exit_requested = true;
		}
		runtime_state->sync.cv.notify_all();
#endif
		return ret;
	}
#ifndef BUILTIN
	ret = register_signal(); // Register signal handler
	if(ret < 0){
		return ret;
	}
#endif

	int key = 0;			   // Key for BPF map
	obj = peek_fd_bpf::open(); // Open BPF program
	if (!obj)
	{
#ifndef BUILTIN
		exit(-1); // Exit if opening failed
#else
		ret = -1;
		goto err_out;
#endif
	}
#ifdef BUILTIN
	disable_all_trace_autoload(false);
#endif

	enable_read_trace();
	enable_write_trace(); 

	if (peek_fd_bpf::load(obj)) // Load BPF program
	{
		ret = -1;
		goto err_out;
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
#ifdef BUILTIN
	runtime_state->fds_promise.set_value(PeekFds{filter_fd, log_map_fd});
#endif
	rb = ring_buffer__new(log_map_fd, handle_event, NULL, NULL);
	if (!rb)
	{
		ret = -1;
		goto err_out; // Handle error
	}

	printf("start peeking\n");
	// Create a thread for processing the ring buffer
	if(pthread_create(&t1, NULL, ringbuf_worker, NULL) != 0)
	{
		pr_error("Failed to create ringbuf thread");
		ret = -1;
		goto err_out;
	};
#ifndef BUILTIN
	follow_trace_pipe(); // Read trace pipe
#else
	{
		std::lock_guard<std::mutex> lock(runtime_state->sync.m);
		runtime_state->sync.init_done = true;
	}
	runtime_state->sync.cv.notify_all();
	{
		std::unique_lock<std::mutex> lock(runtime_state->sync.m);
		runtime_state->sync.cv.wait(lock, [&] { return runtime_state->sync.exit_requested; });
	}
#endif
	pthread_join(t1, NULL); // Wait for the worker thread to finish
	printf("normally exit\n");
err_out:
	if (rb)
	{
		ring_buffer__free(rb); // Free ring buffer if allocated
	}
	peek_fd_bpf::detach(obj);  // Detach BPF program
	peek_fd_bpf::destroy(obj); // Clean up BPF program
	return ret;				   // Exit successfully or error based on ret value
}
