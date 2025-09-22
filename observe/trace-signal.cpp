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
struct ring_buffer *rb = NULL;
static int filter_fd;
static pthread_t t1;
static bool exit_flag = false;
struct Rule rule = {};

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
void Usage(const char *arg0)
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
	char *buf = (char *)calloc(4096, 1);
	if (!buf)
	{
		fprintf(stderr, "Failed to allocate buffer from heap\n");
		exit(EXIT_FAILURE);
	}

	optind = 1;
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
			exit(0);
			break;
		default: // Invalid option
			free(buf);
			Usage(argv[0]);
			exit(-1);
			break;
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
void register_signal(void)
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

// Main function
int main(int argc, char *args[])
{
	int iter_fd;
	ssize_t rd_sz;
	char *buf = (char *)calloc(4096, 1);
	if (!buf)
	{
		fprintf(stderr, "Failed to allocate buffer from heap\n");
		exit(EXIT_FAILURE);
	}

	parse_args(argc, args); // Parse command line arguments
	register_signal();		// Register signal handler

	int key = 0;							 // Key for BPF map
	obj = trace_signal_bpf::open_and_load(); // Load BPF program
	if (!obj)
	{
		goto cleanup; // Exit if loading failed
	}

	if (0 != trace_signal_bpf::attach(obj))
	{
		goto cleanup; // Attach BPF program
	}

	// Get file descriptor for filter map and update it with the rule
	filter_fd = bpf_get_map_fd(obj->obj, "filter", goto cleanup);
	if (0 != bpf_map_update_elem(filter_fd, &key, &rule, BPF_ANY))
	{
		printf("Error: bpf_map_update_elem");
		goto cleanup; // Handle error
	}

	// Create a ring buffer for logs
	log_map_fd = bpf_get_map_fd(obj->obj, "logs", goto cleanup);
	rb = ring_buffer__new(log_map_fd, handle_event, NULL, NULL);
	if (!rb)
	{
		goto cleanup; // Handle error
	}

	iter_fd = bpf_iter_create(bpf_link__fd(obj->links.dump_task));
	if (iter_fd < 0)
	{
		fprintf(stderr, "Error creating BPF iterator\n");
		goto cleanup;
	}

	while ((rd_sz = read(iter_fd, buf, sizeof(buf))) > 0)
	{
	}

	close(iter_fd);

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
	follow_trace_pipe();	// Read trace pipe
	pthread_join(t1, NULL); // Wait for the worker thread to finish

cleanup:
	if (rb)
	{
		ring_buffer__free(rb); // Free ring buffer if allocated
	}
	trace_signal_bpf::detach(obj);	// Detach BPF program
	trace_signal_bpf::destroy(obj); // Clean up BPF program
	free(buf);						// Free allocated buffer
	return 0;						// Exit successfully
}