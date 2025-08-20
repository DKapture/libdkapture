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

#include "run-queue.skel.h"
#include "Ucom.h"
#include "jhash.h"

#include <stdexcept>
#include <sstream>
#include <map>
#include <vector>

struct Rule
{
	struct
	{
		pid_t min;
		pid_t max;
	} pid;
	struct
	{
		pid_t min;
		pid_t max;
	} tgid;
	u32 on_rq : 2;
	u32 on_cpu : 2;
	struct
	{
		u64 min;
		u64 max;
	} utime;
	struct
	{
		u64 min;
		u64 max;
	} stime;
	struct
	{
		u64 min;
		u64 max;
	} start_time;

	struct
	{
		int min;
		int max;
	} priority;
	char comm[16];
};

// Structure to log data
struct BpfData
{
	pid_t pid;
	pid_t tgid;
	u32 cpu;
	u32 on_rq : 1;
	u32 on_cpu : 1;
	u64 utime;
	u64 stime;
	u64 start_time;

	int priority;
	char comm[16];
};

static run_queue_bpf *obj;
static int log_map_fd;
static struct ring_buffer *rb = NULL;
static int filter_fd;
static pthread_t t1;
static bool exit_flag = false;
static int iter_fd;
static struct Rule rule = {
	.pid = {0, INT_MAX},
	.tgid = {0, INT_MAX},
	.on_rq = 1,
	.on_cpu = 1,
	.utime = {0, UINT64_MAX},
	.stime = {0, UINT64_MAX},
	.start_time = {0, UINT64_MAX},
	.priority = {0, INT_MAX},
	.comm = {0}
};

static struct option lopts[] = {
	{"tgid",		 required_argument, 0, 'P'},
	{"tid",		required_argument, 0, 'p'},
	{"on-rq",	  no_argument,	   0, 'r'},
	{"on-cpu",	   no_argument,		0, 'c'},
	{"utime",	  required_argument, 0, 'u'},
	{"stime",	  required_argument, 0, 's'},
	{"start_time", required_argument, 0, 'S'},
	{"priority",	 required_argument, 0, 'd'},
	{"comm",		 required_argument, 0, 'C'},
	{"help",		 no_argument,		  0, 'h'},
	{0,			0,				 0, 0  }
};

// Structure for help messages
struct HelpMsg
{
	const char *argparam; // Argument parameter
	const char *msg;	  // Help message
};

// Help messages
static HelpMsg help_msg[] = {
	{"<tgid>",	   "process pid to filter\n"						},
	{"<tid>",		  "process tid to filter\n"					   },
	{"",			 "whether process is on run queue currently\n"  },
	{"",			 "whether process is running on cpu currently\n"},
	{"<utime>",		"process user time to filter\n"				   },
	{"<stime>",		"process system time to filter\n"				 },
	{"<start_time>", "process start time to filter\n"				 },
	{"<priority>",   "process priority to filter\n"				 },
	{"<comm>",	   "process command line to filter\n"			 },
	{"",			 "print this help message\n"					},
};

// Function to print usage information
void Usage(const char *arg0)
{
	printf("Usage: %s [option]\n", arg0);
	printf("  print each task on each percpu run queue\n\n");
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

void parse_range(const std::string &range_str, u64 &min_val, u64 &max_val)
{
	size_t dash_pos = range_str.find('-');
	if (dash_pos == std::string::npos)
	{
		// Single number
		try
		{
			min_val = max_val = std::stoull(range_str);
		}
		catch (const std::invalid_argument &e)
		{
			throw std::invalid_argument("Invalid number format: " + range_str);
		}
		catch (const std::out_of_range &e)
		{
			throw std::out_of_range("Number out of range: " + range_str);
		}
	}
	else
	{
		// Range
		try
		{
			min_val = std::stoull(range_str.substr(0, dash_pos));
			max_val = std::stoull(range_str.substr(dash_pos + 1));
		}
		catch (const std::invalid_argument &e)
		{
			throw std::invalid_argument("Invalid range format: " + range_str);
		}
		catch (const std::out_of_range &e)
		{
			throw std::out_of_range(
				"Number out of range in range: " + range_str
			);
		}
	}
}

void parse_range(const std::string &range_str, u32 &min_val, u32 &max_val)
{
	u64 minv = 0, maxv = 0;
	parse_range(range_str, minv, maxv);
	min_val = minv;
	max_val = maxv;
}

// Parse command line arguments
void parse_args(int argc, char **argv)
{
	int opt, opt_idx;
	optind = 1;
	std::string sopts = long_opt2short_opt(lopts); // Convert long options to
												   // short options
	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0)
	{
		switch (opt)
		{
		case 'P':
			parse_range(optarg, *(u32 *)&rule.pid.min, *(u32 *)&rule.pid.max);
			break;
		case 'p':
			parse_range(optarg, *(u32 *)&rule.tgid.min, *(u32 *)&rule.tgid.max);
			rule.tgid.max = atoi(optarg);
			break;
		case 'r':
			rule.on_cpu = 1;
			break;
		case 'c':
			rule.on_cpu = 1;
			break;
		case 'u':
			parse_range(optarg, rule.utime.min, rule.utime.max);
			break;
		case 's':
			parse_range(optarg, rule.stime.min, rule.stime.max);
			break;
		case 'S':
			parse_range(optarg, rule.start_time.min, rule.start_time.max);
			break;
		case 'd':
			parse_range(
				optarg,
				*(u32 *)&rule.priority.min,
				*(u32 *)&rule.priority.max
			);
			break;
		case 'C':
			strncpy(rule.comm, optarg, 16);
			rule.comm[15] = 0;
			break;
		case 'h':
			Usage(argv[0]);
			exit(0);
			break;
		default:
			Usage(argv[0]);
			exit(-1);
			break;
		}
	}
}

std::map<u32, std::vector<struct BpfData>> runqueques;
// Handle events from the ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct BpfData *log = (const struct BpfData *)data; // Cast data to
															  // BpfData
															  // structure
	auto it = runqueques.find(log->cpu);
	if (it == runqueques.end())
	{
		runqueques[log->cpu] = std::vector<struct BpfData>();
	}

	runqueques[log->cpu].push_back(*log);

	return 0;
}

// Worker thread for processing ring buffer
void *ringbuf_worker(void *)
{
	while (!exit_flag)
	{
		int err = ring_buffer__poll(rb, 1000 /* timeout in ms */);

		if (err == 0 && iter_fd == -1)
		{
			break;
		}
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
		exit(EXIT_FAILURE);
	}
}

static void summary_print(void)
{
	for (auto &it : runqueques)
	{
		std::vector<struct BpfData> &logs = it.second;
		printf("\non run queue of cpu%d:\n", it.first);
		for (auto &log : logs)
		{
			printf(
				"\t%s %d %d %d %d %llu %llu %llu %u %d\n",
				log.comm,
				log.pid,
				log.tgid,
				log.on_cpu,
				log.on_rq,
				log.start_time,
				log.stime,
				log.utime,
				log.cpu,
				log.priority
			);
		}
	}
	printf("\n");
}

// Main function
int main(int argc, char *args[])
{
	char *buf = (char *)calloc(4096, 1);
	if (!buf)
	{
		fprintf(stderr, "Failed to allocate buffer from heap\n");
		exit(EXIT_FAILURE);
	}
	ssize_t rd_sz = 0;

	parse_args(argc, args); // Parse command line arguments
	register_signal();		// Register signal handler

	int key = 0;						  // Key for BPF map
	obj = run_queue_bpf::open_and_load(); // Load BPF program
	if (!obj)
	{
		goto cleanup; // Exit if loading failed
	}

	if (0 != run_queue_bpf::attach(obj))
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

	while ((rd_sz = read(iter_fd, buf, 4096)) > 0)
	{
	}

	close(iter_fd);
	iter_fd = -1;

	// Create a thread for processing the ring buffer
	pthread_create(&t1, NULL, ringbuf_worker, NULL);
	read_trace();			// Read trace
	pthread_join(t1, NULL); // Wait for the worker thread to finish
	summary_print();

cleanup:
	if (rb)
	{
		ring_buffer__free(rb); // Free ring buffer if allocated
	}
	run_queue_bpf::detach(obj);	 // Detach BPF program
	run_queue_bpf::destroy(obj); // Clean up BPF program
	free(buf);					 // Free allocated buffer
	return 0;
}