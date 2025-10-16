// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <signal.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <vector>
#include <thread>
#include <atomic>
#include <map>

#include "com.h"

#include "net-traffic.skel.h"
#include "types.h"

static net_traffic_bpf *obj;

#define PF_INET 2
#define TRAFFIC_IN -1
#define TRAFFIC_OUT 1

struct BpfData
{
	pid_t pid;
	u32 traffic;
	u32 remote_ip;
	u16 remote_port;
	short dir;
	char comm[];
};

struct Rule
{
	u32 remote_ip;
	u16 remote_port;
	u16 dir;
	union
	{
		struct
		{
			u32 not_pid;
			pid_t pid;
		};
		char comm[16];
	};
};

#define SLICE_IP(x)                                                            \
	((x >> 24) & 0xff), ((x >> 16) & 0xff), ((x >> 8) & 0xff), ((x) & 0xff)

struct Rule rule = {0};
static int filter_fd;
static int log_map_fd;
struct ring_buffer *rb = NULL;
static std::atomic<bool> exit_flag(false);
std::map<std::string, unsigned long> traffic_stat_proc;
std::map<unsigned int, unsigned long> traffic_stat_ip;

static struct option lopts[] = {
	{"comm",	 required_argument, 0, 'c'},
	{"pid",	required_argument, 0, 'p'},
	{"remote", required_argument, 0, 'r'},
	{"port",	 required_argument, 0, 'P'},
	{"dir",	required_argument, 0, 'd'},
	{"help",	 no_argument,		  0, 'h'},
	{0,		0,				 0, 0  }
};

// Structure for help messages
struct HelpMsg
{
	const char *argparam; // Argument parameter
	const char *msg;	  // Help message
};

// Help messages
static HelpMsg help_msg[] = {
	{"<process name>", "process name to filter\n"	 },
	{"<process id>",	 "process id to filter\n"		 },
	{"<remote ip>",	"remote ip to filter\n"		   },
	{"<remote port>",  "remote port to filter\n"	   },
	{"<direction>",	"traffic direction to filter\n"},
	{"",			   "print this help message\n"	},
};

// Function to print usage information
void Usage(const char *arg0)
{
	printf("Usage: %s [option]\n", arg0);
	printf("  statistic network traffic per process, per ip, per port or per "
		   "interface\n\n");
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
	optind = 1;
	std::string sopts = long_opt2short_opt(lopts); // Convert long options to
												   // short options
	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0)
	{
		switch (opt)
		{
		case 'c': // Process name
			strncpy(rule.comm, optarg, sizeof(rule.comm));
			rule.comm[sizeof(rule.comm) - 1] = 0;
			break;
		case 'p': // Process ID
			rule.pid = atoi(optarg);
			break;
		case 'r': // Remote IP
			rule.remote_ip = inet_addr(optarg);
			break;
		case 'P': // Remote port
			rule.remote_port = atoi(optarg);
			break;
		case 'd': // Direction
			rule.dir = atoi(optarg);
			break;
		case 'h': // Help
			Usage(argv[0]);
			exit(0);
			break;
		default: // Invalid option
			Usage(argv[0]);
			exit(-1);
			break;
		}
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct BpfData *log = (const struct BpfData *)data;
	printf(
		"[%s] %s[%d] %s %d.%d.%d.%d:%d, traffic: %u\n",
		get_time().c_str(),
		log->comm,
		log->pid,
		log->dir == TRAFFIC_IN ? "from" : "to",
		SLICE_IP(log->remote_ip),
		log->remote_port,
		log->traffic
	);

	if (traffic_stat_proc.find(log->comm) == traffic_stat_proc.end())
	{
		traffic_stat_proc[log->comm] = 0;
	}
	traffic_stat_proc[log->comm] += log->traffic;

	if (traffic_stat_ip.find(log->remote_ip) == traffic_stat_ip.end())
	{
		traffic_stat_ip[log->remote_ip] = 0;
	}
	traffic_stat_ip[log->remote_ip] += log->traffic;
	return 0;
}

void ringbuf_worker(void)
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
}

void register_signal()
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

bool bpf_attachable(const char *name)
{
	struct btf *vmlinux_btf;
	int err, id;

	vmlinux_btf = btf__load_vmlinux_btf();
	err = libbpf_get_error(vmlinux_btf);
	if (err)
	{
		return false;
	}

	id = btf__find_by_name_kind(vmlinux_btf, name, BTF_KIND_FUNC);

	btf__free(vmlinux_btf);
	return id > 0;
}

static void fix_attach_point(net_traffic_bpf *obj)
{
	if (!bpf_attachable("__sock_sendmsg"))
	{
		bpf_program__set_autoload(obj->progs.__sock_sendmsg, false);
	}
	else
	{
		bpf_program__set_autoload(obj->progs.sock_sendmsg, false);
		bpf_program__set_autoload(obj->progs.sock_write_iter, false);
		bpf_program__set_autoload(obj->progs.__sys_sendto_entry, false);
		bpf_program__set_autoload(obj->progs.socket_sendmsg, false);
		bpf_program__set_autoload(obj->progs.__sys_sendto_exit, false);
		bpf_program__set_autoload(obj->progs.____sys_sendmsg, false);
	}
}

int main(int argc, char **argv)
{
	std::vector<struct Rule> rules;

	parse_args(argc, argv);

	register_signal();
	std::thread *rb_thread;

	obj = net_traffic_bpf::open();
	if (!obj)
	{
		exit(-1);
	}

	fix_attach_point(obj);
	if (net_traffic_bpf::load(obj) < 0)
	{
		exit(-1);
	}
	if (0 != net_traffic_bpf::attach(obj))
	{
		exit(-1);
	}

	filter_fd = bpf_get_map_fd(obj->obj, "filter", goto err_out);
	log_map_fd = bpf_get_map_fd(obj->obj, "logs", goto err_out);
	rb = ring_buffer__new(log_map_fd, handle_event, NULL, NULL);
	if (!rb)
	{
		goto err_out; // Handle error
	}

	rb_thread = new std::thread(ringbuf_worker);
	follow_trace_pipe();

	rb_thread->join();
	delete rb_thread;
err_out:
	if (rb)
	{
		ring_buffer__free(rb);
	}
	net_traffic_bpf::detach(obj);  // Detach BPF program
	net_traffic_bpf::destroy(obj); // Clean up BPF object
	return -1;
}