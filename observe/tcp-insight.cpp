// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcp-insight.h"
#include "tcp-insight.skel.h"

/* Global variables */
static volatile bool exiting = false;
static bool verbose = false;
static bool show_timestamp = false;
static bool show_stats = false;
static struct tcp_insight_bpf *skel;

/* Environment structure for command line arguments */
static struct env
{
	pid_t pid;
	char comm[16];
	char saddr[16];
	char daddr[16];
	int sport;
	int dport;
	int event_mask;
	int min_duration;
	int max_duration;
	long min_bytes;
	long max_bytes;
	int min_rtt;
	int max_rtt;
	int state_filter;
} env = {
	.pid = 0,
	.sport = 0,
	.dport = 0,
	.event_mask = 0,
	.min_duration = 0,
	.max_duration = 0,
	.min_bytes = 0,
	.max_bytes = 0,
	.min_rtt = 0,
	.max_rtt = 0,
	.state_filter = 0,
};

/* Command line options */
static const struct argp_option opts[] = {
	{"pid", 'p', "PID", 0, "Process ID to trace", 0},
	{"comm", 'c', "COMM", 0, "Process name to trace", 0},
	{"saddr", 's', "ADDR", 0, "Source address to filter", 0},
	{"daddr", 'd', "ADDR", 0, "Destination address to filter", 0},
	{"sport", ARG_SPORT, "PORT", 0, "Source port to filter", 0},
	{"dport", ARG_DPORT, "PORT", 0, "Destination port to filter", 0},
	{"events", 'e', "MASK", 0, "Event types to trace (bitmask)", 0},
	{"min-duration", ARG_MIN_DURATION, "MS", 0, "Minimum connection duration", 0
	},
	{"max-duration", ARG_MAX_DURATION, "MS", 0, "Maximum connection duration", 0
	},
	{"min-bytes", ARG_MIN_BYTES, "BYTES", 0, "Minimum bytes transferred", 0},
	{"max-bytes", ARG_MAX_BYTES, "BYTES", 0, "Maximum bytes transferred", 0},
	{"min-rtt", ARG_MIN_RTT, "US", 0, "Minimum RTT in microseconds", 0},
	{"max-rtt", ARG_MAX_RTT, "US", 0, "Maximum RTT in microseconds", 0},
	{"state", 'S', "STATE", 0, "Filter by TCP state (1-12)", 0},
	{"verbose", 'v', NULL, 0, "Verbose output", 0},
	{"timestamp", 't', NULL, 0, "Show timestamps", 0},
	{"stats", 'T', NULL, 0, "Show connection statistics", 0},
	{},
};

/* Program documentation */
static char args_doc[] = "";
static char doc[] =
	"tcp-insight - TCP subsystem observation tool\n"
	"\n"
	"USAGE: tcp-insight [OPTIONS]\n"
	"\n"
	"EXAMPLES:\n"
	"    tcp-insight                    # Trace all TCP events\n"
	"    tcp-insight -p 1234            # Trace specific process\n"
	"    tcp-insight -s 192.168.1.100   # Trace specific source address\n"
	"    tcp-insight -e 0x1F            # Trace connection lifecycle events\n"
	"    tcp-insight --min-rtt 1000     # Trace high latency connections\n"
	"    tcp-insight -v -t              # Verbose output with timestamps\n"
	"\n"
	"Event types (for -e bitmask):\n"
	"    1   CONNECT         TCP connection initiated\n"
	"    2   ACCEPT          TCP connection accepted\n"
	"    4   SEND            TCP data sent\n"
	"    8   RECEIVE         TCP data received\n"
	"    16  RETRANSMIT      TCP retransmission\n"
	"    32  CLOSE           TCP connection closed\n"
	"    64  RESET           TCP connection reset\n"
	"    128 CWND_CHANGE     Congestion window change\n"
	"    256 RTT_UPDATE      RTT measurement update\n"
	"    512 SLOW_START      Slow start phase\n"
	"    1024 CONG_AVOID     Congestion avoidance\n"
	"    2048 FAST_RECOVERY  Fast recovery phase\n"
	"    4096 WINDOW_UPDATE  Receive window update\n"
	"    8192 SACK           SACK event\n"
	"    16384 TIMEOUT       RTO timeout\n";

/* Statistics tracking */
static struct
{
	unsigned long total_events;
	unsigned long connection_events;
	unsigned long data_events;
	unsigned long performance_events;
	unsigned long error_events;
} stats;

/* Function prototypes */
static error_t parse_arg(int key, char *arg, struct argp_state *state);
static void sig_handler(int sig);
static int libbpf_print_fn(
	enum libbpf_print_level level,
	const char *format,
	va_list args
);
static int handle_event(void *ctx, void *data, size_t data_sz);
static void print_header();
static const char *tcp_event_type_str(int type);
static const char *tcp_state_str(int state);
static void format_address(char *buf, size_t len, __u32 addr, __u16 port);
static void format_timestamp(char *buf, size_t len, __u64 timestamp);
static void print_connection_stats();
static int setup_filters();
static __u32 parse_addr(const char *addr_str);
static void cleanup();

/* Argument parser configuration */
static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.args_doc = args_doc,
	.doc = doc,
};

/* Signal handler */
static void sig_handler(int sig)
{
	exiting = true;
}

/* libbpf print function */
static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
	{
		return 0;
	}
	return vfprintf(stderr, format, args);
}

/* TCP event type to string conversion */
static const char *tcp_event_type_str(int type)
{
	switch (type)
	{
	case TCP_EVENT_STATE_CHANGE:
		return "STATE_CHANGE";
	case TCP_EVENT_RETRANSMIT:
		return "RETRANSMIT";
	case TCP_EVENT_SEND_RESET:
		return "SEND_RESET";
	case TCP_EVENT_RECV_RESET:
		return "RECV_RESET";
	case TCP_EVENT_SEND_DATA:
		return "SEND_DATA";
	case TCP_EVENT_RECV_DATA:
		return "RECV_DATA";
	case TCP_EVENT_SOCK_DESTROY:
		return "DESTROY";
	case TCP_EVENT_CONG_STATE:
		return "CONG_STATE";
	case TCP_EVENT_WIN_ADJUST:
		return "WIN_ADJUST";
	case TCP_EVENT_PERF_SAMPLE:
		return "PERF_SAMPLE";
	case TCP_EVENT_KPROBE_SEND:
		return "KPROBE_SEND";
	case TCP_EVENT_KPROBE_RECV:
		return "KPROBE_RECV";
	case TCP_EVENT_KPROBE_RETRANS:
		return "KPROBE_RETRANS";
	default:
		return "UNKNOWN";
	}
}

/* TCP state to string conversion */
static const char *tcp_state_str(int state)
{
	switch (state)
	{
	case TCP_ESTABLISHED:
		return "ESTABLISHED";
	case TCP_SYN_SENT:
		return "SYN_SENT";
	case TCP_SYN_RECV:
		return "SYN_RECV";
	case TCP_FIN_WAIT1:
		return "FIN_WAIT1";
	case TCP_FIN_WAIT2:
		return "FIN_WAIT2";
	case TCP_TIME_WAIT:
		return "TIME_WAIT";
	case TCP_CLOSE:
		return "CLOSE";
	case TCP_CLOSE_WAIT:
		return "CLOSE_WAIT";
	case TCP_LAST_ACK:
		return "LAST_ACK";
	case TCP_LISTEN:
		return "LISTEN";
	case TCP_CLOSING:
		return "CLOSING";
	case TCP_NEW_SYN_RECV:
		return "NEW_SYN_RECV";
	default:
		return "UNKNOWN";
	}
}

/* Format IP address and port */
static void format_address(char *buf, size_t len, __u32 addr, __u16 port)
{
	struct in_addr in_addr = {.s_addr = addr};
	snprintf(buf, len, "%s:%d", inet_ntoa(in_addr), port);
}

/* Format timestamp */
static void format_timestamp(char *buf, size_t len, __u64 timestamp)
{
	struct timespec ts;
	struct tm *tm;

	ts.tv_sec = timestamp / 1000000000;
	ts.tv_nsec = timestamp % 1000000000;

	tm = localtime(&ts.tv_sec);
	strftime(buf, len, "%H:%M:%S", tm);

	char ms_buf[16];
	snprintf(ms_buf, sizeof(ms_buf), ".%03ld", ts.tv_nsec / 1000000);
	strncat(buf, ms_buf, len - strlen(buf) - 1);
}

/* Parse IP address string to __u32 */
static __u32 parse_addr(const char *addr_str)
{
	struct in_addr addr;
	if (inet_aton(addr_str, &addr) == 0)
	{
		fprintf(stderr, "Invalid IP address: %s\n", addr_str);
		exit(1);
	}
	return addr.s_addr;
}

/* Print output header */
static void print_header()
{
	if (show_timestamp)
	{
		printf("%-12s ", "TIME");
	}
	printf(
		"%-16s %-6s %-6s %-15s %-22s %-22s %-12s %-6s %-6s %-8s %s\n",
		"COMM",
		"PID",
		"TID",
		"EVENT",
		"SADDR:SPORT",
		"DADDR:DPORT",
		"STATE",
		"CWND",
		"RTT",
		"BYTES",
		"DETAILS"
	);
}

/* Command line argument parser */
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key)
	{
	case 'p':
		env.pid = strtol(arg, NULL, 10);
		if (env.pid <= 0)
		{
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		strncpy(env.comm, arg, sizeof(env.comm) - 1);
		env.comm[sizeof(env.comm) - 1] = '\0';
		break;
	case 's':
		strncpy(env.saddr, arg, sizeof(env.saddr) - 1);
		env.saddr[sizeof(env.saddr) - 1] = '\0';
		break;
	case 'd':
		strncpy(env.daddr, arg, sizeof(env.daddr) - 1);
		env.daddr[sizeof(env.daddr) - 1] = '\0';
		break;
	case ARG_SPORT:
		env.sport = strtol(arg, NULL, 10);
		if (env.sport <= 0 || env.sport > 65535)
		{
			fprintf(stderr, "Invalid source port: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARG_DPORT:
		env.dport = strtol(arg, NULL, 10);
		if (env.dport <= 0 || env.dport > 65535)
		{
			fprintf(stderr, "Invalid destination port: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'e':
		env.event_mask = strtol(arg, NULL, 0);
		if (env.event_mask < 0 || env.event_mask > TCP_EVENT_MASK_ALL)
		{
			fprintf(stderr, "Invalid event mask: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARG_MIN_DURATION:
		env.min_duration = strtol(arg, NULL, 10);
		if (env.min_duration < 0)
		{
			fprintf(stderr, "Invalid minimum duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARG_MAX_DURATION:
		env.max_duration = strtol(arg, NULL, 10);
		if (env.max_duration < 0)
		{
			fprintf(stderr, "Invalid maximum duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARG_MIN_BYTES:
		env.min_bytes = strtol(arg, NULL, 10);
		if (env.min_bytes < 0)
		{
			fprintf(stderr, "Invalid minimum bytes: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARG_MAX_BYTES:
		env.max_bytes = strtol(arg, NULL, 10);
		if (env.max_bytes < 0)
		{
			fprintf(stderr, "Invalid maximum bytes: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARG_MIN_RTT:
		env.min_rtt = strtol(arg, NULL, 10);
		if (env.min_rtt < 0)
		{
			fprintf(stderr, "Invalid minimum RTT: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARG_MAX_RTT:
		env.max_rtt = strtol(arg, NULL, 10);
		if (env.max_rtt < 0)
		{
			fprintf(stderr, "Invalid maximum RTT: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'S':
		env.state_filter = strtol(arg, NULL, 10);
		if (env.state_filter < 1 || env.state_filter >= TCP_MAX_STATES)
		{
			fprintf(
				stderr,
				"Invalid TCP state: %s (valid range: 1-%d)\n",
				arg,
				TCP_MAX_STATES - 1
			);
			argp_usage(state);
		}
		break;
	case 'v':
		verbose = true;
		break;
	case 't':
		show_timestamp = true;
		break;
	case 'T':
		show_stats = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

/* Setup filtering rules in eBPF maps */
static int setup_filters()
{
	struct tcp_filter_rule rule = {};
	__u32 key = 0; // Global rule key

	// Set up PID filter
	if (env.pid > 0)
	{
		rule.pid = env.pid;
		key = env.pid;
	}

	// Set up address filters
	if (strlen(env.saddr) > 0)
	{
		rule.addr.ipv4.saddr = parse_addr(env.saddr);
	}

	if (strlen(env.daddr) > 0)
	{
		rule.addr.ipv4.daddr = parse_addr(env.daddr);
	}

	// Set up port filters
	if (env.sport > 0)
	{
		rule.sport = env.sport;
	}

	if (env.dport > 0)
	{
		rule.dport = env.dport;
	}

	// Set up event mask filter
	if (env.event_mask > 0)
	{
		rule.event_mask = env.event_mask;
	}

	// Set up duration filters
	if (env.min_duration > 0)
	{
		rule.min_duration = env.min_duration;
	}

	if (env.max_duration > 0)
	{
		rule.max_duration = env.max_duration;
	}

	// Set up bytes filters
	if (env.min_bytes > 0)
	{
		rule.min_bytes = env.min_bytes;
	}

	if (env.max_bytes > 0)
	{
		rule.max_bytes = env.max_bytes;
	}

	// Set up RTT filters
	if (env.min_rtt > 0)
	{
		rule.min_rtt = env.min_rtt;
	}

	if (env.max_rtt > 0)
	{
		rule.max_rtt = env.max_rtt;
	}

	// Set up state filter
	if (env.state_filter > 0)
	{
		rule.tcp_state = env.state_filter;
	}

	// Update the rules map
	int rules_fd = bpf_map__fd(skel->maps.rules_map);
	if (rules_fd < 0)
	{
		fprintf(stderr, "Failed to get rules map fd\n");
		return -1;
	}

	int err = bpf_map_update_elem(rules_fd, &key, &rule, BPF_ANY);
	if (err)
	{
		fprintf(stderr, "Failed to update rules map: %d\n", err);
		return -1;
	}

	if (verbose)
	{
		printf("Filter rules configured:\n");
		if (env.pid > 0)
		{
			printf("  PID: %d\n", env.pid);
		}
		if (strlen(env.comm) > 0)
		{
			printf("  Command: %s\n", env.comm);
		}
		if (strlen(env.saddr) > 0)
		{
			printf("  Source address: %s\n", env.saddr);
		}
		if (strlen(env.daddr) > 0)
		{
			printf("  Destination address: %s\n", env.daddr);
		}
		if (env.sport > 0)
		{
			printf("  Source port: %d\n", env.sport);
		}
		if (env.dport > 0)
		{
			printf("  Destination port: %d\n", env.dport);
		}
		if (env.event_mask > 0)
		{
			printf("  Event mask: 0x%x\n", env.event_mask);
		}
		if (env.min_duration > 0)
		{
			printf("  Min duration: %d ms\n", env.min_duration);
		}
		if (env.max_duration > 0)
		{
			printf("  Max duration: %d ms\n", env.max_duration);
		}
		if (env.min_bytes > 0)
		{
			printf("  Min bytes: %ld\n", env.min_bytes);
		}
		if (env.max_bytes > 0)
		{
			printf("  Max bytes: %ld\n", env.max_bytes);
		}
		if (env.min_rtt > 0)
		{
			printf("  Min RTT: %d us\n", env.min_rtt);
		}
		if (env.max_rtt > 0)
		{
			printf("  Max RTT: %d us\n", env.max_rtt);
		}
		if (env.state_filter > 0)
		{
			printf("  TCP state: %s\n", tcp_state_str(env.state_filter));
		}
		printf("\n");
	}

	return 0;
}

/* Event handler callback */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct tcp_event *e = (struct tcp_event *)data;
	char timestamp_buf[32] = "";
	char saddr_buf[32], daddr_buf[32];

	// Update statistics
	stats.total_events++;

	switch (e->type)
	{
	case TCP_EVENT_STATE_CHANGE:
	case TCP_EVENT_SOCK_DESTROY:
		stats.connection_events++;
		break;
	case TCP_EVENT_SEND_DATA:
	case TCP_EVENT_RECV_DATA:
	case TCP_EVENT_RETRANSMIT:
	case TCP_EVENT_KPROBE_SEND:
	case TCP_EVENT_KPROBE_RECV:
	case TCP_EVENT_KPROBE_RETRANS:
		stats.data_events++;
		break;
	case TCP_EVENT_CONG_STATE:
	case TCP_EVENT_WIN_ADJUST:
	case TCP_EVENT_PERF_SAMPLE:
		stats.performance_events++;
		break;
	case TCP_EVENT_SEND_RESET:
	case TCP_EVENT_RECV_RESET:
		stats.error_events++;
		break;
	}

	// Apply command name filter in userspace if specified
	if (strlen(env.comm) > 0)
	{
		if (strstr(e->comm, env.comm) == NULL)
		{
			return 0;
		}
	}

	// Format addresses
	format_address(
		saddr_buf,
		sizeof(saddr_buf),
		((e->family == AF_INET) ? e->addr.ipv4.saddr : 0),
		e->sport
	);
	format_address(
		daddr_buf,
		sizeof(daddr_buf),
		((e->family == AF_INET) ? e->addr.ipv4.daddr : 0),
		e->dport
	);

	// Format timestamp if requested
	if (show_timestamp)
	{
		format_timestamp(timestamp_buf, sizeof(timestamp_buf), e->timestamp);
		printf("%-12s ", timestamp_buf);
	}

	// Extract event-specific data
	char state_buf[16] = "N/A";
	char cwnd_buf[16] = "N/A";
	char rtt_buf[16] = "N/A";
	char bytes_buf[16] = "N/A";
	char details_buf[64] = "N/A";

	switch (e->type)
	{
	case TCP_EVENT_STATE_CHANGE:
		snprintf(
			state_buf,
			sizeof(state_buf),
			"%s->%s",
			tcp_state_str(e->data.state_change.oldstate),
			tcp_state_str(e->data.state_change.newstate)
		);
		snprintf(
			details_buf,
			sizeof(details_buf),
			"skaddr=0x%p",
			e->data.state_change.skaddr
		);
		break;

	case TCP_EVENT_PERF_SAMPLE:
		snprintf(
			cwnd_buf,
			sizeof(cwnd_buf),
			"%u",
			e->data.perf_sample.snd_cwnd
		);
		snprintf(rtt_buf, sizeof(rtt_buf), "%u", e->data.perf_sample.srtt);
		snprintf(
			bytes_buf,
			sizeof(bytes_buf),
			"%u",
			e->data.perf_sample.data_len
		);
		snprintf(
			details_buf,
			sizeof(details_buf),
			"ssthresh=%u rcv_wnd=%u",
			e->data.perf_sample.ssthresh,
			e->data.perf_sample.rcv_wnd
		);
		break;

	case TCP_EVENT_RETRANSMIT:
		snprintf(
			state_buf,
			sizeof(state_buf),
			"%s",
			tcp_state_str(e->data.retransmit.state)
		);
		snprintf(
			details_buf,
			sizeof(details_buf),
			"skb=0x%p sk=0x%p",
			e->data.retransmit.skbaddr,
			e->data.retransmit.skaddr
		);
		break;

	case TCP_EVENT_SEND_DATA:
	case TCP_EVENT_RECV_DATA:
		snprintf(bytes_buf, sizeof(bytes_buf), "%d", e->data.data_transfer.ret);
		snprintf(
			details_buf,
			sizeof(details_buf),
			"flags=0x%x sk=0x%p",
			e->data.data_transfer.flags,
			e->data.data_transfer.sk
		);
		break;

	case TCP_EVENT_SEND_RESET:
	case TCP_EVENT_RECV_RESET:
		snprintf(
			state_buf,
			sizeof(state_buf),
			"%s",
			tcp_state_str(e->data.reset.state)
		);
		snprintf(
			details_buf,
			sizeof(details_buf),
			"skb=0x%p sk=0x%p cookie=%llu",
			e->data.reset.skbaddr,
			e->data.reset.skaddr,
			e->data.reset.sock_cookie
		);
		break;

	case TCP_EVENT_CONG_STATE:
		snprintf(
			details_buf,
			sizeof(details_buf),
			"cong_state=%u sk=0x%p",
			e->data.cong_state.cong_state,
			e->data.cong_state.skaddr
		);
		break;

	case TCP_EVENT_WIN_ADJUST:
		snprintf(
			details_buf,
			sizeof(details_buf),
			"sk=0x%p cookie=%llu",
			e->data.win_adjust.skaddr,
			e->data.win_adjust.sock_cookie
		);
		break;

	case TCP_EVENT_SOCK_DESTROY:
		snprintf(
			details_buf,
			sizeof(details_buf),
			"sk=0x%p cookie=%llu",
			e->data.destroy.skaddr,
			e->data.destroy.sock_cookie
		);
		break;

	case TCP_EVENT_KPROBE_SEND:
	case TCP_EVENT_KPROBE_RECV:
	case TCP_EVENT_KPROBE_RETRANS:
		snprintf(bytes_buf, sizeof(bytes_buf), "%zu", e->data.kprobe.size);
		snprintf(
			details_buf,
			sizeof(details_buf),
			"flags=0x%x sk=0x%p",
			e->data.kprobe.flags,
			e->data.kprobe.sk
		);
		break;
	}

	// Print the event with extracted data
	printf(
		"%-16s %-6d %-6d %-15s %-22s %-22s %-12s %-6s %-6s %-8s %s\n",
		e->comm,
		e->pid,
		e->tid,
		tcp_event_type_str(e->type),
		saddr_buf,
		daddr_buf,
		state_buf,
		cwnd_buf,
		rtt_buf,
		bytes_buf,
		details_buf
	);

	return 0;
}

/* Print connection statistics */
static void print_connection_stats()
{
	printf("\n=== TCP Insight Statistics ===\n");
	printf("Total events: %lu\n", stats.total_events);
	printf("Connection events: %lu\n", stats.connection_events);
	printf("Data events: %lu\n", stats.data_events);
	printf("Performance events: %lu\n", stats.performance_events);
	printf("Error events: %lu\n", stats.error_events);

	// Try to get eBPF global statistics
	int stats_fd = bpf_map__fd(skel->maps.global_stats);
	if (stats_fd >= 0)
	{
		__u32 key = 0;
		struct tcp_global_stats bpf_stats;

		if (bpf_map_lookup_elem(stats_fd, &key, &bpf_stats) == 0)
		{
			printf("\n=== eBPF Global Statistics ===\n");
			printf("Total eBPF events: %llu\n", bpf_stats.total_events);
			printf("Total connections: %llu\n", bpf_stats.connections_opened);
			printf("Total bytes sent: %llu\n", bpf_stats.bytes_sent);
			printf("Total bytes received: %llu\n", bpf_stats.bytes_received);
			printf("Total retransmits: %llu\n", bpf_stats.retransmits);
			printf("Average RTT: %u us\n", 0);
			printf("Average CWND: %u\n", 0);
			printf("Active connections: %u\n", 0);
		}
	}
	printf("\n");
}

/* Cleanup function */
static void cleanup()
{
	if (skel)
	{
		tcp_insight_bpf__destroy(skel);
		skel = NULL;
	}
}

/* Main program */
int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
	{
		return err;
	}

	/* Set up libbpf logging */
	libbpf_set_print(libbpf_print_fn);

	/* Set up signal handlers */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Increase RLIMIT_MEMLOCK to load BPF maps */
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
	{
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		return 1;
	}

	/* Load and verify BPF application */
	skel = tcp_insight_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load BPF program */
	err = tcp_insight_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	/* Attach BPF programs */
	err = tcp_insight_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	/* Setup filters */
	err = setup_filters();
	if (err)
	{
		fprintf(stderr, "Failed to setup filters: %d\n", err);
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(
		bpf_map__fd(skel->maps.events),
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

	/* Print header */
	print_header();

	if (verbose)
	{
		printf("TCP Insight started. Press Ctrl-C to exit.\n\n");
	}

	/* Process events */
	while (!exiting)
	{
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

	/* Print final statistics if requested */
	if (show_stats)
	{
		print_connection_stats();
	}

cleanup:
	/* Cleanup */
	ring_buffer__free(rb);
	cleanup();

	return err < 0 ? -err : 0;
}