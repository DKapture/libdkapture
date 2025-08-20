#include <signal.h>
#include <unistd.h>
#include <iostream>
#include <cstring>
#include <getopt.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tc-cgroup.skel.h"

#define EGRESS 1
#define INGRESS 0
#define DEFAULT_RATE_BPS 5 * 1024 * 1024 // Default 5MB/s

// Event structure, matching BPF program
struct event_t
{
	__u32 pid;
	__u32 bytes_sent;
	__u32 bytes_dropped;
	__u32 packets_sent;
	__u32 packets_dropped;
	__u64 timestamp;
};

// Rate limiting rule structure
struct CgroupRule
{
	uint64_t rate_bps;	 // Rate limit (bytes/second)
	uint8_t gress;		 // Direction: EGRESS=1, INGRESS=0
	uint32_t time_scale; // Time scale (seconds)
};

// Global state variables
static struct tc_cgroup_bpf *skel = nullptr;
static struct ring_buffer *rb = nullptr;
static volatile bool running = true;
static struct CgroupRule rule = {0};
static std::string cgroup_path;

// Command line option definitions
static struct option lopts[] = {
	{"cgroup",	   required_argument, 0, 'c'},
	{"rate",		 required_argument, 0, 'r'},
	{"direction", required_argument, 0, 'd'},
	{"timescale", required_argument, 0, 't'},
	{"help",		 no_argument,		  0, 'h'},
	{0,		   0,				 0, 0  }
};

// Parse bandwidth string (supports K/M/G suffixes)
static uint64_t parse_bandwidth(const char *str)
{
	if (!str)
	{
		return DEFAULT_RATE_BPS;
	}

	char *endptr;
	errno = 0;
	uint64_t value = strtoull(str, &endptr, 10);

	// Simple validation: check for conversion errors
	if (errno == ERANGE || value == 0)
	{
		return DEFAULT_RATE_BPS;
	}

	if (*endptr == '\0')
	{
		return value;
	}
	else if (strcasecmp(endptr, "K") == 0)
	{
		return value * 1024;
	}
	else if (strcasecmp(endptr, "M") == 0)
	{
		return value * 1024 * 1024;
	}
	else if (strcasecmp(endptr, "G") == 0)
	{
		return value * 1024 * 1024 * 1024;
	}

	return DEFAULT_RATE_BPS;
}

// Ring buffer event handling callback
static int handle_traffic_event(void *ctx, void *data, size_t data_sz)
{
	if (data_sz != sizeof(event_t))
	{
		return 0;
	}

	const struct event_t *e = static_cast<const struct event_t *>(data);

	std::cout << "Tracked process: PID " << e->pid;

	if (e->bytes_dropped > 0)
	{
		std::cout << " [DROP] " << e->bytes_dropped << " bytes" << std::endl;
	}
	else if (e->bytes_sent > 0)
	{
		std::cout << " [SEND] " << e->bytes_sent << " bytes" << std::endl;
	}
	else
	{
		std::cout << " [MATCH]" << std::endl;
	}

	return 0;
}

// Signal handler
static void sig_handler(int sig)
{
	std::cout << "\nReceived signal " << sig << ", exiting..." << std::endl;
	running = false;
}

// libbpf log print callback function
static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

// Print usage information
void Usage(const char *arg0)
{
	std::cout << "Usage: " << arg0 << " [options]" << std::endl;
	std::cout << "Options:" << std::endl;
	std::cout << "  -c, --cgroup <path>  Cgroup path" << std::endl;
	std::cout << "  -r, --rate <rate>      Rate limit (supports K/M/G suffixes)"
			  << std::endl;
	std::cout << "  -d, --direction <dir>  Match direction (egress=outgoing, "
				 "ingress=incoming)"
			  << std::endl;
	std::cout << "  -t, --timescale <sec>  Time scale (seconds, controls burst "
				 "tolerance)"
			  << std::endl;
	std::cout << "  -h, --help            Show help information" << std::endl;
	std::cout << std::endl;
	std::cout << "Time Scale Examples:" << std::endl;
	std::cout << "  -t 1     : 1 second scale, strict rate limiting, low burst "
				 "tolerance"
			  << std::endl;
	std::cout << "  -t 60    : 1 minute scale, allows short-term bursts, "
				 "long-term average rate limiting"
			  << std::endl;
	std::cout << "  -t 3600  : 1 hour scale, allows long-term bursts, suitable "
				 "for long-term bandwidth management"
			  << std::endl;
	std::cout << std::endl;
	std::cout << "Note: This program will limit traffic for the entire cgroup, "
				 "not individual processes"
			  << std::endl;
}

// Safe string to integer conversion
template <typename T>
static bool safe_str_to_int(const char *str, T *result, T min_val, T max_val)
{
	static_assert(std::is_integral_v<T>, "T must be an integral type");

	if (!str || !result)
	{
		return false;
	}

	char *endptr;
	errno = 0;

	if constexpr (std::is_signed_v<T>)
	{
		long val = strtol(str, &endptr, 10);
		if (errno == ERANGE || val < static_cast<long>(min_val) ||
			val > static_cast<long>(max_val))
		{
			return false;
		}
		*result = static_cast<T>(val);
	}
	else
	{
		unsigned long val = strtoul(str, &endptr, 10);
		if (errno == ERANGE || val > static_cast<unsigned long>(max_val))
		{
			return false;
		}
		*result = static_cast<T>(val);
	}

	if (*endptr != '\0')
	{
		return false;
	}

	return true;
}

// Parse command line arguments
void parse_args(int argc, char **argv)
{
	int opt, opt_idx;
	std::string sopts = "c:r:d:t:h";

	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0)
	{
		switch (opt)
		{
		case 'c': // Cgroup path
			cgroup_path = optarg;
			break;
		case 'r': // Rate limit
			rule.rate_bps = parse_bandwidth(optarg);
			if (rule.rate_bps == 0)
			{
				std::cerr << "Error: Invalid rate limit '" << optarg << "'"
						  << std::endl;
				exit(-1);
			}
			break;
		case 'd': // Match direction
			if (strcasecmp(optarg, "egress") == 0)
			{
				rule.gress = EGRESS;
			}
			else if (strcasecmp(optarg, "ingress") == 0)
			{
				rule.gress = INGRESS;
			}
			else
			{
				std::cerr << "Error: Invalid direction '" << optarg << "'"
						  << std::endl;
				exit(-1);
			}
			break;
		case 't': // Time scale
			if (!safe_str_to_int(
					optarg,
					&rule.time_scale,
					static_cast<uint32_t>(1),
					static_cast<uint32_t>(3600)
				))
			{
				std::cerr << "Error: Invalid time scale '" << optarg << "'"
						  << std::endl;
				exit(-1);
			}
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

	// Check required parameters
	if (cgroup_path.empty())
	{
		std::cerr << "Error: Cgroup path must be specified (-c)" << std::endl;
		Usage(argv[0]);
		exit(-1);
	}

	// Set default values
	if (rule.rate_bps == 0)
	{
		std::cout << "Using default rate limit: " << DEFAULT_RATE_BPS << " B/s"
				  << std::endl;
		rule.rate_bps = DEFAULT_RATE_BPS;
	}
	else
	{
		std::cout << "Setting rate limit: " << rule.rate_bps << " B/s ("
				  << (rule.rate_bps / 1024.0 / 1024.0) << " MB/s)" << std::endl;
	}

	if (rule.time_scale == 0)
	{
		rule.time_scale = 1;
		std::cout << "Using default time scale: 1 second" << std::endl;
	}
	else
	{
		std::cout << "Setting time scale: " << rule.time_scale << " seconds"
				  << std::endl;
	}

	std::cout << "Cgroup path: " << cgroup_path << std::endl;
	std::cout << "Match direction: "
			  << (rule.gress ? "EGRESS (outgoing)" : "INGRESS (incoming)")
			  << std::endl;
	std::cout << "Rate limit: " << rule.rate_bps << " B/s ("
			  << (rule.rate_bps / 1024.0 / 1024.0) << " MB/s)" << std::endl;
	std::cout << "Time scale: " << rule.time_scale
			  << " seconds (max bucket capacity: "
			  << (rule.rate_bps * rule.time_scale / 1024.0 / 1024.0) << " MB)"
			  << std::endl;
}

// Configure rate limiting rules to BPF map
static bool setup_cgroup_rules()
{
	struct bpf_map *map =
		bpf_object__find_map_by_name(skel->obj, "cgroup_rules");
	if (!map)
	{
		std::cerr << "Cannot find cgroup_rules map" << std::endl;
		return false;
	}

	uint32_t key = 0;

	struct
	{
		__u64 rate_bps;
		__u8 gress;
		__u32 time_scale;
	} rule_data = {
		.rate_bps = rule.rate_bps,
		.gress = rule.gress,
		.time_scale = rule.time_scale
	};

	int err = bpf_map__update_elem(
		map,
		&key,
		sizeof(key),
		&rule_data,
		sizeof(rule_data),
		BPF_ANY
	);
	if (err)
	{
		std::cerr << "Failed to set rate limiting rules: " << err << std::endl;
		return false;
	}

	return true;
}

// Main function
int main(int argc, char **argv)
{
	int cgroup_fd = -1;
	int err;

	// Check root privileges
	if (getuid() != 0)
	{
		std::cerr << "Error: This program must be run with root privileges"
				  << std::endl;
		return 1;
	}

	// Parse command line arguments
	parse_args(argc, argv);

	// Simple path validation
	if (cgroup_path.empty() || cgroup_path[0] != '/')
	{
		std::cerr << "Error: Invalid cgroup path: " << cgroup_path << std::endl;
		return 1;
	}

	// Set libbpf log print callback function
	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// Open and load eBPF program
	skel = tc_cgroup_bpf__open_and_load();
	if (!skel)
	{
		std::cerr << "Failed to open and load BPF skeleton: " << strerror(errno)
				  << std::endl;
		return 1;
	}

	// Configure rate limiting rules
	if (!setup_cgroup_rules())
	{
		err = -1;
		goto cleanup;
	}

	// Open cgroup file descriptor
	cgroup_fd = open(cgroup_path.c_str(), O_RDONLY);
	if (cgroup_fd < 0)
	{
		std::cerr << "Failed to open cgroup: " << cgroup_path << " ("
				  << strerror(errno) << ")" << std::endl;
		err = -1;
		goto cleanup;
	}

	// Attach eBPF program to cgroup based on direction
	if (rule.gress == EGRESS)
	{
		err = bpf_prog_attach(
			bpf_program__fd(skel->progs.cgroup_skb_egress),
			cgroup_fd,
			BPF_CGROUP_INET_EGRESS,
			0
		);
	}
	else
	{
		err = bpf_prog_attach(
			bpf_program__fd(skel->progs.cgroup_skb_ingress),
			cgroup_fd,
			BPF_CGROUP_INET_INGRESS,
			0
		);
	}

	if (err)
	{
		std::cerr << "Failed to attach cgroup program: " << err << " ("
				  << strerror(-err) << ")" << std::endl;
		goto cleanup;
	}

	std::cout << "Successfully attached cgroup program to " << cgroup_path
			  << std::endl;
	std::cout << "Match direction: "
			  << (rule.gress ? "EGRESS (outgoing)" : "INGRESS (incoming)")
			  << std::endl;
	std::cout << "Rate limit: " << rule.rate_bps << " B/s" << std::endl;
	std::cout << "Note: Will limit traffic for all processes in the cgroup"
			  << std::endl;

	// Set up ring buffer for event polling
	rb = ring_buffer__new(
		bpf_map__fd(skel->maps.ringbuf),
		handle_traffic_event,
		nullptr,
		nullptr
	);
	if (!rb)
	{
		std::cerr << "Failed to create ring buffer" << std::endl;
		err = -1;
		goto cleanup;
	}

	std::cout << "Starting process traffic monitoring..." << std::endl;

	// Main event loop - poll ring buffer for traffic events
	while (running)
	{
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR)
		{
			continue;
		}
		if (err < 0)
		{
			std::cerr << "Ring buffer polling error: " << err << std::endl;
			break;
		}
	}

	// Detach eBPF program
	if (rule.gress == EGRESS)
	{
		err = bpf_prog_detach2(
			bpf_program__fd(skel->progs.cgroup_skb_egress),
			cgroup_fd,
			BPF_CGROUP_INET_EGRESS
		);
	}
	else
	{
		err = bpf_prog_detach2(
			bpf_program__fd(skel->progs.cgroup_skb_ingress),
			cgroup_fd,
			BPF_CGROUP_INET_INGRESS
		);
	}

	if (err)
	{
		std::cerr << "Failed to detach cgroup program: " << err << std::endl;
		goto cleanup;
	}

cleanup:
	// Clean up resources
	if (cgroup_fd >= 0)
	{
		close(cgroup_fd);
	}

	if (rb)
	{
		ring_buffer__free(rb);
	}
	if (skel)
	{
		tc_cgroup_bpf__destroy(skel);
	}

	return err < 0 ? -err : 0;
}
