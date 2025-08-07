#include <signal.h>
#include <unistd.h>
#include <iostream>
#include <cstring>
#include <getopt.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "tc-port.skel.h"

// Constant definitions
#define DEFAULT_RATE_BPS 1000000  // Default 1MB/s
#define EGRESS   1
#define INGRESS  0

// Event structure, matching BPF program
struct event_t {
    __u32    sip;           // Source IP address
    __u32    dip;           // Destination IP address
    __u32    sport;         // Source port
    __u32    dport;         // Destination port
    __u32    protocol;      // Protocol type
    __u32    action;        // Action taken (pass/drop)
    __u32    bytes_sent;    // Bytes sent
    __u32    bytes_dropped; // Bytes dropped
    __u32    packets_sent;  // Packets sent
    __u32    packets_dropped; // Packets dropped
    __u64    timestamp;     // Timestamp
};

// Traffic control rule structure
struct TrafficRule {
    uint32_t target_ip;     // IP address to match
    uint16_t target_port;   // Port to match
    uint64_t rate_bps;      // Rate limit (bytes/second)
    uint8_t gress;          // 1=match destination IP:port (egress), 0=match source IP:port (ingress)
    uint32_t time_scale;    // Time scale (seconds)
};

// Global state variables
static struct tc_port_bpf *skel = nullptr;
static struct ring_buffer *rb = nullptr;
static volatile bool running = true;
static struct TrafficRule rule = {0};
static unsigned int ifindex = 0;

// Command line option definitions
static struct option lopts[] = {
    {"interface", required_argument, 0, 'I'},
    {"ip", required_argument, 0, 'i'},
    {"port", required_argument, 0, 'p'},
    {"rate", required_argument, 0, 'r'},
    {"direction", required_argument, 0, 'd'},
    {"timescale", required_argument, 0, 't'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
};

// Format IP address
static std::string format_ip(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    return inet_ntoa(addr);
}

// Parse bandwidth string (supports K/M/G suffixes)
static uint64_t parse_bandwidth(const char *str) {
    if (!str) return DEFAULT_RATE_BPS;
    
    char *endptr;
    uint64_t value = strtoull(str, &endptr, 10);
    
    if (*endptr == '\0') {
        return value;
    } else if (strcasecmp(endptr, "K") == 0) {
        return value * 1024;
    } else if (strcasecmp(endptr, "M") == 0) {
        return value * 1024 * 1024;
    } else if (strcasecmp(endptr, "G") == 0) {
        return value * 1024 * 1024 * 1024;
    }
    
    return DEFAULT_RATE_BPS;
}

// Parse IP address string
static bool parse_ip_address(const char *str, uint32_t *result) {
    if (!str || !result) return false;
    
    struct in_addr addr;
    if (inet_pton(AF_INET, str, &addr) != 1) {
        return false;
    }
    
    *result = ntohl(addr.s_addr);
    return true;
}

// Ring buffer event handling callback
static int handle_traffic_event(void *ctx, void *data, size_t data_sz) {
    if (data_sz != sizeof(event_t)) {
        return 0;
    }
    
    const struct event_t *e = static_cast<const struct event_t*>(data);
    
    std::string src_ip = format_ip(e->sip);
    std::string dst_ip = format_ip(e->dip);
    
    // Print tracked IP and port information
    std::cout << "Traffic: " << src_ip << ":" << e->sport << " -> "
              << dst_ip << ":" << e->dport;
    
    if (e->bytes_dropped > 0) {
        std::cout << " [DROP] " << e->bytes_dropped << " bytes" << std::endl;
    } else if (e->bytes_sent > 0) {
        std::cout << " [SEND] " << e->bytes_sent << " bytes" << std::endl;
    } else {
        std::cout << " [MATCH]" << std::endl;
    }
    
    return 0;
}

// Signal handler
static void sig_handler(int sig) {
    std::cout << "\nReceived signal " << sig << ", exiting..." << std::endl;
    running = false;
}

// libbpf log print callback function
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

// Print usage information
void Usage(const char *arg0) {
    std::cout << "Usage: " << arg0 << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -I, --interface <if>  Network interface name" << std::endl;
    std::cout << "  -i, --ip <ip>         IP address to match" << std::endl;
    std::cout << "  -p, --port <port>     Port to match" << std::endl;
    std::cout << "  -r, --rate <rate>     Rate limit (supports K/M/G suffixes)" << std::endl;
    std::cout << "  -d, --direction <dir> Match direction (egress/ingress)" << std::endl;
    std::cout << "  -t, --timescale <sec> Time scale (seconds, controls burst tolerance)" << std::endl;
    std::cout << "  -h, --help            Show help information" << std::endl;
    std::cout << std::endl;
    std::cout << "Direction Configuration:" << std::endl;
    std::cout << "  -d egress  : Match destination IP:port (outgoing traffic)" << std::endl;
    std::cout << "  -d ingress : Match source IP:port (incoming traffic to local machine)" << std::endl;
    std::cout << std::endl;
    std::cout << "Time Scale Examples:" << std::endl;
    std::cout << "  -t 1     : 1 second scale, strict rate limiting, low burst tolerance" << std::endl;
    std::cout << "  -t 60    : 1 minute scale, allows short-term bursts, long-term average rate limiting" << std::endl;
    std::cout << "  -t 3600  : 1 hour scale, allows long-term bursts, suitable for long-term bandwidth management" << std::endl;
    std::cout << std::endl;
}

// Safe string to integer conversion
template<typename T>
static bool safe_str_to_int(const char *str, T *result, T min_val, T max_val) {
    static_assert(std::is_integral_v<T>, "T must be an integral type");
    
    if (!str || !result) return false;
    
    char *endptr;
    errno = 0;
    
    if constexpr (std::is_signed_v<T>) {
        long val = strtol(str, &endptr, 10);
        if (errno == ERANGE || val < static_cast<long>(min_val) || val > static_cast<long>(max_val)) {
            return false;
        }
        *result = static_cast<T>(val);
    } else {
        unsigned long val = strtoul(str, &endptr, 10);
        if (errno == ERANGE || val > static_cast<unsigned long>(max_val)) {
            return false;
        }
        *result = static_cast<T>(val);
    }
    
    if (*endptr != '\0') {
        return false;
    }
    
    return true;
}

// Parse command line arguments
void parse_args(int argc, char **argv) {
    int opt, opt_idx;
    std::string sopts = "I:i:p:r:d:t:h";
    
    while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0) {
        switch (opt) {
        case 'I': // Network interface
            ifindex = if_nametoindex(optarg);
            if (ifindex == 0) {
                std::cerr << "Error: Invalid interface name '" << optarg << "'" << std::endl;
                exit(-1);
            }
            break;
        case 'i': // Target IP address
            if (!parse_ip_address(optarg, &rule.target_ip)) {
                std::cerr << "Error: Invalid IP address '" << optarg << "'" << std::endl;
                exit(-1);
            }
            break;
        case 'p': // Target port
            if (!safe_str_to_int(optarg, &rule.target_port, static_cast<uint16_t>(1), static_cast<uint16_t>(65535))) {
                std::cerr << "Error: Invalid port '" << optarg << "'" << std::endl;
                exit(-1);
            }
            break;
        case 'r': // Rate limit
            rule.rate_bps = parse_bandwidth(optarg);
            if (rule.rate_bps == 0) {
                std::cerr << "Error: Invalid rate limit '" << optarg << "'" << std::endl;
                exit(-1);
            }
            break;
        case 'd': // Match direction
            if (strcasecmp(optarg, "egress") == 0) {
                rule.gress = EGRESS; // Match destination IP:port
            } else if (strcasecmp(optarg, "ingress") == 0) {
                rule.gress = INGRESS; // Match source IP:port
            } else {
                std::cerr << "Error: Invalid direction '" << optarg << "'" << std::endl;
                exit(-1);
            }
            break;
        case 't': // Time scale
            if (!safe_str_to_int(optarg, &rule.time_scale, static_cast<uint32_t>(1), static_cast<uint32_t>(3600))) {
                std::cerr << "Error: Invalid time scale '" << optarg << "'" << std::endl;
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
    if (ifindex == 0) {
        std::cerr << "Error: Network interface must be specified (-I)" << std::endl;
        Usage(argv[0]);
        exit(-1);
    }
    
    if (rule.target_ip == 0) {
        std::cerr << "Error: Target IP address must be specified (-i)" << std::endl;
        Usage(argv[0]);
        exit(-1);
    }
    
    if (rule.target_port == 0) {
        std::cerr << "Error: Target port must be specified (-p)" << std::endl;
        Usage(argv[0]);
        exit(-1);
    }

    // Set default values
    if (rule.rate_bps == 0) {
        std::cout << "Using default rate limit: " << DEFAULT_RATE_BPS << " B/s" << std::endl;
        rule.rate_bps = DEFAULT_RATE_BPS;
    } else {
        std::cout << "Setting rate limit: " << rule.rate_bps << " B/s (" 
                  << (rule.rate_bps / 1024.0 / 1024.0) << " MB/s)" << std::endl;
    }
    
    if (rule.time_scale == 0) {
        rule.time_scale = 1;  // Default 1 second time scale
        std::cout << "Using default time scale: 1 second" << std::endl;
    } else {
        std::cout << "Setting time scale: " << rule.time_scale << " seconds" << std::endl;
    }
    
    std::cout << "Network interface: " << ifindex << std::endl;
    std::cout << "Match IP: " << format_ip(rule.target_ip) << std::endl;
    std::cout << "Match port: " << rule.target_port << std::endl;
    std::cout << "Match direction: " << (rule.gress ? "EGRESS (destination)" : "INGRESS (source)") << std::endl;
    std::cout << "Rate limit: " << rule.rate_bps << " B/s (" 
              << (rule.rate_bps / 1024.0 / 1024.0) << " MB/s)" << std::endl;
    std::cout << "Time scale: " << rule.time_scale << " seconds (max bucket capacity: " 
              << (rule.rate_bps * rule.time_scale / 1024.0 / 1024.0) << " MB)" << std::endl;
}

// Configure traffic control rules to BPF map
static bool setup_traffic_rules() {
    struct bpf_map *map = bpf_object__find_map_by_name(skel->obj, "traffic_rules");
    if (!map) {
        std::cerr << "Cannot find traffic_rules map" << std::endl;
        return false;
    }
    
    uint32_t key = 0;
    
    struct {
        __u32 target_ip;
        __u16 target_port;
        __u64 rate_bps;
        __u8 gress;
        __u32 time_scale;  // Add time scale field
    } rule_data = {
        .target_ip = rule.target_ip,
        .target_port = rule.target_port,
        .rate_bps = rule.rate_bps,
        .gress = rule.gress,
        .time_scale = rule.time_scale
    };
    
    int err = bpf_map__update_elem(map, &key, sizeof(key), &rule_data, sizeof(rule_data), BPF_ANY);
    if (err) {
        std::cerr << "Failed to set traffic control rules: " << err << std::endl;
        return false;
    }
    
    return true;
}

// Main function
int main(int argc, char **argv) {
    bool hook_created_egress = false;
    bool hook_created_ingress = false;
    int err;
    
    // Check root privileges
    if (getuid() != 0) {
        std::cerr << "Error: This program must be run with root privileges" << std::endl;
        return 1;
    }
    
    // Parse command line arguments
    parse_args(argc, argv);

    // Egress direction
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook_egress, .ifindex = (int)ifindex, .attach_point = BPF_TC_EGRESS);
    // Ingress direction
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook_ingress, .ifindex = (int)ifindex, .attach_point = BPF_TC_INGRESS);

    // Define TC attachment options for egress
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts_egress, .handle = 1, .priority = 1);

    // Define TC attachment options for ingress
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts_ingress, .handle = 1, .priority = 1);
    
    // Set libbpf log print callback function
    libbpf_set_print(libbpf_print_fn);
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // Open and load eBPF program
    skel = tc_port_bpf__open_and_load();
    if (!skel) {
        std::cerr << "Failed to open and load BPF skeleton" << std::endl;
        return 1;
    }
    
    // Configure traffic control rules
    if (!setup_traffic_rules()) {
        goto cleanup;
    }
    
    // Create TC hook (qdisc) for egress direction
    err = bpf_tc_hook_create(&tc_hook_egress);
    if (!err) {
        hook_created_egress = true;
        std::cout << "Successfully created TC hook (egress direction)" << std::endl;
    } else if (err == -EEXIST) {
        std::cout << "TC hook (egress direction) already exists" << std::endl;
    } else {
        std::cerr << "Failed to create TC hook (egress direction): " << err << " (" << strerror(-err) << ")" << std::endl;
        goto cleanup;
    }

    // Create TC hook (qdisc) for ingress direction
    err = bpf_tc_hook_create(&tc_hook_ingress);
    if (!err) {
        hook_created_ingress = true;
        std::cout << "Successfully created TC hook (ingress direction)" << std::endl;
    } else if (err == -EEXIST) {
        std::cout << "TC hook (ingress direction) already exists" << std::endl;
    } else {
        std::cerr << "Failed to create TC hook (ingress direction): " << err << " (" << strerror(-err) << ")" << std::endl;
        goto cleanup;
    }
    
    // Get eBPF program tc_egress file descriptor and assign to tc_opts structure
    tc_opts_egress.prog_fd = bpf_program__fd(skel->progs.tc_egress);
    // Attach eBPF program tc_egress to TC hook tc_hook_egress according to tc_opts
    err = bpf_tc_attach(&tc_hook_egress, &tc_opts_egress);
    if (err) {
        std::cerr << "Failed to attach TC program (egress direction): " << err << " (" << strerror(-err) << ")" << std::endl;
        goto cleanup;
    }
    
    // Get eBPF program tc_ingress file descriptor and assign to tc_opts structure
    tc_opts_ingress.prog_fd = bpf_program__fd(skel->progs.tc_ingress);
    // Attach eBPF program tc_ingress to TC hook tc_hook_ingress according to tc_opts
    err = bpf_tc_attach(&tc_hook_ingress, &tc_opts_ingress);
    if (err) {
        std::cerr << "Failed to attach TC program (ingress direction): " << err << " (" << strerror(-err) << ")" << std::endl;
        goto cleanup;
    }
       
    std::cout << "Successfully attached TC program to interface " << ifindex << " (egress direction)" << std::endl;
    std::cout << "Successfully attached TC program to interface " << ifindex << " (ingress direction)" << std::endl;
    std::cout << "Match IP: " << format_ip(rule.target_ip) << std::endl;
    std::cout << "Match port: " << rule.target_port << std::endl;
    std::cout << "Match direction: " << (rule.gress ? "EGRESS (destination IP:port)" : "INGRESS (source IP:port)") << std::endl;
    std::cout << "Rate limit: " << rule.rate_bps << " B/s" << std::endl;
    
    // Set up ring buffer for event polling
    rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), handle_traffic_event, nullptr, nullptr);
    if (!rb) {
        std::cerr << "Failed to create ring buffer" << std::endl;
        err = -1;
        goto cleanup;
    }
    
    std::cout << "Starting traffic monitoring..." << std::endl;
    
    // Main event loop - poll ring buffer for traffic events
    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            continue; // Interrupted by signal, continue polling
        }
        if (err < 0) {
            std::cerr << "Ring buffer polling error: " << err << std::endl;
            break;
        }
    }
    
    // Clear tc_opts fields
    tc_opts_egress.flags = tc_opts_egress.prog_fd = tc_opts_egress.prog_id = 0;
    // Detach eBPF program from TC hook
    err = bpf_tc_detach(&tc_hook_egress, &tc_opts_egress);
    if (err) {
        std::cerr << "Failed to detach TC program (egress direction): " << err << std::endl;
        goto cleanup;
    }

    // Clear tc_opts fields
    tc_opts_ingress.flags = tc_opts_ingress.prog_fd = tc_opts_ingress.prog_id = 0; 
    err = bpf_tc_detach(&tc_hook_ingress, &tc_opts_ingress);
    if (err) {
        std::cerr << "Failed to detach TC program (ingress direction): " << err << std::endl;
        goto cleanup;
    }
    
cleanup:
    // Clean up previously created TC hooks
    if (hook_created_egress) {
        bpf_tc_hook_destroy(&tc_hook_egress);
    }

    if (hook_created_ingress) {
        bpf_tc_hook_destroy(&tc_hook_ingress);
    }

    // Clean up eBPF environment
    if (rb) {
        ring_buffer__free(rb);
    }
    if (skel) {
        tc_port_bpf__destroy(skel);
    }
    
    return -err;
}
