#include <sys/resource.h>
#include <signal.h>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <getopt.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "arp-observe.skel.h"

// ARP event structure matching BPF program
struct arp_event {
    unsigned char src_mac[6];
    unsigned char dst_mac[6];
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t opcode;
    uint64_t timestamp;
};

// Global state variables
static struct arp_observe_bpf *skel = nullptr;
static struct ring_buffer *rb = nullptr;
static volatile bool running = true;
static uint32_t target_ip = 0;  // 0 means show all ARP packets
static unsigned int ifindex = 0;

// Command line options
static struct option lopts[] = {
    {"ip", required_argument, 0, 'i'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
};

// Format current time as HH:MM:SS
static std::string format_time() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    std::ostringstream time_ss;
    time_ss << std::put_time(&tm, "%H:%M:%S");
    return time_ss.str();
}

// Format MAC address as hex string
static std::string format_mac(const unsigned char *mac) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; i++) {
        if (i > 0) oss << ":";
        oss << std::setw(2) << static_cast<int>(mac[i]);
    }
    return oss.str();
}

// Format IP address from host byte order
static std::string format_ip(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);  // Convert to network byte order for display
    return inet_ntoa(addr);
}

// Get ARP opcode description
static std::string get_arp_opcode_desc(uint16_t opcode) {
    switch (opcode) {
        case 1: return "ARP_REQUEST";
        case 2: return "ARP_REPLY";
        case 3: return "RARP_REQUEST";
        case 4: return "RARP_REPLY";
        default: return "UNKNOWN";
    }
}

// Check if ARP event should be displayed based on IP filter
static bool should_display_arp_event(const struct arp_event *e) {
    if (target_ip == 0) {
        return true;  // Show all ARP packets if no IP filter is set
    }
    
    // Show only ARP packets involving the target IP
    return (e->src_ip == target_ip || e->dst_ip == target_ip);
}

// Ring buffer event handler callback
static int handle_arp_event(void *ctx, void *data, size_t data_sz) {
    if (data_sz != sizeof(arp_event)) {
        std::cerr << "Invalid data size: " << data_sz << " bytes" << std::endl;
        return 0;
    }
    
    const struct arp_event *e = static_cast<const struct arp_event*>(data);
    
    // Check if this ARP event should be displayed
    if (!should_display_arp_event(e)) {
        return 0;  // Skip display for this event
    }
    
    // Format event data for display
    std::string time_str = format_time();
    std::string src_mac = format_mac(e->src_mac);
    std::string dst_mac = format_mac(e->dst_mac);
    std::string src_ip = format_ip(e->src_ip);
    std::string dst_ip = format_ip(e->dst_ip);
    std::string opcode_desc = get_arp_opcode_desc(e->opcode);
    
    // Display ARP event information
    std::cout << "[" << std::setw(8) << std::left << time_str << "] "
              << std::setw(15) << std::left << src_ip << " -> "
              << std::setw(15) << std::left << dst_ip << " "
              << std::setw(17) << std::left << src_mac << " -> "
              << std::setw(17) << std::left << dst_mac << " "
              << opcode_desc << std::endl;
    
    return 0;
}

// Signal handler for graceful shutdown
static void sig_handler(int sig) {
    std::cout << "\nReceived signal " << sig << ", exiting..." << std::endl;
    running = false;
}

// Display usage information
void Usage(const char *arg0) {
    std::cout << "Usage: " << arg0 << " <interface> [options]" << std::endl;
    std::cout << "  ARP packet monitoring tool." << std::endl << std::endl;
    std::cout << "Arguments:" << std::endl;
    std::cout << "  <interface>        Network interface name (e.g., eth0, lo)" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -i, --ip <ip>     Show only ARP packets involving this IP (e.g., 192.168.1.1)" << std::endl;
    std::cout << "  -h, --help        Show help information" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << arg0 << " eth0" << std::endl;
    std::cout << "  " << arg0 << " lo -i 192.168.1.1" << std::endl;
    std::cout << "  " << arg0 << " eth0 --ip 10.0.0.1" << std::endl;
}

// Parse IP address string to host byte order
static bool parse_ip_address(const char *str, uint32_t *result) {
    if (!str || !result) return false;
    
    struct in_addr addr;
    if (inet_pton(AF_INET, str, &addr) != 1) {
        return false;
    }
    
    *result = ntohl(addr.s_addr);  // Convert to host byte order
    return true;
}

// Parse command line arguments
void parse_args(int argc, char **argv, int start_idx) {
    int opt, opt_idx;
    std::string sopts = "i:h";
    
    optind = start_idx;
    
    while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0) {
        switch (opt) {
        case 'i':
            if (!parse_ip_address(optarg, &target_ip)) {
                std::cerr << "Error: Invalid IP address '" << optarg << "'" << std::endl;
                exit(-1);
            }
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
    
    std::cout << "\n=============== ARP Monitor =================" << std::endl << std::endl;
}

// Check if running with root privileges
static bool check_privileges() {
    if (getuid() != 0) {
        std::cerr << "Error: This program must be run as root" << std::endl;
        return false;
    }
    return true;
}

// Set resource limits for BPF operations
static bool setup_resource_limits() {
    struct rlimit rlim = {
        .rlim_cur = 512UL << 20,
        .rlim_max = 512UL << 20,
    };
    
    int err = setrlimit(RLIMIT_MEMLOCK, &rlim);
    if (err) {
        std::cerr << "Failed to set resource limits: " << strerror(errno) << std::endl;
        return false;
    }
    return true;
}

// Display startup information
static void print_startup_info() {
    std::cout << "=== eBPF XDP ARP Monitor Started ===" << std::endl;
    std::cout << "Press Ctrl+C to stop monitoring" << std::endl;
    std::cout << std::endl;
    
    if (target_ip != 0) {
        std::cout << "Filtering: Show only ARP packets involving " << format_ip(target_ip) << std::endl;
    } else {
        std::cout << "Filtering: Show all ARP packets" << std::endl;
    }
    std::cout << std::endl;
    
    std::cout << "ARP Events:" << std::endl;
    std::cout << "Time      Source IP       Dest IP         Source MAC        Dest MAC         Opcode" << std::endl;
    std::cout << std::endl;
}

// Clean up resources on exit
static void cleanup_resources() {
    std::cout << "Cleaning up resources..." << std::endl;
    
    running = false;
    target_ip = 0;
    
    if (rb) {
        ring_buffer__free(rb);
    }
    if (skel) {
        arp_observe_bpf__destroy(skel);
    }
    
    std::cout << "ARP monitoring stopped" << std::endl;
}

// Main function
int main(int argc, char *args[]) 
{
    int err;
    
    if (argc < 2) {
        Usage(args[0]);
        return 1;
    }
    
    // Check root privileges
    if (!check_privileges()) {
        return 1;
    }
    
    // Get interface index from name
    const char *ifname = args[1];
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        std::cerr << "Error: Invalid interface name " << ifname << std::endl;
        return 1;
    }
    
    // Parse command line arguments
    parse_args(argc, args, 1);
    
    // Set up signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // Set resource limits for BPF
    if (!setup_resource_limits()) {
        return 1;
    }
    
    // Load BPF program using skeleton
    skel = arp_observe_bpf__open();
    if (!skel) {
        std::cerr << "Failed to open BPF skeleton: " << strerror(errno) << std::endl;
        return 1;
    }
    
    err = arp_observe_bpf__load(skel);
    if (err) {
        std::cerr << "Failed to load BPF skeleton: " << err << " (" << strerror(-err) << ")" << std::endl;
        goto cleanup;
    }
    
    // Attach BPF program
    err = arp_observe_bpf__attach(skel);
    if (err) {
        std::cerr << "Failed to attach BPF program: " << err << " (" << strerror(-err) << ")" << std::endl;
        goto cleanup;
    }
    
    // Attach XDP program to network interface
    skel->links.capture_arp = bpf_program__attach_xdp(skel->progs.capture_arp, ifindex);
    if (!skel->links.capture_arp) {
        err = -errno;
        std::cerr << "Failed to attach XDP program to interface: " << strerror(errno) << std::endl;
        goto cleanup;
    }
    
    std::cout << "Successfully attached XDP program to interface " << ifname << std::endl;
    
    // Set up ring buffer for event polling
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_arp_event, nullptr, nullptr);
    if (!rb) {
        std::cerr << "Failed to create ring buffer" << std::endl;
        err = -1;
        goto cleanup;
    }
    
    std::cout << "Start polling ring buffer" << std::endl;
    
    print_startup_info();
    
    // Main event loop - poll ring buffer for ARP events
    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            continue; // Interrupted by signal, continue polling
        }
        if (err < 0) {
            std::cerr << "Error polling ring buffer: " << err << std::endl;
            break;
        }
    }
    
cleanup:
    cleanup_resources();
    
    return 0;
}
