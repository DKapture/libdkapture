
#include <signal.h>
#include <unistd.h>
#include <iostream>
#include <cstring>
#include <getopt.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include "tc-if.skel.h"

#include <cassert>
#include <stdexcept>
#include <memory>
#include <system_error>
#include <functional>
#include <future>
#include <string>
#include <chrono>
#include <thread>
#include <vector>
#include <map>

#define MAX_ERROR_MESSAGE_LENGTH 512
#define MAX_RETRY_DELAY_MS 1000
#define ERROR_LOG_BUFFER_SIZE 1000
#define DEFAULT_RATE_BPS 1000000
#define MAX_STRING_LENGTH 256

struct event_t {
    uint32_t action;
    uint32_t bytes_sent;
    uint32_t bytes_dropped;
    uint32_t packets_sent;
    uint32_t packets_dropped;
    uint64_t timestamp;
    uint8_t  eth_src[6];
    uint8_t  eth_dst[6];
    uint16_t eth_type;
    uint32_t packet_size;
    uint32_t packet_type;
    uint64_t type_rate_bps;
    uint64_t type_smooth_rate_bps;
};

static volatile bool running = true;
static unsigned int ifindex = 0;
static struct ring_buffer *rb = nullptr;
static struct tc_if_bpf *skel = nullptr;

struct traffic_rule {
    uint64_t rate_bps;
    uint8_t gress;
    uint32_t time_scale;
};

static struct traffic_rule rule = {0};

#define EGRESS   1
#define INGRESS  0

static struct option lopts[] = {
    {"interface", required_argument, nullptr, 'I'},
    {"rate", required_argument, nullptr, 'r'},
    {"direction", required_argument, nullptr, 'd'},
    {"timescale", required_argument, nullptr, 't'},
    {"help", no_argument, nullptr, 'h'},
    {nullptr, 0, nullptr, 0}
};

struct SafeString {
    const char* str_;      // String content pointer
    const char* context_;  // String context description
};

// Create and initialize a SafeString structure
static SafeString* safe_string_create(const char* str, const char* context)
{
    SafeString* safe_str = static_cast<SafeString*>(malloc(sizeof(SafeString)));
    if (safe_str)
    {
        safe_str->str_ = str;
        safe_str->context_ = context ? context : "";
    }
    return safe_str;
}

// Free SafeString structure memory
static void safe_string_destroy(SafeString* safe_str)
{
    if (safe_str)
    {
        free(safe_str);
    }
}

// Check if SafeString is valid
static int safe_string_is_valid(const SafeString* safe_str)
{
    if (!safe_str || !safe_str->str_) return 0;
    return 1;
}

// Get string length safely
static size_t safe_string_length(const SafeString* safe_str)
{
    if (!safe_str || !safe_str->str_)
    {
        return 0;
    }
    return strlen(safe_str->str_);
}

// Get C-style string pointer
static const char* safe_string_c_str(const SafeString* safe_str)
{ 
    return safe_str ? safe_str->str_ : NULL; 
}

// Get string context
static const char* safe_string_context(const SafeString* safe_str)
{ 
    return safe_str ? safe_str->context_ : NULL; 
}

enum class ErrorCode {
    SUCCESS = 0,
    NULL_POINTER = 1,
    INVALID_PARAMETER = 2,
    MEMORY_ALLOCATION_FAILED = 3,
    FILE_OPERATION_FAILED = 4,
    NETWORK_OPERATION_FAILED = 5,
    BPF_OPERATION_FAILED = 6,
    TC_OPERATION_FAILED = 7,
    TIMEOUT_ERROR = 8,
    PERMISSION_DENIED = 9,
    RESOURCE_UNAVAILABLE = 10,
    UNKNOWN_ERROR = 99
};

struct ErrorInfo {
    ErrorCode code;
    char message[MAX_STRING_LENGTH];
    char function[MAX_STRING_LENGTH];
    char file[MAX_STRING_LENGTH];
    int line;
};

struct ErrorHandler {
    ErrorInfo error_log_[100];  // Error log buffer, stores up to 100 errors
    size_t error_count;         // Current error count
};

// Initialize ErrorInfo structure with error details
static void error_info_init(ErrorInfo* info, ErrorCode code, const char* msg, 
                           const char* func, const char* file, int line)
{
    if (!info)
    {
        return;
    }
    
    info->code = code;
    info->line = line;
    
    strncpy(info->message, msg ? msg : "", sizeof(info->message) - 1);
    info->message[sizeof(info->message) - 1] = '\0';
    
    strncpy(info->function, func ? func : "", sizeof(info->function) - 1);
    info->function[sizeof(info->function) - 1] = '\0';
    
    strncpy(info->file, file ? file : "", sizeof(info->file) - 1);
    info->file[sizeof(info->file) - 1] = '\0';
}

// Initialize error handler
static void error_handler_init(ErrorHandler* handler)
{
    if (!handler)
    {
        return;
    }
    
    handler->error_count = 0;
}

// Cleanup error handler (no-op in single process)
static void error_handler_cleanup(ErrorHandler* handler)
{
    if (!handler)
    {
        return;
    }
}

// Log error to handler buffer and stderr
static void error_handler_log_error(ErrorHandler* handler, const ErrorInfo* error)
{
    if (!handler || !error)
    {
        return;
    }
    
    // Add error to log buffer (circular buffer implementation)
    if (handler->error_count < 100)
    {
        handler->error_log_[handler->error_count] = *error;
        handler->error_count++;
    }
    else
    {
        // Shift all errors down and add new one at the end
        for (size_t i = 0; i < 99; i++)
        {
            handler->error_log_[i] = handler->error_log_[i + 1];
        }
        handler->error_log_[99] = *error;
    }
    
    // Print error to stderr
    fprintf(stderr, "Error [%d] in %s (%s:%d): %s\n", 
            (int)error->code, error->function, error->file, error->line, error->message);
}

// Get current error count
static size_t error_handler_get_error_count(const ErrorHandler* handler)
{
    if (!handler)
    {
        return 0;
    }
    
    return handler->error_count;
}

static ErrorHandler global_error_handler;

// Log error with automatic context detection
static void log_error(ErrorCode code, const std::string& message)
{
    ErrorInfo error_info;
    error_info_init(&error_info, code, message.c_str(), __FUNCTION__, __FILE__, __LINE__);
    error_handler_log_error(&global_error_handler, &error_info);
}

// Retry operation with exponential backoff
template<typename Func>
auto retry_operation(Func&& func, size_t max_retries) -> decltype(func())
{
    size_t attempt = 0;
    std::chrono::milliseconds delay(100);
    
    while (attempt < max_retries)
    {
        try
        {
            return func();
        }
        catch (const std::exception& e)
        {
            attempt++;
            if (attempt >= max_retries)
            {
                throw;
            }
            
            std::cerr << "Operation failed (attempt " << attempt << "/" << max_retries 
                      << "): " << e.what() << ". Retrying in " << delay.count() << "ms..." << std::endl;
            
            std::this_thread::sleep_for(delay);
            delay *= 2; // Exponential backoff
            if (delay.count() > MAX_RETRY_DELAY_MS)
            {
                delay = std::chrono::milliseconds(MAX_RETRY_DELAY_MS);
            }
        }
    }
    
    throw std::runtime_error("Max retry attempts exceeded");
}

// Safely allocate memory with error handling
template<typename T>
T* safe_allocate(size_t count, const std::string& context = "")
{
    try
    {
        T* ptr = new T[count];
        if (!ptr)
        {
            std::cerr << "Failed to allocate memory for " << count << " elements in " << context << std::endl;
        }
        return ptr;
    }
    catch (const std::bad_alloc& e)
    {
        std::cerr << "Memory allocation failed in " << context << ": " << e.what() << std::endl;
        return nullptr;
    }
}

// Safely deallocate memory with error handling
template<typename T>
void safe_deallocate(T* ptr, const std::string& context = "")
{
    if (ptr)
    {
        try
        {
            delete[] ptr;
        }
        catch (const std::exception& e)
        {
            std::cerr << "Memory deallocation failed in " << context << ": " << e.what() << std::endl;
        }
    }
}

// Check if pointer is valid and log error if null
static bool safe_check(const void* ptr, const std::string& context)
{
    if (!ptr)
    {
        log_error(ErrorCode::NULL_POINTER, "Null pointer detected in " + context);
        return false;
    }
    return true;
}

// Check pointer validity and return specified value if null
template<typename T>
static T safe_check_return(const void* ptr, const std::string& context, T retval)
{
    if (!ptr)
    {
        log_error(ErrorCode::NULL_POINTER, "Null pointer detected in " + context);
        return retval;
    }
    return true; // Return true when pointer is valid
}

// Safely convert string to integer with range validation
template<typename T>
static bool safe_str_to_int(const char *str, T *result, T min_val, T max_val, 
                           const std::string& context = "") 
{
    std::cerr << "DEBUG: safe_str_to_int called with str='" << str << "', min=" << min_val << ", max=" << max_val << ", context=" << context << std::endl;
    
    // Validate input parameters
    if (!safe_check_return(str, "Input string pointer in " + context, false)) 
    {
        std::cerr << "DEBUG: safe_check_return failed for str" << std::endl;
        return false;
    }

    if (!safe_check_return(result, "Output result pointer in " + context, false)) 
    {
        std::cerr << "DEBUG: safe_check_return failed for result" << std::endl;
        return false;
    }
    
    if (strlen(str) == 0) 
    {
        std::cerr << "DEBUG: Empty string" << std::endl;
        std::cerr << "Empty string in " << context << std::endl;
        return false;
    }
    
    static_assert(std::is_integral_v<T>, "T must be an integral type");
    
    char *endptr;
    errno = 0;
    
    if constexpr (std::is_signed_v<T>) 
    {
        long val = strtol(str, &endptr, 10);
        std::cerr << "DEBUG: strtol returned " << val << ", errno=" << errno << std::endl;
        if (errno == ERANGE || val < static_cast<long>(min_val) || val > static_cast<long>(max_val)) 
        {
            std::cerr << "DEBUG: Value out of range" << std::endl;
            std::cerr << "Value out of range in " << context << ": " << val << " (min: " << min_val << ", max: " << max_val << ")" << std::endl;
            return false;
        }
        *result = static_cast<T>(val);
    } 
    else 
    {
        unsigned long val = strtoul(str, &endptr, 10);
        std::cerr << "DEBUG: strtoul returned " << val << ", errno=" << errno << std::endl;
        if (errno == ERANGE || val > static_cast<unsigned long>(max_val)) 
        {
            std::cerr << "DEBUG: Value out of range" << std::endl;
            std::cerr << "Value out of range in " << context << ": " << val << " (max: " << max_val << ")" << std::endl;
            return false;
        }
        *result = static_cast<T>(val);
    }
    
    if (*endptr != '\0') 
    {
        std::cerr << "DEBUG: Invalid characters at end: " << endptr << std::endl;
        std::cerr << "Invalid characters in " << context << ": " << endptr << std::endl;
        return false;
    }
    
    std::cerr << "DEBUG: safe_str_to_int successful, result=" << *result << std::endl;
    return true;
}

// Parse bandwidth string with K/M/G suffixes
static uint64_t parse_bandwidth(const char *str, const std::string& context = "") 
{
    if (!str) 
    {
        std::cerr << "Null bandwidth string pointer in " << context << ", using default" << std::endl;
        return DEFAULT_RATE_BPS;
    }
    
    if (strlen(str) == 0) 
    {
        std::cerr << "Empty bandwidth string in " << context << ", using default" << std::endl;
        return DEFAULT_RATE_BPS;
    }
    
    char *endptr;
    uint64_t value = strtoull(str, &endptr, 10);
    
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
    
    std::cerr << "Invalid bandwidth suffix in " << context << ": " << endptr << ", using default" << std::endl;
    return DEFAULT_RATE_BPS;
}

// Format MAC address as xx:xx:xx:xx:xx:xx
static std::string format_mac_address(const uint8_t* mac)
{
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(mac_str);
}

// Get human-readable EtherType description
static std::string get_ethertype_description(uint16_t eth_type)
{
    switch (eth_type)
    {
        case 0x0800: return "IPv4";
        case 0x0806: return "ARP";
        case 0x86DD: return "IPv6";
        case 0x8100: return "802.1Q VLAN";
        case 0x8847: return "MPLS";
        case 0x8864: return "PPPoE";
        default: return "Unknown";
    }
}

// Get human-readable packet type description
static std::string get_packet_type_description(uint32_t packet_type)
{
    switch (packet_type)
    {
        case 1: return "IPv4";
        case 2: return "ARP";
        case 3: return "IPv6";
        case 4: return "802.1Q VLAN";
        case 5: return "MPLS";
        case 6: return "PPPoE";
        case 0: return "Unknown/Other";
        default: return "Unknown";
    }
}

// Format flow rate with appropriate units (bps, Kbps, Mbps, Gbps)
static std::string format_flow_rate(uint64_t rate_bps)
{
    if (rate_bps >= 1000000000)
    {
        return std::to_string(rate_bps / 1000000000) + " Gbps";
    }
    else if (rate_bps >= 1000000)
    {
        return std::to_string(rate_bps / 1000000) + " Mbps";
    }
    else if (rate_bps >= 1000)
    {
        return std::to_string(rate_bps / 1000) + " Kbps";
    }
    else
    {
        return std::to_string(rate_bps) + " bps";
    }
}

// Handle traffic events from BPF ring buffer
static int handle_traffic_event(void *ctx, void *data, size_t data_sz)
{
    if (data_sz != sizeof(event_t))
    {
        return 0;
    }
    
    const struct event_t *e = static_cast<const struct event_t*>(data);
    
    // Print interface-level traffic information with Ethernet details
    std::cout << "Interface Traffic: ";
    
    if (e->bytes_dropped > 0)
    {
        std::cout << "[DROP] " << e->bytes_dropped << " bytes, " << e->packets_dropped << " packets" << std::endl;
    }
    else if (e->bytes_sent > 0)
    {
        std::cout << "[PASS] " << e->bytes_sent << " bytes, " << e->packets_sent << " packets" << std::endl;
    }
    else
    {
        std::cout << "[MATCH]" << std::endl;
    }
    
    // Display Ethernet header information
    std::cout << "  Ethernet Header:" << std::endl;
    std::cout << "    Source MAC: " << format_mac_address(e->eth_src) << std::endl;
    std::cout << "    Dest MAC:   " << format_mac_address(e->eth_dst) << std::endl;
    std::cout << "    EtherType:  0x" << std::hex << e->eth_type << std::dec 
              << " (" << get_ethertype_description(e->eth_type) << ")" << std::endl;
    std::cout << "    Packet Size: " << e->packet_size << " bytes" << std::endl;
    
    // Display packet type statistics and flow rate
    std::cout << "  Packet Type Statistics:" << std::endl;
    std::cout << "    Type: " << get_packet_type_description(e->packet_type) << " (ID: " << e->packet_type << ")" << std::endl;
    std::cout << "    Current Flow Rate: " << format_flow_rate(e->type_rate_bps) << std::endl;
    std::cout << "    Smooth Flow Rate: " << format_flow_rate(e->type_smooth_rate_bps) << " (EMA)" << std::endl;
    
    return 0;
}

// Signal handler for graceful shutdown
static void sig_handler(int sig)
{
    std::cout << "\nReceived signal " << sig << ", exiting..." << std::endl;
    running = false;
}

// libbpf print function redirector
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

// Display program usage information
void Usage(const char *arg0)
{
    std::cout << "Usage: " << arg0 << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -I, --interface <if>  Network interface name (required)" << std::endl;
    std::cout << "  -r, --rate <rate>     Rate limit (supports K/M/G suffixes)" << std::endl;
    std::cout << "  -d, --direction <dir> Match direction (egress/ingress)" << std::endl;
    std::cout << "  -t, --timescale <sec> Time scale (seconds, controls burst tolerance)" << std::endl;
    std::cout << "  -h, --help            Show help information" << std::endl;
    std::cout << std::endl;
    std::cout << "Direction Configuration:" << std::endl;
    std::cout << "  -d egress  : Match destination IP:port (outgoing traffic)" << std::endl;
    std::cout << "  -d ingress : Match source IP:port (incoming traffic to local machine)" << std::endl;
    std::cout << "  -t 1     : 1 second scale, strict rate limiting, low burst tolerance" << std::endl;
    std::cout << "  -t 60    : 1 minute scale, allows short-term bursts, long-term average rate limiting" << std::endl;
    std::cout << "  -t 3600  : 1 hour scale, allows long-term bursts, suitable for long-term bandwidth management" << std::endl;
    std::cout << std::endl;
}

// Parse command line arguments and validate parameters
void parse_args(int argc, char **argv)
{
    int opt, opt_idx;
    std::string sopts = "I:r:d:t:h";
    
    while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0)
    {
        switch (opt)
        {
        case 'I': // Network interface
            ifindex = if_nametoindex(optarg);
            if (ifindex == 0)
            {
                std::cerr << "Error: Invalid interface name '" << optarg << "'" << std::endl;
                throw std::runtime_error("Invalid interface name");
            }
            break;
        case 'r': // Rate limit
            rule.rate_bps = parse_bandwidth(optarg);
            if (rule.rate_bps == 0)
            {
                std::cerr << "Error: Invalid rate limit '" << optarg << "'" << std::endl;
                throw std::runtime_error("Invalid rate limit");
            }
            break;
        case 'd': // Match direction
            if (strcasecmp(optarg, "egress") == 0)
            {
                rule.gress = EGRESS; // Match destination IP:port
            }
            else if (strcasecmp(optarg, "ingress") == 0)
            {
                rule.gress = INGRESS; // Match source IP:port
            }
            else
            {
                std::cerr << "Error: Invalid direction '" << optarg << "'" << std::endl;
                throw std::runtime_error("Invalid direction");
            }
            break;
        case 't': // Time scale
            if (!safe_str_to_int(optarg, &rule.time_scale, static_cast<uint32_t>(1), static_cast<uint32_t>(3600)))
            {
                std::cerr << "Error: Invalid time scale '" << optarg << "'" << std::endl;
                throw std::runtime_error("Invalid time scale");
            }
            break;
        case 'h': // Help
            Usage(argv[0]);
            throw std::runtime_error("Help requested");
        default: // Invalid option
            Usage(argv[0]);
            throw std::runtime_error("Invalid option");
        }
    }
    
    // Check required parameters - now only interface is required
    if (ifindex == 0)
    {
        std::cerr << "Error: Network interface must be specified (-I)" << std::endl;
        Usage(argv[0]);
        throw std::runtime_error("Network interface must be specified");
    }
    
    // Allow interface-level rate limiting (no matching criteria required)
    // At least one matching criteria must be specified, OR rate limit must be specified
    if (rule.rate_bps == 0)
    {
        std::cerr << "Error: Rate limit must be specified (-r)" << std::endl;
        Usage(argv[0]);
        throw std::runtime_error("Rate limit must be specified");
    }

    // Set default values
    if (rule.rate_bps == 0)
    {
        std::cout << "Using default rate limit: " << DEFAULT_RATE_BPS << " B/s" << std::endl;
        rule.rate_bps = DEFAULT_RATE_BPS;
    }
    else
    {
        std::cout << "Setting rate limit: " << rule.rate_bps << " B/s (" 
                  << (rule.rate_bps / 1024.0 / 1024.0) << " MB/s)" << std::endl;
    }
    
    if (rule.time_scale == 0)
    {
        rule.time_scale = 1;  // Default 1 second time scale
        std::cout << "Using default time scale: 1 second" << std::endl;
    }
    else
    {
        std::cout << "Setting time scale: " << rule.time_scale << " seconds" << std::endl;
    }
    
    std::cout << "Network interface: " << ifindex << std::endl;
    std::cout << "Match direction: " << (rule.gress ? "EGRESS (destination)" : "INGRESS (source)") << std::endl;
    std::cout << "Rate limit: " << rule.rate_bps << " B/s (" 
              << (rule.rate_bps / 1024.0 / 1024.0) << " MB/s)" << std::endl;
    std::cout << "Time scale: " << rule.time_scale << " seconds (max bucket capacity: " 
              << (rule.rate_bps * rule.time_scale / 1024.0 / 1024.0) << " MB)" << std::endl;
}

// Setup traffic control rules in BPF map
static bool setup_traffic_rules()
{
    error_handler_init(&global_error_handler);
    
    if (!safe_check(skel, "BPF skeleton in setup_traffic_rules"))
    {
        ErrorInfo error_info;
        error_info_init(&error_info, ErrorCode::NULL_POINTER, "BPF skeleton is null", __FUNCTION__, __FILE__, __LINE__);
        error_handler_log_error(&global_error_handler, &error_info);
        return false;
    }
    
    struct bpf_map *map = bpf_object__find_map_by_name(skel->obj, "traffic_rules");
    if (!map)
    {
        ErrorInfo error_info;
        error_info_init(&error_info, ErrorCode::BPF_OPERATION_FAILED, "Cannot find traffic_rules map", __FUNCTION__, __FILE__, __LINE__);
        error_handler_log_error(&global_error_handler, &error_info);
        std::cerr << "Cannot find traffic_rules map" << std::endl;
        return false;
    }
    
    uint32_t key = 0;
    
    struct
    {
        __u64 rate_bps;
        __u8  gress;
        __u32 time_scale;
    } rule_data = {
        .rate_bps = rule.rate_bps,
        .gress = rule.gress,
        .time_scale = rule.time_scale
    };
    
    int err = bpf_map__update_elem(map, &key, sizeof(key), &rule_data, sizeof(rule_data), BPF_ANY);
    if (err)
    {
        ErrorInfo error_info;
        error_info_init(&error_info, ErrorCode::BPF_OPERATION_FAILED, "Failed to set traffic control rules", __FUNCTION__, __FILE__, __LINE__);
        error_handler_log_error(&global_error_handler, &error_info);
        std::cerr << "Failed to set traffic control rules: " << err << std::endl;
        return false;
    }
    
    std::cout << "Successfully configured traffic control rules" << std::endl;
    std::cout << "Error count during setup: " << error_handler_get_error_count(&global_error_handler) << std::endl;
    
    return true;
}

// Validate program configuration parameters
static bool validate_configuration()
{
    SafeString* interface_str = safe_string_create("interface validation", "validate_configuration");
    if (!safe_string_is_valid(interface_str))
    {
        std::cerr << "Failed to create interface validation string" << std::endl;
        return false;
    }
    
    // Validate interface index
    if (ifindex == 0)
    {
        std::cerr << "Invalid interface index: " << ifindex << std::endl;
        safe_string_destroy(interface_str);
        return false;
    }
    
    // Validate rate limit
    if (rule.rate_bps == 0)
    {
        std::cerr << "Invalid rate limit: " << rule.rate_bps << std::endl;
        safe_string_destroy(interface_str);
        return false;
    }
    
    // Validate time scale
    if (rule.time_scale < 1 || rule.time_scale > 3600)
    {
        std::cerr << "Invalid time scale: " << rule.time_scale << " (must be between 1 and 3600 seconds)" << std::endl;
        safe_string_destroy(interface_str);
        return false;
    }
    
    // Validate direction
    if (rule.gress != EGRESS && rule.gress != INGRESS)
    {
        std::cerr << "Invalid direction: " << (int)rule.gress << std::endl;
        safe_string_destroy(interface_str);
        return false;
    }
    
    std::cout << "Configuration validation passed" << std::endl;
    std::cout << "Interface string length: " << safe_string_length(interface_str) << std::endl;
    std::cout << "Interface string context: " << safe_string_context(interface_str) << std::endl;
    
    safe_string_destroy(interface_str);
    return true;
}

// Report operation success/failure status
static void report_operation_status(const std::string& operation, bool success, const std::string& details = "")
{
    if (success)
    {
        // Print success status directly
        std::cout << "✓ " << operation << " completed successfully" << std::endl;
    }
    else
    {
        // Only log errors when operations fail
        ErrorInfo error_info;
        error_info_init(&error_info, ErrorCode::UNKNOWN_ERROR, 
                       ("Operation failed: " + operation + " - " + details).c_str(), 
                       __FUNCTION__, __FILE__, __LINE__);
        error_handler_log_error(&global_error_handler, &error_info);
        
        // Print failure status
        std::cerr << "✗ " << operation << " failed: " << details << std::endl;
    }
}

// Display traffic control statistics
static void display_statistics()
{
    SafeString* stats_str = safe_string_create("traffic statistics", "display_statistics");
    if (!safe_string_is_valid(stats_str))
    {
        std::cerr << "Failed to create statistics string" << std::endl;
        return;
    }
    
    SafeString* interface_str = safe_string_create("interface information", "display_statistics");
    if (!safe_string_is_valid(interface_str))
    {
        std::cerr << "Failed to create interface string" << std::endl;
        safe_string_destroy(stats_str);
        return;
    }
    
    std::cout << "\n=== Traffic Control Statistics ===" << std::endl;
    std::cout << "Statistics string: " << safe_string_c_str(stats_str) << std::endl;
    std::cout << "Statistics context: " << safe_string_context(stats_str) << std::endl;
    std::cout << "Statistics length: " << safe_string_length(stats_str) << std::endl;
    
    std::cout << "Interface string: " << safe_string_c_str(interface_str) << std::endl;
    std::cout << "Interface context: " << safe_string_context(interface_str) << std::endl;
    std::cout << "Interface length: " << safe_string_length(interface_str) << std::endl;
    
    std::cout << "Network interface: " << ifindex << std::endl;
    std::cout << "Rate limit: " << rule.rate_bps << " B/s (" 
              << (rule.rate_bps / 1024.0 / 1024.0) << " MB/s)" << std::endl;
    std::cout << "Time scale: " << rule.time_scale << " seconds" << std::endl;
    std::cout << "Direction: " << (rule.gress ? "EGRESS" : "INGRESS") << std::endl;
    std::cout << "Max bucket capacity: " << (rule.rate_bps * rule.time_scale / 1024.0 / 1024.0) << " MB" << std::endl;
    std::cout << "===================================" << std::endl;
    
    safe_string_destroy(stats_str);
    safe_string_destroy(interface_str);
}

// Display packet type statistics summary
static void display_packet_type_summary()
{
    std::cout << "\n=== PACKET TYPE STATISTICS SUMMARY ===" << std::endl;
    std::cout << "Timestamp: " << std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() << std::endl;
    
    std::cout << "This would show statistics for each packet type:" << std::endl;
    std::cout << "  - IPv4 packets and flow rate" << std::endl;
    std::cout << "  - ARP packets and flow rate" << std::endl;
    std::cout << "  - IPv6 packets and flow rate" << std::endl;
    std::cout << "  - VLAN packets and flow rate" << std::endl;
    std::cout << "  - MPLS packets and flow rate" << std::endl;
    std::cout << "  - PPPoE packets and flow rate" << std::endl;
    std::cout << "  - Unknown/Other packets and flow rate" << std::endl;
    std::cout << "=====================================" << std::endl;
}

// Display smooth flow rate algorithm information
static void display_smooth_flow_info()
{
    std::cout << "\n=== SMOOTH FLOW RATE ALGORITHM INFO ===" << std::endl;
    std::cout << "Exponential Moving Average (EMA) Algorithm:" << std::endl;
    std::cout << "  Formula: smooth = (smooth - smooth/8) + (new_rate * 2^13)" << std::endl;
    std::cout << "  Weight: 1/8 = 12.5% for new measurements" << std::endl;
    std::cout << "  Scaling: 2^13 = 8192x for precision" << std::endl;
    std::cout << "  Benefits:" << std::endl;
    std::cout << "    - Reduces noise and sudden spikes" << std::endl;
    std::cout << "    - Maintains responsiveness to trends" << std::endl;
    std::cout << "    - Provides stable flow rate readings" << std::endl;
    std::cout << "  Time Window: 1 second sliding window" << std::endl;
    std::cout << "  Update Frequency: Every second" << std::endl;
    std::cout << "=========================================" << std::endl;
}

// Main program entry point - TC traffic control with BPF
int main(int argc, char **argv)
{
    bool hook_created_egress = false;
    bool hook_created_ingress = false;
    int err = 0;
    
    if (getuid() != 0)
    {
        std::cerr << "Error: This program must be run with root privileges" << std::endl;
        return 1;
    }
    
    try
    {
        parse_args(argc, argv);
    }
    catch (const std::runtime_error& e)
    {
        std::cerr << "Error parsing arguments: " << e.what() << std::endl;
        return 1;
    }

    if (!validate_configuration())
    {
        std::cerr << "Configuration validation failed, exiting..." << std::endl;
        return 1;
    }

    report_operation_status("Command line argument parsing", true);

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook_egress, .ifindex = (int)ifindex, .attach_point = BPF_TC_EGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook_ingress, .ifindex = (int)ifindex, .attach_point = BPF_TC_INGRESS);

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts_egress, .handle = 1, .priority = 1);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts_ingress, .handle = 1, .priority = 1);
    
    libbpf_set_print(libbpf_print_fn);
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    skel = tc_if_bpf__open_and_load();
    if (!skel)
    {
        std::cerr << "Failed to open and load BPF skeleton" << std::endl;
        return 1;
    }
    
    if (!setup_traffic_rules())
    {
        goto cleanup;
    }
    
    err = bpf_tc_hook_create(&tc_hook_egress);
    if (!err)
    {
        hook_created_egress = true;
        std::cout << "Successfully created TC hook (egress direction)" << std::endl;
        report_operation_status("TC hook creation (egress)", true);
    }
    else if (err == -EEXIST)
    {
        std::cout << "TC hook (egress direction) already exists" << std::endl;
        report_operation_status("TC hook creation (egress)", true, "already exists");
    }
    else
    {
        std::cerr << "Failed to create TC hook (egress direction): " << err << " (" << strerror(-err) << ")" << std::endl;
        report_operation_status("TC hook creation (egress)", false, strerror(-err));
        goto cleanup;
    }

    err = bpf_tc_hook_create(&tc_hook_ingress);
    if (!err)
    {
        hook_created_ingress = true;
        std::cout << "Successfully created TC hook (ingress direction)" << std::endl;
        report_operation_status("TC hook creation (ingress)", true);
    }
    else if (err == -EEXIST)
    {
        std::cout << "TC hook (ingress direction) already exists" << std::endl;
        report_operation_status("TC hook creation (ingress)", true, "already exists");
    }
    else
    {
        std::cerr << "Failed to create TC hook (ingress direction): " << err << " (" << strerror(-err) << ")" << std::endl;
        report_operation_status("TC hook creation (ingress)", false, strerror(-err));
        goto cleanup;
    }
    
    tc_opts_egress.prog_fd = bpf_program__fd(skel->progs.tc_egress);
    err = bpf_tc_attach(&tc_hook_egress, &tc_opts_egress);
    if (err)
    {
        std::cerr << "Failed to attach TC program (egress direction): " << err << " (" << strerror(-err) << ")" << std::endl;
        report_operation_status("TC program attachment (egress)", false, strerror(-err));
        goto cleanup;
    }
    report_operation_status("TC program attachment (egress)", true);
    
    tc_opts_ingress.prog_fd = bpf_program__fd(skel->progs.tc_ingress);
    err = bpf_tc_attach(&tc_hook_ingress, &tc_opts_ingress);
    if (err)
    {
        std::cerr << "Failed to attach TC program (ingress direction): " << err << " (" << strerror(-err) << ")" << std::endl;
        report_operation_status("TC program attachment (ingress)", false, strerror(-err));
        goto cleanup;
    }
    report_operation_status("TC program attachment (ingress)", true);
       
    std::cout << "Successfully attached TC program to interface " << ifindex << " (egress direction)" << std::endl;
    std::cout << "Successfully attached TC program to interface " << ifindex << " (ingress direction)" << std::endl;
    std::cout << "Match direction: " << (rule.gress ? "EGRESS (destination IP:port)" : "INGRESS (source IP:port)") << std::endl;
    std::cout << "Rate limit: " << rule.rate_bps << " B/s" << std::endl;
    
    rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), handle_traffic_event, nullptr, nullptr);
    if (!rb)
    {
        std::cerr << "Failed to create ring buffer" << std::endl;
        err = -1;
        goto cleanup;
    }
    
    std::cout << "Starting traffic monitoring..." << std::endl;
    
    display_statistics();
    
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
        
        static auto last_summary_time = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_summary_time).count() >= 10)
        {
            display_packet_type_summary();
            display_smooth_flow_info();
            last_summary_time = now;
        }
    }
     
cleanup:
     // Properly detach TC programs before cleanup
    tc_opts_egress.flags = tc_opts_egress.prog_fd = tc_opts_egress.prog_id = 0;
    err = bpf_tc_detach(&tc_hook_egress, &tc_opts_egress);
    if (err)
    {
        std::cerr << "Failed to detach TC program (egress direction): " << err << std::endl;
    }

    tc_opts_ingress.flags = tc_opts_ingress.prog_fd = tc_opts_ingress.prog_id = 0; 
    err = bpf_tc_detach(&tc_hook_ingress, &tc_opts_ingress);
    if (err)
    {
        std::cerr << "Failed to detach TC program (ingress direction): " << err << std::endl;
    }
    
    if (hook_created_egress)
    {
        bpf_tc_hook_destroy(&tc_hook_egress);
        report_operation_status("TC hook cleanup (egress)", true);
    }

    if (hook_created_ingress)
    {
        bpf_tc_hook_destroy(&tc_hook_ingress);
        report_operation_status("TC hook cleanup (ingress)", true);
    }

    if (rb)
    {
        ring_buffer__free(rb);
        report_operation_status("Ring buffer cleanup", true);
    }
    if (skel)
    {
        tc_if_bpf__destroy(skel);
        report_operation_status("BPF skeleton cleanup", true);
    }
    
    std::cout << "Final error count: " << error_handler_get_error_count(&global_error_handler) << std::endl;
    error_handler_cleanup(&global_error_handler);
    
    return err < 0 ? 1 : 0;
}