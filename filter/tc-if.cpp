
#include <signal.h>
#include <unistd.h>
#include <cstring>
#include <getopt.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include "tc-if.skel.h"
#include "../include/log.h"

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

/**
 * @brief 网络接口流量事件结构体
 * 用于传递网络接口级别的流量统计和控制信息
 */
struct event_t
{
	uint32_t action;                ///< 执行的动作
	uint32_t bytes_sent;            ///< 发送的字节数
	uint32_t bytes_dropped;         ///< 丢弃的字节数
	uint32_t packets_sent;          ///< 发送的数据包数
	uint32_t packets_dropped;       ///< 丢弃的数据包数
	uint64_t timestamp;             ///< 时间戳
	uint8_t eth_src[6];             ///< 源MAC地址
	uint8_t eth_dst[6];             ///< 目标MAC地址
	uint16_t eth_type;              ///< 以太网类型
	uint32_t packet_size;           ///< 数据包大小
	uint32_t packet_type;           ///< 数据包类型
	uint64_t type_rate_bps;         ///< 类型流量速率（字节/秒）
	uint64_t type_smooth_rate_bps;  ///< 平滑流量速率（字节/秒）
};

static volatile bool running = true;
static unsigned int ifindex = 0;
static struct ring_buffer *rb = nullptr;
static struct tc_if_bpf *skel = nullptr;

/**
 * @brief 流量控制规则结构体
 * 定义网络接口的流量控制参数
 */
struct traffic_rule
{
	uint64_t rate_bps;   ///< 速率限制（字节/秒）
	uint8_t gress;       ///< 流量方向（EGRESS=1，INGRESS=0）
	uint32_t time_scale; ///< 时间刻度（秒）
};

static struct traffic_rule rule = {0};

#define EGRESS 1
#define INGRESS 0

static struct option lopts[] = {
	{"interface", required_argument, nullptr, 'I'},
	{"rate",		 required_argument, nullptr, 'r'},
	{"direction", required_argument, nullptr, 'd'},
	{"timescale", required_argument, nullptr, 't'},
	{"help",		 no_argument,		  nullptr, 'h'},
	{nullptr,	  0,				 nullptr, 0  }
};

struct SafeString
{
	const char *str_;	  // String content pointer
	const char *context_; // String context description
};

// Create and initialize a SafeString structure
static SafeString *safe_string_create(const char *str, const char *context)
{
	SafeString *safe_str =
		static_cast<SafeString *>(malloc(sizeof(SafeString)));
	if (safe_str)
	{
		safe_str->str_ = str;
		safe_str->context_ = context ? context : "";
	}
	return safe_str;
}

// Free SafeString structure memory
static void safe_string_destroy(SafeString *safe_str)
{
	if (safe_str)
	{
		free(safe_str);
	}
}

// Check if SafeString is valid
static int safe_string_is_valid(const SafeString *safe_str)
{
	if (!safe_str || !safe_str->str_)
	{
		return 0;
	}
	return 1;
}

// Get string length safely
static size_t safe_string_length(const SafeString *safe_str)
{
	if (!safe_str || !safe_str->str_)
	{
		return 0;
	}
	return strlen(safe_str->str_);
}

// Get C-style string pointer
static const char *safe_string_c_str(const SafeString *safe_str)
{
	return safe_str ? safe_str->str_ : NULL;
}

// Get string context
static const char *safe_string_context(const SafeString *safe_str)
{
	return safe_str ? safe_str->context_ : NULL;
}

enum class ErrorCode
{
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

struct ErrorInfo
{
	ErrorCode code;
	char message[MAX_STRING_LENGTH];
	char function[MAX_STRING_LENGTH];
	char file[MAX_STRING_LENGTH];
	int line;
};

struct ErrorHandler
{
	ErrorInfo error_log_[100]; // Error log buffer, stores up to 100 errors
	size_t error_count;		   // Current error count
};

// Initialize ErrorInfo structure with error details
static void error_info_init(
	ErrorInfo *info,
	ErrorCode code,
	const char *msg,
	const char *func,
	const char *file,
	int line
)
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
static void error_handler_init(ErrorHandler *handler)
{
	if (!handler)
	{
		return;
	}

	handler->error_count = 0;
}

// Cleanup error handler (no-op in single process)
static void error_handler_cleanup(ErrorHandler *handler)
{
	if (!handler)
	{
		return;
	}
}

// Log error to handler buffer and stderr
static void
error_handler_log_error(ErrorHandler *handler, const ErrorInfo *error)
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
	fprintf(
		stderr,
		"Error [%d] in %s (%s:%d): %s\n",
		(int)error->code,
		error->function,
		error->file,
		error->line,
		error->message
	);
}

// Get current error count
static size_t error_handler_get_error_count(const ErrorHandler *handler)
{
	if (!handler)
	{
		return 0;
	}

	return handler->error_count;
}

static ErrorHandler global_error_handler;

// Log error with automatic context detection
static void log_error(ErrorCode code, const std::string &message)
{
	ErrorInfo error_info;
	error_info_init(
		&error_info,
		code,
		message.c_str(),
		__FUNCTION__,
		__FILE__,
		__LINE__
	);
	error_handler_log_error(&global_error_handler, &error_info);
}

// Retry operation with exponential backoff
template <typename Func>
auto retry_operation(Func &&func, size_t max_retries) -> decltype(func())
{
	size_t attempt = 0;
	std::chrono::milliseconds delay(100);

	while (attempt < max_retries)
	{
		try
		{
			return func();
		}
		catch (const std::exception &e)
		{
			attempt++;
			if (attempt >= max_retries)
			{
				throw;
			}

			pr_warn(
				"Operation failed (attempt %zu/%zu): %s. Retrying in %ldms...",
				attempt,
				max_retries,
				e.what(),
				delay.count()
			);

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
template <typename T>
T *safe_allocate(size_t count, const std::string &context = "")
{
	try
	{
		T *ptr = new T[count];
		if (!ptr)
		{
			pr_error(
				"Failed to allocate memory for %zu elements in %s",
				count,
				context.c_str()
			);
		}
		return ptr;
	}
	catch (const std::bad_alloc &e)
	{
		pr_error(
			"Memory allocation failed in %s: %s",
			context.c_str(),
			e.what()
		);
		return nullptr;
	}
}

// Safely deallocate memory with error handling
template <typename T>
void safe_deallocate(T *ptr, const std::string &context = "")
{
	if (ptr)
	{
		try
		{
			delete[] ptr;
		}
		catch (const std::exception &e)
		{
			pr_error(
				"Memory deallocation failed in %s: %s",
				context.c_str(),
				e.what()
			);
		}
	}
}

// Check if pointer is valid and log error if null
static bool safe_check(const void *ptr, const std::string &context)
{
	if (!ptr)
	{
		log_error(
			ErrorCode::NULL_POINTER,
			"Null pointer detected in " + context
		);
		return false;
	}
	return true;
}

// Check pointer validity and return specified value if null
template <typename T>
static T
safe_check_return(const void *ptr, const std::string &context, T retval)
{
	if (!ptr)
	{
		log_error(
			ErrorCode::NULL_POINTER,
			"Null pointer detected in " + context
		);
		return retval;
	}
	return true; // Return true when pointer is valid
}

// Safely convert string to integer with range validation
template <typename T>
static bool safe_str_to_int(
	const char *str,
	T *result,
	T min_val,
	T max_val,
	const std::string &context = ""
)
{
	pr_debug(
		"safe_str_to_int called with str='%s', min=%d, max=%d, context=%s",
		str,
		min_val,
		max_val,
		context.c_str()
	);

	// Validate input parameters
	if (!safe_check_return(str, "Input string pointer in " + context, false))
	{
		pr_debug("safe_check_return failed for str");
		return false;
	}

	if (!safe_check_return(
			result,
			"Output result pointer in " + context,
			false
		))
	{
		pr_debug("safe_check_return failed for result");
		return false;
	}

	if (strlen(str) == 0)
	{
		pr_debug("Empty string");
		pr_error("Empty string in %s", context.c_str());
		return false;
	}

	static_assert(std::is_integral_v<T>, "T must be an integral type");

	char *endptr;
	errno = 0;

	if constexpr (std::is_signed_v<T>)
	{
		long val = strtol(str, &endptr, 10);
		pr_debug("strtol returned %ld, errno=%d", val, errno);
		if (errno == ERANGE || val < static_cast<long>(min_val) ||
			val > static_cast<long>(max_val))
		{
			pr_debug("Value out of range");
			pr_error(
				"Value out of range in %s: %ld (min: %d, max: %d)",
				context.c_str(),
				val,
				min_val,
				max_val
			);
			return false;
		}
		*result = static_cast<T>(val);
	}
	else
	{
		unsigned long val = strtoul(str, &endptr, 10);
		pr_debug("strtoul returned %lu, errno=%d", val, errno);
		if (errno == ERANGE || val > static_cast<unsigned long>(max_val))
		{
			pr_debug("Value out of range");
			pr_error(
				"Value out of range in %s: %lu (max: %d)",
				context.c_str(),
				val,
				max_val
			);
			return false;
		}
		*result = static_cast<T>(val);
	}

	if (*endptr != '\0')
	{
		pr_debug("Invalid characters at end: %s", endptr);
		pr_error("Invalid characters in %s: %s", context.c_str(), endptr);
		return false;
	}

	pr_debug("safe_str_to_int successful, result=%d", *result);
	return true;
}

// Parse bandwidth string with K/M/G suffixes
static uint64_t
parse_bandwidth(const char *str, const std::string &context = "")
{
	if (!str)
	{
		pr_warn(
			"Null bandwidth string pointer in %s, using default",
			context.c_str()
		);
		return DEFAULT_RATE_BPS;
	}

	if (strlen(str) == 0)
	{
		pr_warn("Empty bandwidth string in %s, using default", context.c_str());
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

	pr_warn(
		"Invalid bandwidth suffix in %s: %s, using default",
		context.c_str(),
		endptr
	);
	return DEFAULT_RATE_BPS;
}

// Format MAC address as xx:xx:xx:xx:xx:xx
static std::string format_mac_address(const uint8_t *mac)
{
	char mac_str[18];
	snprintf(
		mac_str,
		sizeof(mac_str),
		"%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0],
		mac[1],
		mac[2],
		mac[3],
		mac[4],
		mac[5]
	);
	return std::string(mac_str);
}

// Get human-readable EtherType description
static std::string get_ethertype_description(uint16_t eth_type)
{
	switch (eth_type)
	{
	case 0x0800:
		return "IPv4";
	case 0x0806:
		return "ARP";
	case 0x86DD:
		return "IPv6";
	case 0x8100:
		return "802.1Q VLAN";
	case 0x8847:
		return "MPLS";
	case 0x8864:
		return "PPPoE";
	default:
		return "Unknown";
	}
}

// Get human-readable packet type description
static std::string get_packet_type_description(uint32_t packet_type)
{
	switch (packet_type)
	{
	case 1:
		return "IPv4";
	case 2:
		return "ARP";
	case 3:
		return "IPv6";
	case 4:
		return "802.1Q VLAN";
	case 5:
		return "MPLS";
	case 6:
		return "PPPoE";
	case 0:
		return "Unknown/Other";
	default:
		return "Unknown";
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

/**
 * @brief 处理来自BPF环形缓冲区的流量事件
 * 接收并处理网络接口的流量统计和控制事件
 * @param ctx 上下文指针（未使用）
 * @param data 事件数据指针
 * @param data_sz 数据大小
 * @return 总是返回0
 */
static int handle_traffic_event(void *ctx, void *data, size_t data_sz)
{
	if (data_sz != sizeof(event_t))
	{
		return 0;
	}

	const struct event_t *e = static_cast<const struct event_t *>(data);

	// Print interface-level traffic information with Ethernet details
	pr_info("Interface Traffic: ");

	if (e->bytes_dropped > 0)
	{
		pr_info(
			"[DROP] %u bytes, %u packets",
			e->bytes_dropped,
			e->packets_dropped
		);
	}
	else if (e->bytes_sent > 0)
	{
		pr_info("[PASS] %u bytes, %u packets", e->bytes_sent, e->packets_sent);
	}
	else
	{
		pr_info("[MATCH]");
	}

	// Display Ethernet header information
	pr_info("  Ethernet Header:");
	pr_info("    Source MAC: %s", format_mac_address(e->eth_src).c_str());
	pr_info("    Dest MAC:   %s", format_mac_address(e->eth_dst).c_str());
	pr_info(
		"    EtherType:  0x%x (%s)",
		e->eth_type,
		get_ethertype_description(e->eth_type).c_str()
	);
	pr_info("    Packet Size: %u bytes", e->packet_size);

	// Display packet type statistics and flow rate
	pr_info("  Packet Type Statistics:");
	pr_info(
		"    Type: %s (ID: %u)",
		get_packet_type_description(e->packet_type).c_str(),
		e->packet_type
	);
	pr_info(
		"    Current Flow Rate: %s",
		format_flow_rate(e->type_rate_bps).c_str()
	);
	pr_info(
		"    Smooth Flow Rate: %s (EMA)",
		format_flow_rate(e->type_smooth_rate_bps).c_str()
	);

	return 0;
}

// Signal handler for graceful shutdown
static void sig_handler(int sig)
{
	pr_info("\nReceived signal %d, exiting...", sig);
	running = false;
}

// libbpf print function redirector
static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

/**
 * @brief 显示程序使用说明
 * @param arg0 程序名称
 */
void Usage(const char *arg0)
{
	pr_info("Usage: %s [options]", arg0);
	pr_info("Options:");
	pr_info("  -I, --interface <if>  Network interface name (required)");
	pr_info("  -r, --rate <rate>     Rate limit (supports K/M/G suffixes)");
	pr_info("  -d, --direction <dir> Match direction (egress/ingress)");
	pr_info("  -t, --timescale <sec> Time scale (seconds, controls burst "
			"tolerance)");
	pr_info("  -h, --help            Show help information");
	pr_info("");
	pr_info("Direction Configuration:");
	pr_info("  -d egress  : Match destination IP:port (outgoing traffic)");
	pr_info("  -d ingress : Match source IP:port (incoming traffic to local "
			"machine)");
	pr_info("  -t 1     : 1 second scale, strict rate limiting, low burst "
			"tolerance");
	pr_info("  -t 60    : 1 minute scale, allows short-term bursts, long-term "
			"average rate limiting");
	pr_info("  -t 3600  : 1 hour scale, allows long-term bursts, suitable for "
			"long-term bandwidth management");
	pr_info("");
}

/**
 * @brief 解析命令行参数并验证参数
 * @param argc 参数个数
 * @param argv 参数数组
 */
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
				pr_error("Error: Invalid interface name '%s'", optarg);
				throw std::runtime_error("Invalid interface name");
			}
			break;
		case 'r': // Rate limit
			rule.rate_bps = parse_bandwidth(optarg);
			if (rule.rate_bps == 0)
			{
				pr_error("Error: Invalid rate limit '%s'", optarg);
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
				pr_error("Error: Invalid direction '%s'", optarg);
				throw std::runtime_error("Invalid direction");
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
				pr_error("Error: Invalid time scale '%s'", optarg);
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
		pr_error("Error: Network interface must be specified (-I)");
		Usage(argv[0]);
		throw std::runtime_error("Network interface must be specified");
	}

	// Allow interface-level rate limiting (no matching criteria required)
	// At least one matching criteria must be specified, OR rate limit must be
	// specified
	if (rule.rate_bps == 0)
	{
		pr_error("Error: Rate limit must be specified (-r)");
		Usage(argv[0]);
		throw std::runtime_error("Rate limit must be specified");
	}

	// Set default values
	if (rule.rate_bps == 0)
	{
		pr_info("Using default rate limit: %u B/s", DEFAULT_RATE_BPS);
		rule.rate_bps = DEFAULT_RATE_BPS;
	}
	else
	{
		pr_info(
			"Setting rate limit: %llu B/s (%.2f MB/s)",
			rule.rate_bps,
			(rule.rate_bps / 1024.0 / 1024.0)
		);
	}

	if (rule.time_scale == 0)
	{
		rule.time_scale = 1; // Default 1 second time scale
		pr_info("Using default time scale: 1 second");
	}
	else
	{
		pr_info("Setting time scale: %u seconds", rule.time_scale);
	}

	pr_info("Network interface: %u", ifindex);
	pr_info(
		"Match direction: %s",
		(rule.gress ? "EGRESS (destination)" : "INGRESS (source)")
	);
	pr_info(
		"Rate limit: %llu B/s (%.2f MB/s)",
		rule.rate_bps,
		(rule.rate_bps / 1024.0 / 1024.0)
	);
	pr_info(
		"Time scale: %u seconds (max bucket capacity: %.2f MB)",
		rule.time_scale,
		(rule.rate_bps * rule.time_scale / 1024.0 / 1024.0)
	);
}

// Setup traffic control rules in BPF map
static bool setup_traffic_rules()
{
	error_handler_init(&global_error_handler);

	if (!safe_check(skel, "BPF skeleton in setup_traffic_rules"))
	{
		ErrorInfo error_info;
		error_info_init(
			&error_info,
			ErrorCode::NULL_POINTER,
			"BPF skeleton is null",
			__FUNCTION__,
			__FILE__,
			__LINE__
		);
		error_handler_log_error(&global_error_handler, &error_info);
		return false;
	}

	struct bpf_map *map =
		bpf_object__find_map_by_name(skel->obj, "traffic_rules");
	if (!map)
	{
		ErrorInfo error_info;
		error_info_init(
			&error_info,
			ErrorCode::BPF_OPERATION_FAILED,
			"Cannot find traffic_rules map",
			__FUNCTION__,
			__FILE__,
			__LINE__
		);
		error_handler_log_error(&global_error_handler, &error_info);
		pr_error("Cannot find traffic_rules map");
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
		ErrorInfo error_info;
		error_info_init(
			&error_info,
			ErrorCode::BPF_OPERATION_FAILED,
			"Failed to set traffic control rules",
			__FUNCTION__,
			__FILE__,
			__LINE__
		);
		error_handler_log_error(&global_error_handler, &error_info);
		pr_error("Failed to set traffic control rules: %d", err);
		return false;
	}

	pr_info("Successfully configured traffic control rules");
	pr_info(
		"Error count during setup: %zu",
		error_handler_get_error_count(&global_error_handler)
	);

	return true;
}

// Validate program configuration parameters
static bool validate_configuration()
{
	SafeString *interface_str =
		safe_string_create("interface validation", "validate_configuration");
	if (!safe_string_is_valid(interface_str))
	{
		pr_error("Failed to create interface validation string");
		return false;
	}

	// Validate interface index
	if (ifindex == 0)
	{
		pr_error("Invalid interface index: %u", ifindex);
		safe_string_destroy(interface_str);
		return false;
	}

	// Validate rate limit
	if (rule.rate_bps == 0)
	{
		pr_error("Invalid rate limit: %llu", rule.rate_bps);
		safe_string_destroy(interface_str);
		return false;
	}

	// Validate time scale
	if (rule.time_scale < 1 || rule.time_scale > 3600)
	{
		pr_error(
			"Invalid time scale: %u (must be between 1 and 3600 seconds)",
			rule.time_scale
		);
		safe_string_destroy(interface_str);
		return false;
	}

	// Validate direction
	if (rule.gress != EGRESS && rule.gress != INGRESS)
	{
		pr_error("Invalid direction: %d", (int)rule.gress);
		safe_string_destroy(interface_str);
		return false;
	}

	pr_info("Configuration validation passed");
	pr_info("Interface string length: %zu", safe_string_length(interface_str));
	pr_info("Interface string context: %s", safe_string_context(interface_str));

	safe_string_destroy(interface_str);
	return true;
}

// Report operation success/failure status
static void report_operation_status(
	const std::string &operation,
	bool success,
	const std::string &details = ""
)
{
	if (success)
	{
		// Print success status directly
		pr_info("✓ %s completed successfully", operation.c_str());
	}
	else
	{
		// Only log errors when operations fail
		ErrorInfo error_info;
		error_info_init(
			&error_info,
			ErrorCode::UNKNOWN_ERROR,
			("Operation failed: " + operation + " - " + details).c_str(),
			__FUNCTION__,
			__FILE__,
			__LINE__
		);
		error_handler_log_error(&global_error_handler, &error_info);

		// Print failure status
		pr_error("✗ %s failed: %s", operation.c_str(), details.c_str());
	}
}

// Display traffic control statistics
static void display_statistics()
{
	SafeString *stats_str =
		safe_string_create("traffic statistics", "display_statistics");
	if (!safe_string_is_valid(stats_str))
	{
		pr_error("Failed to create statistics string");
		return;
	}

	SafeString *interface_str =
		safe_string_create("interface information", "display_statistics");
	if (!safe_string_is_valid(interface_str))
	{
		pr_error("Failed to create interface string");
		safe_string_destroy(stats_str);
		return;
	}

	pr_info("\n=== Traffic Control Statistics ===");
	pr_info("Statistics string: %s", safe_string_c_str(stats_str));
	pr_info("Statistics context: %s", safe_string_context(stats_str));
	pr_info("Statistics length: %zu", safe_string_length(stats_str));

	pr_info("Interface string: %s", safe_string_c_str(interface_str));
	pr_info("Interface context: %s", safe_string_context(interface_str));
	pr_info("Interface length: %zu", safe_string_length(interface_str));

	pr_info("Network interface: %u", ifindex);
	pr_info(
		"Rate limit: %llu B/s (%.2f MB/s)",
		rule.rate_bps,
		(rule.rate_bps / 1024.0 / 1024.0)
	);
	pr_info("Time scale: %u seconds", rule.time_scale);
	pr_info("Direction: %s", (rule.gress ? "EGRESS" : "INGRESS"));
	pr_info(
		"Max bucket capacity: %.2f MB",
		(rule.rate_bps * rule.time_scale / 1024.0 / 1024.0)
	);
	pr_info("===================================");

	safe_string_destroy(stats_str);
	safe_string_destroy(interface_str);
}

// Display packet type statistics summary
static void display_packet_type_summary()
{
	pr_info("\n=== PACKET TYPE STATISTICS SUMMARY ===");
	pr_info(
		"Timestamp: %ld",
		std::chrono::duration_cast<std::chrono::seconds>(
			std::chrono::system_clock::now().time_since_epoch()
		)
			.count()
	);

	pr_info("This would show statistics for each packet type:");
	pr_info("  - IPv4 packets and flow rate");
	pr_info("  - ARP packets and flow rate");
	pr_info("  - IPv6 packets and flow rate");
	pr_info("  - VLAN packets and flow rate");
	pr_info("  - IPv6 packets and flow rate");
	pr_info("  - PPPoE packets and flow rate");
	pr_info("  - Unknown/Other packets and flow rate");
	pr_info("=====================================");
}

// Display smooth flow rate algorithm information
static void display_smooth_flow_info()
{
	pr_info("\n=== SMOOTH FLOW RATE ALGORITHM INFO ===");
	pr_info("Exponential Moving Average (EMA) Algorithm:");
	pr_info("  Formula: smooth = (smooth - smooth/8) + (new_rate * 2^13)");
	pr_info("  Weight: 1/8 = 12.5%% for new measurements");
	pr_info("  Scaling: 2^13 = 8192x for precision");
	pr_info("  Benefits:");
	pr_info("    - Reduces noise and sudden spikes");
	pr_info("    - Maintains responsiveness to trends");
	pr_info("    - Provides stable flow rate readings");
	pr_info("  Time Window: 1 second sliding window");
	pr_info("  Update Frequency: Every second");
	pr_info("=========================================");
}

/**
 * @brief 主程序入口点 - 基于BPF的TC流量控制
 * @param argc 命令行参数个数
 * @param argv 命令行参数数组
 * @return 程序退出状态，0表示成功，其他值表示失败
 */
int main(int argc, char **argv)
{
	bool hook_created_egress = false;
	bool hook_created_ingress = false;
	int err = 0;

	if (getuid() != 0)
	{
		pr_error("Error: This program must be run with root privileges");
		return 1;
	}

	try
	{
		parse_args(argc, argv);
	}
	catch (const std::runtime_error &e)
	{
		pr_error("Error parsing arguments: %s", e.what());
		return 1;
	}

	if (!validate_configuration())
	{
		pr_error("Configuration validation failed, exiting...");
		return 1;
	}

	report_operation_status("Command line argument parsing", true);

	DECLARE_LIBBPF_OPTS(
		bpf_tc_hook,
		tc_hook_egress,
		.ifindex = (int)ifindex,
		.attach_point = BPF_TC_EGRESS
	);
	DECLARE_LIBBPF_OPTS(
		bpf_tc_hook,
		tc_hook_ingress,
		.ifindex = (int)ifindex,
		.attach_point = BPF_TC_INGRESS
	);

	DECLARE_LIBBPF_OPTS(
		bpf_tc_opts,
		tc_opts_egress,
		.handle = 1,
		.priority = 1
	);
	DECLARE_LIBBPF_OPTS(
		bpf_tc_opts,
		tc_opts_ingress,
		.handle = 1,
		.priority = 1
	);

	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = tc_if_bpf__open_and_load();
	if (!skel)
	{
		pr_error("Failed to open and load BPF skeleton");
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
		pr_info("Successfully created TC hook (egress direction)");
		report_operation_status("TC hook creation (egress)", true);
	}
	else if (err == -EEXIST)
	{
		pr_info("TC hook (egress direction) already exists");
		report_operation_status(
			"TC hook creation (egress)",
			true,
			"already exists"
		);
	}
	else
	{
		pr_error(
			"Failed to create TC hook (egress direction): %d (%s)",
			err,
			strerror(-err)
		);
		report_operation_status(
			"TC hook creation (egress)",
			false,
			strerror(-err)
		);
		goto cleanup;
	}

	err = bpf_tc_hook_create(&tc_hook_ingress);
	if (!err)
	{
		hook_created_ingress = true;
		pr_info("Successfully created TC hook (ingress direction)");
		report_operation_status("TC hook creation (ingress)", true);
	}
	else if (err == -EEXIST)
	{
		pr_info("TC hook (ingress direction) already exists");
		report_operation_status(
			"TC hook creation (ingress)",
			true,
			"already exists"
		);
	}
	else
	{
		pr_error(
			"Failed to create TC hook (ingress direction): %d (%s)",
			err,
			strerror(-err)
		);
		report_operation_status(
			"TC hook creation (ingress)",
			false,
			strerror(-err)
		);
		goto cleanup;
	}

	tc_opts_egress.prog_fd = bpf_program__fd(skel->progs.tc_egress);
	err = bpf_tc_attach(&tc_hook_egress, &tc_opts_egress);
	if (err)
	{
		pr_error(
			"Failed to attach TC program (egress direction): %d (%s)",
			err,
			strerror(-err)
		);
		report_operation_status(
			"TC program attachment (egress)",
			false,
			strerror(-err)
		);
		goto cleanup;
	}
	report_operation_status("TC program attachment (egress)", true);

	tc_opts_ingress.prog_fd = bpf_program__fd(skel->progs.tc_ingress);
	err = bpf_tc_attach(&tc_hook_ingress, &tc_opts_ingress);
	if (err)
	{
		pr_error(
			"Failed to attach TC program (ingress direction): %d (%s)",
			err,
			strerror(-err)
		);
		report_operation_status(
			"TC program attachment (ingress)",
			false,
			strerror(-err)
		);
		goto cleanup;
	}
	report_operation_status("TC program attachment (ingress)", true);

	pr_info(
		"Successfully attached TC program to interface %u (egress direction)",
		ifindex
	);
	pr_info(
		"Successfully attached TC program to interface %u (ingress direction)",
		ifindex
	);
	pr_info(
		"Match direction: %s",
		(rule.gress ? "EGRESS (destination IP:port)"
					: "INGRESS (source IP:port)")
	);
	pr_info("Rate limit: %llu B/s", rule.rate_bps);

	rb = ring_buffer__new(
		bpf_map__fd(skel->maps.ringbuf),
		handle_traffic_event,
		nullptr,
		nullptr
	);
	if (!rb)
	{
		pr_error("Failed to create ring buffer");
		err = -1;
		goto cleanup;
	}

	pr_info("Starting traffic monitoring...");

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
			pr_error("Ring buffer polling error: %d", err);
			break;
		}

		static auto last_summary_time = std::chrono::steady_clock::now();
		auto now = std::chrono::steady_clock::now();
		if (std::chrono::duration_cast<std::chrono::seconds>(
				now - last_summary_time
			)
				.count() >= 10)
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
		pr_error("Failed to detach TC program (egress direction): %d", err);
	}

	tc_opts_ingress.flags = tc_opts_ingress.prog_fd = tc_opts_ingress.prog_id =
		0;
	err = bpf_tc_detach(&tc_hook_ingress, &tc_opts_ingress);
	if (err)
	{
		pr_error("Failed to detach TC program (ingress direction): %d", err);
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

	pr_info(
		"Final error count: %zu",
		error_handler_get_error_count(&global_error_handler)
	);
	error_handler_cleanup(&global_error_handler);

	return err < 0 ? 1 : 0;
}