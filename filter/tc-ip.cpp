
#include <signal.h>
#include <unistd.h>
#include <cstring>
#include <getopt.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/netfilter.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include "tc-ip.skel.h"
#include "../include/Ulog.h"

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

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define MAX_ERROR_MESSAGE_LENGTH 512
#define MAX_RETRY_DELAY_MS 1000
#define ERROR_LOG_BUFFER_SIZE 1000

#define DEFAULT_RATE_BPS 1000000
#define MAX_STRING_LENGTH 256

#define EGRESS 1
#define INGRESS 0

#define RULE_TYPE_RATE_LIMIT 0
#define RULE_TYPE_DROP 1
#define RULE_TYPE_LOG 2

struct event_t
{
	uint32_t sip; // Source IP address
	uint32_t dip; // Destination IP address
	uint32_t sport; // Source port
	uint32_t dport; // Destination port
	uint32_t protocol; // Protocol type
	uint32_t action; // Action taken (pass/drop)
	uint32_t bytes_sent; // Bytes sent
	uint32_t bytes_dropped; // Bytes dropped
	uint32_t packets_sent; // Packets sent
	uint32_t packets_dropped; // Packets dropped
	uint64_t timestamp; // Timestamp
	uint8_t event_type; // Event type for different operations
};

struct traffic_rule
{
	uint32_t target_ip;
	uint16_t target_port;
	uint8_t target_protocol;
	uint64_t rate_bps;
	uint8_t gress;
	uint32_t time_scale;
	uint32_t match_mask;
	uint8_t rule_type; // 0=rate_limit, 1=drop, 2=log
};

struct SafeString
{
	const char *str_;
	const char *context_;
};

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
	ErrorInfo error_log_[100];
	size_t error_count;
};

static bool parse_ip_address(const char *str, uint32_t *result,
			     const std::string &context = "");
static bool parse_protocol(const char *str, uint8_t *result,
			   const std::string &context = "");
static uint64_t parse_bandwidth(const char *str,
				const std::string &context = "");
static std::string format_ip(uint32_t ip, const std::string &context = "");
template <typename T>
static bool safe_str_to_int(const char *str, T *result, T min_val, T max_val,
			    const std::string &context = "");

static void log_error(ErrorCode code, const std::string &message);

static volatile bool running = true;
static struct ring_buffer *rb = nullptr;
static struct tc_ip_bpf *skel = nullptr;

static int netfilter_fd_ingress = -1;
static int netfilter_fd_egress = -1;

static struct traffic_rule rule = { 0 };

static ErrorHandler global_error_handler;

static struct option lopts[] = {
	{ "ip", required_argument, nullptr, 'i' },
	{ "port", required_argument, nullptr, 'p' },
	{ "protocol", required_argument, nullptr, 'P' },
	{ "rate", required_argument, nullptr, 'r' },
	{ "direction", required_argument, nullptr, 'd' },
	{ "timescale", required_argument, nullptr, 't' },
	{ "rule-type", required_argument, nullptr, 'T' },
	{ "drop", no_argument, nullptr, 'D' },
	{ "log", no_argument, nullptr, 'L' },
	{ "help", no_argument, nullptr, 'h' },
	{ nullptr, 0, nullptr, 0 }
};

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

static void safe_string_destroy(SafeString *safe_str)
{
	if (safe_str)
	{
		free(safe_str);
	}
}

static int safe_string_is_valid(const SafeString *safe_str)
{
	if (!safe_str || !safe_str->str_)
		return 0;
	return 1;
}

static size_t safe_string_length(const SafeString *safe_str)
{
	if (!safe_str || !safe_str->str_)
		return 0;
	return strlen(safe_str->str_);
}

static const char *safe_string_c_str(const SafeString *safe_str)
{
	return safe_str ? safe_str->str_ : NULL;
}

static const char *safe_string_context(const SafeString *safe_str)
{
	return safe_str ? safe_str->context_ : NULL;
}

static bool safe_check(const void *ptr, const std::string &context)
{
	if (!ptr)
	{
		log_error(ErrorCode::NULL_POINTER,
			  "Null pointer detected in " + context);
		return false;
	}
	return true;
}

void Usage(const char *arg0)
{
	pr_info("Usage: %s [options]", arg0);
	pr_info("Description: Netfilter-based IP traffic control and monitoring tool");
	pr_info("             Works at network protocol level, affects all traffic globally");
	pr_info("");
	pr_info("Options:");
	pr_info("  -i, --ip <ip>         IP address to match (optional, use 'any' for all IPs)");
	pr_info("  -p, --port <port>     Port to match (optional, use 'any' for all ports)");
	pr_info("  -P, --protocol <proto> Protocol to match (optional: tcp/udp/any)");
	pr_info("  -r, --rate <rate>     Rate limit (supports K/M/G suffixes)");
	pr_info("  -d, --direction <dir> Match direction (egress/ingress)");
	pr_info("  -t, --timescale <sec> Time scale (seconds, controls burst tolerance)");
	pr_info("  -T, --rule-type <type> Rule type (rate/drop/log, default: rate)");
	pr_info("  -D, --drop            Shortcut for rule-type=drop");
	pr_info("  -L, --log             Shortcut for rule-type=log");
	pr_info("  -h, --help            Show help information");
	pr_info("");
	pr_info("Matching Examples:");
	pr_info("  -i 192.168.1.1                    : Match specific IP only");
	pr_info("  -p 80                             : Match specific port only");
	pr_info("  -P tcp                            : Match TCP protocol only");
	pr_info("  -i 192.168.1.1 -p 80             : Match specific IP and port");
	pr_info("  -i 192.168.1.1 -P tcp            : Match specific IP and TCP protocol");
	pr_info("  -p 80 -P tcp                      : Match TCP traffic on port 80");
	pr_info("  -i any -p any -P any              : Match all traffic (not recommended)");
	pr_info("");
	pr_info("Rule Type Examples:");
	pr_info("  -T rate -r 100M                   : Apply rate limiting at 100 Mbps");
	pr_info("  -D                                 : Apply drop rule (block traffic)");
	pr_info("  -L                                 : Apply log rule (monitor traffic)");
	pr_info("  -T drop -i 192.168.1.100          : Drop traffic from specific IP");
	pr_info("  -T log -p 22                      : Log SSH traffic (port 22)");
	pr_info("");
	pr_info("Combination Examples:");
	pr_info("  -i 192.168.1.1 -p 80 -T drop     : Drop HTTP traffic from specific IP");
	pr_info("  -P tcp -p 443 -T rate -r 50M      : Rate limit HTTPS traffic to 50 Mbps");
	pr_info("  -i 10.0.0.0/8 -T log             : Log all traffic from 10.0.0.0/8 network");
	pr_info("  -P tcp -p 443 -T rate -r 50M      : Rate limit HTTPS traffic to 50 Mbps");
	pr_info("  -i 10.0.0.0/8 -T log             : Log all traffic from 10.0.0.0/8 network");
	pr_info("  -d egress -T drop                 : Drop all outgoing traffic");
	pr_info("  -T rate -r 100M                   : Rate limit all traffic globally");
	pr_info("  -T log                             : Log all traffic globally");
	pr_info("");
	pr_info("Direction Configuration:");
	pr_info("  -d egress  : Match destination IP:port (outgoing traffic)");
	pr_info("  -d ingress : Match source IP:port (incoming traffic to local machine)");
	pr_info("");
	pr_info("Time Scale Examples:");
	pr_info("  -t 1     : 1 second scale, strict rate limiting, low burst tolerance");
	pr_info("  -t 60    : 1 minute scale, allows short-term bursts, long-term average rate limiting");
	pr_info("  -t 3600  : 1 hour scale, allows long-term bursts, suitable for long-term bandwidth management");
	pr_info("");
	pr_info("Note: This tool operates at the Netfilter level, affecting all network traffic");
	pr_info("      globally, not limited to specific network interfaces.");
}

void parse_args(int argc, char **argv)
{
	int opt, opt_idx;
	std::string sopts = "i:p:P:r:d:t:T:DLh";

	if (!safe_check(argv, "Command line arguments array"))
	{
		pr_error("Invalid command line arguments");
		exit(-1);
	}

	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) >
	       0)
	{
		switch (opt)
		{
		case 'i': // Target IP address
			if (strcasecmp(optarg, "any") == 0 ||
			    strcasecmp(optarg, "*") == 0)
			{
				rule.target_ip = 0;
			}
			else if (!parse_ip_address(optarg, &rule.target_ip))
			{
				pr_error("Invalid IP address '%s'", optarg);
				exit(-1);
			}
			break;
		case 'p': // Target port
			if (strcasecmp(optarg, "any") == 0 ||
			    strcasecmp(optarg, "*") == 0)
			{
				rule.target_port = 0;
			}
			else if (!safe_str_to_int(optarg, &rule.target_port,
						  static_cast<uint16_t>(1),
						  static_cast<uint16_t>(65535)))
			{
				pr_error("Invalid port '%s'", optarg);
				exit(-1);
			}
			break;
		case 'P': // Target protocol
			if (!parse_protocol(optarg, &rule.target_protocol))
			{
				pr_error(
					"Invalid protocol '%s'. Supported: tcp, udp, any",
					optarg);
				exit(-1);
			}
			break;
		case 'r': // Rate limit
			rule.rate_bps = parse_bandwidth(optarg);
			if (rule.rate_bps == 0)
			{
				pr_error("Invalid rate limit '%s'", optarg);
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
				pr_error("Invalid direction '%s'", optarg);
				exit(-1);
			}
			break;
		case 't': // Time scale
			if (!safe_str_to_int(optarg, &rule.time_scale,
					     static_cast<uint32_t>(1),
					     static_cast<uint32_t>(3600)))
			{
				pr_error("Invalid time scale '%s'", optarg);
				exit(-1);
			}
			break;
		case 'T': // Rule type
			if (strcasecmp(optarg, "rate") == 0)
			{
				rule.rule_type = RULE_TYPE_RATE_LIMIT;
			}
			else if (strcasecmp(optarg, "drop") == 0)
			{
				rule.rule_type = RULE_TYPE_DROP;
			}
			else if (strcasecmp(optarg, "log") == 0)
			{
				rule.rule_type = RULE_TYPE_LOG;
			}
			else
			{
				pr_error(
					"Invalid rule type '%s'. Supported: rate, drop, log",
					optarg);
				exit(-1);
			}
			break;
		case 'D': // Drop rule (shortcut)
			rule.rule_type = RULE_TYPE_DROP;
			break;
		case 'L': // Log rule (shortcut)
			rule.rule_type = RULE_TYPE_LOG;
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

	rule.match_mask = 0;
	if (rule.target_ip != 0)
		rule.match_mask |= 1;
	if (rule.target_port != 0)
		rule.match_mask |= 2;
	if (rule.target_protocol != 0)
		rule.match_mask |= 4;

	if (rule.rule_type == 0 && rule.rate_bps > 0)
	{
		rule.rule_type = RULE_TYPE_RATE_LIMIT;
	}

	if (rule.rule_type == RULE_TYPE_RATE_LIMIT && rule.rate_bps == 0)
	{
		pr_error(
			"Rate limit must be specified for rate limiting rules (-r)");
		Usage(argv[0]);
		exit(-1);
	}

	if (rule.time_scale == 0)
	{
		rule.time_scale = 1;
		pr_info("Using default time scale: 1 second");
	}

	if (rule.match_mask == 0)
	{
		pr_info("Global traffic control (all traffic)");
	}
	else
	{
		pr_info("Match criteria:");
		if (rule.target_ip != 0)
		{
			pr_info("  IP: %s", format_ip(rule.target_ip).c_str());
		}
		else
		{
			pr_info("  IP: any");
		}
		if (rule.target_port != 0)
		{
			pr_info("  Port: %d", rule.target_port);
		}
		else
		{
			pr_info("  Port: any");
		}
		if (rule.target_protocol != 0)
		{
			pr_info("  Protocol: %d", (int)rule.target_protocol);
			if (rule.target_protocol == IPPROTO_TCP)
				pr_info(" (TCP)");
			else if (rule.target_protocol == IPPROTO_UDP)
				pr_info(" (UDP)");
		}
		else
		{
			pr_info("  Protocol: any");
		}
	}

	pr_info("Rule type: ");
	switch (rule.rule_type)
	{
	case RULE_TYPE_RATE_LIMIT:
		pr_info("Rate limiting");
		if (rule.rate_bps > 0)
		{
			pr_info(" (%llu B/s)", rule.rate_bps);
		}
		break;
	case RULE_TYPE_DROP:
		pr_info("Drop");
		break;
	case RULE_TYPE_LOG:
		pr_info("Log");
		break;
	default:
		pr_info("Unknown");
		break;
	}

	pr_info("Match direction: %s",
		(rule.gress ? "EGRESS (destination)" : "INGRESS (source)"));
	if (rule.rule_type == RULE_TYPE_RATE_LIMIT)
	{
		pr_info("Time scale: %u seconds (max bucket capacity: %.2f MB)",
			rule.time_scale,
			(rule.rate_bps * rule.time_scale / 1024.0 / 1024.0));
	}
}

template <typename T>
static bool safe_str_to_int(const char *str, T *result, T min_val, T max_val,
			    const std::string &context)
{
	if (strlen(str) == 0)
	{
		pr_error("Empty string in %s", context.c_str());
		return false;
	}

	static_assert(std::is_integral_v<T>, "T must be an integral type");

	char *endptr;
	errno = 0;

	if constexpr (std::is_signed_v<T>)
	{
		long val = strtol(str, &endptr, 10);
		if (errno == ERANGE || val < static_cast<long>(min_val) ||
		    val > static_cast<long>(max_val))
		{
			pr_error("Value out of range in %s: %ld",
				 context.c_str(), val);
			return false;
		}
		*result = static_cast<T>(val);
	}
	else
	{
		unsigned long val = strtoul(str, &endptr, 10);
		if (errno == ERANGE ||
		    val > static_cast<unsigned long>(max_val))
		{
			pr_error("Value out of range in %s: %lu",
				 context.c_str(), val);
			return false;
		}
		*result = static_cast<T>(val);
	}

	if (*endptr != '\0')
	{
		pr_error("Invalid characters in %s: %s", context.c_str(),
			 endptr);
		return false;
	}

	return true;
}

static bool parse_ip_address(const char *str, uint32_t *result,
			     const std::string &context)
{
	if (strlen(str) == 0)
	{
		pr_error("Empty IP address string in %s", context.c_str());
		return false;
	}

	if (strlen(str) > 15)
	{
		pr_error("IP address string too long in %s", context.c_str());
		return false;
	}

	struct in_addr addr;
	if (inet_pton(AF_INET, str, &addr) != 1)
	{
		pr_error("Invalid IP address format in %s: %s", context.c_str(),
			 str);
		return false;
	}

	*result = ntohl(addr.s_addr);
	return true;
}

static uint64_t parse_bandwidth(const char *str, const std::string &context)
{
	if (!str)
	{
		pr_warn("Null bandwidth string pointer in %s, using default",
			context.c_str());
		return DEFAULT_RATE_BPS;
	}

	if (strlen(str) == 0)
	{
		pr_warn("Empty bandwidth string in %s, using default",
			context.c_str());
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

	pr_warn("Invalid bandwidth suffix in %s: %s, using default",
		context.c_str(), endptr);
	return DEFAULT_RATE_BPS;
}

static bool parse_protocol(const char *str, uint8_t *result,
			   const std::string &context)
{
	if (strlen(str) == 0)
	{
		pr_error("Empty protocol string in %s", context.c_str());
		return false;
	}

	if (strcasecmp(str, "tcp") == 0)
	{
		*result = IPPROTO_TCP;
	}
	else if (strcasecmp(str, "udp") == 0)
	{
		*result = IPPROTO_UDP;
	}
	else if (strcasecmp(str, "any") == 0 || strcasecmp(str, "*") == 0)
	{
		*result = 0;
	}
	else
	{
		if (!safe_str_to_int(str, result, static_cast<uint8_t>(0),
				     static_cast<uint8_t>(255), context))
		{
			pr_error("Failed to parse protocol number in %s: %s",
				 context.c_str(), str);
			return false;
		}
	}
	return true;
}

static std::string format_ip(uint32_t ip, const std::string &context)
{
	try
	{
		struct in_addr addr;
		addr.s_addr = htonl(ip);
		const char *result = inet_ntoa(addr);

		if (!result)
		{
			pr_error("Failed to format IP address in %s: %u",
				 context.c_str(), ip);
			return "0.0.0.0";
		}

		return std::string(result);
	}
	catch (const std::exception &e)
	{
		pr_error("Exception in IP formatting in %s: %s",
			 context.c_str(), e.what());
		return "0.0.0.0";
	}
}

static void error_info_init(ErrorInfo *info, ErrorCode code, const char *msg,
			    const char *func, const char *file, int line)
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

static void error_handler_init(ErrorHandler *handler)
{
	if (!handler)
	{
		return;
	}

	handler->error_count = 0;
}

static void error_handler_cleanup(ErrorHandler *handler)
{
	if (!handler)
	{
		return;
	}
}

static void error_handler_log_error(ErrorHandler *handler,
				    const ErrorInfo *error)
{
	if (!handler || !error)
	{
		return;
	}

	if (handler->error_count < 100)
	{
		handler->error_log_[handler->error_count] = *error;
		handler->error_count++;
	}
	else
	{
		for (size_t i = 0; i < 99; i++)
		{
			handler->error_log_[i] = handler->error_log_[i + 1];
		}
		handler->error_log_[99] = *error;
	}

	pr_error("Error [%d] in %s (%s:%d): %s", (int)error->code,
		 error->function, error->file, error->line, error->message);
}

static size_t error_handler_get_error_count(const ErrorHandler *handler)
{
	if (!handler)
	{
		return 0;
	}

	size_t count;
	count = handler->error_count;
	return count;
}

static void error_handler_clear_error_log(ErrorHandler *handler)
{
	if (!handler)
	{
		return;
	}

	handler->error_count = 0;
}

static void log_error(ErrorCode code, const std::string &message)
{
	ErrorInfo error_info;
	error_info_init(&error_info, code, message.c_str(), __FUNCTION__,
			__FILE__, __LINE__);
	error_handler_log_error(&global_error_handler, &error_info);
}

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

			pr_warn("Operation failed (attempt %zu/%zu): %s. Retrying in %ldms...",
				attempt, max_retries, e.what(), delay.count());

			std::this_thread::sleep_for(delay);
			delay *= 2;
			if (delay.count() > MAX_RETRY_DELAY_MS)
			{
				delay = std::chrono::milliseconds(
					MAX_RETRY_DELAY_MS);
			}
		}
	}

	throw std::runtime_error("Max retry attempts exceeded");
}

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
				count, context.c_str());
		}
		return ptr;
	}
	catch (const std::bad_alloc &e)
	{
		pr_error("Memory allocation failed in %s: %s", context.c_str(),
			 e.what());
		return nullptr;
	}
}

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
			pr_error("Memory deallocation failed in %s: %s",
				 context.c_str(), e.what());
		}
	}
}

static int handle_traffic_event(void *ctx, void *data, size_t data_sz)
{
	if (data_sz != sizeof(event_t))
	{
		return 0;
	}

	const struct event_t *e = static_cast<const struct event_t *>(data);

	std::string src_ip = format_ip(e->sip);
	std::string dst_ip = format_ip(e->dip);

	switch (e->event_type)
	{
	case 0:
		pr_info("Traffic: %s:%d -> %s:%d [PASS] %u bytes",
			src_ip.c_str(), e->sport, dst_ip.c_str(), e->dport,
			e->bytes_sent);
		break;

	case 1:
		pr_info("Traffic: %s:%d -> %s:%d [DROP] %u bytes",
			src_ip.c_str(), e->sport, dst_ip.c_str(), e->dport,
			e->bytes_dropped);
		break;

	case 2:
		pr_info("Traffic: %s:%d -> %s:%d [RATE_LIMIT_DROP] %u bytes",
			src_ip.c_str(), e->sport, dst_ip.c_str(), e->dport,
			e->bytes_dropped);
		break;

	case 3:
		pr_info("Traffic: %s:%d -> %s:%d [LOG] %u bytes",
			src_ip.c_str(), e->sport, dst_ip.c_str(), e->dport,
			e->bytes_sent);
		break;

	default:
		pr_info("Traffic: %s:%d -> %s:%d [UNKNOWN] %u bytes",
			src_ip.c_str(), e->sport, dst_ip.c_str(), e->dport,
			e->bytes_sent);
		break;
	}

	return 0;
}

static void sig_handler(int sig)
{
	pr_info("Received signal %d, exiting...", sig);
	running = false;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}

static bool setup_traffic_rules()
{
	SafeString *context_str = safe_string_create(
		"setup_traffic_rules", "traffic control configuration");
	if (!safe_string_is_valid(context_str))
	{
		log_error(
			ErrorCode::MEMORY_ALLOCATION_FAILED,
			"Failed to create context string for traffic rules setup");
		return false;
	}

	struct bpf_map *map =
		bpf_object__find_map_by_name(skel->obj, "traffic_rules");
	if (!map)
	{
		log_error(ErrorCode::BPF_OPERATION_FAILED,
			  "Cannot find traffic_rules map");
		pr_error("Cannot find traffic_rules map");
		safe_string_destroy(context_str);
		return false;
	}

	uint32_t key = 0;

	struct
	{
		__u32 target_ip;
		__u16 target_port;
		__u8 target_protocol;
		__u64 rate_bps;
		__u8 gress;
		__u32 time_scale;
		__u32 match_mask;
		__u8 rule_type;
	} rule_data = { .target_ip = rule.target_ip,
			.target_port = rule.target_port,
			.target_protocol = rule.target_protocol,
			.rate_bps = rule.rate_bps,
			.gress = rule.gress,
			.time_scale = rule.time_scale,
			.match_mask = rule.match_mask,
			.rule_type = rule.rule_type };

	int err = bpf_map__update_elem(map, &key, sizeof(key), &rule_data,
				       sizeof(rule_data), BPF_ANY);
	if (err)
	{
		log_error(ErrorCode::BPF_OPERATION_FAILED,
			  "Failed to set traffic control rules: " +
				  std::to_string(err));
		pr_error("Failed to set traffic control rules: %d", err);
		safe_string_destroy(context_str);
		return false;
	}

	std::string context = safe_string_c_str(context_str) ?
				      safe_string_c_str(context_str) :
				      "unknown";
	std::string context_info = safe_string_context(context_str) ?
					   safe_string_context(context_str) :
					   "no context";
	size_t context_length = safe_string_length(context_str);
	pr_info("Traffic rules configured successfully in context: %s (%s, length: %zu)",
		context.c_str(), context_info.c_str(), context_length);

	safe_string_destroy(context_str);
	return true;
}

int main(int argc, char **argv)
{
	int err;
	union bpf_attr attr = {};

	if (getuid() != 0)
	{
		pr_error("This program must be run with root privileges");
		return 1;
	}

	error_handler_init(&global_error_handler);
	error_handler_clear_error_log(&global_error_handler);

	parse_args(argc, argv);

	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = tc_ip_bpf__open_and_load();
	if (!skel)
	{
		log_error(ErrorCode::BPF_OPERATION_FAILED,
			  "Failed to open and load BPF skeleton");
		pr_error("Failed to open and load BPF skeleton");
		goto cleanup;
	}

	if (!setup_traffic_rules())
	{
		log_error(ErrorCode::TC_OPERATION_FAILED,
			  "Failed to setup traffic control rules");
		pr_error("Failed to setup traffic control rules");
		goto cleanup;
	}

	attr.link_create.prog_fd = bpf_program__fd(skel->progs.netfilter_hook);
	attr.link_create.attach_type = BPF_NETFILTER;
	attr.link_create.netfilter.pf = NFPROTO_IPV4;
	attr.link_create.netfilter.hooknum = NF_INET_LOCAL_IN;
	attr.link_create.netfilter.priority = -128;

	netfilter_fd_ingress =
		syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
	if (netfilter_fd_ingress < 0)
	{
		log_error(ErrorCode::NETWORK_OPERATION_FAILED,
			  "Failed to attach netfilter ingress program");
		pr_error("Failed to attach netfilter ingress program: %s",
			 strerror(errno));
		goto cleanup;
	}

	attr.link_create.netfilter.hooknum = NF_INET_LOCAL_OUT;
	netfilter_fd_egress =
		syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
	if (netfilter_fd_egress < 0)
	{
		log_error(ErrorCode::NETWORK_OPERATION_FAILED,
			  "Failed to attach netfilter egress program");
		pr_error("Failed to attach netfilter egress program: %s",
			 strerror(errno));
		close(netfilter_fd_ingress);
		goto cleanup;
	}

	pr_info("Successfully attached netfilter program (both directions)");
	pr_info("Match direction: %s",
		(rule.gress ? "EGRESS (destination IP:port)" :
			      "INGRESS (source IP:port)"));

	rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf),
			      handle_traffic_event, nullptr, nullptr);
	if (!rb)
	{
		log_error(ErrorCode::BPF_OPERATION_FAILED,
			  "Failed to create ring buffer");
		pr_error("Failed to create ring buffer");
		err = -1;
		goto cleanup;
	}

	pr_info("Starting global traffic monitoring...");

	while (running)
	{
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR)
		{
			continue;
		}
		if (err < 0)
		{
			log_error(ErrorCode::BPF_OPERATION_FAILED,
				  "Ring buffer polling error: " +
					  std::to_string(err));
			pr_error("Ring buffer polling error: %d", err);
			break;
		}
	}

cleanup:
	if (netfilter_fd_ingress >= 0)
	{
		close(netfilter_fd_ingress);
	}
	if (netfilter_fd_egress >= 0)
	{
		close(netfilter_fd_egress);
	}

	if (rb)
	{
		ring_buffer__free(rb);
	}
	if (skel)
	{
		tc_ip_bpf__destroy(skel);
	}

	error_handler_cleanup(&global_error_handler);

	size_t error_count =
		error_handler_get_error_count(&global_error_handler);
	if (error_count > 0)
	{
		pr_info("Program completed with %zu errors logged",
			error_count);
	}

	return err < 0 ? 1 : 0;
}
