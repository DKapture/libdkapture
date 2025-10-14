// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <sys/resource.h>
#include <signal.h>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <climits>
#include <cstdint>
#include "signal-filter.h"
#include "signal-filter.skel.h"

/**
 * @brief 事件结构体，用于与BPF程序进行环形缓冲区通信
 */
struct event_t
{
	uint32_t sender_pid;    ///< 发送者进程ID
	char sender_comm[16];   ///< 发送者进程名称
	uint32_t target_pid;    ///< 目标进程ID
	char target_comm[16];   ///< 目标进程名称
	uint32_t sig;           ///< 信号编号
	int32_t result;         ///< 操作结果
	uint64_t generate_time; ///< 信号生成时间
	uint64_t deliver_time;  ///< 信号传递时间
	uint32_t action;        ///< 执行的动作
	uint64_t timestamp;     ///< 时间戳
	char filter_flag;       ///< 过滤标志
};

/**
 * @brief 统一的信号映射结构体
 * 将信号名称与信号编号进行映射
 */
struct SignalMapping
{
	const char *name; ///< 信号名称
	int number;       ///< 信号编号
};

// Signal name to number mapping table
static const SignalMapping signal_map[] = {
	{nullptr,	  0 },
	   {"SIGHUP",	  1 },
	{"SIGINT",	   2 },
	   {"SIGQUIT",   3 },
	{"SIGILL",	   4 },
	   {"SIGTRAP",   5 },
	{"SIGABRT",	6 },
	   {"SIGBUS",	  7 },
	{"SIGFPE",	   8 },
	   {"SIGKILL",   9 },
	{"SIGUSR1",	10},
	   {"SIGSEGV",   11},
	{"SIGUSR2",	12},
	   {"SIGPIPE",   13},
	{"SIGALRM",	14},
	   {"SIGTERM",   15},
	{"SIGSTKFLT", 16},
	   {"SIGCHLD",   17},
	{"SIGCONT",	18},
	   {"SIGSTOP",   19},
	{"SIGTSTP",	20},
	   {"SIGTTIN",   21},
	{"SIGTTOU",	22},
	   {"SIGURG",	  23},
	{"SIGXCPU",	24},
	   {"SIGXFSZ",   25},
	{"SIGVTALRM", 26},
	   {"SIGPROF",   27},
	{"SIGWINCH",	 28},
	   {"SIGIO",	 29},
	{"SIGPWR",	   30},
	   {"SIGSYS",	  31}
};

static const size_t signal_map_size =
	sizeof(signal_map) / sizeof(signal_map[0]);

// Global state variables
static struct signal_filter_bpf *skel = nullptr;
static struct ring_buffer *rb = nullptr;
static volatile bool running = true;
static struct Rule rule = {0};

// Command line options definition
static struct option lopts[] = {
	{"sender-pid", required_argument, 0, 'P'},
	{"recv-pid",	 required_argument, 0, 'p'},
	{"sender-uid", required_argument, 0, 'U'},
	{"sig",		required_argument, 0, 'S'},
	{"help",		 no_argument,		  0, 'h'},
	{0,			0,				 0, 0  }
};

/**
 * @brief 帮助信息结构体
 * 存储命令行选项的参数和说明信息
 */
struct HelpMsg
{
	const char *argparam; ///< 参数描述
	const char *msg;      ///< 帮助信息
};

// Help messages for command line options
static HelpMsg help_msg[] = {
	{"<sender-pid>", "Filter by sender process ID\n"	},
	{"<recv-pid>",   "Filter by receiver process ID\n"},
	{"<sender-uid>", "Filter by sender user ID\n"	 },
	{"<sig>",		  "Filter by signal type\n"		   },
	{"",			 "Show this help message\n"	   },
};

/**
 * @brief 将信号编号转换为信号名称
 * @param sig 信号编号
 * @return 信号名称字符串，如果未知则返回"UNKNOWN"
 */
static const char *get_signal_name(int sig)
{
	if (sig >= 0 && sig < (int)signal_map_size && signal_map[sig].name)
	{
		return signal_map[sig].name;
	}
	return "UNKNOWN";
}

/**
 * @brief 格式化当前时间为 HH:MM:SS 格式
 * @return 格式化的时间字符串
 */
static std::string format_time()
{
	auto now = std::chrono::system_clock::now();
	auto time_t = std::chrono::system_clock::to_time_t(now);
	auto tm = *std::localtime(&time_t);

	std::ostringstream time_ss;
	time_ss << std::put_time(&tm, "%H:%M:%S");
	return time_ss.str();
}

/**
 * @brief 将信号名称转换为信号编号
 * @param signal_name 信号名称字符串
 * @return 信号编号，如果未找到则返回-1
 */
static int signal_name_to_number(const char *signal_name)
{
	if (!signal_name)
	{
		return -1;
	}

	for (size_t i = 0; i < signal_map_size; i++)
	{
		if (signal_map[i].name && strcmp(signal_name, signal_map[i].name) == 0)
		{
			return signal_map[i].number;
		}
	}
	return -1;
}

/**
 * @brief 处理来自BPF的信号跟踪事件
 * @param ctx 上下文指针（未使用）
 * @param data 事件数据指针
 * @param data_sz 数据大小
 * @return 处理结果，0表示成功，-1表示失败
 */
static int handle_trace_event(void *ctx, void *data, size_t data_sz)
{
	// Validate data size
	if (data_sz != sizeof(event_t))
	{
		std::cerr << "Invalid data size in handle_trace_event" << std::endl;
		return -1;
	}

	const struct event_t *e = static_cast<const struct event_t *>(data);

	// Validate string lengths to prevent buffer overflows
	if (strnlen(e->sender_comm, sizeof(e->sender_comm)) >=
			sizeof(e->sender_comm) ||
		strnlen(e->target_comm, sizeof(e->target_comm)) >=
			sizeof(e->target_comm))
	{
		std::cerr << "Invalid string length in event data" << std::endl;
		return -1;
	}

	const char *signal_name = get_signal_name(e->sig);
	uint64_t latency_ns = e->deliver_time - e->generate_time;
	double latency_us = latency_ns / 1000.0;
	std::string time_str = format_time();

	// Print signal trace information
	std::cout << std::setw(8) << std::left << time_str << " " << std::setw(10)
			  << std::right << e->sender_pid << "            " << std::setw(12)
			  << std::left << e->sender_comm << "  " << std::setw(10)
			  << std::right << e->target_pid << "           " << std::setw(12)
			  << std::left << e->target_comm << "       " << std::setw(12)
			  << std::left << signal_name << "   " << std::setw(12) << std::left
			  << e->result << "   " << std::fixed << std::setprecision(2)
			  << std::setw(8) << latency_us << " us" << std::endl;

	return 0;
}

/**
 * @brief 处理来自BPF的信号拦截事件
 * @param ctx 上下文指针（未使用）
 * @param data 事件数据指针
 * @param data_sz 数据大小
 * @return 处理结果，0表示成功，-1表示失败
 */
static int handle_intercept_event(void *ctx, void *data, size_t data_sz)
{
	// Validate data size
	if (data_sz != sizeof(event_t))
	{
		std::cerr << "Invalid data size in handle_intercept_event" << std::endl;
		return -1;
	}

	const struct event_t *e = static_cast<const struct event_t *>(data);

	// Validate string lengths to prevent buffer overflows
	if (strnlen(e->target_comm, sizeof(e->target_comm)) >=
		sizeof(e->target_comm))
	{
		std::cerr << "Invalid string length in event data" << std::endl;
		return -1;
	}

	const char *signal_name = get_signal_name(e->sig);
	const char *action_str = e->action == 1 ? "BLOCKED" : "ALLOWED";
	std::string time_str = format_time();

	// Print interception information
	std::cout << "[INTERCEPT] " << std::setw(8) << std::left << time_str << " "
			  << std::setw(10) << std::right << e->target_pid << "            "
			  << std::setw(12) << std::left << e->target_comm << "         "
			  << std::setw(12) << std::left << signal_name << "            "
			  << std::setw(8) << std::left << action_str << std::endl;

	return 0;
}

// Event handler function array
int (*handle_array[EVENTNUMBER])(void *ctx, void *data, size_t data_sz) = {
	handle_trace_event,
	handle_intercept_event
};

/**
 * @brief 主事件调度器 - 将事件路由到适当的处理器
 * @param ctx 上下文指针
 * @param data 事件数据指针
 * @param data_sz 数据大小
 * @return 处理结果，0表示成功，-1表示失败
 */
static int handle_all_event(void *ctx, void *data, size_t data_sz)
{
	// Validate data size
	if (data_sz != sizeof(event_t))
	{
		std::cerr << "Invalid data size in handle_all_event" << std::endl;
		return -1;
	}

	const struct event_t *e = static_cast<const struct event_t *>(data);

	// Validate filter_flag to prevent array bounds violation
	if (e->filter_flag < 0 || e->filter_flag >= EVENTNUMBER)
	{
		std::cerr << "Invalid filter_flag value" << std::endl;
		return -1;
	}

	return handle_array[(int)e->filter_flag](ctx, data, data_sz);
}

// Signal handler for graceful shutdown
static void sig_handler(int sig)
{
	std::cout << "\nReceived signal " << get_signal_name(sig) << ", exiting..."
			  << std::endl;
	running = false;
}

// Print usage information
void Usage(const char *arg0)
{
	std::cout << "Usage: " << arg0 << " [options]" << std::endl;
	std::cout << "  Trace and intercept inter-process signal communication."
			  << std::endl
			  << std::endl;
	std::cout << "Options:" << std::endl;
	for (int i = 0; lopts[i].name; i++)
	{
		std::cout << "  -" << (char)lopts[i].val << ", --" << lopts[i].name
				  << " " << help_msg[i].argparam << std::endl;
		std::cout << "\t" << help_msg[i].msg;
	}
	std::cout << std::endl;
	std::cout << "Rule Logic: All rules must be satisfied to intercept signals"
			  << std::endl;
	std::cout << "Default Behavior: Allow all signals when no rules are set"
			  << std::endl;
	std::cout << "Examples:" << std::endl;
	std::cout << "  " << arg0 << " --sender-pid 1234 --sig 15" << std::endl;
	std::cout << "  " << arg0 << " --recv-pid 5678 --sig 9" << std::endl;
	std::cout << "  " << arg0 << " --sender-uid 1000 --sig 9" << std::endl;
}

// Generic safe string to integer conversion with overflow protection
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

	// Use appropriate conversion function based on type
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

	// Check if conversion was complete
	if (*endptr != '\0')
	{
		return false;
	}

	return true;
}

// Type-specific conversion functions using the generic template
static bool safe_str_to_uint32(const char *str, uint32_t *result)
{
	return safe_str_to_int(str, result, 0U, UINT32_MAX);
}

static bool safe_str_to_pid_t(const char *str, pid_t *result)
{
	return safe_str_to_int(
		str,
		result,
		static_cast<pid_t>(1),
		static_cast<pid_t>(INT_MAX)
	);
}

static bool safe_str_to_uid_t(const char *str, uid_t *result)
{
	return safe_str_to_int(
		str,
		result,
		static_cast<uid_t>(0),
		static_cast<uid_t>(UINT_MAX)
	);
}

// Convert long options to short options string
std::string long_opt2short_opt(const option lopts[])
{
	std::string sopts = "";
	for (int i = 0; lopts[i].name; i++)
	{
		sopts += lopts[i].val;
		switch (lopts[i].has_arg)
		{
		case no_argument:
			break;
		case required_argument:
			sopts += ":";
			break;
		case optional_argument:
			sopts += "::";
			break;
		default:
			abort();
		}
	}
	return sopts;
}

// Parse command line arguments and validate input
void parse_args(int argc, char **argv)
{
	int opt, opt_idx;
	std::string sopts = long_opt2short_opt(lopts);

	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0)
	{
		switch (opt)
		{
		case 'P': // Sender process ID
			if (!safe_str_to_pid_t(optarg, &rule.sender_pid) ||
				rule.sender_pid == 0)
			{
				std::cerr << "Error: Invalid sender PID '" << optarg
						  << "'. PID must be positive" << std::endl;
				exit(-1);
			}
			break;
		case 'p': // Receiver process ID
			if (!safe_str_to_pid_t(optarg, &rule.recv_pid) ||
				rule.recv_pid == 0)
			{
				std::cerr << "Error: Invalid receiver PID '" << optarg
						  << "'. PID must be positive" << std::endl;
				exit(-1);
			}
			break;
		case 'U': // Sender user ID
			if (!safe_str_to_uid_t(optarg, &rule.sender_uid))
			{
				std::cerr << "Error: Invalid sender UID '" << optarg
						  << "'. UID must be non-negative" << std::endl;
				exit(-1);
			}
			break;
		case 'S': // Signal type
			rule.sig = signal_name_to_number(optarg);
			if (rule.sig == -1)
			{
				uint32_t sig_num;
				if (!safe_str_to_uint32(optarg, &sig_num) || sig_num == 0 ||
					sig_num > 31)
				{
					std::cerr << "Error: Invalid signal '" << optarg << "'. ";
					std::cerr << "Use signal name (e.g., SIGUSR1) or number "
								 "(1-31)"
							  << std::endl;
					exit(-1);
				}
				rule.sig = sig_num;
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

	// Print parsed filter rules
	std::cout << "\n=============== Filter Rules =================" << std::endl
			  << std::endl;
	std::cout << "\tSender PID = " << rule.sender_pid << std::endl;
	std::cout << "\tReceiver PID = " << rule.recv_pid << std::endl;
	std::cout << "\tSender UID = " << rule.sender_uid << std::endl;
	std::cout << "\tSignal type = " << rule.sig << " ("
			  << get_signal_name(rule.sig) << ")" << std::endl;
	std::cout << "\n========================================" << std::endl
			  << std::endl;
}

// Check if program is running with root privileges
static bool check_privileges()
{
	if (getuid() != 0)
	{
		std::cerr << "Error: This program must be run as root" << std::endl;
		return false;
	}
	return true;
}

// Configure BPF maps with filter rules
static bool setup_bpf_maps(struct signal_filter_bpf *skel)
{
	int err;

	// Set interception mode to rule filter mode
	uint32_t key = 0;
	uint32_t interception_mode = MODE_RULE_FILTER;
	err = bpf_map__update_elem(
		skel->maps.interception_mode,
		&key,
		sizeof(key),
		&interception_mode,
		sizeof(interception_mode),
		BPF_ANY
	);
	if (err)
	{
		std::cerr << "Failed to set interception mode: " << err << std::endl;
		return false;
	}

	// Set filter rules to BPF map
	err = bpf_map__update_elem(
		skel->maps.filter_rules,
		&key,
		sizeof(key),
		&rule,
		sizeof(rule),
		BPF_ANY
	);
	if (err)
	{
		std::cerr << "Failed to set filter rules: " << err << std::endl;
		return false;
	}

	return true;
}

// Load and attach BPF program
static bool setup_bpf_program(struct signal_filter_bpf **skel)
{
	int err;

	*skel = signal_filter_bpf__open();
	if (!*skel)
	{
		std::cerr << "Failed to open BPF skeleton" << std::endl;
		return false;
	}

	err = signal_filter_bpf__load(*skel);
	if (err)
	{
		std::cerr << "Failed to load BPF skeleton: " << err << std::endl;
		signal_filter_bpf__destroy(*skel);
		return false;
	}

	err = signal_filter_bpf__attach(*skel);
	if (err)
	{
		std::cerr << "Failed to attach BPF skeleton: " << err << std::endl;
		signal_filter_bpf__destroy(*skel);
		return false;
	}

	return true;
}

// Setup ring buffer for event communication
static bool
setup_ring_buffer(struct signal_filter_bpf *skel, struct ring_buffer **rb)
{
	*rb = ring_buffer__new(
		bpf_map__fd(skel->maps.ringbuf),
		handle_all_event,
		nullptr,
		nullptr
	);
	if (!*rb)
	{
		std::cerr << "Failed to create ring buffer" << std::endl;
		return false;
	}
	return true;
}

// Print startup information and usage instructions
static void print_startup_info()
{
	std::cout << "=== eBPF Signal Filter Started ===" << std::endl;
	std::cout << "Press Ctrl+C to stop filter" << std::endl;
	std::cout << std::endl;

	std::cout << "Mode: Rule-based Intercept Mode" << std::endl;
	std::cout << "Rule Logic: All rules must be satisfied to intercept signals"
			  << std::endl;
	std::cout << "Default Behavior: Allow all signals when no rules are set"
			  << std::endl;
	std::cout << std::endl;

	std::cout << "Features:" << std::endl;
	std::cout << "  - Real-time signal monitoring and logging" << std::endl;
	std::cout << "  - Rule-based signal interception" << std::endl;
	std::cout << "  - Multiple filter criteria support (PID, UID, Signal)"
			  << std::endl;
	std::cout << std::endl;
	std::cout << "SIGNAL TRACING:" << std::endl;
	std::cout << "TIME      SENDER           S-COMM             RCVER          "
				 " R-COMM             SIGNAL             RESULT        LATENCY"
			  << std::endl;
	std::cout << std::endl;
	std::cout << "SIGNAL INTERCEPTION:" << std::endl;
	std::cout << "TIME      TARGET_PID       TARGET_COMM        SIGNAL         "
				 " ACTION"
			  << std::endl;
	std::cout << std::endl;
}

// Set resource limits for BPF operations
static bool setup_resource_limits()
{
	struct rlimit rlim = {
		.rlim_cur = 512UL << 20,
		.rlim_max = 512UL << 20,
	};

	int err = setrlimit(RLIMIT_MEMLOCK, &rlim);
	if (err)
	{
		std::cerr << "Failed to set rlimit: " << strerror(errno) << std::endl;
		return false;
	}
	return true;
}

// Cleanup resources on program exit
static void
cleanup_resources(struct ring_buffer *rb, struct signal_filter_bpf *skel)
{
	std::cout << "Cleaning up resources..." << std::endl;

	// Reset global state
	running = false;
	rule = {0};

	// Cleanup BPF resources
	if (rb)
	{
		ring_buffer__free(rb);
	}
	if (skel)
	{
		signal_filter_bpf__destroy(skel);
	}

	std::cout << "Signal filter stopped" << std::endl;
}

// Initialize signal filter components
static bool initialize_signal_filter()
{
	if (!setup_resource_limits())
	{
		return false;
	}

	if (!setup_bpf_program(&skel))
	{
		return false;
	}

	if (!setup_bpf_maps(skel))
	{
		signal_filter_bpf__destroy(skel);
		return false;
	}

	if (!setup_ring_buffer(skel, &rb))
	{
		signal_filter_bpf__destroy(skel);
		return false;
	}

	return true;
}

// Main event processing loop
static void run_event_loop()
{
	while (running)
	{
		int err = ring_buffer__poll(rb, 100);
		if (err < 0)
		{
			if (err == -EINTR)
			{
				break;
			}
			std::cerr << "Error polling ring buffer: " << err << std::endl;
			break;
		}
	}
}

/**
 * @brief 主函数 - 信号过滤器程序入口点
 * @param argc 命令行参数个数
 * @param args 命令行参数数组
 * @return 程序退出状态，0表示成功，1表示失败
 */
int main(int argc, char *args[])
{
	// Check root privileges
	if (!check_privileges())
	{
		return 1;
	}

	parse_args(argc, args);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	if (!initialize_signal_filter())
	{
		return 1;
	}

	print_startup_info();
	run_event_loop();
	cleanup_resources(rb, skel);

	return 0;
}