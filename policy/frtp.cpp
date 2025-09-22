/**
 * @file frtp.cpp
 * @brief 文件系统实时保护(File Real-Time Protection)用户空间程序
 *
 * 该程序实现了基于eBPF的文件系统访问控制系统的用户空间部分。
 * 它通过加载和配置eBPF程序来监控和控制进程对特定文件的访问权限，
 * 支持基于进程路径或PID的细粒度访问控制策略。
 *
 * 主要功能:
 * - 解析策略配置文件
 * - 加载eBPF程序到内核
 * - 配置访问控制规则
 * - 实时监控和日志记录违规访问
 *
 * @version 1.0
 */

#include "log.h"
#include <cstdint>
#include <stdio.h>
#include <fcntl.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <getopt.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <vector>
#include <thread>
#include <atomic>
#include <dirent.h>
#include <map>
#include "com.h"

#include "frtp.skel.h"

/** @brief BPF程序对象指针 */
static frtp_bpf *obj;

/** @brief 操作类型定义，用于表示文件访问模式 */
typedef uint32_t Action;

/** @brief 文件读取模式标志 */
#define FMODE_READ (0x1)
/** @brief 文件写入模式标志 */
#define FMODE_WRITE (0x2)
/** @brief 文件执行模式标志 */
#define FMODE_EXEC (0x20)

/**
 * @brief 将旧格式设备号转换为新格式
 *
 * 将传统的dev_t设备号转换为eBPF程序中使用的32位格式。
 * 新格式将主设备号放在高12位，次设备号放在低20位。
 *
 * @param old 旧格式的设备号
 * @return 新格式的32位设备号
 */
static inline uint32_t dev_old2new(dev_t old)
{
	uint32_t major = gnu_dev_major(old);
	uint32_t minor = gnu_dev_minor(old);
	return ((major & 0xfff) << 20) | (minor & 0xfffff);
}

/**
 * @brief 目标文件标识结构
 *
 * 用于唯一标识一个文件系统中的文件，通过设备号和inode号组合。
 */
struct Target
{
	uint32_t dev; /**< 设备号 */
	ino_t ino;	  /**< inode号 */

	bool operator<(const Target &other) const
	{
		if (dev != other.dev)
		{
			return dev < other.dev;
		}
		return ino < other.ino;
	}
};

/**
 * @brief 访问控制规则结构
 *
 * 定义了一条访问控制规则，包含进程标识、操作类型和目标文件。
 * 支持两种进程标识方式：进程路径匹配或具体PID。
 */
struct Rule
{
	union
	{
		struct
		{
			uint32_t not_pid; /**< 标志位，0表示使用PID，1表示使用进程路径 */
			pid_t pid; /**< 进程ID */
		};
		char process[4096]; /**< 进程路径字符串 */
	};
	Action act;			  /**< 禁止的操作类型 */
	struct Target target; /**< 目标文件标识 */
};

/**
 * @brief BPF程序日志数据结构
 *
 * 用于从eBPF程序向用户空间传递违规访问的日志信息。
 */
struct BpfData
{
	Action act; /**< 违规的操作类型 */
	pid_t pid;	/**< 违规进程的PID */
	struct Target target;
	char process[]; /**< 变长字段，包含进程路径,可能包含目标文件名*/
};

char line[8192];
static int filter_fd;
static int log_map_fd;
struct ring_buffer *rb = NULL;
static std::atomic<bool> exit_flag(false);
const char *policy_file = NULL;
static std::map<Target, std::string> target2path_map;

#ifdef BUILTIN
struct FrtpLog
{
	unsigned int act;
	pid_t pid;
	const char *binary;
	const char *target;
};
static std::vector<FrtpLog> *logs;
static FILE *stdout_bak;
#endif

static struct option lopts[] = {
	{"policy-file", required_argument, 0, 'p'},
	{"help",		 no_argument,		  0, 'h'},
	{0,			 0,				 0, 0  }
};

/**
 * @brief 帮助信息结构
 *
 * 用于存储命令行选项的帮助信息。
 */
struct HelpMsg
{
	const char *argparam; /**< 参数说明 */
	const char *msg;	  /**< 帮助信息 */
};

// Help messages
static HelpMsg help_msg[] = {
	{"<policy-file>", "specify the policy file to load policy\n"},
	{"",			  "print this help message\n"				},
};

/**
 * @brief 打印程序使用帮助信息
 *
 * 显示程序的用法、选项和参数说明。
 *
 * @param arg0 程序名称(argv[0])
 */
static void Usage(const char *arg0)
{
	printf("Usage: %s [option]\n", arg0);
	printf("  protect system files from malicious opening according to the "
		   "policy file\n\n");
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

/**
 * @brief 将长选项数组转换为短选项字符串
 *
 * 根据getopt_long使用的选项结构数组，生成getopt使用的短选项字符串格式。
 *
 * @param lopts 长选项数组
 * @return 短选项字符串，格式如"p:h"
 */
static std::string long_opt2short_opt(const option lopts[])
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

/**
 * @brief 解析命令行参数
 *
 * 处理程序的命令行选项，包括策略文件路径和帮助信息。
 *
 * @param argc 参数个数
 * @param argv 参数数组
 * @return 0表示成功，1表示显示帮助后退出，-1表示参数错误
 */
static int parse_args(int argc, char **argv)
{
	int opt, opt_idx;
	optind = 0;
	opterr = 0;
	std::string sopts = long_opt2short_opt(lopts); // Convert long options to
												   // short options
	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0)
	{

		switch (opt)
		{
		case 'p': // Process ID
			policy_file = optarg;
			break;
		case 'h': // Help
			Usage(argv[0]);
			return 1;
		default: // Invalid option
			Usage(argv[0]);
			return -1;
		}
	}

	if (!policy_file)
	{
#ifndef BUILTIN
		policy_file = "/etc/dkapture/policy/frtp.pol";
		pr_info("No policy file specified, use frtp.pol as default");
#else
		pr_error("No policy file specified.");
		return -1;
#endif
	}
	return 0;
}

/**
 * @brief 将操作标志转换为可读字符串
 *
 * 将Action类型的位标志转换为便于显示的字符串格式。
 *
 * @param act 操作标志，可以是FMODE_READ、FMODE_WRITE、FMODE_EXEC的组合
 * @return 操作描述字符串，如"read/write"或"exec"
 */
static std::string act2str(Action act)
{
	std::string str;
	if (act & FMODE_READ)
	{
		str += "read/";
	}
	if (act & FMODE_WRITE)
	{
		str += "write/";
	}
	if (act & FMODE_EXEC)
	{
		str += "exec/";
	}

	if (!str.empty())
	{
		str.pop_back();
	}
	return str;
}

/**
 * @brief 将文件路径转换为Target结构
 *
 * 获取指定路径文件的设备号和inode号，填充到Target结构中。
 *
 * @param path 文件路径
 * @param target 输出的Target结构指针
 * @return 0表示成功，-1表示失败
 */
static int path2target(const char *path, struct Target *target)
{
	if (access(path, F_OK) == -1)
	{
		pr_error("File %s pr_error: %s\n", path, strerror(errno));
		return -1;
	}

	struct stat st;
	if (stat(path, &st) != 0)
	{
		pr_error("stat %s: %s\n", path, strerror(errno));
		return -1;
	}

	target->ino = st.st_ino;
	target->dev = dev_old2new(st.st_dev);
	target2path_map[*target] = path;
	return 0;
}

/**
 * @brief 递归添加目录及其子目录的保护规则
 *
 * 遍历指定目录下的所有子目录，为每个目录创建对应的保护规则。
 * 这用于实现目录级别的访问控制。
 *
 * @param dir_path 目录路径
 * @param base_rule 基础规则模板
 * @param rules 规则列表，新规则将添加到此列表中
 */
static void add_directories_recursively(
	const char *dir_path,
	const struct Rule *base_rule,
	std::vector<struct Rule> &rules
)
{
	struct Rule dir_rule = *base_rule;
	path2target(dir_path, &dir_rule.target);
	rules.emplace_back(dir_rule);

	DIR *dir = opendir(dir_path);
	if (!dir)
	{
		pr_error("Cannot open directory %s: %s", dir_path, strerror(errno));
		return;
	}

	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL)
	{
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
		{
			continue;
		}

		char full_path[PATH_MAX];
		snprintf(
			full_path,
			sizeof(full_path),
			"%s/%s",
			dir_path,
			entry->d_name
		);

		struct stat st;
		if (lstat(full_path, &st) != 0)
		{
			pr_error("Cannot stat %s: %s", full_path, strerror(errno));
			continue;
		}

		if (S_ISDIR(st.st_mode))
		{
			add_directories_recursively(full_path, base_rule, rules);
		}
	}

	closedir(dir);
}

/**
 * @brief 解析策略配置文件
 *
 * 读取并解析策略文件，将其中的规则转换为Rule结构并添加到规则列表中。
 * 策略文件格式: forbid type=identifier action target_path
 *
 * @param filename 策略文件路径
 * @param rules 规则列表，解析的规则将添加到此列表中
 * @return 0表示成功，-1表示失败
 */
static int
parse_policy_file(const char *filename, std::vector<struct Rule> &rules)
{
	FILE *file = fopen(filename, "r");
	if (!file)
	{
		pr_error("fopen: %s: %s\n", strerror(errno), filename);
		return -1;
	}

	char line[8192];
	while (fgets(line, sizeof(line), file))
	{
		char action[21];
		char type[21];
		char identifier[4096];
		char target_path[4096];

		if (line[0] == '#')
		{
			continue;
		}

		if (sscanf(
				line,
				"forbid %20[^=]=%4095s %20s %4095s",
				type,
				identifier,
				action,
				target_path
			) != 4)
		{
			pr_error("Invalid line: %s", line);
			continue;
		}

		struct Rule rule = {0};

		if (strcmp(type, "proc") == 0)
		{
			if (identifier[0] != '/')
			{
				pr_error("Invalid process path: %s", identifier);
				continue;
			}
			strncpy(rule.process, identifier, sizeof(rule.process));
			rule.process[sizeof(rule.process) - 1] = 0;
		}
		else if (strcmp(type, "pid") == 0)
		{
			char *endptr;
			rule.pid = strtol(identifier, &endptr, 10);
			if (*endptr != '\0' || rule.pid < 0)
			{
				pr_error("Invalid PID: %s", identifier);
				continue;
			}
			rule.not_pid = 0;
		}
		else
		{
			pr_error("Invalid type: %s", type);
			continue;
		}

		if (strcmp(action, "r") == 0)
		{
			rule.act = FMODE_READ;
		}
		else if (strcmp(action, "w") == 0)
		{
			rule.act = FMODE_WRITE;
		}
		else if (strcmp(action, "rw") == 0)
		{
			rule.act = FMODE_READ | FMODE_WRITE;
		}
		else
		{
			pr_error("Invalid action: %s", action);
			continue;
		}

		bool is_dir = false;
		size_t path_len = strlen(target_path);

		if (target_path[0] != '/')
		{
			pr_error("Invalid target path: %s", target_path);
			continue;
		}

		if (path_len >= 2 && strcmp(target_path + path_len - 2, "/*") == 0)
		{
			target_path[path_len - 2] = '\0';
			is_dir = true;
		}
		else if (path_len > 1 && target_path[path_len - 1] == '/')
		{
			target_path[path_len - 1] = '\0';
			is_dir = true;
		}

		struct stat st;
		if (stat(target_path, &st) != 0)
		{
			pr_error("Cannot access path %s: %s", target_path, strerror(errno));
			continue;
		}

		if (is_dir)
		{
			if (S_ISDIR(st.st_mode))
			{
				pr_info(
					"Rule (diretory): %s %s %s %s",
					type,
					identifier,
					action,
					target_path
				);
				add_directories_recursively(target_path, &rule, rules);
			}
			else
			{
				pr_error(
					"Path %s with wildcard is not a directory",
					target_path
				);
				continue;
			}
		}
		else
		{
			if (S_ISREG(st.st_mode))
			{
				path2target(target_path, &rule.target);
				rules.emplace_back(rule);
				pr_info(
					"Rule (regular file): %s %s %s %s",
					type,
					identifier,
					action,
					target_path
				);
			}
			else
			{
				pr_error("Path %s is not a regular file", target_path);
				continue;
			}
		}
	}

	fclose(file);
	return 0;
}

/**
 * @brief 将规则加载到BPF映射中
 *
 * 将解析好的规则列表写入到eBPF程序的filter映射中，供内核态程序使用。
 *
 * @param rules 要加载的规则列表
 * @return 0表示成功，-1表示失败
 */
static int load_rules(const std::vector<struct Rule> &rules)
{
	uint32_t key = 0;
	for (const auto &rule : rules)
	{
		key++;
		if (bpf_map_update_elem(filter_fd, &key, &rule, BPF_ANY) != 0)
		{
			perror("bpf_map_update_elem");
			return -1;
		}
	}
	return 0;
}

/**
 * @brief 处理来自eBPF程序的事件
 *
 * 处理通过ring buffer从eBPF程序传递上来的违规访问事件，
 * 解析事件数据并记录日志。
 *
 * @param ctx 上下文指针(未使用)
 * @param data 事件数据指针
 * @param data_sz 数据大小
 * @return 0表示成功处理
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct BpfData *log = (const struct BpfData *)data; // Cast data to
															  // BpfData
															  // structure
	size_t plen = strlen(log->process);
	const char *fname = log->process + plen + 1;
	std::string target_path =
		target2path_map[log->target] +
		(std::string(fname).length() > 0 ? std::string("/") + fname : "");
	pr_warn(
		"[%s]!!!: %s[%d] tried to %s %s, denied!",
		get_time().c_str(),
		log->process,
		log->pid,
		act2str(log->act).c_str(),
		target_path.length() > 0 ? target_path.c_str() : "<no matched>"
	);
	return 0;
}

/**
 * @brief Ring buffer工作线程函数
 *
 * 持续轮询ring buffer，处理来自eBPF程序的事件。
 * 该函数在独立线程中运行，直到接收到退出信号。
 */
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

/**
 * @brief 注册信号处理函数
 *
 * 注册SIGINT信号处理函数，用于优雅地退出程序。
 * 当接收到Ctrl+C信号时，设置退出标志。
 *
 * @return 0表示成功，-1表示失败
 */
static int register_signal()
{
	struct sigaction sa;
	sa.sa_handler = [](int) { exit_flag = true; }; // Set exit flag on signal
	sa.sa_flags = 0;							   // No special flags
	sigemptyset(&sa.sa_mask); // No additional signals to block
	// Register the signal handler for SIGINT
	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		perror("sigaction");
		return -1;
	}
	return 0;
}

#ifdef BUILTIN
void frtp_init(FILE *output, std::vector<FrtpLog> *v)
{
	logs = v;
	target2path_map.clear();
	exit_flag = false;
	rb = NULL;
	policy_file = NULL;
	stdout_bak = stdout;
	fflush(stdout);
	stdout = output;
	Log::set_file(output);
}

void frtp_deinit()
{
	fflush(stdout);
	stdout = stdout_bak;
	Log::set_file(stderr);
}
#endif

/**
 * @brief 主函数 - 程序入口点
 *
 * 初始化并运行文件系统实时保护系统。完成以下工作：
 * 1. 解析命令行参数
 * 2. 注册信号处理
 * 3. 加载并附加eBPF程序
 * 4. 解析策略文件并加载规则
 * 5. 启动事件监控循环
 *
 * @param argc 命令行参数个数
 * @param argv 命令行参数数组
 * @param output 输出文件指针(仅BUILTIN模式)
 * @param timeout 超时时间(仅BUILTIN模式)
 * @return 0表示成功，非0表示失败
 */
#ifdef BUILTIN
int frtp_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
{
	std::vector<struct Rule> rules;
	std::thread *rb_thread;
	int ret = parse_args(argc, argv);
	if (ret > 0)
	{
		return 0;
	}
	else if (ret < 0)
	{
		return ret;
	}

#ifndef BUILTIN
	ret = register_signal();
	if (ret < 0)
	{
		return ret;
	}
#endif

	obj = frtp_bpf::open_and_load();
	if (!obj)
	{
		return -1;
	}

	filter_fd = bpf_get_map_fd(obj->obj, "filter", goto out_destroy);

	log_map_fd = bpf_get_map_fd(obj->obj, "logs", goto out_destroy);

	if (0 != frtp_bpf::attach(obj))
	{
		ret = -1;
		goto out_destroy;
	}

#ifndef BUILTIN
	rb = ring_buffer__new(log_map_fd, handle_event, NULL, NULL);
#else
	rb = ring_buffer__new(log_map_fd, handle_event, logs, NULL);
#endif
	if (!rb)
	{
		ret = -1;
		goto out_detach;
	}

	ret = parse_policy_file(policy_file, rules);
	if (ret)
	{
		goto out_detach;
	}

	ret = load_rules(rules);
	if (ret)
	{
		goto out_detach;
	}

	rb_thread = new std::thread(ringbuf_worker);
#ifndef BUILTIN
	follow_trace_pipe();
#else
	std::this_thread::sleep_for(std::chrono::microseconds(logs->size() * 10));
	exit_flag = true;
#endif
	rb_thread->join();
	delete rb_thread;

out_detach:
	frtp_bpf::detach(obj); // Detach BPF program
out_destroy:
	frtp_bpf::destroy(obj); // Clean up BPF object
	return ret;
}