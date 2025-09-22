/**
 * @file elfverify.cpp
 * @brief ELF可执行文件验证和访问控制系统
 *
 * 该程序实现了基于eBPF的可执行文件访问控制系统，防止执行来自不可信源的应用程序。
 * 通过LSM hook机制拦截mmap和execve系统调用，根据预设的白名单策略来控制用户
 * 对特定可执行文件的执行权限。支持基于文件路径和用户ID的访问控制规则。
 *
 * 主要功能：
 * - 拦截可执行文件的映射和执行操作
 * - 支持基于文件路径的白名单控制
 * - 支持基于用户ID的访问权限控制
 * - 实时日志记录和事件上报
 * - 递归目录权限继承
 *
 * @version 1.0
 */

#include "log.h"
#include <cstdint>
#include <stdio.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <getopt.h>
#include <sys/stat.h>
#include <vector>
#include <thread>
#include <atomic>
#include <dirent.h>
#include <pwd.h>
#include "com.h"

#include "elfverify.skel.h"

/** @brief BPF程序对象指针 */
static elfverify_bpf *obj;

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
 * 用于唯一标识文件系统中的一个文件，通过设备号和inode号组合。
 */
struct Target
{
	uint32_t dev; /**< 设备号 */
	ino_t ino;	  /**< inode号 */
};

/**
 * @brief 访问控制规则结构
 *
 * 定义了一条访问控制规则，支持两种类型：基于文件目标的规则和基于用户ID的规则。
 * 使用union结构来节省内存空间。
 */
struct Rule
{
	union
	{
		struct Target target; /**< 文件目标标识 */
		struct
		{
			int not_uid; /**< 标志位，0表示使用用户ID规则 */
			uid_t uid;	 /**< 用户ID */
		};
	};
};

/**
 * @brief BPF程序日志数据结构
 *
 * 用于从eBPF程序向用户空间传递违规访问的日志信息。
 */
struct BpfData
{
	uid_t uid;	   /**< 违规用户的ID */
	pid_t pid;	   /**< 违规进程的PID */
	int is_binary; /**< 标志位，1表示二进制文件，0表示脚本文件 */
	struct Target target; /**< 目标文件标识 */
};

static char line[8192];
static int whitelist_fd;
static int log_map_fd;
static struct ring_buffer *rb = NULL;
static std::atomic<bool> exit_flag(false);
static const char *policy_file = NULL;

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
void Usage(const char *arg0)
{
	printf("Usage: %s [option]\n", arg0);
	printf("  prevent the execution of applications from untrusted sources "
		   "according to the policy file\n\n");
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

/**
 * @brief 解析命令行参数
 *
 * 处理程序的命令行选项，包括策略文件路径和帮助信息。
 * 支持BUILTIN模式用于测试环境。
 *
 * @param argc 参数个数
 * @param argv 参数数组
 * @param output 输出文件指针（仅BUILTIN模式）
 * @return BUILTIN模式下返回解析结果，0表示成功，非0表示失败
 */
#ifdef BUILTIN
int parse_args(int argc, char **argv, FILE *output)
#else
void parse_args(int argc, char **argv)
#endif
{
	int opt, opt_idx;
#ifdef BUILTIN
	optind = 0; // Reset getopt for multiple calls in test mode
	opterr = 0; // Suppress getopt error messages in test mode
#endif
	std::string sopts = long_opt2short_opt(lopts); // Convert long options to
												   // short options
	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) != -1
	)
	{
		switch (opt)
		{
		case 'p': // Policy File
			policy_file = optarg;
			break;
		case 'h': // Help
			Usage(argv[0]);
#ifdef BUILTIN
			if (output)
			{
				fprintf(output, "Help displayed\n");
			}
			return 0; // Success for help
#else
			exit(0);
#endif
			break;
		case '?': // Invalid option (handled by getopt)
		default:  // Invalid option
			Usage(argv[0]);
#ifdef BUILTIN
			if (output)
			{
				fprintf(output, "Invalid option\n");
			}
			return -1; // Error for invalid option
#else
			exit(-1);
#endif
			break;
		}
	}

	if (!policy_file)
	{
		policy_file = "elfverify.pol";
#ifdef BUILTIN
		if (output)
		{
			fprintf(
				output,
				"\nNo policy file specified, use elfverify.pol as default\n\n"
			);
		}
#else
		printf("\nNo policy file specified, use elfverify.pol as default\n\n");
#endif
	}
#ifdef BUILTIN
	return 0; // Success
#endif
}

/**
 * @brief 注册信号处理函数
 *
 * 注册SIGINT信号处理函数，用于优雅地退出程序。
 * 当接收到Ctrl+C信号时，设置退出标志。
 */
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

/**
 * @brief 将文件路径转换为Target结构
 *
 * 获取指定路径文件的设备号和inode号，填充到Target结构中。
 * 在BUILTIN测试模式下，遇到错误时设置虚拟值并继续执行。
 *
 * @param path 文件路径
 * @param target 输出的Target结构指针
 */
static void path2target(const char *path, struct Target *target)
{
	if (access(path, F_OK) == -1)
	{
		pr_error("file %s: %s", path, strerror(errno));
#ifdef BUILTIN
		// In test mode, set dummy values and continue
		target->ino = 0;
		target->dev = 0;
		return;
#else
		exit(EXIT_FAILURE);
#endif
	}

	struct stat st;
	if (stat(path, &st) != 0)
	{
		pr_error("stat %s: %s", path, strerror(errno));
#ifdef BUILTIN
		// In test mode, set dummy values and continue
		target->ino = 0;
		target->dev = 0;
		return;
#else
		exit(EXIT_FAILURE);
#endif
	}

	target->ino = st.st_ino;
	target->dev = dev_old2new(st.st_dev);
	// pr_info("Add file: %x %lu", target->dev, target->ino);
}

/**
 * @brief 递归添加目录及其子目录的保护规则
 *
 * 遍历指定目录下的所有子目录和文件，为每个条目创建对应的访问控制规则。
 * 跳过符号链接以避免循环引用问题。
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
			pr_error("Cannot lstat %s: %s", full_path, strerror(errno));
			continue;
		}

		if (S_ISLNK(st.st_mode))
		{
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
 * @brief 将用户名转换为用户ID
 *
 * 通过getpwnam系统调用将用户名字符串转换为对应的用户ID。
 * 在BUILTIN测试模式下，查找失败时设置默认UID并继续执行。
 *
 * @param user 用户名字符串
 * @param uid 输出的用户ID指针
 */
static void user2uid(const char *user, uid_t *uid)
{
	struct passwd *pw = getpwnam(user);
	if (pw)
	{
		*uid = pw->pw_uid;
	}
	else
	{
#ifdef BUILTIN
		// In test mode, set dummy uid and continue
		*uid = 1000;
		return;
#else
		exit(EXIT_FAILURE);
#endif
	}
}

/**
 * @brief 解析策略配置文件
 *
 * 读取并解析策略文件，将其中的规则转换为Rule结构并添加到规则列表中。
 * 支持两种类型的规则：
 * - path=<路径>：基于文件路径的规则
 * - user=<用户名>：基于用户的规则
 *
 * @param filename 策略文件路径
 * @return 解析后的规则列表
 */
std::vector<struct Rule> parse_policy_file(const char *filename)
{
	std::vector<struct Rule> rules;
	FILE *file = fopen(filename, "r");
	if (!file)
	{
		pr_error("fopen: %s: %s", strerror(errno), filename);
#ifdef BUILTIN
		// In test mode, return empty rules and continue
		return rules;
#else
		exit(EXIT_FAILURE);
#endif
	}

	while (fgets(line, sizeof(line), file))
	{
		char type[5];
		char content[4096];

		if (line[0] == '#')
		{
			continue;
		}

		if (sscanf(line, "%4[^=]=%4095s", type, content) != 2)
		{
			pr_error("Invalid line: %s", line);
			continue;
		}
		struct Rule rule = {0};

		if (strcmp(type, "path") == 0)
		{
			struct stat st;
			if (stat(content, &st) != 0)
			{
				pr_error("Cannot access path %s: %s", content, strerror(errno));
				continue;
			}
			if (S_ISDIR(st.st_mode))
			{
				add_directories_recursively(content, &rule, rules);
			}
			else
			{
				path2target(content, &rule.target);
				rules.emplace_back(rule);
			}
		}
		else if (strcmp(type, "user") == 0)
		{
			user2uid(content, &rule.uid);
			rules.emplace_back(rule);
		}

		pr_info("Rule: %s %s", type, content);
	}
	fclose(file);
	return rules;
}

/**
 * @brief 将规则加载到BPF映射中
 *
 * 将解析好的规则列表写入到eBPF程序的whitelist映射中，供内核态程序使用。
 * 在BUILTIN测试模式下，映射更新失败时继续执行而不退出。
 *
 * @param rules 要加载的规则列表
 */
void load_rules(const std::vector<struct Rule> &rules)
{
	uint32_t key = 0;
	for (const auto &rule : rules)
	{
		key++;
		if (bpf_map_update_elem(whitelist_fd, &key, &rule, BPF_ANY) != 0)
		{
			perror("bpf_map_update_elem");
#ifdef BUILTIN
			// In test mode, continue on map update failure
			continue;
#else
			exit(EXIT_FAILURE);
#endif
		}
	}
}

/**
 * @brief 处理来自eBPF程序的事件
 *
 * 处理通过ring buffer从eBPF程序传递上来的违规访问事件，
 * 解析事件数据并记录日志。
 *
 * @param ctx 上下文指针（未使用）
 * @param data 事件数据指针
 * @param data_sz 数据大小
 * @return 0表示成功处理
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct BpfData *log = (const struct BpfData *)data; // Cast data to
															  // BpfData
															  // structure
	pr_info(
		"process %d of user %d tried to execve %s file "
		"(dev: %x, ino: %lu), denied!",
		log->pid,
		log->uid,
		log->is_binary ? "binary" : "script",
		log->target.dev,
		log->target.ino
	);
	return 0;
}

/**
 * @brief Ring buffer工作线程函数
 *
 * 持续轮询ring buffer，处理来自eBPF程序的事件。
 * 该函数在独立线程中运行，直到接收到退出信号。
 */
static void ringbuf_worker(void)
{
	while (!exit_flag)
	{
		int err = ring_buffer__poll(rb, 1000 /* timeout in ms */);
		// Check for errors during polling
		if (err < 0 && err != -EINTR)
		{
			pr_error("Error polling ring buffer: %d", err);
			sleep(5); // Sleep before retrying
		}
	}
}

/**
 * @brief 主函数 - 程序入口点
 *
 * 初始化并运行ELF文件验证和访问控制系统。完成以下工作：
 * 1. 解析命令行参数
 * 2. 注册信号处理
 * 3. 加载并附加eBPF程序
 * 4. 解析策略文件并加载规则
 * 5. 启动事件监控循环
 *
 * @param argc 命令行参数个数
 * @param argv 命令行参数数组
 * @param output 输出文件指针（仅BUILTIN模式）
 * @param timeout 超时时间（仅BUILTIN模式）
 * @return 0表示成功，非0表示失败
 */
#ifdef BUILTIN
int elfverify_init(int argc, char **argv, FILE *output, int64_t timeout)
#else
int main(int argc, char **argv)
#endif
{
	std::vector<struct Rule> rules;
	std::thread *rb_thread;

#ifdef BUILTIN
	int parse_result = parse_args(argc, argv, output);
	if (parse_result != 0)
	{
		return parse_result; // Return error code from parse_args
	}
	if (output)
	{
		Log::set_file(output);
	}
	register_signal();
#else
	parse_args(argc, argv);
	register_signal();
#endif

	obj = elfverify_bpf::open_and_load();
	if (!obj)
	{
#ifdef BUILTIN
		return -1;
#else
		exit(-1);
#endif
	}

	whitelist_fd = bpf_get_map_fd(obj->obj, "whitelist", goto err_out);
	log_map_fd = bpf_get_map_fd(obj->obj, "logs", goto err_out);
	rb = ring_buffer__new(log_map_fd, handle_event, NULL, NULL);
	if (!rb)
	{
		goto err_out;
	}
	rules = parse_policy_file(policy_file);
	load_rules(rules);

	pr_info("Program start");
	if (0 != elfverify_bpf::attach(obj))
	{
#ifdef BUILTIN
		goto err_out;
#else
		exit(-1);
#endif
	}

	rb_thread = new std::thread(ringbuf_worker);

#ifdef BUILTIN
	// In test mode, run for limited time
	if (timeout > 0)
	{
		std::this_thread::sleep_for(std::chrono::microseconds(timeout));
		exit_flag = true;
	}
	else
	{
		follow_trace_pipe();
	}
#else
	follow_trace_pipe();
#endif

	rb_thread->join();
	delete rb_thread;

#ifdef BUILTIN
	// In test mode, clean exit
	elfverify_bpf::detach(obj);
	elfverify_bpf::destroy(obj);
	return 0;
#endif

err_out:
	elfverify_bpf::detach(obj);
	elfverify_bpf::destroy(obj);
	return -1;
}