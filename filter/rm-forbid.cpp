#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
#include <limits.h>
#include <getopt.h>
#include <string>
#include <signal.h>
#include <atomic>
#include <vector>
#include <algorithm>
#include <pthread.h>
#include <map>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/sysmacros.h> // 添加这个头文件用于设备号操作

#include "rm-forbid.skel.h"
#include "Ucom.h"
#include "jhash.h"

/**
 * @brief 设备号转换函数，参考frtp
 * 将旧的设备号格式转换为新格式
 * @param old 旧格式的设备号
 * @return 新格式的设备号
 */
static inline uint32_t dev_old2new(dev_t old)
{
	uint32_t major = gnu_dev_major(old);
	uint32_t minor = gnu_dev_minor(old);
	return ((major & 0xfff) << 20) | (minor & 0xfffff);
}

/**
 * @brief 禁止删除规则结构体
 * 定义要保护的文件的设备号和inode
 */
struct Rule
{
	dev_t dev; ///< 设备号
	u64 inode; ///< inode编号
} rule;

static rm_forbid_bpf *obj;
static int filter_fd;
static std::atomic<bool> exit_flag(false);

static struct option lopts[] = {
	{"path",	 required_argument, 0, 'p'},
	{"dev",	required_argument, 0, 'd'},
	{"inode", required_argument, 0, 'i'},
	{"help",	 no_argument,		  0, 'h'},
	{0,		0,				 0, 0  }
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

static HelpMsg help_msg[] = {
	{"[path]",  "path of the file to watch on\n"					   },
	{"[dev]",
	 "the device number of filesystem to which the inode belong.\n"
	 "\tyou can get the dev by running command 'stat -c %d <file>'\n"
	}, // 更新帮助信息
	{"[inode]", "inode of the file to watch on\n"					 },
	{"",		 "print this help message\n"							},
};

/**
 * @brief 打印程序使用说明
 * @param arg0 程序名称
 */
void Usage(const char *arg0)
{
	printf("Usage: %s [option]\n", arg0);
	printf("  To query who are occupying the specified file.\n\n");
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
 * @brief 将长选项转换为短选项字符串
 * @param lopts 长选项数组
 * @return 短选项字符串
 */
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
			DIE("Code internal bug!!!\n");
			abort();
		}
	}
	return sopts;
}

/**
 * @brief 获取文件系统设备号
 * @param path 文件路径
 * @param dev 输出参数，存储设备号
 */
static void get_fs_dev(const char *path, dev_t *dev)
{
	if (access(path, F_OK) == -1)
	{
		pr_error("File %s pr_error: %s\n", path, strerror(errno));
		exit(EXIT_FAILURE);
	}
	struct stat st;
	if (stat(path, &st) != 0)
	{
		pr_error("stat %s: %s\n", path, strerror(errno));
		exit(EXIT_FAILURE);
	}

	*dev = st.st_dev;
	printf("Device number of %s is %lu\n", path, (unsigned long)*dev);
}

/**
 * @brief 解析命令行参数
 * @param argc 参数个数
 * @param argv 参数数组
 */
void parse_args(int argc, char **argv)
{
	int opt, opt_idx;
	optind = 1;
	std::string sopts = long_opt2short_opt(lopts);
	while ((opt = getopt_long(argc, argv, sopts.c_str(), lopts, &opt_idx)) > 0)
	{
		switch (opt)
		{
		case 'p':
		{
			dev_t fs_dev;
			get_fs_dev(optarg, &fs_dev);
			rule.dev = fs_dev;
			break;
		}
		case 'd':
			rule.dev = strtoul(optarg, NULL, 10); // 直接解析设备号
			break;
		case 'i':
			rule.inode = atoi(optarg);
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
}

/**
 * @brief 注册信号处理函数
 * 注册SIGINT信号的处理函数，用于优雅退出程序
 */
void register_signal()
{
	struct sigaction sa;
	sa.sa_handler = [](int)
	{
		exit_flag = true;
		stop_trace();
	};
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		perror("sigaction");
		exit(EXIT_FAILURE);
	}
}

/**
 * @brief 主函数 - 禁止删除文件监控程序入口点
 * @param argc 命令行参数个数
 * @param args 命令行参数数组
 * @return 程序退出状态，0表示成功，-1表示失败
 */
int main(int argc, char *args[])
{
	int key = 0;
	parse_args(argc, args);
	register_signal();

	obj = rm_forbid_bpf::open_and_load();
	if (!obj)
	{
		exit(-1);
	}

	if (0 != rm_forbid_bpf::attach(obj))
	{
		exit(-1);
	}

	filter_fd = bpf_get_map_fd(obj->obj, "filter", goto err_out);

	if (0 != bpf_map_update_elem(filter_fd, &key, &rule, BPF_ANY))
	{
		printf("Error: bpf_map_update_elem");
		goto err_out;
	}

	follow_trace_pipe();

err_out:
	rm_forbid_bpf::detach(obj);
	rm_forbid_bpf::destroy(obj);
	return 0;
}