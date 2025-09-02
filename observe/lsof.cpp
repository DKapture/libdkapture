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
#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <algorithm>
#include <pthread.h>
#include <map>
#include <sys/sysmacros.h> // 添加这个头文件用于设备号操作

#include "lsof.skel.h"
#include "Ucom.h"
#include "jhash.h"

#define PAGE_SIZE 4096

// 添加设备号转换函数，参考frtp
static inline uint32_t dev_old2new(dev_t old)
{
	uint32_t major = gnu_dev_major(old);
	uint32_t minor = gnu_dev_minor(old);
	return ((major & 0xfff) << 20) | (minor & 0xfffff);
}

union Rule
{
	char path[PAGE_SIZE];
	struct
	{
		u64 not_inode; // used for judging whether it's inode filter
		u64 inode;
		dev_t dev; // 设备号
	};
} rule;

struct BpfData
{
	uid_t uid;
	pid_t pid;
	int fd;
	char comm[16];
};

static lsof_bpf *obj;
static int log_map_fd;
struct ring_buffer *rb = NULL;
static int filter_fd;
static pthread_t t1;
static int iter_fd;
static std::atomic<bool> exit_flag(false);
static std::map<pid_t, std::vector<struct BpfData>> log_stat;

static struct option lopts[] = {
	{"path",	 required_argument, 0, 'p'},
	{"dev",	required_argument, 0, 'd'},
	{"inode", required_argument, 0, 'i'},
	{"help",	 no_argument,		  0, 'h'},
	{0,		0,				 0, 0  }
};

struct HelpMsg
{
	const char *argparam;
	const char *msg;
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

void parse_args(int argc, char *args[])
{
	int opt, opt_idx;
	int optbits = 0;
	optind = 1;
	std::string sopts = long_opt2short_opt(lopts);
	while ((opt = getopt_long(argc, args, sopts.c_str(), lopts, &opt_idx)) > 0)
	{
		switch (opt)
		{
		case 'p':
			strncpy(rule.path, optarg, sizeof(rule.path));
			rule.path[sizeof(rule.path) - 1] = 0;
			optbits |= 1;
			break;
		case 'd':
			rule.dev = strtoul(optarg, NULL, 10); // 直接解析设备号
			rule.not_inode = 0;
			optbits |= 1 << 1;
			break;
		case 'i':
			rule.inode = atoi(optarg);
			rule.not_inode = 0;
			optbits |= 1 << 2;
			break;
		case 'h':
			Usage(args[0]);
			exit(0);
			break;
		default:
			Usage(args[0]);
			exit(-1);
			break;
		}
	}

	if ((optbits & 1) && (optbits & 4))
	{
		printf("error: -p and -i can't be used together\n");
		exit(-1);
	}

	if (!!(optbits & 2) ^ !!(optbits & 4))
	{
		printf("error: -d and -i must be used together\n"); // 更新错误信息
		exit(-1);
	}

	if (rule.path[0] == 0 && rule.inode == 0)
	{
		printf("\nYou need to specify a file path or file inode number to\n"
			   "watch on by the options -p(--path) or -i(--inode)\n\n");
		exit(-1);
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct BpfData *log = (const struct BpfData *)data;
	u64 key = log->pid;
	log_stat[key].push_back(*log);
	return 0;
}

static void summary_print(void)
{
	printf("%16s %6s %8s   %s\n", "COMM", "UID", "PID", "FD");
	printf("--------------------------------------------\n");
	for (auto &it : log_stat)
	{
		std::vector<struct BpfData> &logs = it.second;
		pid_t pid = it.first;
		uid_t uid = logs[0].uid;
		char *comm = logs[0].comm;
		printf("%16s %6d %8d   ", comm, uid, pid);
		size_t vma_cnt = 0;
		for (auto &log : logs)
		{
			if (log.fd == -1)
			{
				vma_cnt++;
			}
			else
			{
				printf("%d ", log.fd);
			}
		}
		if (vma_cnt)
		{
			printf("vma(%ld)\n", vma_cnt);
		}
		else
		{
			printf("\n");
		}
	}
	printf("\n");
}

void *ringbuf_worker(void *)
{
	while (!exit_flag)
	{
		int err = ring_buffer__poll(rb, 100 /* timeout in ms */);

		if (err < 0 && err != -EINTR)
		{
			pr_error("Error polling ring buffer: %d\n", err);
			sleep(5);
		}

		if (err == 0 && iter_fd == -1)
		{
			break;
		}
	}
	stop_trace();
	kill(getpid(), SIGINT);
	return NULL;
}

void register_signal()
{
	struct sigaction sa;
	sa.sa_handler = [](int) { exit_flag = true; };
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		perror("sigaction");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *args[])
{
	ssize_t rd_sz = 0;
	char buf[PATH_MAX] = {0};

	parse_args(argc, args);
	register_signal();

	int key = 0;
	obj = lsof_bpf::open_and_load();
	if (!obj)
	{
		exit(-1);
	}

	if (0 != lsof_bpf::attach(obj))
	{
		exit(-1);
	}

	filter_fd = bpf_get_map_fd(obj->obj, "filter", goto err_out);

	if (0 != bpf_map_update_elem(filter_fd, &key, &rule, BPF_ANY))
	{
		printf("Error: bpf_map_update_elem");
		goto err_out;
	}

	log_map_fd = bpf_get_map_fd(obj->obj, "logs", goto err_out);
	rb = ring_buffer__new(log_map_fd, handle_event, NULL, NULL);
	if (!rb)
	{
		goto err_out;
	}

	iter_fd = bpf_iter_create(bpf_link__fd(obj->links.file_iterator));
	if (iter_fd < 0)
	{
		fprintf(stderr, "Error creating BPF iterator\n");
		goto err_out;
	}

	while ((rd_sz = read(iter_fd, buf, sizeof(buf))) > 0)
	{
	}

	close(iter_fd);
	iter_fd = bpf_iter_create(bpf_link__fd(obj->links.vma_iterator));
	if (iter_fd < 0)
	{
		fprintf(stderr, "Error creating BPF iterator\n");
		goto err_out;
	}

	while ((rd_sz = read(iter_fd, buf, sizeof(buf))) > 0)
	{
	}

	close(iter_fd);
	iter_fd = -1;

	printf("Scanning for file %s...\n", rule.path);
	pthread_create(&t1, NULL, ringbuf_worker, NULL);
	follow_trace_pipe();
	pthread_join(t1, NULL);
	summary_print();

err_out:
	if (rb)
	{
		ring_buffer__free(rb);
	}
	lsof_bpf::detach(obj);
	lsof_bpf::destroy(obj);
	return 0;
}