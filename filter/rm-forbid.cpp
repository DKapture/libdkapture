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
#include <uuid/uuid.h>

#include "rm-forbid.skel.h"
#include "Ucom.h"
#include "jhash.h"

struct Rule
{
	uuid_t dev_uuid;
	u64 inode;
} rule;

static rm_forbid_bpf *obj;
static int filter_fd;
static std::atomic<bool> exit_flag(false);

static struct option lopts[] = {
	{"path",	 required_argument, 0, 'p'},
	{"uuid",	 required_argument, 0, 'u'},
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
	{"[path]",  "path of the file to watch on\n"		   },
	{"[uuid]",
	 "the uuid of filesystem to which the inode belong.\n"
	 "\tyou can get the uuid by running command 'blkid'\n"},
	{"[inode]", "inode of the file to watch on\n"		 },
	{"",		 "print this help message\n"				},
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

static void get_fs_uuid(const char *path, char *uuid, size_t uuid_size)
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

	char dev_path[PATH_MAX];
	snprintf(
		dev_path,
		sizeof(dev_path),
		"/dev/block/%u:%u",
		(u32)(st.st_dev >> 8),
		(u32)(st.st_dev & 0xff)
	);

	struct stat tstat = {};
	if (stat(dev_path, &tstat) != 0)
	{
		pr_error("stat %s: %s\n", dev_path, strerror(errno));
		exit(EXIT_FAILURE);
	}

	DIR *dir = opendir("/dev/disk/by-uuid");
	if (!dir)
	{
		pr_error("opendir /dev/disk/by-uuid: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL)
	{
		char link_path[PATH_MAX];
		snprintf(
			link_path,
			sizeof(link_path),
			"/dev/disk/by-uuid/%s",
			entry->d_name
		);

		struct stat vstat = {};
		if (stat(link_path, &vstat) != 0)
		{
			pr_error("stat %s: %s\n", link_path, strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (memcmp(&tstat.st_rdev, &vstat.st_rdev, sizeof(dev_t)) != 0)
		{
			continue;
		}

		strncpy(uuid, entry->d_name, uuid_size);
		uuid[uuid_size - 1] = 0;
		printf("UUID of device %s is %s\n", dev_path, uuid);
		closedir(dir);
		return;
	}

	closedir(dir);
	fprintf(stderr, "UUID not found for device %s\n", dev_path);
	exit(EXIT_FAILURE);
}

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
			char dev_uuid[UUID_STR_LEN] = {0};
			get_fs_uuid(optarg, (char *)&dev_uuid, sizeof(dev_uuid));
			optarg = dev_uuid;
			fallthrough;
		}
		case 'u':
			if (uuid_parse(optarg, rule.dev_uuid) == -1)
			{
				printf("uuid format pr_error\n");
				exit(-1);
			}
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