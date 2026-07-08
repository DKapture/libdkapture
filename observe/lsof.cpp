// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <argp.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "dkapture.h"

struct FileKey
{
	dev_t dev;
	unsigned long inode;

	bool operator<(const FileKey &other) const
	{
		if (dev != other.dev)
		{
			return dev < other.dev;
		}
		return inode < other.inode;
	}
};

enum QueryMode
{
	QUERY_NONE,
	QUERY_SINGLE_OBJECT,
	QUERY_FS_DEV,
	QUERY_DIR_CHILDREN,
};

struct Rule
{
	char path[PATH_MAX];
	char dir_path[PATH_MAX];
	unsigned long long inode;
	dev_t dev;
	QueryMode mode;
} rule = {
	.path = {0},
	.dir_path = {0},
	.inode = 0,
	.dev = 0,
	.mode = QUERY_NONE,
};

struct LsofEntry
{
	uid_t uid = 0;
	pid_t pid = 0;
	std::string comm;
	std::vector<int> fds;
	size_t vma_cnt = 0;
};

static std::map<pid_t, LsofEntry> log_stat;
static std::map<pid_t, uid_t> uid_stat;
static std::set<FileKey> dir_children;

static struct option lopts[] = {
	{"path", required_argument, 0, 'p'},
	{"dev", required_argument, 0, 'd'},
	{"inode", required_argument, 0, 'i'},
	{"fs-dev", required_argument, 0, 1000},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

struct HelpMsg
{
	const char *argparam;
	const char *msg;
};

static HelpMsg help_msg[] = {
	{"[path]",
	 "path of the target object.\n"
	 "\tThe path is resolved by stat(2) and matched by (dev,inode).\n"
	 "\tThis queries one filesystem object only.\n"},
	{"[dev]",
	 "the device number of filesystem to which the inode belong.\n"
	 "\tyou can get the dev by running command 'stat -c %d <file>'\n"},
	{"[inode]", "inode of the file to watch on\n"},
	{"[dev]",
	 "match all file objects on the specified filesystem device.\n"},
	{"", "print this help message\n"},
};

static void Usage(const char *arg0)
{
	printf("Usage: %s [option]\n", arg0);
	printf("  To query who are occupying the specified file.\n\n");
	printf("Query modes:\n");
	printf("  -p <path>      match one filesystem object by stat(2)\n");
	printf("  -d <dev> -i <inode>\n");
	printf("                 match one filesystem object by (dev,inode)\n");
	printf("      --fs-dev <dev>\n");
	printf("                 match all objects on one filesystem device\n");
	printf("  +d <dir>       match direct children of one directory only\n\n");
	printf("Options:\n");
	for (int i = 0; lopts[i].name; i++)
	{
		if (lopts[i].val > 0 && lopts[i].val < 128)
		{
			printf(
				"  -%c, --%s %s\n\t%s\n",
				lopts[i].val,
				lopts[i].name,
				help_msg[i].argparam,
				help_msg[i].msg
			);
		}
		else
		{
			printf(
				"      --%s %s\n\t%s\n",
				lopts[i].name,
				help_msg[i].argparam,
				help_msg[i].msg
			);
		}
	}
	printf("  +d [dir]\n\tmatch direct children of one directory only\n");
}

static std::string long_opt2short_opt(const option lopts[])
{
	std::string sopts;
	for (int i = 0; lopts[i].name; i++)
	{
		if (lopts[i].val > 0 && lopts[i].val < 128)
		{
			sopts += static_cast<char>(lopts[i].val);
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
				fprintf(stderr, "Code internal bug\n");
				abort();
			}
		}
	}
	return sopts;
}

static int resolve_path_rule(void)
{
	struct stat st = {};
	if (stat(rule.path, &st) != 0)
	{
		return -errno;
	}

	rule.dev = st.st_dev;
	rule.inode = st.st_ino;
	return 0;
}

static int collect_dir_children(const char *path)
{
	struct stat st = {};
	if (stat(path, &st) != 0)
	{
		return -errno;
	}
	if (!S_ISDIR(st.st_mode))
	{
		return -ENOTDIR;
	}

	DIR *dir = opendir(path);
	if (!dir)
	{
		return -errno;
	}

	dir_children.clear();
	const int dfd = dirfd(dir);
	struct dirent *ent;
	while ((ent = readdir(dir)) != nullptr)
	{
		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
		{
			continue;
		}

		struct stat child_st = {};
		if (fstatat(dfd, ent->d_name, &child_st, 0) != 0)
		{
			continue;
		}

		dir_children.insert(FileKey{
			.dev = child_st.st_dev,
			.inode = child_st.st_ino,
		});
	}

	closedir(dir);
	return 0;
}

static void parse_args(int argc, char *args[])
{
	int opt, opt_idx;
	int mode_count = 0;
	std::vector<char *> filtered_args;

	filtered_args.push_back(args[0]);
	for (int i = 1; i < argc; i++)
	{
		if (strcmp(args[i], "+d") == 0)
		{
			if (i + 1 >= argc)
			{
				fprintf(stderr, "error: +d requires a directory argument\n");
				exit(-1);
			}
			strncpy(rule.dir_path, args[i + 1], sizeof(rule.dir_path));
			rule.dir_path[sizeof(rule.dir_path) - 1] = 0;
			rule.mode = QUERY_DIR_CHILDREN;
			mode_count++;
			i++;
			continue;
		}
		filtered_args.push_back(args[i]);
	}
	filtered_args.push_back(nullptr);

	optind = 1;
	std::string sopts = long_opt2short_opt(lopts);
	while ((opt = getopt_long(
				static_cast<int>(filtered_args.size() - 1),
				filtered_args.data(),
				sopts.c_str(),
				lopts,
				&opt_idx
			)) > 0)
	{
		switch (opt)
		{
		case 'p':
			strncpy(rule.path, optarg, sizeof(rule.path));
			rule.path[sizeof(rule.path) - 1] = 0;
			rule.mode = QUERY_SINGLE_OBJECT;
			mode_count++;
			break;
		case 'd':
			rule.dev = strtoul(optarg, NULL, 10);
			break;
		case 'i':
			rule.inode = strtoull(optarg, NULL, 10);
			break;
		case 1000:
			rule.dev = strtoul(optarg, NULL, 10);
			rule.mode = QUERY_FS_DEV;
			mode_count++;
			break;
		case 'h':
			Usage(args[0]);
			exit(0);
		default:
			Usage(args[0]);
			exit(-1);
		}
	}

	if (rule.mode == QUERY_NONE && rule.dev != 0 && rule.inode != 0)
	{
		rule.mode = QUERY_SINGLE_OBJECT;
		mode_count++;
	}

	if (mode_count != 1)
	{
		fprintf(
			stderr,
			"error: specify exactly one of -p, -d/-i, --fs-dev, or +d\n"
		);
		exit(-1);
	}

	if (rule.mode == QUERY_SINGLE_OBJECT && rule.path[0] != '\0')
	{
		int err = resolve_path_rule();
		if (err)
		{
			fprintf(
				stderr,
				"failed to stat %s: %s\n",
				rule.path,
				strerror(-err)
			);
			exit(-1);
		}
	}
	else if (rule.mode == QUERY_SINGLE_OBJECT &&
			 (rule.dev == 0 || rule.inode == 0))
	{
		fprintf(stderr, "error: -d and -i must be used together\n");
		exit(-1);
	}
	else if (rule.mode == QUERY_DIR_CHILDREN)
	{
		int err = collect_dir_children(rule.dir_path);
		if (err)
		{
			fprintf(
				stderr,
				"failed to scan directory %s: %s\n",
				rule.dir_path,
				strerror(-err)
			);
			exit(-1);
		}
	}
}

static bool match_file(dev_t dev, unsigned long inode)
{
	switch (rule.mode)
	{
	case QUERY_SINGLE_OBJECT:
		return rule.dev == dev && rule.inode == inode;
	case QUERY_FS_DEV:
		return rule.dev == dev;
	case QUERY_DIR_CHILDREN:
		return dir_children.find(FileKey{dev, inode}) != dir_children.end();
	default:
		return false;
	}
}

static void update_entry(pid_t pid, const char *comm)
{
	auto &entry = log_stat[pid];
	entry.pid = pid;
	entry.comm = comm;
	auto uid_it = uid_stat.find(pid);
	if (uid_it != uid_stat.end())
	{
		entry.uid = uid_it->second;
	}
}

static int handle_event(void *ctx, const void *data, size_t data_sz)
{
	(void)ctx;

	if (!data || data_sz < sizeof(DKapture::DataHdr))
	{
		return -EINVAL;
	}

	const auto *hdr = static_cast<const DKapture::DataHdr *>(data);
	switch (hdr->type)
	{
	case DKapture::PROC_PID_FD:
	{
		if (hdr->dsz < sizeof(DKapture::DataHdr) + sizeof(ProcPidFd) ||
			data_sz < hdr->dsz)
		{
			return -EINVAL;
		}

		const auto *fd = reinterpret_cast<const ProcPidFd *>(hdr->data);
		if (!match_file(fd->dev, fd->inode))
		{
			return 0;
		}

		update_entry(hdr->pid, hdr->comm);
		log_stat[hdr->pid].fds.push_back(fd->fd);
		return 0;
	}
	case DKapture::PROC_PID_STATUS:
	{
		if (hdr->dsz < sizeof(DKapture::DataHdr) + sizeof(ProcPidStatus) ||
			data_sz < hdr->dsz)
		{
			return -EINVAL;
		}

		const auto *status = reinterpret_cast<const ProcPidStatus *>(hdr->data);
		uid_stat[hdr->pid] = status->uid[0];
		auto it = log_stat.find(hdr->pid);
		if (it != log_stat.end())
		{
			it->second.uid = status->uid[0];
		}
		return 0;
	}
	case DKapture::PROC_PID_VMA_FILE:
	{
		if (hdr->dsz <
				sizeof(DKapture::DataHdr) + sizeof(ProcPidVmaFile) ||
			data_sz < hdr->dsz)
		{
			return -EINVAL;
		}

		const auto *vma =
			reinterpret_cast<const ProcPidVmaFile *>(hdr->data);
		if (!match_file(vma->dev, vma->inode))
		{
			return 0;
		}

		update_entry(hdr->pid, hdr->comm);
		log_stat[hdr->pid].vma_cnt++;
		return 0;
	}
	default:
		return 0;
	}
}

static void summary_print(void)
{
	printf("%16s %6s %8s   %s\n", "COMM", "UID", "PID", "FD");
	printf("--------------------------------------------\n");
	for (auto &it : log_stat)
	{
		LsofEntry &entry = it.second;
		printf(
			"%16s %6d %8d   ",
			entry.comm.c_str(),
			entry.uid,
			entry.pid
		);

		for (int fd : entry.fds)
		{
			printf("%d ", fd);
		}

		if (entry.vma_cnt)
		{
			printf("vma(%ld)", entry.vma_cnt);
		}
		printf("\n");
	}
	printf("\n");
}

static void print_scan_target(void)
{
	printf("Scanning ");
	switch (rule.mode)
	{
	case QUERY_SINGLE_OBJECT:
		if (rule.path[0] != '\0')
		{
			printf(
				"file %s (dev=%lu inode=%llu)",
				rule.path,
				(unsigned long)rule.dev,
				rule.inode
			);
		}
		else
		{
			printf("(dev=%lu inode=%llu)", (unsigned long)rule.dev, rule.inode);
		}
		break;
	case QUERY_FS_DEV:
		printf("filesystem device dev=%lu", (unsigned long)rule.dev);
		break;
	case QUERY_DIR_CHILDREN:
		printf(
			"direct children of %s (%zu objects)",
			rule.dir_path,
			dir_children.size()
		);
		break;
	default:
		printf("unknown target");
		break;
	}
	printf("...\n");
}

int main(int argc, char *args[])
{
	parse_args(argc, args);

	std::unique_ptr<DKapture> dk(DKapture::new_instance());
	if (!dk)
	{
		fprintf(stderr, "Failed to create DKapture instance\n");
		return 1;
	}

	int err = dk->open(stderr, DKapture::INFO);
	if (err)
	{
		fprintf(
			stderr,
			"Failed to open DKapture: %d (%s)\n",
			-err,
			strerror(-err)
		);
		return 1;
	}

	std::vector<DKapture::DataType> dts = {
		DKapture::PROC_PID_FD,
		DKapture::PROC_PID_STATUS,
		DKapture::PROC_PID_VMA_FILE,
	};
	ssize_t ret = dk->read(dts, handle_event, nullptr);
	if (ret < 0)
	{
		fprintf(
			stderr,
			"Failed to read process file usage: %ld (%s)\n",
			-ret,
			strerror(-ret)
		);
		dk->close();
		return 1;
	}

	print_scan_target();
	summary_print();

	dk->close();
	return 0;
}
