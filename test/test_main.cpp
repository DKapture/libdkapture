// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

// This file uses/derives from googletest
// Copyright 2008, Google Inc.
// Licensed under the BSD 3-Clause License
// See NOTICE for full license text

#include "dkapture.h"
#include "log.h"
#include <sys/shm.h>
#include "gtest/gtest.h"
#include "bpf/libbpf.h"
#include <sched.h>
#include <sys/mount.h>

#include <dirent.h>

FILE *gtest_fp;

static int libbpf_user_print(
	enum libbpf_print_level level,
	const char *format,
	va_list args
)
{
	if (level == LIBBPF_DEBUG)
	{
		return 0;
	}
	return vfprintf(gtest_fp, format, args);
}

void clean_up(void)
{
	// 删除所有共享内存段
	struct shmid_ds shm_info;
	int maxid = shmctl(0, SHM_INFO, (struct shmid_ds *)&shm_info);
	if (maxid >= 0)
	{
		for (int id = 0; id <= maxid; ++id)
		{
			int shmid = shmctl(id, SHM_STAT, &shm_info);
			if (shmid < 0)
			{
				continue;
			}
			// 检查共享内存段是否仍然存在且可访问
			if (shmctl(shmid, IPC_STAT, &shm_info) < 0)
			{
				continue;
			}
			// 尝试删除共享内存段
			if (shmctl(shmid, IPC_RMID, NULL) == 0)
			{
				pr_info("Successfully removed shared memory segment %d", shmid);
			}
			else
			{
				pr_warn(
					"Failed to remove shared memory segment %d: %s",
					shmid,
					strerror(errno)
				);
			}
		}
	}
	else
	{
		pr_warn("Failed to get shared memory info: %s", strerror(errno));
	}

	// 删除之前可能残留的目录
	DIR *dir = opendir("/sys/fs/bpf/dkapture");
	if (dir)
	{
		struct dirent *entry;
		char path[PATH_MAX];
		while ((entry = readdir(dir)) != NULL)
		{
			if (strcmp(entry->d_name, ".") == 0 ||
				strcmp(entry->d_name, "..") == 0)
			{
				continue;
			}
			snprintf(
				path,
				sizeof(path),
				"/sys/fs/bpf/dkapture/%s",
				entry->d_name
			);
			if (unlink(path) == 0)
			{
				pr_info("Successfully removed BPF file: %s", entry->d_name);
			}
			else
			{
				pr_warn(
					"Failed to remove BPF file %s: %s",
					entry->d_name,
					strerror(errno)
				);
			}
		}
		closedir(dir);
		if (rmdir("/sys/fs/bpf/dkapture") == 0)
		{
			pr_info("Successfully removed BPF directory");
		}
		else
		{
			pr_warn("Failed to remove BPF directory: %s", strerror(errno));
		}
	}
}

void set_up(void)
{
	uid_t ori_uid = getuid();
	/**
	 * 切换挂载空间和用户空间
	 */
	if (unshare(CLONE_NEWNS | CLONE_NEWUSER) != 0)
	{
		pr_error("unshare: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	/**
	 * 将自己在当前用户空间映射成root
	 */
	char buf[32];
	sprintf(buf, "0 %d 1", ori_uid);
	int fd = open("/proc/self/uid_map", O_WRONLY);
	assert(fd > 0);
	ssize_t wsz = write(fd, buf, strlen(buf));
	assert(wsz > 0);
	// 创建临时目录 /tmp/bpf
	if (system("mkdir -p /tmp/bpf") != 0)
	{
		pr_error("mkdir /tmp/bpf");
		exit(EXIT_FAILURE);
	}

	// 挂载 /tmp/bpf 到 /sys/bpf
	if (mount("/tmp/bpf", "/sys/fs/bpf", NULL, MS_BIND, NULL) != 0)
	{
		pr_error("mount: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	pr_info("Mounted /tmp/bpf to /sys/bpf in a new mount namespace.\n");
}

int main(int argc, char **argv)
{
	set_up();
	clean_up();
	pr_warn("log message is redirected to file /tmp/dkapture.log");
	gtest_fp = fopen("/tmp/dkapture.log", "w");
	assert(gtest_fp != NULL);
	libbpf_set_print(libbpf_user_print);
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}