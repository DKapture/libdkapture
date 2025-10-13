// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1-only

/**
 * user space common header file.
 */
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <execinfo.h>
#include <stdlib.h>

#include <sys/syscall.h>
#include <linux/bpf.h>

#include "log.h"

#pragma once

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define DEBUG(on, fmt, args...)                                                \
	do                                                                         \
	{                                                                          \
		if (on)                                                                \
		{                                                                      \
			pr_debug(fmt, ##args);                                             \
		}                                                                      \
	} while (0)

static inline int
sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

#define bpf_find_prog(obj, name)                                               \
	({                                                                         \
		struct bpf_program *prog;                                              \
		prog = bpf_object__find_program_by_name(obj, name);                    \
		if (!prog)                                                             \
		{                                                                      \
			pr_error("fail to find bpf program " name "");                     \
			goto err_out;                                                      \
		}                                                                      \
		prog;                                                                  \
	})

#define bpf_get_prog_fd(prog)                                                  \
	({                                                                         \
		int fd;                                                                \
		fd = bpf_program__fd(prog);                                            \
		if (fd < 0)                                                            \
		{                                                                      \
			pr_error("fail to get bpf program fd " #prog "");                  \
			goto err_out;                                                      \
		}                                                                      \
		fd;                                                                    \
	})

#define bpf_get_map_fd(obj, name, err_opt)                                     \
	({                                                                         \
		int fd = bpf_object__find_map_fd_by_name(obj, name);                   \
		if (fd < 0)                                                            \
		{                                                                      \
			pr_error("Fail to locate map " name "");                           \
			err_opt;                                                           \
		}                                                                      \
		fd;                                                                    \
	})

#define bpf_syscall(cmd, attr)                                                 \
	({                                                                         \
		int fd;                                                                \
		fd = sys_bpf(cmd, &attr, sizeof(attr));                                \
		if (fd < 0)                                                            \
		{                                                                      \
			pr_error(                                                          \
				"bpf syscall failure(%s): cmd: " #cmd " line: %d",             \
				strerror(errno),                                               \
				__LINE__                                                       \
			);                                                                 \
			goto err_out;                                                      \
		}                                                                      \
		(fd);                                                                  \
	})

#define bpf_attach_kprobe(prog, probe)                                         \
	({                                                                         \
		struct bpf_link *link;                                                 \
		link = bpf_program__attach_kprobe(prog, false, probe);                 \
		if (!link)                                                             \
		{                                                                      \
			pr_error(                                                          \
				"bpf attach kprobe failure(%s)"                                \
				" line: %d",                                                   \
				strerror(errno),                                               \
				__LINE__                                                       \
			);                                                                 \
			goto err_out;                                                      \
		}                                                                      \
		link;                                                                  \
	})

#define bpf_attach_kretprobe(prog, probe)                                      \
	({                                                                         \
		struct bpf_link *link;                                                 \
		link = bpf_program__attach_kprobe(prog, true, probe);                  \
		if (!link)                                                             \
		{                                                                      \
			pr_error(                                                          \
				"bpf attach kretprobe failure(%s)"                             \
				" line: %d",                                                   \
				strerror(errno),                                               \
				__LINE__                                                       \
			);                                                                 \
			goto err_out;                                                      \
		}                                                                      \
		link;                                                                  \
	})

#define bpf_get_prog_fd(prog)                                                  \
	({                                                                         \
		int fd;                                                                \
		fd = bpf_program__fd(prog);                                            \
		if (fd < 0)                                                            \
		{                                                                      \
			pr_error("fail to get bpf program fd " #prog "");                  \
			goto err_out;                                                      \
		}                                                                      \
		fd;                                                                    \
	})

#define bpf_attach_tcx(prog, ifi)                                              \
	({                                                                         \
		bpf_link *link;                                                        \
		struct bpf_tcx_opts opts = {};                                         \
		opts.sz = sizeof(struct bpf_tcx_opts);                                 \
		link = bpf_program__attach_tcx(prog, ifi, &opts);                      \
		if (link == 0)                                                         \
		{                                                                      \
			pr_error(                                                          \
				"fail to get bpf program fd " #prog ": "                       \
				"%s %d",                                                       \
				strerror(errno),                                               \
				__LINE__                                                       \
			);                                                                 \
			goto err_out;                                                      \
		}                                                                      \
		link;                                                                  \
	})

#define bpf_create_iter(link, opt)                                             \
	({                                                                         \
		/* lfd: iterator link fd*/                                             \
		/* ifd: iterator fd */                                                 \
		int ifd;                                                               \
		int lfd;                                                               \
		lfd = bpf_link__fd(link);                                              \
		ifd = bpf_iter_create(lfd);                                            \
		if (ifd < 0)                                                           \
		{                                                                      \
			pr_error(                                                          \
				"fail to creating iterator '" #link "': %s",                   \
				strerror(errno)                                                \
			);                                                                 \
			opt;                                                               \
		}                                                                      \
		ifd;                                                                   \
	})

static inline unsigned long reverse_long(unsigned long v)
{
	if (sizeof(long) == 8)
	{
		return (v & 0x00000000000000ffL) << 56 |
			   (v & 0x000000000000ff00L) << 48 |
			   (v & 0x0000000000ff0000L) << 40 |
			   (v & 0x00000000ff000000L) << 32 |
			   (v & 0x000000ff00000000L) << 24 |
			   (v & 0x0000ff0000000000L) << 16 |
			   (v & 0x00ff000000000000L) << 8 | (v & 0xff00000000000000L) << 0;
	}
	else
	{
		return (v & 0x000000ff) << 24 | (v & 0x0000ff00) << 16 |
			   (v & 0x00ff0000) << 8 | (v & 0xff000000) << 0;
	}
}

static ssize_t write_file(const char *str, const char *path)
{
	int fd = open(path, O_WRONLY | O_TRUNC);
	if (fd < 0)
	{
		pr_error("open %s: %s", path, strerror(errno));
		return -1;
	}
	ssize_t sz = write(fd, str, strlen(str) + 1);
	if (sz < 0)
	{
		pr_error("write %s: %s", path, strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return sz;
}

class Trace
{
  private:
	int tracing_pipe_fd = -1;
	FILE *fp = nullptr;
	pthread_t t = 0;

  public:
	~Trace()
	{
		stop();
	}
	int start(void)
	{
		write_file("1", "/sys/kernel/debug/tracing/tracing_on");
		write_file("", "/sys/kernel/debug/tracing/trace");
		return 0;
	}

	void stop(void)
	{
		if (t)
		{
			pthread_cancel(t);
			pthread_join(t, NULL);
			t = 0;
		}
		if (tracing_pipe_fd > 0)
		{
			close(tracing_pipe_fd);
			tracing_pipe_fd = -1;
		}
		write_file("0", "/sys/kernel/debug/tracing/tracing_on");
	}

	void print(void)
	{
		int fd = open("/sys/kernel/debug/tracing/trace", O_RDWR, 0);
		assert(fd > 0);
		// write(trace_fd, "", 1);
		ssize_t sz;
		static char buf[4096];
		while ((sz = read(fd, buf, sizeof(buf))) > 0)
		{
			if (buf[0] != '#')
			{
				fwrite(buf, 1, sz, stdout);
			}
		}
		write(fd, "", 1);
		close(fd);
	}

	void follow(FILE *fp = nullptr)
	{
		pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, nullptr);
		tracing_pipe_fd =
			open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY);
		if (tracing_pipe_fd < 0)
		{
			pr_warn("trace file has been occupied");
			return;
		}
		if (fp == nullptr)
		{
			fp = stdout;
		}

		while (1)
		{
			static char buf[4096];
			ssize_t sz = read(tracing_pipe_fd, buf, sizeof(buf));
			if (sz > 0)
			{
				fwrite(buf, 1, sz, fp);
			}
			if (sz < 0)
			{
				break;
			}
		}
		close(tracing_pipe_fd);
		tracing_pipe_fd = -1;
	}

	void async_follow(FILE *fp = nullptr)
	{
		int ret;
		this->fp = fp;
		ret = pthread_create(
			&t,
			NULL,
			[](void *arg) -> void *
			{
				Trace *trace = (Trace *)arg;
				trace->follow(trace->fp);
				return NULL;
			},
			this
		);
		if (ret)
		{
			pr_error("cannot create thread: %s", strerror(errno));
			return;
		}
		pr_debug("trace thread created");
	}

	static void pstack()
	{
		const int max_frames = 64; // 最大堆栈深度
		void *buffer[max_frames];
		int num_frames = backtrace(buffer, max_frames); // 获取堆栈地址
		char **symbols =
			backtrace_symbols(buffer, num_frames); // 将地址转换为符号

		if (symbols == nullptr)
		{
			perror("backtrace_symbols");
			return;
		}

		printf("Stack trace:\n");
		for (int i = 0; i < num_frames; ++i)
		{
			printf("%s\n", symbols[i]);
		}

		free(symbols); // 释放符号数组
	}
};

static int trace_fd = -1;

static inline void stop_trace(void)
{
	close(trace_fd);
	trace_fd = -1;
}

static inline void follow_trace_pipe(FILE *fp = nullptr)
{
repeat:
	trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY);
	if (trace_fd < 0)
	{
		pr_warn("trace file has been occupied");
		sleep(3600);
		goto repeat;
	}
	if (fp == nullptr)
	{
		fp = stdout;
	}

	while (1)
	{
		static char buf[4096];
		ssize_t sz = read(trace_fd, buf, sizeof(buf));
		if (sz > 0)
		{
			fwrite(buf, 1, sz, fp);
		}
		if (sz < 0)
		{
			break;
		}
	}
	stop_trace();
}

static inline void read_trace(void)
{
	int fd = open("/sys/kernel/debug/tracing/trace", O_RDWR, 0);
	assert(fd > 0);
	// write(trace_fd, "", 1);
	ssize_t sz;
	static char buf[4096];
	while ((sz = read(fd, buf, sizeof(buf))) > 0)
	{
		if (buf[0] != '#')
		{
			fwrite(buf, 1, sz, stdout);
		}
	}
	close(fd);
}

#include <string>
static inline std::string get_time(void)
{
	char buffer[20] = {0};
	time_t timestamp = time(NULL);
	struct tm *info = localtime(&timestamp);
	if (!info)
	{
		return "";
	}
	strftime(buffer, sizeof buffer, "%H:%M:%S", info);

	return std::string(buffer);
}

#define DIE(fmt, args...)                                                      \
	{                                                                          \
		pr_error(                                                              \
			"[%s][%s:%d]: " fmt,                                               \
			get_time().c_str(),                                                \
			__FILE_NAME__,                                                     \
			__LINE__,                                                          \
			##args                                                             \
		);                                                                     \
		fflush(stdout);                                                        \
	}

#define BUG(fmt, args...)                                                      \
	{                                                                          \
		pr_error(                                                              \
			"[%s][%s:%d]: " fmt,                                               \
			get_time().c_str(),                                                \
			__FILE_NAME__,                                                     \
			__LINE__,                                                          \
			##args                                                             \
		);                                                                     \
		fflush(stdout);                                                        \
		exit(-1);                                                              \
	}

#define SAFE_DELETE(ptr)                                                       \
	do                                                                         \
	{                                                                          \
		if (ptr)                                                               \
		{                                                                      \
			delete ptr;                                                        \
			ptr = nullptr;                                                     \
		}                                                                      \
	} while (0)
