// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <vector>
#include <string>

#include "dkapture.h"
#include "arpa/inet.h"

static bool bexit = false;
static int dk_lifetime = 128; // ms

// Command line options structure
struct Options
{
	bool procfs_read = false;
	bool file_watch = false;
	bool memory_scan = false;
	bool fs_watch = false;
	bool irq_watch = false;
	bool socket_read = false;
	int monitor_duration = 0; // 0 means infinite
	std::string watch_file = "/usr/bin/ls";
	std::string procfs_node = ""; // 新增：指定procfs节点类型
	pid_t memory_scan_pid = 0; // 新增：指定内存扫描的目标进程PID，0表示所有进程
};

static Options g_options;

// 将字符串转换为对应的DataType
DKapture::DataType string_to_datatype(const std::string &node_name)
{
	if (node_name == "stat")
	{
		return DKapture::PROC_PID_STAT;
	}
	if (node_name == "io")
	{
		return DKapture::PROC_PID_IO;
	}
	if (node_name == "traffic")
	{
		return DKapture::PROC_PID_traffic;
	}
	if (node_name == "statm")
	{
		return DKapture::PROC_PID_STATM;
	}
	if (node_name == "schedstat")
	{
		return DKapture::PROC_PID_SCHEDSTAT;
	}
	if (node_name == "fd")
	{
		return DKapture::PROC_PID_FD;
	}
	if (node_name == "status")
	{
		return DKapture::PROC_PID_STATUS;
	}
	if (node_name == "net")
	{
		return DKapture::PROC_PID_NET;
	}
	if (node_name == "cmdline")
	{
		return DKapture::PROC_PID_CMDLINE;
	}
	if (node_name == "env")
	{
		return DKapture::PROC_PID_ENV;
	}
	if (node_name == "cwd")
	{
		return DKapture::PROC_PID_CWD;
	}
	if (node_name == "root")
	{
		return DKapture::PROC_PID_ROOT;
	}
	if (node_name == "exe")
	{
		return DKapture::PROC_PID_EXE;
	}
	if (node_name == "maps")
	{
		return DKapture::PROC_PID_MAPS;
	}
	if (node_name == "sock")
	{
		return DKapture::PROC_PID_sock;
	}
	if (node_name == "ns")
	{
		return DKapture::PROC_PID_NS;
	}
	if (node_name == "loginuid")
	{
		return DKapture::PROC_PID_LOGINUID;
	}
	// 默认返回STAT类型
	return DKapture::PROC_NONE;
}

static int print_task_sock(void *ctx, const void *data, size_t data_sz)
{
	assert(data_sz == sizeof(DKapture::DataHdr) + sizeof(ProcPidSock));
	const DKapture::DataHdr *hdr = (typeof(hdr))data;
	ProcPidSock *sk = (ProcPidSock *)hdr->data;
	if (data_sz < sizeof(*hdr) + sizeof(*sk))
	{
		printf("data size too small: %zu\n", data_sz);
		return -1;
	}
	if (hdr->type != DKapture::PROC_PID_sock)
	{
		printf("unknown data type: %d\n", hdr->type);
		return -1;
	}
	if (sk->family == AF_INET)
	{
		char lip[16] = {};
		char rip[16] = {};
		inet_ntop(AF_INET, &sk->lip, lip, sizeof(lip));
		inet_ntop(AF_INET, &sk->rip, rip, sizeof(rip));
		printf(
			"%10d %16s %10lu %3d %5u %5u %5u %s:%u %s:%u\n",
			hdr->pid,
			hdr->comm,
			sk->ino,
			sk->fd,
			sk->family,
			sk->type,
			sk->state,
			lip,
			ntohs(sk->lport),
			rip,
			ntohs(sk->rport)
		);
	}
	else if (sk->family == AF_INET6)
	{
		char lipv6[48] = {};
		char ripv6[48] = {};
		inet_ntop(AF_INET6, &sk->lipv6, lipv6, sizeof(lipv6));
		inet_ntop(AF_INET6, &sk->ripv6, ripv6, sizeof(ripv6));
		printf(
			"%10d %16s %10lu %3d %5u %5u %5u "
			"[%s]:%u [%s]:%u\n",
			hdr->pid,
			hdr->comm,
			sk->ino,
			sk->fd,
			sk->family,
			sk->type,
			sk->state,
			lipv6,
			ntohs(sk->lport),
			ripv6,
			ntohs(sk->rport)
		);
	}
	else
	{
		printf(
			"%10d %16s %10lu %3d %5u %5u %5u\n",
			hdr->pid,
			hdr->comm,
			sk->ino,
			sk->fd,
			sk->family,
			sk->type,
			sk->state
		);
	}
	return 0;
}

int print_file_log(void *ctx, const void *data, size_t data_sz)
{
	FileLog *flog = (FileLog *)data;
	if (flog->log_type == DKapture::FILE_LOG_OPEN)
	{
		const struct OpenLog *log = (typeof(log))flog;
		printf(
			"Open: %lu pid: %d mode: %d\n",
			log->i_ino,
			flog->pid,
			log->f_mode
		);
	}
	else if (flog->log_type == DKapture::FILE_LOG_CLOSE)
	{
		const struct CloseLog *log = (typeof(log))flog;
		printf("Close: %lu pid: %d\n", log->i_ino, flog->pid);
	}
	return 0;
}

int print_call_stack(void *ctx, const void *_data, size_t data_sz)
{
	printf("%s", _data);
	return 0;
}

int print_proc_info(void *ctx, const void *_data, size_t data_sz)
{
	const DKapture::DataHdr *data = (typeof(data))_data;
	while (data_sz > (int)sizeof(DKapture::DataHdr))
	{
		switch (data->type)
		{
		case DKapture::PROC_PID_STAT:
		{
			const struct ProcPidStat *stat = (typeof(stat))data->data;
			printf(
				"pid: %d tgid: %d comm: %s nice: %d pgid: %d utime: %lu stime: "
				"%lu\n",
				data->pid,
				data->tgid,
				data->comm,
				stat->nice,
				stat->pgid,
				stat->utime,
				stat->stime
			);
		}
		break;
		case DKapture::PROC_PID_IO:
		{
			const struct ProcPidIo *io = (typeof(io))data->data;
			printf(
				"pid: %d tgid: %d comm: %s rd: %lu wr: %lu\n",
				data->pid,
				data->tgid,
				data->comm,
				io->rchar,
				io->wchar
			);
		}
		break;
		case DKapture::PROC_PID_traffic:
		{
			const struct ProcPidTraffic *traffic = (typeof(traffic))data->data;
			printf(
				"pid: %d tgid: %d comm: %s rbytes: %lu wbytes: %lu\n",
				data->pid,
				data->tgid,
				data->comm,
				traffic->rbytes,
				traffic->wbytes
			);
		}
		break;
		case DKapture::PROC_PID_STATM:
		{
			const struct ProcPidStatm *statm = (typeof(statm))data->data;
			printf(
				"pid: %8d comm: %15s vsize: %10d resident: %10d shared: %10d\n",
				data->pid,
				data->comm,
				statm->size,
				statm->resident,
				statm->shared
			);
		}
		break;
		case DKapture::PROC_PID_SCHEDSTAT:
		{
			const struct ProcPidSchedstat *stat = (typeof(stat))data->data;
			printf(
				"pid: %d comm: %s cputime: %llu %llu %llu\n",
				data->pid,
				data->comm,
				stat->cpu_time,
				stat->rq_wait_time,
				stat->timeslices
			);
		}
		break;
		case DKapture::PROC_PID_FD:
		{
			const struct ProcPidFd *fd = (typeof(fd))data->data;
			printf(
				"pid: %d tgid: %d comm: %s fd: %d ino: %lu mode: %lu dev: %u\n",
				data->pid,
				data->tgid,
				data->comm,
				fd->fd,
				fd->inode,
				fd->i_mode,
				fd->dev
			);
		}
		break;
		case DKapture::PROC_PID_STATUS:
		{
			const struct ProcPidStatus *status = (typeof(status))data->data;
			printf(
				"pid: %d tgid: %d comm: %s umask: %d state: %d uid: %d %d %d "
				"%d gid: %d %d %d %d\n",
				data->pid,
				data->tgid,
				data->comm,
				status->state,
				status->umask,
				status->uid[0],
				status->uid[1],
				status->uid[2],
				status->uid[3],
				status->gid[0],
				status->gid[1],
				status->gid[2],
				status->gid[3]
			);
		}
		break;
		case DKapture::PROC_PID_NS:
		{
			const struct ProcPidNs *ns = (typeof(ns))data->data;
			printf(
				"pid: %d tgid: %d comm: %s cgroup_ns: %u ipc_ns: %u mnt_ns: %u"
				" net_ns: %u pid_ns: %u pid_ns_for_children: %u time_ns: %u"
				" time_ns_for_children: %u user_ns: %u uts_ns: %u\n",
				data->pid,
				data->tgid,
				data->comm,
				ns->cgroup,
				ns->ipc,
				ns->mnt,
				ns->net,
				ns->pid,
				ns->pid_for_children,
				ns->time,
				ns->time_for_children,
				ns->user,
				ns->uts
			);
		}
		break;
		case DKapture::PROC_PID_LOGINUID:
		{
			const struct ProcPidLoginuid *loginuid =
				(typeof(loginuid))data->data;
			printf(
				"pid: %d tgid: %d comm: %s loginuid: %d\n",
				data->pid,
				data->tgid,
				data->comm,
				loginuid->loginuid.val
			);
		}
		break;
		default:
			printf("Unknown type: %d\n", data->type);
			break;
		}
		data_sz -= data->dsz;
		data = (DKapture::DataHdr *)((char *)data + data->dsz);
	}
	return 0;
}
static char g_call_buf[40960];

static const char *gen_mount_call(const struct mount_args *e)
{
	snprintf(
		g_call_buf,
		sizeof(g_call_buf),
		"mount(\"%s\", \"%s\", \"%s\", %d, \"%s\") = `%d",
		e->source,
		e->target,
		e->filesystemtype,
		e->flags,
		e->data,
		e->ret
	);
	return g_call_buf;
}

static const char *gen_umount_call(const struct umount_args *e)
{
	snprintf(
		g_call_buf,
		sizeof(g_call_buf),
		"umount(\"%s\", %d) = %d",
		e->target,
		e->flags,
		e->ret
	);
	return g_call_buf;
}

static const char *gen_fsopen_call(const struct fsopen_args *e)
{
	snprintf(
		g_call_buf,
		sizeof(g_call_buf),
		"fsopen(\"%s\", %u) = %d",
		e->fsname,
		e->flags,
		e->ret
	);
	return g_call_buf;
}

static const char *gen_fsconfig_call(const struct fsconfig_args *e)
{
	snprintf(
		g_call_buf,
		sizeof(g_call_buf),
		"fsconfig(%d, %u, \"%s\", \"%s\", %d) = %d",
		e->fd,
		e->cmd,
		e->key,
		e->value,
		e->aux,
		e->ret
	);
	return g_call_buf;
}

static const char *gen_fsmount_call(const struct fsmount_args *e)
{
	snprintf(
		g_call_buf,
		sizeof(g_call_buf),
		"fsmount(%d, %u, %u) = %d",
		e->fs_fd,
		e->flags,
		e->attr_flags,
		e->ret
	);
	return g_call_buf;
}

static const char *gen_fsmovemount_call(const struct move_mount_args *e)
{
	snprintf(
		g_call_buf,
		sizeof(g_call_buf),
		"move_mount(%d, \"%s\", %d, \"%s\", %u) = %d",
		e->from_dfd,
		e->from_pathname,
		e->to_dfd,
		e->to_pathname,
		e->flags,
		e->ret
	);
	return g_call_buf;
}
static const char *gen_fspick_call(const struct fspick_args *e)
{
	snprintf(
		g_call_buf,
		sizeof(g_call_buf),
		"fspick(%d, \"%s\", %u) = %d",
		e->dfd,
		(const char *)e->path,
		e->flags,
		e->ret
	);
	return g_call_buf;
}

static const char *gen_mount_setattr_call(const struct mount_setattr_args *e)
{
	snprintf(
		g_call_buf,
		sizeof(g_call_buf),
		"mount_setattr(%d, \"%s\", %u, "
		"{attr_set=0x%llx, attr_clr=0x%llx, "
		"propagation=0x%llx, userns_fd=%llu}, %zu) = %d",
		e->dfd,
		e->path,
		e->flags,
		(unsigned long long)e->uattr.attr_set,
		(unsigned long long)e->uattr.attr_clr,
		(unsigned long long)e->uattr.propagation,
		(unsigned long long)e->uattr.userns_fd,
		e->usize,
		e->ret
	);
	return g_call_buf;
}

static const char *gen_open_tree_call(const struct open_tree_args *e)
{
	snprintf(
		g_call_buf,
		sizeof(g_call_buf),
		"open_tree(%d, \"%s\", %u) = %d",
		e->dfd,
		e->filename,
		e->flags,
		e->ret
	);
	return g_call_buf;
}

static int print_mount_info(void *ctx, const void *data, size_t len)
{
	switch (len)
	{
	case sizeof(mount_args):
	{
		const struct mount_args *e = (typeof(e))data;
		printf(
			"%-16s %-7d %-7d %-11u %s\n",
			e->comm,
			e->pid,
			e->tid,
			e->mnt_ns,
			gen_mount_call(e)
		);
		break;
	}
	case sizeof(umount_args):
	{
		const struct umount_args *e = (typeof(e))data;
		printf(
			"%-16s %-7d %-7d %-11u %s\n",
			e->comm,
			e->pid,
			e->tid,
			e->mnt_ns,
			gen_umount_call(e)
		);
		break;
	}
	case sizeof(fsopen_args):
	{
		const struct fsopen_args *e = (const struct fsopen_args *)data;
		printf(
			"%-16s %-7d %-7d %-11u %s\n",
			e->comm,
			e->pid,
			e->tid,
			e->mnt_ns,
			gen_fsopen_call(e)
		);
		break;
	}
	case sizeof(fsconfig_args):
	{
		const struct fsconfig_args *e = (const struct fsconfig_args *)data;
		printf(
			"%-16s %-7d %-7d %-11u %s\n",
			e->comm,
			e->pid,
			e->tid,
			e->mnt_ns,
			gen_fsconfig_call(e)
		);
		break;
	}
	case sizeof(fsmount_args):
	{
		const struct fsmount_args *e = (const struct fsmount_args *)data;
		printf(
			"%-16s %-7d %-7d %-11u %s\n",
			e->comm,
			e->pid,
			e->tid,
			e->mnt_ns,
			gen_fsmount_call(e)
		);
		break;
	}
	case sizeof(move_mount_args):
	{
		const struct move_mount_args *e = (const struct move_mount_args *)data;
		printf(
			"%-16s %-7d %-7d %-11u %s\n",
			e->comm,
			e->pid,
			e->tid,
			e->mnt_ns,
			gen_fsmovemount_call(e)
		);
		break;
	}
	case sizeof(fspick_args):
	{
		const struct fspick_args *e = (const struct fspick_args *)data;
		printf(
			"%-16s %-7d %-7d %-11u %s\n",
			e->comm,
			e->pid,
			e->tid,
			e->mnt_ns,
			gen_fspick_call(e)
		);
		break;
	}
	case sizeof(mount_setattr_args):
	{
		const struct mount_setattr_args *e =
			(const struct mount_setattr_args *)data;
		printf(
			"%-16s %-7d %-7d %-11u %s\n",
			e->comm,
			e->pid,
			e->tid,
			e->mnt_ns,
			gen_mount_setattr_call(e)
		);
		break;
	}
	case sizeof(open_tree_args):
	{
		const struct open_tree_args *e = (const struct open_tree_args *)data;
		printf(
			"%-16s %-7d %-7d %-11u %s\n",
			e->comm,
			e->pid,
			e->tid,
			e->mnt_ns,
			gen_open_tree_call(e)
		);
		break;
	}
	default:
		printf("Unknown event size: %zu\n", len);
		break;
	}

	return 0;
}

static const char *vec_names[] = {
	[HI_SOFTIRQ] = "hi",
	[TIMER_SOFTIRQ] = "timer",
	[NET_TX_SOFTIRQ] = "net_tx",
	[NET_RX_SOFTIRQ] = "net_rx",
	[BLOCK_SOFTIRQ] = "block",
	[IRQ_POLL_SOFTIRQ] = "irq_poll",
	[TASKLET_SOFTIRQ] = "tasklet",
	[SCHED_SOFTIRQ] = "sched",
	[HRTIMER_SOFTIRQ] = "hrtimer",
	[RCU_SOFTIRQ] = "rcu",
};

static int print_irq_info(void *ctx, const void *data, size_t data_sz)
{
	struct irq_event_t *e = (struct irq_event_t *)data;
	if (e->pid == 0)
	{
		return 0;
	}
	// 只处理IRQ类型事件
	if (e->type == IRQ)
	{
		printf(
			"[IRQ] pid=%d tid=%d comm=%s irq=%d name=%s delta=%lluns ret=%d\n",
			e->pid,
			e->tid,
			e->comm,
			e->vec_nr,
			e->name,
			e->delta,
			e->ret
		);
	}
	else if (e->type == SOFT_IRQ)
	{
		printf(
			"[SOFTIRQ] pid=%d tid=%d comm=%s vec=%s delta=%lluns ret=%d\n",
			e->pid,
			e->tid,
			e->comm,
			vec_names[e->vec_nr],
			e->delta,
			e->ret
		);
	}
	return 0;
}

void root_only(void)
{
	if (getuid() != 0)
	{
		fprintf(stderr, "Please run as root\n");
		exit(-1);
	}
}

void print_usage(const char *program_name)
{
	printf("Usage: %s [OPTIONS]\n", program_name);
	printf("Options:\n");
	printf("  -p, --procfs-read [node]        Enable procfs reading\n");
	printf("                                  iterate to read /proc/pid/node "
		   "(e.g., stat, io, traffic)\n");
	printf("                                  Supported nodes: stat, io, "
		   "traffic, statm, schedstat, fd, ns,\n");
	printf("                                             status, net, cmdline, "
		   "env, cwd, root, exe, maps, sock\n");
	printf("  -f, --file-watch [file]         Enable file monitoring (default: "
		   "all files)\n");
	printf("  -m, --memory-scan [pid]         Enable kernel memory leak "
		   "scanning\n");
	printf("                                  If pid is specified, scan only "
		   "that process (default: scan all processes)\n");
	printf("  -s, --fs-watch                  Enable filesystem event "
		   "monitoring\n");
	printf("  -i, --irq-watch                 Enable interrupt event "
		   "monitoring\n");
	printf("  -o, --socket-read               Enable socket information "
		   "reading\n");
	printf("  -t, --duration <seconds>        Monitoring duration in seconds "
		   "(0 for infinite)\n");
	printf("  -h, --help                      Show this help message\n");
	printf("\nExamples:\n");
	printf(
		"  %s -p                    # Run procfs reading for all supported "
		"node\n",
		program_name
	);
	printf(
		"  %s -pstat                # Run procfs reading only stat node\n",
		program_name
	);
	printf(
		"  %s -pio                  # Run procfs reading only io node\n",
		program_name
	);
	printf(
		"  %s -f -t 30              # Monitor file events for 30 seconds\n",
		program_name
	);
	printf(
		"  %s -m -t 60              # Monitor memory leaks for all processes "
		"for 60 seconds\n",
		program_name
	);
	printf(
		"  %s -m1234 -t 60         # Monitor memory leaks for process 1234 "
		"for 60 seconds\n",
		program_name
	);
	printf(
		"  %s -m -s -i -t 60        # Monitor memory, fs, and irq for 60 "
		"seconds\n",
		program_name
	);
	printf(
		"  %s -pstatm -f -t 0       # Run procfs reading for node statm + "
		"infinite file monitoring\n",
		program_name
	);
	printf(
		"  %s -o                    # Run socket reading only\n",
		program_name
	);
}

bool parse_arguments(int argc, char *argv[])
{
	int opt;
	const char *short_options = "p::f::m::siot:h";
	struct option long_options[] = {
		{"procfs-read", optional_argument, 0, 'p'},
		{"file-watch",  optional_argument, 0, 'f'},
		{"memory-scan", optional_argument, 0, 'm'},
		{"fs-watch",	 no_argument,		  0, 's'},
		{"irq-watch",	  no_argument,	   0, 'i'},
		{"socket-read", no_argument,		 0, 'o'},
		{"duration",	 required_argument, 0, 't'},
		{"help",		 no_argument,		  0, 'h'},
		{0,			 0,				 0, 0  }
	};

	while ((opt = getopt_long(argc, argv, short_options, long_options, nullptr)
		   ) != -1)
	{
		switch (opt)
		{
		case 'p':
			g_options.procfs_read = true;
			if (optarg)
			{
				g_options.procfs_node = optarg;
			}
			break;
		case 'f':
			g_options.file_watch = true;
			if (optarg)
			{
				g_options.watch_file = optarg;
			}
			break;
		case 'm':
			g_options.memory_scan = true;
			if (optarg)
			{
				g_options.memory_scan_pid = atoi(optarg);
			}
			break;
		case 's':
			g_options.fs_watch = true;
			break;
		case 'i':
			g_options.irq_watch = true;
			break;
		case 'o':
			g_options.socket_read = true;
			break;
		case 't':
			g_options.monitor_duration = atoi(optarg);
			break;
		case 'h':
			print_usage(argv[0]);
			exit(0);
		default:
			print_usage(argv[0]);
			return false;
		}
	}

	// If no options specified, enable all by default
	if (!g_options.procfs_read && !g_options.file_watch &&
		!g_options.memory_scan && !g_options.fs_watch && !g_options.irq_watch &&
		!g_options.socket_read)
	{
		g_options.procfs_read = true;
		g_options.file_watch = true;
		g_options.memory_scan = true;
		g_options.fs_watch = true;
		g_options.irq_watch = true;
		g_options.socket_read = true;
	}

	return true;
}

class CalculateRunTime
{
  public:
	struct timespec _start;
	void start()
	{
		clock_gettime(CLOCK_MONOTONIC, &_start);
	}

	long delta()
	{
		struct timespec _end;
		clock_gettime(CLOCK_MONOTONIC, &_end);
		return (_end.tv_sec - _start.tv_sec) * 1000000000 +
			   (_end.tv_nsec - _start.tv_nsec);
	}
};

void run_procfs_read(DKapture *dk)
{
	printf("======== Procfs Combined Reading ========\n");

	long delta = 0;

	std::vector<DKapture::DataType> dts;

	if (!g_options.procfs_node.empty())
	{
		// 如果指定了特定节点，只读取该节点
		DKapture::DataType specified_type =
			string_to_datatype(g_options.procfs_node);
		if (specified_type == DKapture::PROC_NONE)
		{
			printf("Invalid procfs node: %s\n", g_options.procfs_node.c_str());
			return;
		}
		dts.push_back(specified_type);
		printf(
			"Reading specified procfs node: %s\n",
			g_options.procfs_node.c_str()
		);
	}
	else
	{
		// 默认读取所有节点
		dts = {
			DKapture::PROC_PID_STAT,
			DKapture::PROC_PID_IO,
			DKapture::PROC_PID_traffic,
			DKapture::PROC_PID_STATM,
			DKapture::PROC_PID_SCHEDSTAT,
			DKapture::PROC_PID_FD,
			DKapture::PROC_PID_STATUS,
			DKapture::PROC_PID_NS,
			DKapture::PROC_PID_LOGINUID,
		};
		printf("Reading all procfs nodes\n");
	}

	CalculateRunTime runtime;
	runtime.start();
	int ret = dk->read(dts, print_proc_info, nullptr);
	delta = runtime.delta();

	if (!g_options.procfs_node.empty())
	{
		printf(
			"read %s node info in /proc/pid/\n",
			g_options.procfs_node.c_str()
		);
	}
	else
	{
		printf("read all stat/statm/io/traffic node info in /proc/pid/\n");
	}
	printf("spent-time(ns): %ld\n", delta);

	if (ret < 0)
	{
		printf("read: %s\n", strerror(-ret));
	}

	printf("======== Procfs Reading Completed ========\n\n");
}

void run_file_watch(DKapture *dk)
{
	printf("======== File Monitoring ========\n");
	printf("Watching file: %s\n", g_options.watch_file.c_str());

	dk->file_watch(g_options.watch_file.c_str(), print_file_log, nullptr);

	if (g_options.monitor_duration > 0)
	{
		printf("Monitoring for %d seconds...\n", g_options.monitor_duration);
		sleep(g_options.monitor_duration);
	}
	else
	{
		printf("Monitoring indefinitely (press Ctrl+C to stop)...\n");
		while (!bexit)
		{
			sleep(1);
		}
	}

	dk->file_watch(nullptr, nullptr, nullptr);
	printf("======== File Monitoring Completed ========\n\n");
}

void run_memory_scan(DKapture *dk)
{
	printf("======== Kernel Memory Leak Scanning ========\n");

	if (g_options.memory_scan_pid == 0)
	{
		printf("Scanning memory leaks for all processes\n");
	}
	else
	{
		printf(
			"Scanning memory leaks for process PID: %d\n",
			g_options.memory_scan_pid
		);
	}

	dk->kmemleak_scan_start(
		g_options.memory_scan_pid,
		print_call_stack,
		nullptr
	);

	if (g_options.monitor_duration > 0)
	{
		printf("Scanning for %d seconds...\n", g_options.monitor_duration);
		sleep(g_options.monitor_duration);
	}
	else
	{
		printf("Scanning indefinitely (press Ctrl+C to stop)...\n");
		while (!bexit)
		{
			sleep(1);
		}
	}

	dk->kmemleak_scan_stop();
	printf("======== Memory Scanning Completed ========\n\n");
}

void run_socket_read(DKapture *dk)
{
	printf("======== Socket Information Reading ========\n");
	dk->read(DKapture::PROC_PID_sock, print_task_sock, nullptr);
	printf("======== Socket Reading Completed ========\n\n");
}

void run_fs_watch(DKapture *dk)
{
	printf("======== Filesystem Event Monitoring ========\n");

	dk->fs_watch(nullptr, print_mount_info, nullptr);

	if (g_options.monitor_duration > 0)
	{
		printf("Monitoring for %d seconds...\n", g_options.monitor_duration);
		sleep(g_options.monitor_duration);
	}
	else
	{
		printf("Monitoring indefinitely (press Ctrl+C to stop)...\n");
		while (!bexit)
		{
			sleep(1);
		}
	}

	dk->fs_watch(nullptr, nullptr, nullptr);
	printf("======== Filesystem Monitoring Completed ========\n\n");
}

void run_irq_watch(DKapture *dk)
{
	printf("======== Interrupt Event Monitoring ========\n");

	dk->irq_watch(print_irq_info, nullptr);

	if (g_options.monitor_duration > 0)
	{
		printf("Monitoring for %d seconds...\n", g_options.monitor_duration);
		sleep(g_options.monitor_duration);
	}
	else
	{
		printf("Monitoring indefinitely (press Ctrl+C to stop)...\n");
		while (!bexit)
		{
			sleep(1);
		}
	}

	dk->irq_watch(nullptr, nullptr);
	printf("======== Interrupt Monitoring Completed ========\n\n");
}

int main(int argc, char *argv[])
{
	int ret = 0;
	root_only();

	// Parse command line arguments
	if (!parse_arguments(argc, argv))
	{
		return 1;
	}

	signal(SIGINT, [](int) { bexit = true; });
	srand(time(NULL));

	DKapture *dk = DKapture::new_instance();
	assert(dk);
	assert(0 == dk->open(stdout, DKapture::DEBUG));
	dk->lifetime(dk_lifetime);

	// Execute selected operations
	if (g_options.procfs_read)
	{
		/******************* procfs 组合读 *****************/
		printf("read procfs equivalently 10 times...\n");
		run_procfs_read(dk);
	}

	if (g_options.file_watch)
	{
		/******************** 文件监控 *********************/
		run_file_watch(dk);
	}

	if (g_options.memory_scan)
	{
		/******************** 内存扫描 *********************/
		run_memory_scan(dk);
	}

	if (g_options.socket_read)
	{
		/***************** Socket信息读取 ******************/
		run_socket_read(dk);
	}

	if (g_options.fs_watch)
	{
		/****************** 文件系统监控 ********************/
		run_fs_watch(dk);
	}

	if (g_options.irq_watch)
	{
		/******************** 中断监控 *********************/
		run_irq_watch(dk);
	}

	dk->close();
	delete dk;
	return 0;
}
