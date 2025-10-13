// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <thread>
#include <unistd.h>
#include <argp.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <signal.h>
#include <atomic>
#include <sys/syscall.h>

// libbpf headers
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// Auto-generated BPF skeleton
#include "proc-info.skel.h"

// Include dkapture headers for data structures
#include "dkapture.h"
#include "com.h"

// Command line options configuration
static struct env
{
	bool verbose;
	bool show_header;
	bool wide_output;
	bool show_threads;
	bool show_io;
	bool show_traffic;
	bool show_statm;
	bool show_status;
	bool show_schedstat;
	bool show_ns;
	bool show_loginuid;
} env = {
	.verbose = false,
	.show_header = true,
	.wide_output = false,
	.show_threads = false,
	.show_io = true,
	.show_traffic = true,
	.show_statm = true,
	.show_status = true,
	.show_schedstat = true,
	.show_ns = true,
	.show_loginuid = true,
};

static proc_info_bpf *obj;
static struct ring_buffer *rb = NULL;
static std::atomic<bool> exit_flag(false);

const char *argp_program_version = "proc-info 1.0";
const char *argp_program_bug_address = NULL;

static const char argp_program_doc[] =
	"proc-info - Display detailed process information\n"
	"\n"
	"BPF version for displaying comprehensive process information including\n"
	"stat, io, traffic, statm, status, and schedstat data\n";

static const struct argp_option opts[] = {
	{"verbose", 'v', NULL, 0, "Display verbose output"},
	{"no-header", 'H', NULL, 0, "Don't display header"},
	{"wide", 'w', NULL, 0, "Don't truncate output"},
	{"threads", 'T', NULL, 0, "Display all threads"},
	{"no-io", 'I', NULL, 0, "Don't show IO information"},
	{"no-traffic", 't', NULL, 0, "Don't show network traffic"},
	{"no-statm", 'm', NULL, 0, "Don't show memory information"},
	{"no-status", 's', NULL, 0, "Don't show status information"},
	{"no-schedstat", 'S', NULL, 0, "Don't show scheduler statistics"},
	{"no-ns", 'n', NULL, 0, "Don't show namespace information"},
	{"no-loginuid", 'l', NULL, 0, "Don't show loginuid information"},
	{},
};

// libbpf print callback
static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
	{
		return 0;
	}
	return vfprintf(stderr, format, args);
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key)
	{
	case 'v':
		env.verbose = true;
		break;
	case 'H':
		env.show_header = false;
		break;
	case 'w':
		env.wide_output = true;
		break;
	case 'T':
		env.show_threads = true;
		break;
	case 'I':
		env.show_io = false;
		break;
	case 't':
		env.show_traffic = false;
		break;
	case 'm':
		env.show_statm = false;
		break;
	case 's':
		env.show_status = false;
		break;
	case 'S':
		env.show_schedstat = false;
		break;
	case 'n':
		env.show_ns = false;
		break;
	case 'l':
		env.show_loginuid = false;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

// Signal handler for clean termination
static void sig_handler(int sig)
{
	exit_flag = true;
}

static void register_signal()
{
	struct sigaction sa;
	sa.sa_handler = sig_handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGINT, &sa, NULL) == -1)
	{
		perror("sigaction");
		exit(EXIT_FAILURE);
	}
}

// Convert clock ticks to human-readable time string
static std::string format_time(unsigned long long time)
{
	unsigned long minutes = time / (60 * sysconf(_SC_CLK_TCK));
	unsigned long seconds = time / sysconf(_SC_CLK_TCK) % 60;

	char buffer[32];
	sprintf(buffer, "%lu:%02lu", minutes, seconds);
	return std::string(buffer);
}

// Convert process state code to a readable character
static char get_state_char(int state)
{
	if (state == 0)
	{
		return 'R'; // Running
	}
	if (state & 1)
	{
		return 'S'; // Interruptible sleep
	}
	if (state & 2)
	{
		return 'D'; // Uninterruptible sleep
	}
	if (state & 4)
	{
		return 'T'; // Stopped
	}
	if (state & 16)
	{
		return 'Z'; // Zombie
	}
	if (state & 32)
	{
		return 'X'; // Dead
	}
	return '?'; // Unknown
}

// Process data received from BPF program
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct DKapture::DataHdr *hdr =
		static_cast<const struct DKapture::DataHdr *>(data);
	static bool header_printed = false;
	static int event_count = 0;

	// Print event info if verbose mode
	if (env.verbose)
	{
		std::cerr << "Received event #" << ++event_count
				  << ", type: " << hdr->type << ", size: " << data_sz
				  << " bytes, pid: " << hdr->pid << ", comm: " << hdr->comm
				  << std::endl;
	}

	// Skip if not showing threads and this is a thread
	if (!env.show_threads && hdr->pid != hdr->tgid)
	{
		return 0;
	}

	// Print table header if needed and not yet printed
	if (env.show_header && !header_printed)
	{
		std::cout << std::setw(5) << "PID"
				  << " " << std::setw(5) << "TGID"
				  << " " << std::setw(16) << "COMM"
				  << " " << std::setw(5) << "STATE"
				  << " " << std::setw(8) << "TYPE"
				  << " ";

		if (env.verbose)
		{
			std::cout << std::setw(8) << "VSIZE"
					  << " " << std::setw(8) << "RSS"
					  << " " << std::setw(8) << "UTIME"
					  << " " << std::setw(8) << "STIME"
					  << " ";
		}

		std::cout << "INFO" << std::endl;
		header_printed = true;
	}

	// Process different data types
	switch (hdr->type)
	{
	case DKapture::PROC_PID_STAT:
	{
		if (!env.show_header)
		{
			break;
		}
		const struct ProcPidStat *stat =
			reinterpret_cast<const struct ProcPidStat *>(hdr->data);

		std::cout << std::setw(5) << hdr->pid << " " << std::setw(5)
				  << hdr->tgid << " " << std::setw(16) << hdr->comm << " "
				  << std::setw(5) << get_state_char(stat->state) << " "
				  << std::setw(8) << "STAT"
				  << " ";

		if (env.verbose)
		{
			std::cout << std::setw(8) << (stat->vsize / 1024) << " "
					  << std::setw(8) << (stat->rss / 1024) << " "
					  << std::setw(8) << format_time(stat->utime) << " "
					  << std::setw(8) << format_time(stat->stime) << " ";
		}

		std::cout << "PPID:" << stat->ppid << " PGID:" << stat->pgid
				  << " SID:" << stat->sid << " NICE:" << stat->nice
				  << std::endl;
		break;
	}

	case DKapture::PROC_PID_IO:
	{
		if (!env.show_io)
		{
			break;
		}
		const struct ProcPidIo *io =
			reinterpret_cast<const struct ProcPidIo *>(hdr->data);

		std::cout << std::setw(5) << hdr->pid << " " << std::setw(5)
				  << hdr->tgid << " " << std::setw(16) << hdr->comm << " "
				  << std::setw(5) << " "
				  << " " << std::setw(8) << "IO"
				  << " ";

		if (env.verbose)
		{
			std::cout << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " ";
		}

		std::cout << "R:" << (io->rchar / 1024) << "KB"
				  << " W:" << (io->wchar / 1024) << "KB"
				  << " RB:" << (io->read_bytes / 1024) << "KB"
				  << " WB:" << (io->write_bytes / 1024) << "KB" << std::endl;
		break;
	}

	case DKapture::PROC_PID_traffic:
	{
		if (!env.show_traffic)
		{
			break;
		}
		const struct ProcPidTraffic *traffic =
			reinterpret_cast<const struct ProcPidTraffic *>(hdr->data);

		std::cout << std::setw(5) << hdr->pid << " " << std::setw(5)
				  << hdr->tgid << " " << std::setw(16) << hdr->comm << " "
				  << std::setw(5) << " "
				  << " " << std::setw(8) << "NET"
				  << " ";

		if (env.verbose)
		{
			std::cout << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " ";
		}

		std::cout << "IN:" << (traffic->rbytes / 1024) << "KB"
				  << " OUT:" << (traffic->wbytes / 1024) << "KB" << std::endl;
		break;
	}

	case DKapture::PROC_PID_STATM:
	{
		if (!env.show_statm)
		{
			break;
		}
		const struct ProcPidStatm *statm =
			reinterpret_cast<const struct ProcPidStatm *>(hdr->data);

		std::cout << std::setw(5) << hdr->pid << " " << std::setw(5)
				  << hdr->tgid << " " << std::setw(16) << hdr->comm << " "
				  << std::setw(5) << " "
				  << " " << std::setw(8) << "MEM"
				  << " ";

		if (env.verbose)
		{
			std::cout << std::setw(8) << (statm->size * 4) << " "
					  << std::setw(8) << (statm->resident * 4) << " "
					  << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " ";
		}

		std::cout << "SIZE:" << (statm->size * 4) << "KB"
				  << " RES:" << (statm->resident * 4) << "KB"
				  << " SHARED:" << (statm->shared * 4) << "KB"
				  << " TEXT:" << (statm->text * 4) << "KB"
				  << " DATA:" << (statm->data * 4) << "KB" << std::endl;
		break;
	}

	case DKapture::PROC_PID_STATUS:
	{
		if (!env.show_status)
		{
			break;
		}
		const struct ProcPidStatus *status =
			reinterpret_cast<const struct ProcPidStatus *>(hdr->data);

		std::cout << std::setw(5) << hdr->pid << " " << std::setw(5)
				  << hdr->tgid << " " << std::setw(16) << hdr->comm << " "
				  << std::setw(5) << get_state_char(status->state) << " "
				  << std::setw(8) << "STATUS"
				  << " ";

		if (env.verbose)
		{
			std::cout << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " ";
		}

		std::cout << "UID:" << status->uid[0] << " EUID:" << status->uid[1]
				  << " GID:" << status->gid[0] << " EGID:" << status->gid[1]
				  << " TRACER:" << status->tracer_pid << std::endl;
		break;
	}

	case DKapture::PROC_PID_SCHEDSTAT:
	{
		if (!env.show_schedstat)
		{
			break;
		}
		const struct ProcPidSchedstat *schedstat =
			reinterpret_cast<const struct ProcPidSchedstat *>(hdr->data);

		std::cout << std::setw(5) << hdr->pid << " " << std::setw(5)
				  << hdr->tgid << " " << std::setw(16) << hdr->comm << " "
				  << std::setw(5) << " "
				  << " " << std::setw(8) << "SCHED"
				  << " ";

		if (env.verbose)
		{
			std::cout << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " ";
		}

		std::cout << "CPU:" << (schedstat->cpu_time / 1000000) << "ms"
				  << " WAIT:" << (schedstat->rq_wait_time / 1000000) << "ms"
				  << " SLICES:" << schedstat->timeslices << std::endl;
		break;
	}

	case DKapture::PROC_PID_FD:
	{
		const struct ProcPidFd *fd =
			reinterpret_cast<const struct ProcPidFd *>(hdr->data);

		std::cout << std::setw(5) << hdr->pid << " " << std::setw(5)
				  << hdr->tgid << " " << std::setw(16) << hdr->comm << " "
				  << std::setw(5) << " "
				  << " " << std::setw(8) << "FD"
				  << " ";

		if (env.verbose)
		{
			std::cout << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " ";
		}

		std::cout << "FD:" << fd->fd << " INODE:" << fd->inode
				  << " DEV:" << std::hex << fd->dev << std::dec
				  << " MODE:" << std::oct << fd->i_mode << std::dec
				  << std::endl;
		break;
	}
	case DKapture::PROC_PID_NS:
	{
		if (!env.show_ns)
		{
			break;
		}
		const struct ProcPidNs *ns =
			reinterpret_cast<const struct ProcPidNs *>(hdr->data);
		std::cout << std::setw(5) << hdr->pid << " " << std::setw(5)
				  << hdr->tgid << " " << std::setw(16) << hdr->comm << " "
				  << std::setw(5) << " "
				  << " " << std::setw(8) << "NS"
				  << " ";

		if (env.verbose)
		{
			std::cout << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " ";
		}

		std::cout << "CGROUP:[" << ns->cgroup << "] IPC:[" << ns->ipc
				  << "] MNT:[" << ns->mnt << "] NET:[" << ns->net << "] PID:["
				  << ns->pid << "] PID_FOR_CHILDREN:[" << ns->pid_for_children
				  << "] TIME:[" << ns->time << "] TIME_FOR_CHILDREN:["
				  << ns->time_for_children << "] USER:[" << ns->user
				  << "] UTS:[" << ns->uts << "]" << std::endl;
		break;
	}
	case DKapture::PROC_PID_LOGINUID:
	{
		if (!env.show_loginuid)
		{
			break;
		}
		const struct ProcPidLoginuid *loginuid =
			reinterpret_cast<const struct ProcPidLoginuid *>(hdr->data);
		std::cout << std::setw(5) << hdr->pid << " " << std::setw(5)
				  << hdr->tgid << " " << std::setw(16) << hdr->comm << " "
				  << std::setw(5) << " "
				  << " " << std::setw(8) << "LOGINUID"
				  << " ";

		if (env.verbose)
		{
			std::cout << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " " << std::setw(8) << " "
					  << " ";
		}

		std::cout << loginuid->loginuid.val << std::endl;
		break;
	}
	default:
		if (env.verbose)
		{
			std::cout << std::setw(5) << hdr->pid << " " << std::setw(5)
					  << hdr->tgid << " " << std::setw(16) << hdr->comm << " "
					  << std::setw(5) << " "
					  << " " << std::setw(8) << "UNKNOWN"
					  << " "
					  << "Type:" << hdr->type << std::endl;
		}
		break;
	}

	return 0;
}

// Trigger the BPF iterator
void trigger_iterator()
{
	int iter_fd = -1;

	iter_fd = bpf_iter_create(bpf_link__fd(obj->links.dump_task));
	if (iter_fd < 0)
	{
		std::cerr << "Error creating BPF iterator\n";
		return;
	}
	char *buf = (char *)malloc(4096);
	if (!buf)
	{
		std::cerr << "Failed to allocate buffer memory\n";
		close(iter_fd);
		return;
	}
	while (read(iter_fd, buf, 4096) > 0)
	{
	}
	free(buf);

	close(iter_fd);
	iter_fd = -1;
}

int main(int argc, char **argv)
{
	int err;
	int iter_fd = -1;
	char buf[8];

	// Parse command line arguments
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
	{
		return err;
	}

	register_signal();
	libbpf_set_print(libbpf_print_fn);

	// Open BPF program
	obj = proc_info_bpf::open();
	if (!obj)
	{
		std::cerr << "Failed to open BPF program: " << errno << " ("
				  << strerror(errno) << ")" << std::endl;
		return 1;
	}

	// Load BPF program
	if (proc_info_bpf::load(obj))
	{
		std::cerr << "Failed to load BPF program" << std::endl;
		proc_info_bpf::destroy(obj);
		return 1;
	}

	union bpf_attr attr = {};
	attr.test.prog_fd = bpf_get_prog_fd(obj->progs.proc_info_init);
	bpf_syscall(BPF_PROG_TEST_RUN, attr);

	// Attach BPF program
	if (proc_info_bpf::attach(obj))
	{
		std::cerr << "Failed to attach BPF program" << std::endl;
		proc_info_bpf::destroy(obj);
		return 1;
	}
	// Set up ring buffer callback
	rb = ring_buffer__new(
		bpf_map__fd(obj->maps.dk_shared_mem),
		handle_event,
		NULL,
		NULL
	);
	if (!rb)
	{
		std::cerr << "Failed to create ring buffer: " << errno << " ("
				  << strerror(errno) << ")" << std::endl;
		proc_info_bpf::detach(obj);
		proc_info_bpf::destroy(obj);
		return 1;
	}

	// Trigger the iterator to collect process information
	iter_fd = bpf_iter_create(bpf_link__fd(obj->links.dump_task));
	if (iter_fd < 0)
	{
		std::cerr << "Error creating BPF iterator\n";
		return 1;
	}
	while (read(iter_fd, buf, sizeof(buf)) > 0)
	{
	}
	close(iter_fd);
	iter_fd = -1;
	exit_flag = true;

	// Process events from ring buffer until exit signal received
	while (1)
	{
		err = ring_buffer__poll(rb, 0);
		if (err < 0 && err != -EINTR)
		{
			std::cerr << "Error polling ring buffer: " << err << std::endl;
			break;
		}
		if (err == 0)
		{
			break;
		}
	}
err_out:
	// Cleanup resources
	std::cerr << "Cleaning up resources..." << std::endl;
	ring_buffer__free(rb);
	proc_info_bpf::detach(obj);
	proc_info_bpf::destroy(obj);

	return 0;
}