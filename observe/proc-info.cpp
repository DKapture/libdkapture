// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <unistd.h>
#include <argp.h>

// Include dkapture headers for data structures
#include "dkapture.h"

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
static int handle_event(void *ctx, const void *data, size_t data_sz)
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

static std::vector<DKapture::DataType> build_data_types()
{
	std::vector<DKapture::DataType> dts = {
		DKapture::PROC_PID_STAT,
		DKapture::PROC_PID_FD,
	};

	if (env.show_io)
	{
		dts.push_back(DKapture::PROC_PID_IO);
	}
	if (env.show_traffic)
	{
		dts.push_back(DKapture::PROC_PID_traffic);
	}
	if (env.show_statm)
	{
		dts.push_back(DKapture::PROC_PID_STATM);
	}
	if (env.show_status)
	{
		dts.push_back(DKapture::PROC_PID_STATUS);
	}
	if (env.show_schedstat)
	{
		dts.push_back(DKapture::PROC_PID_SCHEDSTAT);
	}
	if (env.show_ns)
	{
		dts.push_back(DKapture::PROC_PID_NS);
	}
	if (env.show_loginuid)
	{
		dts.push_back(DKapture::PROC_PID_LOGINUID);
	}

	return dts;
}

int main(int argc, char **argv)
{
	int err;

	// Parse command line arguments
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
	{
		return err;
	}

	DKapture *dk = DKapture::new_instance();
	if (!dk)
	{
		std::cerr << "Failed to create DKapture instance" << std::endl;
		return 1;
	}

	if (dk->open(env.verbose ? stderr : stdout, env.verbose ? DKapture::DEBUG : DKapture::INFO) != 0)
	{
		std::cerr << "Failed to open DKapture (need root?)" << std::endl;
		delete dk;
		return 1;
	}

	std::vector<DKapture::DataType> dts = build_data_types();
	err = dk->read(dts, handle_event, nullptr);

	dk->close();
	delete dk;

	return err < 0 ? 1 : 0;
}
