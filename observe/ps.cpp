// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <argp.h>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <unistd.h>

#include "dkapture.h"

static struct env
{
	bool verbose;
	bool show_header;
	bool wide_output;
	bool show_threads;
} env = {
	.verbose = false,
	.show_header = true,
	.wide_output = false,
	.show_threads = false,
};

struct PrintContext
{
	bool header_printed = false;
	int event_count = 0;
};

const char *argp_program_version = "ps 1.0";
const char *argp_program_bug_address = nullptr;

static const char argp_program_doc[] = "ps - Display process status "
									   "information\n"
									   "\n"
									   "DKapture version of standard ps command "
									   "for displaying process information\n";

static const struct argp_option opts[] = {
	{"verbose", 'v', nullptr, 0, "Display verbose output"},
	{"no-header", 'H', nullptr, 0, "Don't display header"},
	{"wide", 'w', nullptr, 0, "Don't truncate output"},
	{"threads", 'T', nullptr, 0, "Display all threads"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	(void)arg;
	(void)state;

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

static std::string format_time(unsigned long long time)
{
	const long ticks = sysconf(_SC_CLK_TCK);
	unsigned long minutes = time / (60 * ticks);
	unsigned long seconds = (time / ticks) % 60;

	char buffer[32];
	snprintf(buffer, sizeof(buffer), "%lu:%02lu", minutes, seconds);
	return std::string(buffer);
}

static char get_state_char(int state)
{
	if (state == 0)
	{
		return 'R';
	}
	if (state & 1)
	{
		return 'S';
	}
	if (state & 2)
	{
		return 'D';
	}
	if (state & 4)
	{
		return 'T';
	}
	if (state & 16)
	{
		return 'Z';
	}
	if (state & 32)
	{
		return 'X';
	}
	return '?';
}

static void print_header(PrintContext &ctx)
{
	if (!env.show_header || ctx.header_printed)
	{
		return;
	}

	std::cout << std::setw(5) << "PID"
			  << " " << std::setw(5) << "PPID"
			  << " " << std::setw(5) << "PGID"
			  << " ";

	if (env.verbose)
	{
		std::cout << std::setw(5) << "TTY"
				  << " " << std::setw(3) << "NI"
				  << " " << std::setw(6) << "THCNT"
				  << " " << std::setw(8) << "VSIZE"
				  << " ";
	}

	std::cout << std::setw(1) << "S"
			  << " " << std::setw(8) << "%CPU"
			  << " " << std::setw(8) << "TIME"
			  << " "
			  << "COMMAND" << std::endl;
	ctx.header_printed = true;
}

static int handle_event(void *ctx, const void *data, size_t data_sz)
{
	if (!ctx || !data || data_sz < sizeof(DKapture::DataHdr))
	{
		return -EINVAL;
	}

	PrintContext &print_ctx = *static_cast<PrintContext *>(ctx);
	const auto *hdr = static_cast<const DKapture::DataHdr *>(data);

	if (hdr->type != DKapture::PROC_PID_STAT)
	{
		return 0;
	}

	if (hdr->dsz < sizeof(DKapture::DataHdr) + sizeof(ProcPidStat) ||
		data_sz < hdr->dsz)
	{
		return -EINVAL;
	}

	if (!env.show_threads && hdr->pid != hdr->tgid)
	{
		return 0;
	}

	if (env.verbose)
	{
		std::cerr << "Received event #" << ++print_ctx.event_count
				  << ", type: " << hdr->type << ", size: " << hdr->dsz
				  << " bytes, pid: " << hdr->pid << ", comm: " << hdr->comm
				  << std::endl;
	}

	print_header(print_ctx);

	const auto *task = reinterpret_cast<const ProcPidStat *>(hdr->data);
	unsigned long long total_time = task->utime + task->stime;
	double cpu_usage = 0.0;
	unsigned long memory = task->vsize / 1024;
	std::string cpu_time = format_time(total_time);

	std::cout << std::setw(5) << hdr->pid << " " << std::setw(5) << task->ppid
			  << " " << std::setw(5) << task->pgid << " ";

	if (env.verbose)
	{
		std::cout << std::setw(5) << task->tty_nr << " " << std::setw(3)
				  << task->nice << " " << std::setw(6) << task->num_threads
				  << " " << std::setw(8) << memory << " ";
	}

	std::cout << std::setw(1) << get_state_char(task->state) << " "
			  << std::fixed << std::setprecision(1) << std::setw(8) << cpu_usage
			  << " " << std::setw(8) << cpu_time << " " << hdr->comm
			  << std::endl;
	return 0;
}

int main(int argc, char **argv)
{
	int err = argp_parse(&argp, argc, argv, 0, nullptr, nullptr);
	if (err)
	{
		return err;
	}

	std::unique_ptr<DKapture> dk(DKapture::new_instance());
	if (!dk)
	{
		std::cerr << "Failed to create DKapture instance" << std::endl;
		return 1;
	}

	err = dk->open(stderr, env.verbose ? DKapture::DEBUG : DKapture::INFO);
	if (err)
	{
		std::cerr << "Failed to open DKapture: " << -err << " ("
				  << std::strerror(-err) << ")" << std::endl;
		return 1;
	}

	PrintContext ctx;
	ssize_t ret = dk->read(DKapture::PROC_PID_STAT, handle_event, &ctx);
	if (ret < 0)
	{
		std::cerr << "Failed to read process information: " << -ret << " ("
				  << std::strerror(-ret) << ")" << std::endl;
		dk->close();
		return 1;
	}

	dk->close();
	return 0;
}
