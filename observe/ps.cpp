// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <unistd.h>
#include <argp.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <signal.h>
#include <atomic>
#include <sys/syscall.h>

#include "dkapture.h"
#include "com.h"

// Command line options configuration
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

static std::atomic<bool> exit_flag(false);

const char *argp_program_version = "ps 1.0";
const char *argp_program_bug_address = NULL;

static const char argp_program_doc[] = "ps - Display process status "
									   "information\n"
									   "\n"
									   "BPF version of standard ps command for "
									   "displaying process information\n";

static const struct argp_option opts[] = {
	{"verbose", 'v', NULL, 0, "Display verbose output"},
	{"no-header", 'H', NULL, 0, "Don't display header"},
	{"wide", 'w', NULL, 0, "Don't truncate output"},
	{"threads", 'T', NULL, 0, "Display all threads"},
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

static int handle_event(void *ctx, const void *data, size_t data_sz)
{
	const DKapture::DataHdr *hdr = static_cast<const DKapture::DataHdr *>(data);
	const struct ProcPidStat *stat = reinterpret_cast<const struct ProcPidStat *>(hdr->data);
	static bool header_printed = false;
	static int event_count = 0;

	// Print event info if verbose mode
	if (env.verbose)
	{
		std::cerr << "Received event #" << ++event_count
				  << ", size: " << data_sz << " bytes" << std::endl;
	}

	// Print table header if needed and not yet printed
	if (env.show_header && !header_printed)
	{
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

		header_printed = true;
	}

	// Calculate CPU usage (simple approximation)
	unsigned long long total_time = stat->utime + stat->stime;
	double cpu_usage = 0.0; // Would require two sample points for actual CPU
							// usage

	// Calculate memory usage (KB)
	unsigned long memory = stat->vsize / 1024;

	// Convert CPU time to readable format (min:sec)
	std::string cpu_time = format_time(total_time);

	// Output process information
	std::cout << std::setw(5) << hdr->pid << " " << std::setw(5) << stat->ppid
			  << " " << std::setw(5) << stat->pgid << " ";

	if (env.verbose)
	{
		std::cout << std::setw(5) << stat->tty_nr << " " << std::setw(3)
				  << stat->nice << " " << std::setw(6) << stat->num_threads
				  << " " << std::setw(8) << memory << " ";
	}

	std::cout << std::setw(1) << get_state_char(stat->state) << " "
			  << std::fixed << std::setprecision(1) << std::setw(8) << cpu_usage
			  << " " << std::setw(8) << cpu_time << " " << hdr->comm
			  << std::endl;

	return 0;
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

	register_signal();

	DKapture *dk = DKapture::new_instance();
	if (!dk)
	{
		std::cerr << "Failed to create DKapture instance" << std::endl;
		return 1;
	}

	if (dk->open() != 0)
	{
		std::cerr << "Failed to open DKapture (need root?)" << std::endl;
		delete dk;
		return 1;
	}

	dk->read(DKapture::PROC_PID_STAT, handle_event, nullptr);

	dk->close();
	delete dk;

	return 0;
}
