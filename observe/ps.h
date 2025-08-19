#ifndef _PS_H
#define _PS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "vmlinux.h"

	struct dcapture_task
	{
		pid_t pid;
		char comm[TASK_COMM_LEN];
		int state;
		pid_t ppid;
		pid_t pgid;
		pid_t sid;
		int tty_nr;
		int tty_pgrp;
		unsigned int flags;
		unsigned long cmin_flt;
		unsigned long cmaj_flt;
		unsigned long min_flt;
		unsigned long maj_flt;
		unsigned long long utime;
		unsigned long long stime;
		unsigned long long cutime;
		unsigned long long cstime;
		int priority;
		int nice;
		int num_threads;
		unsigned long long start_time;
		unsigned long vsize;
		unsigned long rss;
		unsigned long rsslim;
		unsigned long start_code;
		unsigned long end_code;
		unsigned long start_stack;
		unsigned long kstkesp;
		unsigned long kstkeip;
		unsigned long signal;
		unsigned long blocked;
		unsigned long sigignore;
		unsigned long sigcatch;
		unsigned long wchan;
		int exit_signal;
		int processor;
		unsigned int rt_priority;
		unsigned int policy;
		unsigned long long delayacct_blkio_ticks;
		unsigned long guest_time;
		long cguest_time;
		unsigned long start_data;
		unsigned long end_data;
		unsigned long start_brk;
		unsigned long arg_start;
		unsigned long arg_end;
		unsigned long env_start;
		unsigned long env_end;
		int exit_code;

		// statm
		unsigned long size;
		unsigned long resident;
		unsigned long shared;
		unsigned long text;
		unsigned long data;
	};

#ifdef __cplusplus
}
#endif

#endif
