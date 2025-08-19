#ifndef __WAKEUP_H__
#define __WAKEUP_H__

#define TASK_COMM_LEN 30
#define MAX_SLOTS 26

struct hkey
{
	__u32 pid;
};

struct hist
{
	char comm[TASK_COMM_LEN];
	__u64 wakeup_count;
};

#endif
