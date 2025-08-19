#ifndef __SWITCH_COUNT_H__
#define __SWITCH_COUNT_H__

#define TASK_COMM_LEN 16
#define MAX_SLOTS 26

struct hkey
{
	__u32 pid;
};

struct hist
{
	char comm[TASK_COMM_LEN];
	__u64 count;
};

#endif
