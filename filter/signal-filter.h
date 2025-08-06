#ifndef __SIGNAL_FILTER_H__
#define __SIGNAL_FILTER_H__

#define EVENTNUMBER    2

#define TRACESIGNAL    0
#define FILTERFLAG     1

#define MAX_FILTER_PIDS 64
#define MAX_FILTER_UIDS 64
#define MAX_FILTER_SIGNALS 32

#define MODE_MONITOR_ONLY 0
#define MODE_PID_FILTER 1
#define MODE_UID_FILTER 2
#define MODE_SIGNAL_FILTER 3
#define MODE_RULE_FILTER 4

// Rule structure definition
struct Rule {
    pid_t sender_pid;    // Sender process ID
    pid_t recv_pid;      // Receiver process ID
    uid_t sender_uid;    // Sender user ID
    int sig;             // Signal type
};

#endif