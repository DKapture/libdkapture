#ifndef __TCP_INSIGHT_H
#define __TCP_INSIGHT_H

#ifndef __KERNEL__
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

/* TCP Event Types - Based on actual available tracepoints */
enum tcp_event_type
{
	TCP_EVENT_STATE_CHANGE = 1,	  /* inet_sock_set_state */
	TCP_EVENT_PERF_SAMPLE = 2,	  /* tcp_probe */
	TCP_EVENT_RETRANSMIT = 3,	  /* tcp_retransmit_skb */
	TCP_EVENT_SEND_RESET = 4,	  /* tcp_send_reset */
	TCP_EVENT_RECV_RESET = 5,	  /* tcp_receive_reset */
	TCP_EVENT_SEND_DATA = 6,	  /* sock_send_length */
	TCP_EVENT_RECV_DATA = 7,	  /* sock_recv_length */
	TCP_EVENT_SOCK_DESTROY = 8,	  /* tcp_destroy_sock */
	TCP_EVENT_CONG_STATE = 9,	  /* tcp_cong_state_set */
	TCP_EVENT_WIN_ADJUST = 10,	  /* tcp_rcv_space_adjust */
	TCP_EVENT_KPROBE_SEND = 11,	  /* kprobe tcp_sendmsg */
	TCP_EVENT_KPROBE_RECV = 12,	  /* kprobe tcp_recvmsg */
	TCP_EVENT_KPROBE_RETRANS = 13 /* kprobe tcp_retransmit_skb */
};

/* TCP States */
#ifndef TCP_ESTABLISHED
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_SYN_RECV 3
#define TCP_FIN_WAIT1 4
#define TCP_FIN_WAIT2 5
#define TCP_TIME_WAIT 6
#define TCP_CLOSE 7
#define TCP_CLOSE_WAIT 8
#define TCP_LAST_ACK 9
#define TCP_LISTEN 10
#define TCP_CLOSING 11
#define TCP_NEW_SYN_RECV 12
#define TCP_MAX_STATES 13
#endif

/* Protocol definitions */
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

/* Address families */
#ifndef AF_INET
#define AF_INET 2
#define AF_INET6 10
#endif

/* Tracepoint argument structures - Following framework standard pattern */

/* inet_sock_set_state tracepoint arguments */
struct tp_inet_sock_set_state
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

/* tcp_retransmit_skb tracepoint arguments */
struct tp_tcp_retransmit_skb
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	const void *skbaddr;
	const void *skaddr;
	int state;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

/* tcp_send_reset tracepoint arguments */
struct tp_tcp_send_reset
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	const void *skbaddr;
	const void *skaddr;
	int state;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

/* tcp_receive_reset tracepoint arguments */
struct tp_tcp_receive_reset
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	const void *skaddr;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
	__u64 sock_cookie;
};

/* sock_send_length tracepoint arguments */
struct tp_sock_send_length
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	void *sk;
	__u16 family;
	__u16 protocol;
	int ret;
	int flags;
};

/* sock_recv_length tracepoint arguments */
struct tp_sock_recv_length
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	void *sk;
	__u16 family;
	__u16 protocol;
	int ret;
	int flags;
};

/* tcp_destroy_sock tracepoint arguments */
struct tp_tcp_destroy_sock
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	const void *skaddr;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
	__u64 sock_cookie;
};

/* tcp_cong_state_set tracepoint arguments */
struct tp_tcp_cong_state_set
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	const void *skaddr;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
	__u8 cong_state;
};

/* tcp_rcv_space_adjust tracepoint arguments */
struct tp_tcp_rcv_space_adjust
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	const void *skaddr;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
	__u64 sock_cookie;
};

/* tcp_probe tracepoint arguments */
struct tp_tcp_probe
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	__u8 saddr[28];
	__u8 daddr[28];
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u32 mark;
	__u16 data_len;
	__u32 snd_nxt;
	__u32 snd_una;
	__u32 snd_cwnd;
	__u32 ssthresh;
	__u32 snd_wnd;
	__u32 srtt;
	__u32 rcv_wnd;
	__u64 sock_cookie;
};

/* Unified TCP event structure */
struct tcp_event
{
	__u64 timestamp;
	__u32 pid;
	__u32 tid;
	enum tcp_event_type type;
	char comm[16];

	/* Network addressing */
	__u16 family;
	__u16 protocol;
	__u16 sport;
	__u16 dport;
	union
	{
		struct
		{
			__u32 saddr;
			__u32 daddr;
		} ipv4;
		struct
		{
			__u8 saddr[16];
			__u8 daddr[16];
		} ipv6;
	} addr;

/* Legacy compatibility fields for user space */
#ifndef __KERNEL__
	__u32 saddr;	  /* IPv4 source address (legacy) */
	__u32 daddr;	  /* IPv4 dest address (legacy) */
	__u8 event_type;  /* Legacy event type */
	__u8 state;		  /* Current TCP state */
	__u32 cwnd;		  /* Congestion window */
	__u32 rtt_us;	  /* RTT in microseconds */
	__u64 bytes;	  /* Bytes transferred */
	char details[64]; /* Additional details */
#endif

	/* Event-specific data */
	union
	{
		/* STATE_CHANGE event */
		struct
		{
			int oldstate;
			int newstate;
			const void *skaddr;
		} state_change;

		/* PERF_SAMPLE event */
		struct
		{
			__u32 mark;
			__u16 data_len;
			__u32 snd_nxt;
			__u32 snd_una;
			__u32 snd_cwnd;
			__u32 ssthresh;
			__u32 snd_wnd;
			__u32 srtt;
			__u32 rcv_wnd;
			__u64 sock_cookie;
		} perf_sample;

		/* RETRANSMIT event */
		struct
		{
			const void *skbaddr;
			const void *skaddr;
			int state;
		} retransmit;

		/* SEND_RESET/RECV_RESET event */
		struct
		{
			const void *skbaddr;
			const void *skaddr;
			int state;
			__u64 sock_cookie;
		} reset;

		/* SEND_DATA/RECV_DATA event */
		struct
		{
			void *sk;
			int ret;
			int flags;
			int length;
		} data_transfer;

		/* SOCK_DESTROY event */
		struct
		{
			const void *skaddr;
			__u64 sock_cookie;
		} destroy;

		/* CONG_STATE event */
		struct
		{
			const void *skaddr;
			__u8 cong_state;
		} cong_state;

		/* WIN_ADJUST event */
		struct
		{
			const void *skaddr;
			__u64 sock_cookie;
		} win_adjust;

		/* KPROBE events */
		struct
		{
			void *sk;
			size_t size;
			int flags;
		} kprobe;
	} data;
};

/* Connection tracking */
struct tcp_connection
{
	__u64 conn_id;
	__u64 start_time;
	__u64 last_seen;
	__u32 pid;
	char comm[16];

	/* Network info */
	__u16 family;
	__u16 sport;
	__u16 dport;
	union
	{
		struct
		{
			__u32 saddr;
			__u32 daddr;
		} ipv4;
		struct
		{
			__u8 saddr[16];
			__u8 daddr[16];
		} ipv6;
	} addr;

	/* TCP state */
	int current_state;
	int prev_state;

	/* Performance metrics */
	__u32 snd_cwnd;
	__u32 ssthresh;
	__u32 srtt;
	__u32 rcv_wnd;
	__u64 bytes_sent;
	__u64 bytes_received;
	__u32 retransmits;
	__u32 resets_sent;
	__u32 resets_received;
};

/* Filter rules */
struct tcp_filter_rule
{
	__u32 pid;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u32 event_mask;
	union
	{
		struct
		{
			__u32 saddr;
			__u32 daddr;
		} ipv4;
		struct
		{
			__u8 saddr[16];
			__u8 daddr[16];
		} ipv6;
	} addr;
	__u32 min_rtt;
	__u32 max_rtt;
	__u64 min_bytes;
	__u64 max_bytes;
	__u32 min_duration;
	__u32 max_duration;
	int tcp_state;
};

/* Global statistics */
struct tcp_global_stats
{
	__u64 total_events;
	__u64 state_changes;
	__u64 connections_opened;
	__u64 connections_closed;
	__u64 bytes_sent;
	__u64 bytes_received;
	__u64 retransmits;
	__u64 resets;
	__u64 cong_events;
	__u64 window_adjusts;
};

/* Command line argument constants */
#define ARG_SPORT 1001
#define ARG_DPORT 1002
#define ARG_MIN_DURATION 1003
#define ARG_MAX_DURATION 1004
#define ARG_MIN_BYTES 1005
#define ARG_MAX_BYTES 1006
#define ARG_MIN_RTT 1007
#define ARG_MAX_RTT 1008

/* Event Masks for filtering */
#define TCP_EVENT_MASK_ALL 0xFFFF

/* Compatibility aliases for user space program */
#ifndef __KERNEL__
typedef struct tcp_filter_rule tcp_rule;
typedef struct tcp_global_stats tcp_stats;

/* Compatibility event type aliases */
#define TCP_EVENT_CONNECT TCP_EVENT_STATE_CHANGE
#define TCP_EVENT_ACCEPT TCP_EVENT_STATE_CHANGE
#define TCP_EVENT_SEND TCP_EVENT_SEND_DATA
#define TCP_EVENT_RECEIVE TCP_EVENT_RECV_DATA
#define TCP_EVENT_CLOSE TCP_EVENT_STATE_CHANGE
#define TCP_EVENT_RESET TCP_EVENT_SEND_RESET
#define TCP_EVENT_CWND_CHANGE TCP_EVENT_PERF_SAMPLE
#define TCP_EVENT_RTT_UPDATE TCP_EVENT_PERF_SAMPLE
#define TCP_EVENT_SLOW_START TCP_EVENT_CONG_STATE
#define TCP_EVENT_CONG_AVOID TCP_EVENT_CONG_STATE
#define TCP_EVENT_FAST_RECOVERY TCP_EVENT_CONG_STATE
#define TCP_EVENT_WINDOW_UPDATE TCP_EVENT_WIN_ADJUST
#define TCP_EVENT_SACK TCP_EVENT_PERF_SAMPLE
#define TCP_EVENT_TIMEOUT TCP_EVENT_RETRANSMIT
#endif

/* Map sizes */
#define MAX_CONNECTIONS 10240
#define MAX_RULES 1024
#define MAX_EVENTS 262144

#endif /* __TCP_INSIGHT_H */