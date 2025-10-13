// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

#include "xhci-snoop.skel.h"
#include "com.h"

#define TASK_COMM_LEN 16

// Event type definitions
enum xhci_event_type
{
	XHCI_ALLOC_DEV = 0,
	XHCI_FREE_DEV,
	XHCI_URB_ENQUEUE,
	XHCI_URB_GIVEBACK,
	XHCI_HANDLE_EVENT,
	XHCI_HANDLE_TRANSFER,
	XHCI_QUEUE_TRB,
	XHCI_SETUP_DEVICE,
	XHCI_RING_ALLOC,
	// New event types
	XHCI_ADD_ENDPOINT,
	XHCI_ADDRESS_CTRL_CTX,
	XHCI_ADDRESS_CTX,
	XHCI_ALLOC_VIRT_DEVICE,
	XHCI_CONFIGURE_ENDPOINT,
	XHCI_CONFIGURE_ENDPOINT_CTRL_CTX,
	XHCI_DBC_ALLOC_REQUEST,
	XHCI_DBC_FREE_REQUEST,
	XHCI_DBC_GADGET_EP_QUEUE,
	XHCI_DBC_GIVEBACK_REQUEST,
	XHCI_DBC_HANDLE_EVENT,
	XHCI_DBC_HANDLE_TRANSFER,
	XHCI_DBC_QUEUE_REQUEST,
	XHCI_DBG_ADDRESS,
	XHCI_DBG_CANCEL_URB,
	XHCI_DBG_CONTEXT_CHANGE,
	XHCI_DBG_INIT,
	XHCI_DBG_QUIRKS,
	XHCI_DBG_RESET_EP,
	XHCI_DBG_RING_EXPANSION,
	XHCI_DISCOVER_OR_RESET_DEVICE,
	XHCI_FREE_VIRT_DEVICE,
	XHCI_GET_PORT_STATUS,
	XHCI_HANDLE_CMD_ADDR_DEV,
	XHCI_HANDLE_CMD_CONFIG_EP,
	XHCI_HANDLE_CMD_DISABLE_SLOT,
	XHCI_HANDLE_CMD_RESET_DEV,
	XHCI_HANDLE_CMD_RESET_EP,
	XHCI_HANDLE_CMD_SET_DEQ,
	XHCI_HANDLE_CMD_SET_DEQ_EP,
	XHCI_HANDLE_CMD_STOP_EP,
	XHCI_HANDLE_COMMAND,
	XHCI_HANDLE_PORT_STATUS,
	XHCI_HUB_STATUS_DATA,
	XHCI_INC_DEQ,
	XHCI_INC_ENQ,
	XHCI_RING_EP_DOORBELL,
	XHCI_RING_EXPANSION,
	XHCI_RING_FREE,
	XHCI_RING_HOST_DOORBELL,
	XHCI_SETUP_ADDRESSABLE_VIRT_DEVICE,
	XHCI_SETUP_DEVICE_SLOT,
	XHCI_STOP_DEVICE,
	XHCI_URB_DEQUEUE,
};

// Event structures (should match BPF definitions)
struct xhci_alloc_dev_event_t
{
	unsigned int event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	unsigned long long timestamp;
	unsigned int info;
	unsigned int info2;
	unsigned int tt_info;
	unsigned int state;
};

struct xhci_free_dev_event_t
{
	unsigned int event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	unsigned long long timestamp;
	unsigned int info;
	unsigned int info2;
	unsigned int tt_info;
	unsigned int state;
};

struct xhci_urb_enqueue_event_t
{
	unsigned int event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	unsigned long long timestamp;
	unsigned long long urb;
	unsigned int pipe;
	unsigned int stream;
	int status;
	unsigned int flags;
	int num_mapped_sgs;
	int num_sgs;
	int length;
	int actual;
	int epnum;
	int dir_in;
	int type;
	int slot_id;
};

struct xhci_urb_giveback_event_t
{
	unsigned int event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	unsigned long long timestamp;
	unsigned long long urb;
	unsigned int pipe;
	unsigned int stream;
	int status;
	unsigned int flags;
	int num_mapped_sgs;
	int num_sgs;
	int length;
	int actual;
	int epnum;
	int dir_in;
	int type;
	int slot_id;
};

struct xhci_handle_event_event_t
{
	unsigned int event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	unsigned long long timestamp;
	unsigned int type;
	unsigned int field0;
	unsigned int field1;
	unsigned int field2;
	unsigned int field3;
};

struct xhci_handle_transfer_event_t
{
	unsigned int event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	unsigned long long timestamp;
	unsigned int type;
	unsigned int field0;
	unsigned int field1;
	unsigned int field2;
	unsigned int field3;
};

struct xhci_queue_trb_event_t
{
	unsigned int event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	unsigned long long timestamp;
	unsigned int type;
	unsigned int field0;
	unsigned int field1;
	unsigned int field2;
	unsigned int field3;
};

struct xhci_setup_device_event_t
{
	unsigned int event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	unsigned long long timestamp;
	unsigned long long vdev;
	unsigned long long out_ctx;
	unsigned long long in_ctx;
	int devnum;
	int state;
	int speed;
	unsigned char portnum;
	unsigned char level;
	int slot_id;
};

struct xhci_ring_alloc_event_t
{
	unsigned int event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	unsigned long long timestamp;
	unsigned int type;
	unsigned long long ring;
	unsigned long long enq;
	unsigned long long deq;
	unsigned long long enq_seg;
	unsigned long long deq_seg;
	unsigned int num_segs;
	unsigned int stream_id;
	unsigned int cycle_state;
	unsigned int bounce_buf_len;
};

// New event structures
struct xhci_add_endpoint_event_t
{
	unsigned int event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	unsigned long long timestamp;
	unsigned int info;
	unsigned int info2;
	unsigned long long deq;
	unsigned int tx_info;
};

struct xhci_address_ctx_event_t
{
	unsigned int event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	unsigned long long timestamp;
	int ctx_64;
	unsigned int ctx_type;
	unsigned long long ctx_dma;
	unsigned long long ctx_va;
	unsigned int ctx_ep_num;
	unsigned int ctx_data;
};

struct xhci_alloc_virt_device_event_t
{
	unsigned int event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	unsigned long long timestamp;
	unsigned long long vdev;
	unsigned long long out_ctx;
	unsigned long long in_ctx;
	int devnum;
	int state;
	int speed;
	unsigned char portnum;
	unsigned char level;
	int slot_id;
};

struct xhci_ring_free_event_t
{
	unsigned int event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	unsigned long long timestamp;
	unsigned int type;
	unsigned long long ring;
	unsigned long long enq;
	unsigned long long deq;
	unsigned long long enq_seg;
	unsigned long long deq_seg;
	unsigned int num_segs;
	unsigned int stream_id;
	unsigned int cycle_state;
	unsigned int bounce_buf_len;
};

struct xhci_inc_deq_event_t
{
	unsigned int event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	unsigned long long timestamp;
	unsigned int type;
	unsigned long long ring;
	unsigned long long enq;
	unsigned long long deq;
	unsigned long long enq_seg;
	unsigned long long deq_seg;
	unsigned int num_segs;
	unsigned int stream_id;
	unsigned int cycle_state;
	unsigned int bounce_buf_len;
};

struct xhci_inc_enq_event_t
{
	unsigned int event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	unsigned long long timestamp;
	unsigned int type;
	unsigned long long ring;
	unsigned long long enq;
	unsigned long long deq;
	unsigned long long enq_seg;
	unsigned long long deq_seg;
	unsigned int num_segs;
	unsigned int stream_id;
	unsigned int cycle_state;
	unsigned int bounce_buf_len;
};

struct xhci_ring_ep_doorbell_event_t
{
	unsigned int event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	unsigned long long timestamp;
	unsigned int slot;
	unsigned int doorbell;
};

struct xhci_urb_dequeue_event_t
{
	unsigned int event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	unsigned long long timestamp;
	unsigned long long urb;
	unsigned int pipe;
	unsigned int stream;
	int status;
	unsigned int flags;
	int num_mapped_sgs;
	int num_sgs;
	int length;
	int actual;
	int epnum;
	int dir_in;
	int type;
	int slot_id;
};

struct xhci_dbg_address_event_t
{
	unsigned int event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	unsigned long long timestamp;
	char msg[256];
};

// Generic event structure for simple slot context tracepoints
struct xhci_slot_ctx_event_t
{
	unsigned int event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	unsigned long long timestamp;
	unsigned int info;
	unsigned int info2;
	unsigned int tt_info;
	unsigned int state;
};

static struct env
{
	bool verbose;
	bool timestamp;
	int target_pid;
	int target_tid;
	char *target_comm;
	unsigned long duration;
} env = {
	.verbose = false,
	.timestamp = false,
	.target_pid = 0,
	.target_tid = 0,
	.target_comm = NULL,
	.duration = 0,
};

const char *argp_program_version = "xhci-snoop 1.0";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/"
									   "master/libbpf-tools";
const char argp_program_doc[] =
	"Trace xHCI (USB 3.0) host controller operations.\n"
	"\n"
	"USAGE: xhci-snoop [-h] [-v] [-t] [-p PID] [-T TID] [-c COMM] [-D "
	"DURATION]\n"
	"\n"
	"EXAMPLES:\n"
	"    xhci-snoop             # trace all xHCI operations\n"
	"    xhci-snoop -t          # include timestamps\n"
	"    xhci-snoop -p 1234     # only trace PID 1234\n"
	"    xhci-snoop -c kworker  # only trace command containing 'kworker'\n";

static const struct argp_option opts[] = {
	{"verbose", 'v', NULL, 0, "Verbose debug output"},
	{"timestamp", 't', NULL, 0, "Include timestamp on output"},
	{"pid", 'p', "PID", 0, "Trace process with this PID only"},
	{"tid", 'T', "TID", 0, "Trace thread with this TID only"},
	{"comm", 'c', "COMM", 0, "Trace command containing this string"},
	{"duration", 'D', "DURATION", 0, "Total duration of trace in seconds"},
	{NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key)
	{
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 't':
		env.timestamp = true;
		break;
	case 'p':
		errno = 0;
		env.target_pid = strtol(arg, NULL, 10);
		if (errno)
		{
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'T':
		errno = 0;
		env.target_tid = strtol(arg, NULL, 10);
		if (errno)
		{
			fprintf(stderr, "invalid TID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		env.target_comm = arg;
		break;
	case 'D':
		errno = 0;
		env.duration = strtoul(arg, NULL, 10);
		if (errno)
		{
			fprintf(stderr, "invalid duration: %s\n", arg);
			argp_usage(state);
		}
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

static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
	{
		return 0;
	}
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static void print_header()
{
	if (env.timestamp)
	{
		printf("%-14s ", "TIME(s)");
	}
	printf(
		"%-16s %-7s %-7s %-20s %s\n",
		"COMM",
		"PID",
		"TID",
		"EVENT",
		"DETAILS"
	);
}

static const char *get_usb_type_string(int type)
{
	switch (type)
	{
	case 0:
		return "control";
	case 1:
		return "isoc";
	case 2:
		return "bulk";
	case 3:
		return "intr";
	default:
		return "unknown";
	}
}

static void print_timestamp()
{
	if (env.timestamp)
	{
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		printf("%-14.6f ", ts.tv_sec + ts.tv_nsec / 1e9);
	}
}

static bool should_filter_event(pid_t pid, pid_t tid, const char *comm)
{
	if (env.target_pid && pid != env.target_pid)
	{
		return true;
	}
	if (env.target_tid && tid != env.target_tid)
	{
		return true;
	}
	if (env.target_comm && !strstr(comm, env.target_comm))
	{
		return true;
	}
	return false;
}

static void print_event_alloc_dev(struct xhci_alloc_dev_event_t *e)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-20s info=0x%x info2=0x%x tt_info=0x%x state=0x%x\n",
		e->comm,
		e->pid,
		e->tid,
		"xhci_alloc_dev",
		e->info,
		e->info2,
		e->tt_info,
		e->state
	);
}

static void print_event_free_dev(struct xhci_free_dev_event_t *e)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-20s info=0x%x info2=0x%x tt_info=0x%x state=0x%x\n",
		e->comm,
		e->pid,
		e->tid,
		"xhci_free_dev",
		e->info,
		e->info2,
		e->tt_info,
		e->state
	);
}

static void print_event_urb_enqueue(struct xhci_urb_enqueue_event_t *e)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-20s urb=0x%llx ep%d%s-%s slot=%d len=%d/%d "
		"stream=%u\n",
		e->comm,
		e->pid,
		e->tid,
		"xhci_urb_enqueue",
		e->urb,
		e->epnum,
		e->dir_in ? "in" : "out",
		get_usb_type_string(e->type),
		e->slot_id,
		e->actual,
		e->length,
		e->stream
	);
}

static void print_event_urb_giveback(struct xhci_urb_giveback_event_t *e)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-20s urb=0x%llx ep%d%s-%s slot=%d len=%d/%d "
		"status=%d\n",
		e->comm,
		e->pid,
		e->tid,
		"xhci_urb_giveback",
		e->urb,
		e->epnum,
		e->dir_in ? "in" : "out",
		get_usb_type_string(e->type),
		e->slot_id,
		e->actual,
		e->length,
		e->status
	);
}

static void print_event_handle_event(struct xhci_handle_event_event_t *e)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-20s type=%u trb=0x%x,0x%x,0x%x,0x%x\n",
		e->comm,
		e->pid,
		e->tid,
		"xhci_handle_event",
		e->type,
		e->field0,
		e->field1,
		e->field2,
		e->field3
	);
}

static void print_event_handle_transfer(struct xhci_handle_transfer_event_t *e)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-20s type=%u trb=0x%x,0x%x,0x%x,0x%x\n",
		e->comm,
		e->pid,
		e->tid,
		"xhci_handle_transfer",
		e->type,
		e->field0,
		e->field1,
		e->field2,
		e->field3
	);
}

static void print_event_queue_trb(struct xhci_queue_trb_event_t *e)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-20s type=%u trb=0x%x,0x%x,0x%x,0x%x\n",
		e->comm,
		e->pid,
		e->tid,
		"xhci_queue_trb",
		e->type,
		e->field0,
		e->field1,
		e->field2,
		e->field3
	);
}

static void print_event_setup_device(struct xhci_setup_device_event_t *e)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-20s vdev=0x%llx devnum=%d state=%d speed=%d port=%d "
		"level=%d slot=%d\n",
		e->comm,
		e->pid,
		e->tid,
		"xhci_setup_device",
		e->vdev,
		e->devnum,
		e->state,
		e->speed,
		e->portnum,
		e->level,
		e->slot_id
	);
}

static void print_event_ring_alloc(struct xhci_ring_alloc_event_t *e)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-20s type=%u ring=0x%llx segs=%u stream=%u cycle=%u "
		"bounce=%u\n",
		e->comm,
		e->pid,
		e->tid,
		"xhci_ring_alloc",
		e->type,
		e->ring,
		e->num_segs,
		e->stream_id,
		e->cycle_state,
		e->bounce_buf_len
	);
}

// New print functions
static void print_event_add_endpoint(struct xhci_add_endpoint_event_t *e)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-20s info=0x%x info2=0x%x deq=0x%llx tx_info=0x%x\n",
		e->comm,
		e->pid,
		e->tid,
		"xhci_add_endpoint",
		e->info,
		e->info2,
		e->deq,
		e->tx_info
	);
}

static void print_event_address_ctx(struct xhci_address_ctx_event_t *e)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-20s ctx_64=%d type=%u dma=0x%llx va=0x%llx "
		"ep_num=%u\n",
		e->comm,
		e->pid,
		e->tid,
		"xhci_address_ctx",
		e->ctx_64,
		e->ctx_type,
		e->ctx_dma,
		e->ctx_va,
		e->ctx_ep_num
	);
}

static void
print_event_alloc_virt_device(struct xhci_alloc_virt_device_event_t *e)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-20s vdev=0x%llx devnum=%d state=%d speed=%d port=%d "
		"level=%d slot=%d\n",
		e->comm,
		e->pid,
		e->tid,
		"xhci_alloc_virt_device",
		e->vdev,
		e->devnum,
		e->state,
		e->speed,
		e->portnum,
		e->level,
		e->slot_id
	);
}

static void print_event_configure_endpoint(struct xhci_slot_ctx_event_t *e)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-20s info=0x%x info2=0x%x tt_info=0x%x state=0x%x\n",
		e->comm,
		e->pid,
		e->tid,
		"xhci_configure_endpoint",
		e->info,
		e->info2,
		e->tt_info,
		e->state
	);
}

static void print_event_ring_free(struct xhci_ring_free_event_t *e)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-20s type=%u ring=0x%llx segs=%u stream=%u cycle=%u "
		"bounce=%u\n",
		e->comm,
		e->pid,
		e->tid,
		"xhci_ring_free",
		e->type,
		e->ring,
		e->num_segs,
		e->stream_id,
		e->cycle_state,
		e->bounce_buf_len
	);
}

static void print_event_inc_deq(struct xhci_inc_deq_event_t *e)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-20s type=%u ring=0x%llx enq=0x%llx deq=0x%llx "
		"segs=%u stream=%u\n",
		e->comm,
		e->pid,
		e->tid,
		"xhci_inc_deq",
		e->type,
		e->ring,
		e->enq,
		e->deq,
		e->num_segs,
		e->stream_id
	);
}

static void print_event_inc_enq(struct xhci_inc_enq_event_t *e)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-20s type=%u ring=0x%llx enq=0x%llx deq=0x%llx "
		"segs=%u stream=%u\n",
		e->comm,
		e->pid,
		e->tid,
		"xhci_inc_enq",
		e->type,
		e->ring,
		e->enq,
		e->deq,
		e->num_segs,
		e->stream_id
	);
}

static void print_event_ring_ep_doorbell(struct xhci_ring_ep_doorbell_event_t *e
)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-20s slot=%u doorbell=0x%x\n",
		e->comm,
		e->pid,
		e->tid,
		"xhci_ring_ep_doorbell",
		e->slot,
		e->doorbell
	);
}

static void print_event_urb_dequeue(struct xhci_urb_dequeue_event_t *e)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-20s urb=0x%llx ep%d%s-%s slot=%d len=%d/%d "
		"status=%d stream=%u\n",
		e->comm,
		e->pid,
		e->tid,
		"xhci_urb_dequeue",
		e->urb,
		e->epnum,
		e->dir_in ? "in" : "out",
		get_usb_type_string(e->type),
		e->slot_id,
		e->actual,
		e->length,
		e->status,
		e->stream
	);
}

static void print_event_dbg_address(struct xhci_dbg_address_event_t *e)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-20s msg=\"%s\"\n",
		e->comm,
		e->pid,
		e->tid,
		"xhci_dbg_address",
		e->msg
	);
}

// Generic print function for slot context events
static void
print_event_slot_ctx(struct xhci_slot_ctx_event_t *e, const char *event_name)
{
	if (should_filter_event(e->pid, e->tid, e->comm))
	{
		return;
	}

	print_timestamp();
	printf(
		"%-16s %-7d %-7d %-20s info=0x%x info2=0x%x tt_info=0x%x state=0x%x\n",
		e->comm,
		e->pid,
		e->tid,
		event_name,
		e->info,
		e->info2,
		e->tt_info,
		e->state
	);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	// Determine event type by event_type field
	unsigned int *event_type = (unsigned int *)data;

	switch (*event_type)
	{
	case XHCI_ALLOC_DEV:
		print_event_alloc_dev((struct xhci_alloc_dev_event_t *)data);
		break;
	case XHCI_FREE_DEV:
		print_event_free_dev((struct xhci_free_dev_event_t *)data);
		break;
	case XHCI_URB_ENQUEUE:
		print_event_urb_enqueue((struct xhci_urb_enqueue_event_t *)data);
		break;
	case XHCI_URB_GIVEBACK:
		print_event_urb_giveback((struct xhci_urb_giveback_event_t *)data);
		break;
	case XHCI_HANDLE_EVENT:
		print_event_handle_event((struct xhci_handle_event_event_t *)data);
		break;
	case XHCI_HANDLE_TRANSFER:
		print_event_handle_transfer((struct xhci_handle_transfer_event_t *)data
		);
		break;
	case XHCI_QUEUE_TRB:
		print_event_queue_trb((struct xhci_queue_trb_event_t *)data);
		break;
	case XHCI_SETUP_DEVICE:
		print_event_setup_device((struct xhci_setup_device_event_t *)data);
		break;
	case XHCI_RING_ALLOC:
		print_event_ring_alloc((struct xhci_ring_alloc_event_t *)data);
		break;
	case XHCI_ADD_ENDPOINT:
		print_event_add_endpoint((struct xhci_add_endpoint_event_t *)data);
		break;
	case XHCI_ADDRESS_CTX:
		print_event_address_ctx((struct xhci_address_ctx_event_t *)data);
		break;
	case XHCI_ALLOC_VIRT_DEVICE:
		print_event_alloc_virt_device(
			(struct xhci_alloc_virt_device_event_t *)data
		);
		break;
	case XHCI_CONFIGURE_ENDPOINT:
		print_event_configure_endpoint((struct xhci_slot_ctx_event_t *)data);
		break;
	case XHCI_RING_FREE:
		print_event_ring_free((struct xhci_ring_free_event_t *)data);
		break;
	case XHCI_INC_DEQ:
		print_event_inc_deq((struct xhci_inc_deq_event_t *)data);
		break;
	case XHCI_INC_ENQ:
		print_event_inc_enq((struct xhci_inc_enq_event_t *)data);
		break;
	case XHCI_RING_EP_DOORBELL:
		print_event_ring_ep_doorbell(
			(struct xhci_ring_ep_doorbell_event_t *)data
		);
		break;
	case XHCI_URB_DEQUEUE:
		print_event_urb_dequeue((struct xhci_urb_dequeue_event_t *)data);
		break;
	case XHCI_DBG_ADDRESS:
		print_event_dbg_address((struct xhci_dbg_address_event_t *)data);
		break;
	case XHCI_SETUP_ADDRESSABLE_VIRT_DEVICE:
		print_event_alloc_virt_device(
			(struct xhci_alloc_virt_device_event_t *)data
		);
		break;
	case XHCI_FREE_VIRT_DEVICE:
		print_event_alloc_virt_device(
			(struct xhci_alloc_virt_device_event_t *)data
		);
		break;
	case XHCI_SETUP_DEVICE_SLOT:
		print_event_slot_ctx(
			(struct xhci_slot_ctx_event_t *)data,
			"xhci_setup_device_slot"
		);
		break;
	case XHCI_HANDLE_CMD_ADDR_DEV:
		print_event_slot_ctx(
			(struct xhci_slot_ctx_event_t *)data,
			"xhci_handle_cmd_addr_dev"
		);
		break;
	case XHCI_HANDLE_CMD_CONFIG_EP:
		print_event_slot_ctx(
			(struct xhci_slot_ctx_event_t *)data,
			"xhci_handle_cmd_config_ep"
		);
		break;
	case XHCI_HANDLE_CMD_DISABLE_SLOT:
		print_event_slot_ctx(
			(struct xhci_slot_ctx_event_t *)data,
			"xhci_handle_cmd_disable_slot"
		);
		break;
	case XHCI_HANDLE_CMD_RESET_DEV:
		print_event_slot_ctx(
			(struct xhci_slot_ctx_event_t *)data,
			"xhci_handle_cmd_reset_dev"
		);
		break;
	case XHCI_HANDLE_CMD_RESET_EP:
		print_event_slot_ctx(
			(struct xhci_slot_ctx_event_t *)data,
			"xhci_handle_cmd_reset_ep"
		);
		break;
	case XHCI_HANDLE_CMD_SET_DEQ:
		print_event_slot_ctx(
			(struct xhci_slot_ctx_event_t *)data,
			"xhci_handle_cmd_set_deq"
		);
		break;
	case XHCI_HANDLE_CMD_SET_DEQ_EP:
		print_event_slot_ctx(
			(struct xhci_slot_ctx_event_t *)data,
			"xhci_handle_cmd_set_deq_ep"
		);
		break;
	case XHCI_HANDLE_CMD_STOP_EP:
		print_event_slot_ctx(
			(struct xhci_slot_ctx_event_t *)data,
			"xhci_handle_cmd_stop_ep"
		);
		break;
	case XHCI_CONFIGURE_ENDPOINT_CTRL_CTX:
		print_event_slot_ctx(
			(struct xhci_slot_ctx_event_t *)data,
			"xhci_configure_endpoint_ctrl_ctx"
		);
		break;
	case XHCI_ADDRESS_CTRL_CTX:
		print_event_slot_ctx(
			(struct xhci_slot_ctx_event_t *)data,
			"xhci_address_ctrl_ctx"
		);
		break;
	case XHCI_DISCOVER_OR_RESET_DEVICE:
		print_event_slot_ctx(
			(struct xhci_slot_ctx_event_t *)data,
			"xhci_discover_or_reset_device"
		);
		break;
	case XHCI_STOP_DEVICE:
		print_event_slot_ctx(
			(struct xhci_slot_ctx_event_t *)data,
			"xhci_stop_device"
		);
		break;
	case XHCI_RING_EXPANSION:
		print_event_ring_free((struct xhci_ring_free_event_t *)data);
		break;
	case XHCI_RING_HOST_DOORBELL:
		print_event_ring_ep_doorbell(
			(struct xhci_ring_ep_doorbell_event_t *)data
		);
		break;
	case XHCI_DBG_CANCEL_URB:
	case XHCI_DBG_CONTEXT_CHANGE:
	case XHCI_DBG_INIT:
	case XHCI_DBG_QUIRKS:
	case XHCI_DBG_RESET_EP:
	case XHCI_DBG_RING_EXPANSION:
		print_event_dbg_address((struct xhci_dbg_address_event_t *)data);
		break;
	case XHCI_HANDLE_COMMAND:
		print_event_handle_event((struct xhci_handle_event_event_t *)data);
		break;
	case XHCI_HANDLE_PORT_STATUS:
		print_event_handle_event((struct xhci_handle_event_event_t *)data);
		break;
	case XHCI_HUB_STATUS_DATA:
		print_event_handle_event((struct xhci_handle_event_event_t *)data);
		break;
	case XHCI_GET_PORT_STATUS:
		print_event_handle_event((struct xhci_handle_event_event_t *)data);
		break;
	case XHCI_DBC_ALLOC_REQUEST:
	case XHCI_DBC_FREE_REQUEST:
	case XHCI_DBC_GADGET_EP_QUEUE:
	case XHCI_DBC_GIVEBACK_REQUEST:
	case XHCI_DBC_HANDLE_EVENT:
	case XHCI_DBC_HANDLE_TRANSFER:
	case XHCI_DBC_QUEUE_REQUEST:
		print_event_handle_event((struct xhci_handle_event_event_t *)data);
		break;
	default:
		printf("Unknown event type=%u size=%zu\n", *event_type, data_sz);
		break;
	}

	return 0;
}

int main(int argc, char **argv)
{
	time_t start_time;
	struct ring_buffer *rb = NULL;
	struct xhci_snoop_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
	{
		return err;
	}

	/* Set up libbpf */
	libbpf_set_print(libbpf_print_fn);

	/* Open and load BPF application */
	skel = xhci_snoop_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load and verify BPF application */
	err = xhci_snoop_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint */
	err = xhci_snoop_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(
		bpf_map__fd(skel->maps.events),
		handle_event,
		NULL,
		NULL
	);
	if (!rb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Set up signal handlers */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Print header */
	print_header();

	/* Record start time for duration checking */
	start_time = time(NULL);

	/* Process events */
	while (!exiting)
	{
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling ring buffer: %d\n", err);
			break;
		}

		if (env.duration && (time(NULL) - start_time) >= env.duration)
		{
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	xhci_snoop_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
