#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "Kcom.h"

#define MAX_ENTRIES 1000

#define MAX_EVENT_SIZE 10240
#define RINGBUF_SIZE (1024 * 256)

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

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, char[4096]);
} filter SEC(".maps");

struct tp_xhci_alloc_dev_ctx_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u32 info;
	u32 info2;
	u32 tt_info;
	u32 state;
};

struct tp_xhci_free_dev_ctx_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u32 info;
	u32 info2;
	u32 tt_info;
	u32 state;
};

struct tp_xhci_urb_enqueue_ctx_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	void *urb;
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

struct tp_xhci_urb_giveback_ctx_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	void *urb;
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

struct tp_xhci_handle_event_ctx_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u32 type;
	u32 field0;
	u32 field1;
	u32 field2;
	u32 field3;
};

struct tp_xhci_handle_transfer_ctx_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u32 type;
	u32 field0;
	u32 field1;
	u32 field2;
	u32 field3;
};

struct tp_xhci_queue_trb_ctx_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u32 type;
	u32 field0;
	u32 field1;
	u32 field2;
	u32 field3;
};

struct tp_xhci_setup_device_ctx_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	void *vdev;
	unsigned long long out_ctx;
	unsigned long long in_ctx;
	int devnum;
	int state;
	int speed;
	u8 portnum;
	u8 level;
	int slot_id;
};

struct tp_xhci_ring_alloc_ctx_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u32 type;
	void *ring;
	u64 enq;
	u64 deq;
	u64 enq_seg;
	u64 deq_seg;
	unsigned int num_segs;
	unsigned int stream_id;
	unsigned int cycle_state;
	unsigned int bounce_buf_len;
};

// New context structures
struct tp_xhci_add_endpoint_ctx_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u32 info;
	u32 info2;
	u64 deq;
	u32 tx_info;
};

struct tp_xhci_address_ctx_ctx_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int ctx_64;
	unsigned ctx_type;
	u64 ctx_dma;
	u64 ctx_va;
	unsigned ctx_ep_num;
	u32 ctx_data;
};

struct tp_xhci_alloc_virt_device_ctx_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	void *vdev;
	u64 out_ctx;
	u64 in_ctx;
	int devnum;
	int state;
	int speed;
	u8 portnum;
	u8 level;
	int slot_id;
};

struct tp_xhci_configure_endpoint_ctx_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u32 info;
	u32 info2;
	u32 tt_info;
	u32 state;
};

struct tp_xhci_ring_free_ctx_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u32 type;
	void *ring;
	u64 enq;
	u64 deq;
	u64 enq_seg;
	u64 deq_seg;
	unsigned int num_segs;
	unsigned int stream_id;
	unsigned int cycle_state;
	unsigned int bounce_buf_len;
};

struct tp_xhci_inc_deq_ctx_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u32 type;
	void *ring;
	u64 enq;
	u64 deq;
	u64 enq_seg;
	u64 deq_seg;
	unsigned int num_segs;
	unsigned int stream_id;
	unsigned int cycle_state;
	unsigned int bounce_buf_len;
};

struct tp_xhci_inc_enq_ctx_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u32 type;
	void *ring;
	u64 enq;
	u64 deq;
	u64 enq_seg;
	u64 deq_seg;
	unsigned int num_segs;
	unsigned int stream_id;
	unsigned int cycle_state;
	unsigned int bounce_buf_len;
};

struct tp_xhci_ring_ep_doorbell_ctx_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u32 slot;
	u32 doorbell;
};

struct tp_xhci_urb_dequeue_ctx_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	void *urb;
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

struct tp_xhci_dbg_address_ctx_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	char msg[256]; // Simplified for BPF
};

// Generic context structure for simple slot context tracepoints
struct tp_xhci_slot_ctx_t
{
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	u32 info;
	u32 info2;
	u32 tt_info;
	u32 state;
};

struct xhci_alloc_dev_event_t
{
	u32 event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	u64 timestamp;
	u32 info;
	u32 info2;
	u32 tt_info;
	u32 state;
};

struct xhci_free_dev_event_t
{
	u32 event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	u64 timestamp;
	u32 info;
	u32 info2;
	u32 tt_info;
	u32 state;
};

struct xhci_urb_enqueue_event_t
{
	u32 event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	u64 timestamp;
	u64 urb;
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
	u32 event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	u64 timestamp;
	u64 urb;
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
	u32 event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	u64 timestamp;
	u32 type;
	u32 field0;
	u32 field1;
	u32 field2;
	u32 field3;
};

struct xhci_handle_transfer_event_t
{
	u32 event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	u64 timestamp;
	u32 type;
	u32 field0;
	u32 field1;
	u32 field2;
	u32 field3;
};

struct xhci_queue_trb_event_t
{
	u32 event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	u64 timestamp;
	u32 type;
	u32 field0;
	u32 field1;
	u32 field2;
	u32 field3;
};

struct xhci_setup_device_event_t
{
	u32 event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	u64 timestamp;
	u64 vdev;
	u64 out_ctx;
	u64 in_ctx;
	int devnum;
	int state;
	int speed;
	u8 portnum;
	u8 level;
	int slot_id;
};

struct xhci_ring_alloc_event_t
{
	u32 event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	u64 timestamp;
	u32 type;
	u64 ring;
	u64 enq;
	u64 deq;
	u64 enq_seg;
	u64 deq_seg;
	unsigned int num_segs;
	unsigned int stream_id;
	unsigned int cycle_state;
	unsigned int bounce_buf_len;
};

// New event structures
struct xhci_add_endpoint_event_t
{
	u32 event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	u64 timestamp;
	u32 info;
	u32 info2;
	u64 deq;
	u32 tx_info;
};

struct xhci_address_ctx_event_t
{
	u32 event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	u64 timestamp;
	int ctx_64;
	unsigned ctx_type;
	u64 ctx_dma;
	u64 ctx_va;
	unsigned ctx_ep_num;
	u32 ctx_data;
};

struct xhci_alloc_virt_device_event_t
{
	u32 event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	u64 timestamp;
	u64 vdev;
	u64 out_ctx;
	u64 in_ctx;
	int devnum;
	int state;
	int speed;
	u8 portnum;
	u8 level;
	int slot_id;
};

struct xhci_ring_free_event_t
{
	u32 event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	u64 timestamp;
	u32 type;
	u64 ring;
	u64 enq;
	u64 deq;
	u64 enq_seg;
	u64 deq_seg;
	unsigned int num_segs;
	unsigned int stream_id;
	unsigned int cycle_state;
	unsigned int bounce_buf_len;
};

struct xhci_inc_deq_event_t
{
	u32 event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	u64 timestamp;
	u32 type;
	u64 ring;
	u64 enq;
	u64 deq;
	u64 enq_seg;
	u64 deq_seg;
	unsigned int num_segs;
	unsigned int stream_id;
	unsigned int cycle_state;
	unsigned int bounce_buf_len;
};

struct xhci_inc_enq_event_t
{
	u32 event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	u64 timestamp;
	u32 type;
	u64 ring;
	u64 enq;
	u64 deq;
	u64 enq_seg;
	u64 deq_seg;
	unsigned int num_segs;
	unsigned int stream_id;
	unsigned int cycle_state;
	unsigned int bounce_buf_len;
};

struct xhci_ring_ep_doorbell_event_t
{
	u32 event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	u64 timestamp;
	u32 slot;
	u32 doorbell;
};

struct xhci_urb_dequeue_event_t
{
	u32 event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	u64 timestamp;
	u64 urb;
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
	u32 event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	u64 timestamp;
	char msg[256];
};

// Generic event structure for simple slot context tracepoints
struct xhci_slot_ctx_event_t
{
	u32 event_type;
	pid_t pid;
	pid_t tid;
	char comm[TASK_COMM_LEN];
	u64 timestamp;
	u32 info;
	u32 info2;
	u32 tt_info;
	u32 state;
};

SEC("tracepoint/xhci_hcd/xhci_alloc_dev")
int tp_xhci_alloc_dev(struct tp_xhci_alloc_dev_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_alloc_dev_event_t event = {0};

	event.event_type = XHCI_ALLOC_DEV;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.info = ctx->info;
	event.info2 = ctx->info2;
	event.tt_info = ctx->tt_info;
	event.state = ctx->state;

	DEBUG(
		0,
		"xhci_alloc_dev: pid: %d, tid: %d, comm: %s, info: %u, info2: %u, "
		"tt_info: %u, state: %u\n",
		event.pid,
		event.tid,
		event.comm,
		event.info,
		event.info2,
		event.tt_info,
		event.state
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

SEC("tracepoint/xhci_hcd/xhci_free_dev")
int tp_xhci_free_dev(struct tp_xhci_free_dev_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_free_dev_event_t event = {0};

	event.event_type = XHCI_FREE_DEV;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.info = ctx->info;
	event.info2 = ctx->info2;
	event.tt_info = ctx->tt_info;
	event.state = ctx->state;

	DEBUG(
		0,
		"xhci_free_dev: pid: %d, tid: %d, comm: %s, info: %u, info2: %u, "
		"tt_info: %u, state: %u\n",
		event.pid,
		event.tid,
		event.comm,
		event.info,
		event.info2,
		event.tt_info,
		event.state
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

SEC("tracepoint/xhci_hcd/xhci_urb_enqueue")
int tp_xhci_urb_enqueue(struct tp_xhci_urb_enqueue_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_urb_enqueue_event_t event = {0};

	event.event_type = XHCI_URB_ENQUEUE;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.urb = (u64)ctx->urb;
	event.pipe = ctx->pipe;
	event.stream = ctx->stream;
	event.status = ctx->status;
	event.flags = ctx->flags;
	event.num_mapped_sgs = ctx->num_mapped_sgs;
	event.num_sgs = ctx->num_sgs;
	event.length = ctx->length;
	event.actual = ctx->actual;
	event.epnum = ctx->epnum;
	event.dir_in = ctx->dir_in;
	event.type = ctx->type;
	event.slot_id = ctx->slot_id;

	DEBUG(
		0,
		"xhci_urb_enqueue: pid: %d, tid: %d, comm: %s, urb: %llx, ep%d%s, "
		"slot: %d, len: %d/%d\n",
		event.pid,
		event.tid,
		event.comm,
		event.urb,
		event.epnum,
		event.dir_in ? "in" : "out",
		event.slot_id,
		event.actual,
		event.length
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

SEC("tracepoint/xhci_hcd/xhci_urb_giveback")
int tp_xhci_urb_giveback(struct tp_xhci_urb_giveback_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_urb_giveback_event_t event = {0};

	event.event_type = XHCI_URB_GIVEBACK;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.urb = (u64)ctx->urb;
	event.pipe = ctx->pipe;
	event.stream = ctx->stream;
	event.status = ctx->status;
	event.flags = ctx->flags;
	event.num_mapped_sgs = ctx->num_mapped_sgs;
	event.num_sgs = ctx->num_sgs;
	event.length = ctx->length;
	event.actual = ctx->actual;
	event.epnum = ctx->epnum;
	event.dir_in = ctx->dir_in;
	event.type = ctx->type;
	event.slot_id = ctx->slot_id;

	DEBUG(
		0,
		"xhci_urb_giveback: pid: %d, tid: %d, comm: %s, urb: %llx, ep%d%s, "
		"slot: %d, len: %d/%d, status: %d\n",
		event.pid,
		event.tid,
		event.comm,
		event.urb,
		event.epnum,
		event.dir_in ? "in" : "out",
		event.slot_id,
		event.actual,
		event.length,
		event.status
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

SEC("tracepoint/xhci_hcd/xhci_handle_event")
int tp_xhci_handle_event(struct tp_xhci_handle_event_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_handle_event_event_t event = {0};

	event.event_type = XHCI_HANDLE_EVENT;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.type = ctx->type;
	event.field0 = ctx->field0;
	event.field1 = ctx->field1;
	event.field2 = ctx->field2;
	event.field3 = ctx->field3;

	DEBUG(
		0,
		"xhci_handle_event: pid: %d, tid: %d, comm: %s, type: %u, fields: %u "
		"%u %u %u\n",
		event.pid,
		event.tid,
		event.comm,
		event.type,
		event.field0,
		event.field1,
		event.field2,
		event.field3
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

SEC("tracepoint/xhci_hcd/xhci_handle_transfer")
int tp_xhci_handle_transfer(struct tp_xhci_handle_transfer_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_handle_transfer_event_t event = {0};

	event.event_type = XHCI_HANDLE_TRANSFER;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.type = ctx->type;
	event.field0 = ctx->field0;
	event.field1 = ctx->field1;
	event.field2 = ctx->field2;
	event.field3 = ctx->field3;

	DEBUG(
		0,
		"xhci_handle_transfer: pid: %d, tid: %d, comm: %s, type: %u, fields: "
		"%u %u %u %u\n",
		event.pid,
		event.tid,
		event.comm,
		event.type,
		event.field0,
		event.field1,
		event.field2,
		event.field3
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

SEC("tracepoint/xhci_hcd/xhci_queue_trb")
int tp_xhci_queue_trb(struct tp_xhci_queue_trb_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_queue_trb_event_t event = {0};

	event.event_type = XHCI_QUEUE_TRB;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.type = ctx->type;
	event.field0 = ctx->field0;
	event.field1 = ctx->field1;
	event.field2 = ctx->field2;
	event.field3 = ctx->field3;

	DEBUG(
		0,
		"xhci_queue_trb: pid: %d, tid: %d, comm: %s, type: %u, fields: %u %u "
		"%u %u\n",
		event.pid,
		event.tid,
		event.comm,
		event.type,
		event.field0,
		event.field1,
		event.field2,
		event.field3
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

SEC("tracepoint/xhci_hcd/xhci_setup_device")
int tp_xhci_setup_device(struct tp_xhci_setup_device_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_setup_device_event_t event = {0};

	event.event_type = XHCI_SETUP_DEVICE;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.vdev = (u64)ctx->vdev;
	event.out_ctx = ctx->out_ctx;
	event.in_ctx = ctx->in_ctx;
	event.devnum = ctx->devnum;
	event.state = ctx->state;
	event.speed = ctx->speed;
	event.portnum = ctx->portnum;
	event.level = ctx->level;
	event.slot_id = ctx->slot_id;

	DEBUG(
		0,
		"xhci_setup_device: pid: %d, tid: %d, comm: %s, vdev: %llx, devnum: "
		"%d, state: %d, speed: %d, port: %d, slot: %d\n",
		event.pid,
		event.tid,
		event.comm,
		event.vdev,
		event.devnum,
		event.state,
		event.speed,
		event.portnum,
		event.slot_id
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

SEC("tracepoint/xhci_hcd/xhci_ring_alloc")
int tp_xhci_ring_alloc(struct tp_xhci_ring_alloc_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_ring_alloc_event_t event = {0};

	event.event_type = XHCI_RING_ALLOC;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.type = ctx->type;
	event.ring = (u64)ctx->ring;
	event.enq = ctx->enq;
	event.deq = ctx->deq;
	event.enq_seg = ctx->enq_seg;
	event.deq_seg = ctx->deq_seg;
	event.num_segs = ctx->num_segs;
	event.stream_id = ctx->stream_id;
	event.cycle_state = ctx->cycle_state;
	event.bounce_buf_len = ctx->bounce_buf_len;

	DEBUG(
		0,
		"xhci_ring_alloc: pid: %d, tid: %d, comm: %s, type: %u, ring: %llx, "
		"segs: %u, stream: %u\n",
		event.pid,
		event.tid,
		event.comm,
		event.type,
		event.ring,
		event.num_segs,
		event.stream_id
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

SEC("tracepoint/xhci_hcd/xhci_add_endpoint")
int tp_xhci_add_endpoint(struct tp_xhci_add_endpoint_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_add_endpoint_event_t event = {0};

	event.event_type = XHCI_ADD_ENDPOINT;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.info = ctx->info;
	event.info2 = ctx->info2;
	event.deq = ctx->deq;
	event.tx_info = ctx->tx_info;

	DEBUG(
		0,
		"xhci_add_endpoint: pid: %d, tid: %d, comm: %s, info: %u, info2: %u, "
		"deq: %llx, tx_info: %u\n",
		event.pid,
		event.tid,
		event.comm,
		event.info,
		event.info2,
		event.deq,
		event.tx_info
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

SEC("tracepoint/xhci_hcd/xhci_address_ctx")
int tp_xhci_address_ctx(struct tp_xhci_address_ctx_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_address_ctx_event_t event = {0};

	event.event_type = XHCI_ADDRESS_CTX;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.ctx_64 = ctx->ctx_64;
	event.ctx_type = ctx->ctx_type;
	event.ctx_dma = ctx->ctx_dma;
	event.ctx_va = (u64)ctx->ctx_va;
	event.ctx_ep_num = ctx->ctx_ep_num;
	event.ctx_data = ctx->ctx_data;

	DEBUG(
		0,
		"xhci_address_ctx: pid: %d, tid: %d, comm: %s, ctx_64: %d, type: %u, "
		"dma: %llx, va: %llx\n",
		event.pid,
		event.tid,
		event.comm,
		event.ctx_64,
		event.ctx_type,
		event.ctx_dma,
		event.ctx_va
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

SEC("tracepoint/xhci_hcd/xhci_alloc_virt_device")
int tp_xhci_alloc_virt_device(struct tp_xhci_alloc_virt_device_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_alloc_virt_device_event_t event = {0};

	event.event_type = XHCI_ALLOC_VIRT_DEVICE;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.vdev = (u64)ctx->vdev;
	event.out_ctx = ctx->out_ctx;
	event.in_ctx = ctx->in_ctx;
	event.devnum = ctx->devnum;
	event.state = ctx->state;
	event.speed = ctx->speed;
	event.portnum = ctx->portnum;
	event.level = ctx->level;
	event.slot_id = ctx->slot_id;

	DEBUG(
		0,
		"xhci_alloc_virt_device: pid: %d, tid: %d, comm: %s, vdev: %llx, "
		"devnum: %d, state: %d, speed: %d, port: %d, slot: %d\n",
		event.pid,
		event.tid,
		event.comm,
		event.vdev,
		event.devnum,
		event.state,
		event.speed,
		event.portnum,
		event.slot_id
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

SEC("tracepoint/xhci_hcd/xhci_configure_endpoint")
int tp_xhci_configure_endpoint(struct tp_xhci_configure_endpoint_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_slot_ctx_event_t event = {0};

	event.event_type = XHCI_CONFIGURE_ENDPOINT;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.info = ctx->info;
	event.info2 = ctx->info2;
	event.tt_info = ctx->tt_info;
	event.state = ctx->state;

	DEBUG(
		0,
		"xhci_configure_endpoint: pid: %d, tid: %d, comm: %s, info: %u, info2: "
		"%u, tt_info: %u, state: %u\n",
		event.pid,
		event.tid,
		event.comm,
		event.info,
		event.info2,
		event.tt_info,
		event.state
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

SEC("tracepoint/xhci_hcd/xhci_ring_free")
int tp_xhci_ring_free(struct tp_xhci_ring_free_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_ring_free_event_t event = {0};

	event.event_type = XHCI_RING_FREE;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.type = ctx->type;
	event.ring = (u64)ctx->ring;
	event.enq = ctx->enq;
	event.deq = ctx->deq;
	event.enq_seg = ctx->enq_seg;
	event.deq_seg = ctx->deq_seg;
	event.num_segs = ctx->num_segs;
	event.stream_id = ctx->stream_id;
	event.cycle_state = ctx->cycle_state;
	event.bounce_buf_len = ctx->bounce_buf_len;

	DEBUG(
		0,
		"xhci_ring_free: pid: %d, tid: %d, comm: %s, type: %u, ring: %llx, "
		"segs: %u, stream: %u\n",
		event.pid,
		event.tid,
		event.comm,
		event.type,
		event.ring,
		event.num_segs,
		event.stream_id
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

SEC("tracepoint/xhci_hcd/xhci_inc_deq")
int tp_xhci_inc_deq(struct tp_xhci_inc_deq_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_inc_deq_event_t event = {0};

	event.event_type = XHCI_INC_DEQ;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.type = ctx->type;
	event.ring = (u64)ctx->ring;
	event.enq = ctx->enq;
	event.deq = ctx->deq;
	event.enq_seg = ctx->enq_seg;
	event.deq_seg = ctx->deq_seg;
	event.num_segs = ctx->num_segs;
	event.stream_id = ctx->stream_id;
	event.cycle_state = ctx->cycle_state;
	event.bounce_buf_len = ctx->bounce_buf_len;

	DEBUG(
		0,
		"xhci_inc_deq: pid: %d, tid: %d, comm: %s, type: %u, ring: %llx, segs: "
		"%u, stream: %u\n",
		event.pid,
		event.tid,
		event.comm,
		event.type,
		event.ring,
		event.num_segs,
		event.stream_id
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

SEC("tracepoint/xhci_hcd/xhci_inc_enq")
int tp_xhci_inc_enq(struct tp_xhci_inc_enq_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_inc_enq_event_t event = {0};

	event.event_type = XHCI_INC_ENQ;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.type = ctx->type;
	event.ring = (u64)ctx->ring;
	event.enq = ctx->enq;
	event.deq = ctx->deq;
	event.enq_seg = ctx->enq_seg;
	event.deq_seg = ctx->deq_seg;
	event.num_segs = ctx->num_segs;
	event.stream_id = ctx->stream_id;
	event.cycle_state = ctx->cycle_state;
	event.bounce_buf_len = ctx->bounce_buf_len;

	DEBUG(
		0,
		"xhci_inc_enq: pid: %d, tid: %d, comm: %s, type: %u, ring: %llx, segs: "
		"%u, stream: %u\n",
		event.pid,
		event.tid,
		event.comm,
		event.type,
		event.ring,
		event.num_segs,
		event.stream_id
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

SEC("tracepoint/xhci_hcd/xhci_ring_ep_doorbell")
int tp_xhci_ring_ep_doorbell(struct tp_xhci_ring_ep_doorbell_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_ring_ep_doorbell_event_t event = {0};

	event.event_type = XHCI_RING_EP_DOORBELL;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.slot = ctx->slot;
	event.doorbell = ctx->doorbell;

	DEBUG(
		0,
		"xhci_ring_ep_doorbell: pid: %d, tid: %d, comm: %s, slot: %u, "
		"doorbell: %u\n",
		event.pid,
		event.tid,
		event.comm,
		event.slot,
		event.doorbell
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

SEC("tracepoint/xhci_hcd/xhci_urb_dequeue")
int tp_xhci_urb_dequeue(struct tp_xhci_urb_dequeue_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_urb_dequeue_event_t event = {0};

	event.event_type = XHCI_URB_DEQUEUE;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.urb = (u64)ctx->urb;
	event.pipe = ctx->pipe;
	event.stream = ctx->stream;
	event.status = ctx->status;
	event.flags = ctx->flags;
	event.num_mapped_sgs = ctx->num_mapped_sgs;
	event.num_sgs = ctx->num_sgs;
	event.length = ctx->length;
	event.actual = ctx->actual;
	event.epnum = ctx->epnum;
	event.dir_in = ctx->dir_in;
	event.type = ctx->type;
	event.slot_id = ctx->slot_id;

	DEBUG(
		0,
		"xhci_urb_dequeue: pid: %d, tid: %d, comm: %s, urb: %llx, ep%d%s, "
		"slot: %d, len: %d/%d, status: %d\n",
		event.pid,
		event.tid,
		event.comm,
		event.urb,
		event.epnum,
		event.dir_in ? "in" : "out",
		event.slot_id,
		event.actual,
		event.length,
		event.status
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

// Slot context tracepoints using generic structure
SEC("tracepoint/xhci_hcd/xhci_setup_addressable_virt_device")
int tp_xhci_setup_addressable_virt_device(
	struct tp_xhci_alloc_virt_device_ctx_t *ctx
)
{
	long ret = 0;
	struct xhci_alloc_virt_device_event_t event = {0};

	event.event_type = XHCI_SETUP_ADDRESSABLE_VIRT_DEVICE;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.vdev = (u64)ctx->vdev;
	event.out_ctx = ctx->out_ctx;
	event.in_ctx = ctx->in_ctx;
	event.devnum = ctx->devnum;
	event.state = ctx->state;
	event.speed = ctx->speed;
	event.portnum = ctx->portnum;
	event.level = ctx->level;
	event.slot_id = ctx->slot_id;

	DEBUG(
		0,
		"xhci_setup_addressable_virt_device: pid: %d, tid: %d, comm: %s, vdev: "
		"%llx, devnum: %d, state: %d, speed: %d, port: %d, slot: %d\n",
		event.pid,
		event.tid,
		event.comm,
		event.vdev,
		event.devnum,
		event.state,
		event.speed,
		event.portnum,
		event.slot_id
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

SEC("tracepoint/xhci_hcd/xhci_free_virt_device")
int tp_xhci_free_virt_device(struct tp_xhci_alloc_virt_device_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_alloc_virt_device_event_t event = {0};

	event.event_type = XHCI_FREE_VIRT_DEVICE;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.vdev = (u64)ctx->vdev;
	event.out_ctx = ctx->out_ctx;
	event.in_ctx = ctx->in_ctx;
	event.devnum = ctx->devnum;
	event.state = ctx->state;
	event.speed = ctx->speed;
	event.portnum = ctx->portnum;
	event.level = ctx->level;
	event.slot_id = ctx->slot_id;

	DEBUG(
		0,
		"xhci_free_virt_device: pid: %d, tid: %d, comm: %s, vdev: %llx, "
		"devnum: %d, state: %d, speed: %d, port: %d, slot: %d\n",
		event.pid,
		event.tid,
		event.comm,
		event.vdev,
		event.devnum,
		event.state,
		event.speed,
		event.portnum,
		event.slot_id
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

SEC("tracepoint/xhci_hcd/xhci_setup_device_slot")
int tp_xhci_setup_device_slot(struct tp_xhci_slot_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_slot_ctx_event_t event = {0};

	event.event_type = XHCI_SETUP_DEVICE_SLOT;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.info = ctx->info;
	event.info2 = ctx->info2;
	event.tt_info = ctx->tt_info;
	event.state = ctx->state;

	DEBUG(
		0,
		"xhci_setup_device_slot: pid: %d, tid: %d, comm: %s, info: %u, info2: "
		"%u, tt_info: %u, state: %u\n",
		event.pid,
		event.tid,
		event.comm,
		event.info,
		event.info2,
		event.tt_info,
		event.state
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

// Handle command tracepoints using generic slot context structure
SEC("tracepoint/xhci_hcd/xhci_handle_cmd_addr_dev")
int tp_xhci_handle_cmd_addr_dev(struct tp_xhci_slot_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_slot_ctx_event_t event = {0};

	event.event_type = XHCI_HANDLE_CMD_ADDR_DEV;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.info = ctx->info;
	event.info2 = ctx->info2;
	event.tt_info = ctx->tt_info;
	event.state = ctx->state;

	DEBUG(
		0,
		"xhci_handle_cmd_addr_dev: pid: %d, tid: %d, comm: %s, info: %u, "
		"info2: %u, tt_info: %u, state: %u\n",
		event.pid,
		event.tid,
		event.comm,
		event.info,
		event.info2,
		event.tt_info,
		event.state
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

SEC("tracepoint/xhci_hcd/xhci_handle_cmd_config_ep")
int tp_xhci_handle_cmd_config_ep(struct tp_xhci_slot_ctx_t *ctx)
{
	long ret = 0;
	struct xhci_slot_ctx_event_t event = {0};

	event.event_type = XHCI_HANDLE_CMD_CONFIG_EP;
	event.timestamp = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	ret = bpf_get_current_comm(&event.comm, sizeof(event.comm));
	if (ret < 0)
	{
		bpf_err("Failed to get current comm\n");
	}

	event.info = ctx->info;
	event.info2 = ctx->info2;
	event.tt_info = ctx->tt_info;
	event.state = ctx->state;

	DEBUG(
		0,
		"xhci_handle_cmd_config_ep: pid: %d, tid: %d, comm: %s, info: %u, "
		"info2: %u, tt_info: %u, state: %u\n",
		event.pid,
		event.tid,
		event.comm,
		event.info,
		event.info2,
		event.tt_info,
		event.state
	);

	ret = bpf_ringbuf_output(&events, &event, sizeof(event), 0);
	if (ret < 0)
	{
		bpf_err("Failed to output event to ring buffer\n");
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";