#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "jhash.h"
#include "Kstr-utils.h"
#include "Kcom.h"

#define PATH_MAX 4096  // Maximum path length
#define MAX_ENTRY 1000 // Maximum number of entries in the maps

// Structure to hold buffer information
struct Buf
{
	char path[PATH_MAX]; // Path of the file
	char log[PATH_MAX];	 // Log information
};

// Map to hold memory pool for buffers
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);				// Key type
	__type(value, struct Buf);		// Value type
	__uint(max_entries, MAX_ENTRY); // Maximum entries
} mem_pool SEC(".maps");

// Structure to hold arguments for execve
struct Args
{
	struct linux_binprm *bprm; // Binary parameter
	int fd;					   // File descriptor
	struct filename *filename; // Filename structure
	int flags;				   // Flags
};

// Map to hold arguments for execve
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);				// Key type
	__type(value, struct Args);		// Value type
	__uint(max_entries, MAX_ENTRY); // Maximum entries
} args_map SEC(".maps");

// Structure to define filtering rules
struct Rule
{
	char target_path[PATH_MAX]; // Target path to filter
	u32 depth;					// Depth for parent process tracking
	u32 uid;					// User ID for filtering
};

// Map to hold filtering rules
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);			// Key type
	__type(value, struct Rule); // Value type
	__uint(max_entries, 1);		// Maximum entries
} filter SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024); // 1 MB
} logs SEC(".maps");

// Function to concatenate strings with a limit
static inline void strncat(void *dst, long dsz, const void *src, long ssz)
{
	char *d = (char *)(dst);
	const char *s = (const char *)src;
	// Copy until the source string ends or destination space runs out
	while (ssz > 0 && dsz > 0)
	{
		if (*s == 0)
		{
			return; // Stop if end of source string is reached
		}
		*d++ = *s++; // Copy character
		ssz--;
		dsz--; // Decrement sizes
	}
}

// Buffer for mirroring
static struct Buf buf_mirror = {};

// Kernel probe for execve
SEC("kprobe/bprm_execve")
int BPF_KPROBE(
	bprm_execve,
	struct linux_binprm *bprm,
	int fd,
	struct filename *filename,
	int flags
)
{
	long ret = 0;
	struct Args args =
		{.bprm = bprm, .fd = fd, .filename = filename, .flags = flags};
	pid_t pid = bpf_get_current_pid_tgid(); // Get current process ID
	ret = bpf_map_update_elem(
		&args_map,
		&pid,
		&args,
		BPF_ANY
	); // Update args map
	if (ret != 0)
	{
		bpf_printk(
			"error: bpf_map_update_elem(%ld): %d",
			pid,
			ret
		); // Log error
	}
	return 0; // Return success
}

// Kernel return probe for execve
SEC("kretprobe/bprm_execve")
int BPF_KRETPROBE(bprm_execve_ret, int _ret)
{
	pid_t pid;
	long ret;
	struct Args *args;
	pid = bpf_get_current_pid_tgid(); // Get current process ID
	int key = pid;
	args = bpf_map_lookup_elem(&args_map, &key); // Lookup args
	if (args == NULL)
	{
		bpf_printk("fail to call bpf_map_lookup_elem"); // Log error
		goto exit;
	}
	ret = bpf_map_update_elem(
		&mem_pool,
		&key,
		&buf_mirror,
		BPF_ANY
	); // Update memory pool
	if (ret != 0)
	{
		bpf_printk(
			"error: fail to call bpf_map_update_elem: %d",
			ret
		); // Log error
		goto exit;
	}
	struct Buf *buf = bpf_map_lookup_elem(&mem_pool, &key); // Lookup buffer
	if (buf == NULL)
	{
		bpf_printk("fail to call bpf_map_lookup_elem: %d",
				   ret); // Log error
		goto exit;
	}
	ret = bpf_probe_read_kernel(
		buf->path,
		PATH_MAX,
		args->filename->iname
	); // Read filename
	if (ret)
	{
		bpf_printk("error: bpf_probe_read_kernel %d", ret); // Log error
		goto exit;
	}

	char *filepath = buf->path; // Get file path
	key = 0;					// Reset key for rule lookup
	struct task_struct *current;
	struct Rule *rule;
	rule = bpf_map_lookup_elem(&filter, &key); // Lookup filtering rule
	if (!rule)
	{
		goto exit; // No rule found
	}
	// Check if the file path matches the target path in the rule
	if (rule->target_path[0] && strncmp(filepath, rule->target_path, PATH_MAX))
	{
		goto exit; // Path does not match rule
	}

	u32 depth = rule->depth; // Get depth from rule
	if (depth > 128)
	{
		depth = 128; // Limit depth to 50
	}
	u32 uid = bpf_get_current_uid_gid(); // Get current user ID
	if (rule->uid != (u32)(-1) && uid != rule->uid)
	{
		goto exit; // User ID does not match rule
	}

	current = (struct task_struct *)bpf_get_current_task(); // Get current task
	ret = bpf_probe_read_kernel(
		filepath,
		16,
		&current->comm
	); // Read command name
	if (ret)
	{
		bpf_printk("fail to read comm: %d", ret); // Log error
		goto exit;
	}

	// Prepare logging data
	u64 data[] = {(u64)filepath, (u64)pid};
	char *pbuf = buf->path;	  // Buffer for path
	char *log = buf->log;	  // Buffer for log
	long log_left = PATH_MAX; // Remaining space in log

	// Format the log message
	ret = bpf_snprintf(pbuf, 32, "%s(%lu)", data, sizeof(data));
	if (ret < 1)
	{
		bpf_printk("error: bpf_snprintf: %d", ret); // Log error
		goto exit;
	}
	if (ret > 32)
	{
		goto exit; // Overflow check
	}
	strncat(log, log_left, pbuf, 32); // Concatenate to log
	log_left -= ret - 1;			  // Update remaining space
	log += ret - 1;					  // Move log pointer

	// Traverse parent tasks to build log
	int loop_limit = 0; // Limit for loops
	do
	{
		ret = bpf_probe_read_kernel(
			&current,
			sizeof(current),
			&current->real_parent
		); // Read parent task
		if (ret)
		{
			bpf_printk("fail to read parent: %d", ret); // Log error
			break;
		}
		ret = bpf_probe_read_kernel(
			&pid,
			sizeof(pid),
			&current->pid
		); // Read parent PID
		if (ret)
		{
			bpf_printk("fail to read pid: %d", ret); // Log error
			break;
		}
		char comm[16] = {0}; // Buffer for command
		ret = bpf_probe_read_kernel(
			comm,
			sizeof(comm),
			&current->comm
		); // Read command name
		if (ret)
		{
			bpf_printk("fail to read comm: %d", ret); // Log error
			break;
		}
		// Format parent task log entry
		u64 data[] = {(u64)comm, (u64)pid};
		ret = bpf_snprintf(pbuf, 32, "<-%s(%lu)", data, sizeof(data));
		if (ret < 1)
		{
			bpf_printk("error: bpf_snprintf: %d", ret); // Log error
			break;
		}
		if (ret > 32)
		{
			bpf_err("impossible code branch reached");
			break; // Overflow check
		}
		strncat(log, log_left, pbuf, 32); // Concatenate to log
		log_left -= ret - 1;			  // Update remaining space
		log += ret - 1;					  // Move log pointer
		if (pid == 1 || loop_limit++ >= depth)
		{
			break; // Stop if reached root or limit
		}
	} while (1);

	DEBUG(0, "%s", buf->log);
	// log_left not include the terminating character
	ret =
		bpf_ringbuf_output(&logs, buf->log, sizeof(buf->log) - log_left + 1, 0);
	if (ret)
	{
		bpf_err("ringbuf output: %ld", ret);
	}
exit:
	// Clean up maps
	bpf_map_delete_elem(&mem_pool, &key);
	bpf_map_delete_elem(&args_map, &key);
	return 0; // Return success
}

// License information
char _license[] SEC("license") = "GPL";