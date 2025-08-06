#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "Ktask.h"
#include "Kmem.h"
#include "Kstr-utils.h"
#include <errno.h>
#include "jhash.h"
#include "Kcom.h"

#define __DEBUG 0

char _license[] SEC("license") = "GPL";

typedef u32 Action;

#define FMODE_READ ((fmode_t)0x1)
#define FMODE_WRITE ((fmode_t)0x2)
#define FMODE_EXEC ((fmode_t)0x20)

struct Rule
{
    union
    {
        struct
        {
            u32 not_pid;
            pid_t pid;
        };
        char process[4096];
    };
    Action act;
    char target[4096];
};

struct BpfData
{
    Action act;
    pid_t pid;
    char process[];
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);           // Key type
    __type(value, struct Rule); // Value type
    __uint(max_entries, 1000);  // Maximum entries
} filter SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_t);
    __type(value, char [4096]);
    __uint(max_entries, 1024);
} pid2path SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024); // 1 MB
} logs SEC(".maps");

static void audit_log(pid_t pid, const char* process, const char* target, Action act)
{
    long ret;
    u32 log_bsz;
    u32 log_sz;
    u32 mkey = __LINE__;
    struct BpfData *log = (typeof(log))malloc_page(mkey);
    if (!log)
    {
        bpf_printk("log buffer full");
        return;
    }

    log->pid = pid;
    log->act = act & 0XFF;
    log_bsz = 4096 - sizeof(log);
    log_sz = sizeof(log);

    u64 data[] = {(u64)process};
    ret = bpf_snprintf(log->process, log_bsz / 2,
            "%s", data, sizeof(data));
    if (ret < 0)
    {
        bpf_printk("error: bpf_snprintf: %ld", ret);
        goto exit;
    }

    if (ret > log_bsz / 2)
    {
        ret = log_bsz / 2;
    }

    log_sz += ret;
    data[0] = (u64)target;
    ret = bpf_snprintf(log->process + ret, log_bsz / 2,
            "%s", data, sizeof(data));
    if (ret < 0)
    {
        bpf_printk("error: bpf_snprintf: %ld", ret);
        goto exit;
    }

    if (ret > log_bsz / 2)
    {
        ret = log_bsz / 2;
    }

    log_sz += ret;

    ret = bpf_ringbuf_output(&logs, log, log_sz, 0);
    if (ret)
    {
        bpf_printk("error: bpf_perf_event_output: %ld", ret);
    }

exit:
    if (log)
    {
        free_page(mkey);
    }
}

struct Event
{
    const char *proc_path;
    const char *file_path;
    int act;
};

static long match_callback(
	struct bpf_map *map,
	const void *key,
	void *value,
	void *ctx)
{
    const char *proc_path;
    const char *file_path;
    int act;

    struct Event *event = ctx;
    struct Rule *rule = value;

    proc_path = event->proc_path;
    file_path = event->file_path;
    act = event->act;
    
    if (rule->not_pid)
    {
        if (!proc_path)
        {
            return 0;
        }
        // Check if process path matches
        if (wildcard_match(rule->process, proc_path, 4096))
        {
            return 0;
        }
    }
    else
    {
        pid_t pid = bpf_get_current_pid_tgid();
        if (rule->pid != pid)
        {
            return 0;
        }
    }
    
    if (__DEBUG)
    {
        bpf_printk("proc fit: %s %s %d",
            proc_path, file_path, act);
    }

    // Check if file path matches
    if (wildcard_match(rule->target, file_path, 4096))
    {
        return 0;
    }

    if (__DEBUG)
    {
        bpf_printk("target fit: %s %s %d",
            proc_path, file_path, act);
    }
    // Check if act is a subset of rule->act
    if (act & rule->act)
    {
        event->act = 0;
    }

    return 1;
}

static bool rules_filter(
    const char *proc_path,
    const char *file_path,
    int act)
{
    struct Event event =
    {
        .act = act,
        .proc_path = proc_path,
        .file_path = file_path
    };

    bpf_for_each_map_elem(
        &filter, match_callback, &event, 0);

    return !!event.act;
}

static int _permission_check(
    const char *path,
    fmode_t mode)
{
    pid_t pid;
    char *proc_path = NULL;
    long ret = 0;

    pid = bpf_get_current_pid_tgid();
    
    proc_path = bpf_map_lookup_elem(&pid2path, &pid);

    if (bpf_strncmp(path, 10, "/root/file") == 0)
    {
        bpf_printk("%d proc fit: %s %s %d",
            pid, proc_path, path, mode);
    }
    
    if (!rules_filter(proc_path, path, mode))
    {
        if (proc_path)
            audit_log(pid, proc_path, path, mode);
        else
        {
            char comm[16];
            ret = bpf_get_current_comm(comm, sizeof(comm));
            if (ret)
            {
                bpf_printk("fail to get current comm: %ld", ret);
            }
            else
            {
                audit_log(pid, comm, path, mode);
            }
        }

        if (__DEBUG)
        {
            bpf_printk("permission denied: %s %d", path, mode);
        }
        ret = -EACCES;
    }

    return ret;
}

static int permission_check(
    struct path *path_st,
    fmode_t mode)
{
    char *path = NULL;
    long ret = 0;

    u32 mkey = __LINE__;
    path = malloc_page(mkey);
    if (!path)
    {
        bpf_printk("path buffer full");
        goto exit;
    }

    ret = bpf_d_path(path_st, path, PAGE_SIZE);
    if (ret < 0)
    {
        bpf_printk("fail to get d_path: %d", ret);
        ret = 0;
        goto exit;
    }

    ret = _permission_check(path, mode);

exit:
    if (path)
    {
        free_page(mkey);
    }

    return ret;
}

SEC("lsm/file_open")
int BPF_PROG(file_open,
             struct file *file, int ret)
{
    if (ret)
    {
        return ret;
    }

    return permission_check(&file->f_path, file->f_mode);
}

static long pid2path_callback(
	struct bpf_map *map,
	const void *key,
	void *value,
	void *ctx)
{
    char *filepath = *(char**)ctx;
    struct Rule *rule = value;
    
    if (!rule)
    {
        filepath[4095] = 0;
        return 0;
    }

    if (!rule->not_pid)
    {
        filepath[4095] = 0;
        return 0;
    }

    if (wildcard_match(rule->process, filepath, 4096))
    {
        filepath[4095] = 0;
        return 0;
    }

    filepath[4095] = 1;
    return 1;
}

static bool pid2path_filter(char *file_path)
{
    bpf_for_each_map_elem(
        &filter, pid2path_callback, &file_path, 0);

    bool ret = !!file_path[4095];
    file_path[4095] = 0;    // use last byte as flag
    return ret;
}

static long thead_exit_callback(
	struct bpf_map *map,
	const void *key,
	void *value,
	void *ctx)
{
    struct Rule *rule = value;
    bool *ret = ctx;

    if (!rule)
    {
        *ret = false;
        return 0;
    }

    if (!rule->not_pid)
    {
        *ret = false;
        return 0;
    }

    *ret = true;
    return 1;
}

static bool thread_exit_filter(void)
{
    bool ret = false;
    bpf_for_each_map_elem(
        &filter, thead_exit_callback, &ret, 0);

    return ret;
}

SEC("fexit/bprm_execve")
int BPF_PROG(bprm_execve,
    struct linux_binprm *bprm,
    int fd,
    struct filename *filename,
    int flags)
{
    long ret = 0;
    pid_t pid;
    char *filepath;

    u32 mkey = __LINE__;
    filepath = malloc_page(mkey);
    if (!filepath)
    {
        bpf_printk("error: malloc_page");
        return 0;
    }

    ret = bpf_probe_read_kernel(filepath, 4096, filename->iname);
    if (ret < 0)
    {
        bpf_printk("error: bpf_probe_read_kernel_str: %ld", ret);
        goto exit;
    }

    if (!pid2path_filter(filepath))
    {
        goto exit;
    }

    pid = bpf_get_current_pid_tgid();

    if (__DEBUG)
    {
        bpf_printk("pid2hash: %s pid: %d", filepath, pid);
    }
    ret = bpf_map_update_elem(&pid2path, &pid, filepath, BPF_ANY);
    if (ret)
    {
        bpf_printk("error: bpf_map_update_elem: %ld", ret);
        goto exit;
    }

exit:
    if (filepath)
    {
        free_page(mkey);
    }
    return 0;
}

SEC("fentry/exit_thread")
int BPF_PROG(exit_thread,
    struct task_struct *tsk)
{
    long ret = 0;
    pid_t pid;

    if (!thread_exit_filter())
    {
        return 0;
    }

    pid = bpf_get_current_pid_tgid();
    ret = bpf_map_delete_elem(&pid2path, &pid);
    if (ret && ret != -ENOENT)
    {
        bpf_printk("error: bpf_map_delete_elem: %ld", ret);
    }

    return 0;
}
