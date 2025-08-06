# dkapture性能测试

## proc遍历读取进程信息

测试条件：

1. 仅遍历读取/proc/[pid]/stat信息，作为示例。
2. 循环遍历100次，每次之间无间隔。
3. 遍历的是系统的所有线程（非进程）。

```bash
$ sudo strace -cf ./proc-read-test 100 1>/dev/null 
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 34.41    0.991042           3    257483           read
 32.73    0.942615           3    302186         2 openat
 19.78    0.569749           1    302184           close
 10.21    0.293955           3     89400           getdents64
  2.83    0.081454           1     44706           newfstatat
  0.04    0.001169           1       704           write
  0.00    0.000000           0        22           mmap
  0.00    0.000000           0         6           mprotect
  0.00    0.000000           0         1           munmap
  0.00    0.000000           0         4           brk
  0.00    0.000000           0         1         1 ioctl
  0.00    0.000000           0         2           pread64
  0.00    0.000000           0         1         1 access
  0.00    0.000000           0         1           execve
  0.00    0.000000           0         1           arch_prctl
  0.00    0.000000           0         1           futex
  0.00    0.000000           0         1           set_tid_address
  0.00    0.000000           0         1           set_robust_list
  0.00    0.000000           0         1           prlimit64
  0.00    0.000000           0         1           getrandom
  0.00    0.000000           0         1           rseq
------ ----------- ----------- --------- --------- ----------------
100.00    2.879984           2    996708         4 total
```

## dkapture读取进程信息

测试条件：

1. 仅遍历读取/proc/[pid]/stat信息，作为示例。
2. 循环遍历100次，每次之间休眠500us作为间隔。
3. dkapture数据容忍有效时间设置为1ms，即超过1ms再读数据，数据就会强制执行更新，不再使用内存旧数据。
4. 遍历的是系统的所有线程（非进程）。

```bash
$ sudo strace -cf so/dkapture 100 1>/dev/null 
strace: Process 1542886 attached
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 87.04    0.118218          76      1555           read
 10.95    0.014872         118       125         3 bpf
  0.80    0.001091         109        10           munmap
  0.53    0.000720          13        53           mmap
  0.30    0.000402           4       100           clock_nanosleep
  0.28    0.000381           2       132           close
  0.03    0.000045           7         6           mremap
  0.02    0.000025          25         1           clone3
  0.01    0.000013           2         5           rt_sigprocmask
  0.01    0.000011           0        13           openat
  0.01    0.000007           0        13           mprotect
  0.00    0.000005           1         3           dup2
  0.00    0.000004           4         1           madvise
  0.00    0.000004           2         2           rseq
  0.00    0.000003           1         3           lseek
  0.00    0.000003           1         2           uname
  0.00    0.000003           3         1           epoll_ctl
  0.00    0.000002           2         1           rt_sigaction
  0.00    0.000002           2         1           sysinfo
  0.00    0.000002           2         1           epoll_create1
  0.00    0.000001           0         2           set_robust_list
  0.00    0.000000           0         4           brk
  0.00    0.000000           0         2           pread64
  0.00    0.000000           0         1         1 access
  0.00    0.000000           0         1           execve
  0.00    0.000000           0         1           arch_prctl
  0.00    0.000000           0         1           futex
  0.00    0.000000           0         1           set_tid_address
  0.00    0.000000           0        12           newfstatat
  0.00    0.000000           0         1           prlimit64
  0.00    0.000000           0         1           getrandom
  0.00    0.000000           0         3           memfd_create
  0.00    0.000000           0         2         1 faccessat2
------ ----------- ----------- --------- --------- ----------------
100.00    0.135814          65      2060         5 total
```

## 核心代码对比

1. proc目录遍历

```c++
void traverse_proc()
{
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir)
    {
        printf("Failed to open /proc directory\n");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != nullptr)
    {
        // 检查是否是数字目录（即 PID）
        if (entry->d_type == DT_DIR &&
            std::all_of(entry->d_name, entry->d_name + std::strlen(entry->d_name), ::isdigit))
        {
            std::string pid = std::string(entry->d_name);
            std::string task = "/proc/" + pid + "/task";
            DIR *task_dir = opendir(task.c_str());
            if (!task_dir)
            {
                printf("Failed to open %s directory\n", task.c_str());
                continue;
            }
            struct dirent *task_entry;
            while ((task_entry = readdir(task_dir)) != nullptr)
            {
                pid = std::string(task_entry->d_name);
                if (pid == ".." || pid == ".")
                {
                    continue; // 跳过 "." 和 ".." 目录
                }
                read_proc_stat(task_entry->d_name);
            }
            closedir(task_dir);
        }
    }

    closedir(proc_dir);
}
```

2. dkapture

```c++

ssize_t Dkapture::read(const char *path, char *buf, size_t bsz)
{
    if (m_last_update + m_lifetime < milliseconds())
    {
        m_last_update = milliseconds();
        update();
    }
    copy_to_buf(path, buf, bsz);
    return 0;
}

```
