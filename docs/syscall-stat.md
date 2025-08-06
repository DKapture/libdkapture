# syscall-stat

## 功能描述

syscall-stat可以用来统计指定进程（如果不指定，则是所有进程）系统调用频率的工具，支持使用pid和进程文件路径来过滤被跟踪的进程，当两者都指定了的时候，优先使用pid作为过滤条件，进程文件路径将被忽略。

小技巧：使用进程文件路径或进程名作为过滤条件时，最大的好处就是，可以跟踪一些短暂运行的程序。

## 使用方式

`sudo ./observe/syscall-stat -h`

```c
$ sudo ./observe/syscall-stat -h
Usage: ./observe/syscall-stat [option]
  statistic the frequency of syscall calling of a specific process.
the process can be specified by pid, filepath or comm.
if more than one option is specified, the priority is pid > filepath > comm.

Options:
  -p, --pid [pid]
        stat the syscalls of process of [pid]

  -f, --file [file]
        stat syscalls of process whose filepath is [file]

  -c, --comm [comm]
        stat syscalls of process whose name is [comm]

  -i, --interval [interval]
        the interval to stat syscalls

  -t, --top [top]
        output information in top way

  -h, --help 
        print this help message
```

- -f、-p、-c选项只能三选一，如果指定了多个，则按此优先级进行使用：pid > filepath > comm
- -t 用于指定输出方式和top工具方式相同。
- -i 用于指定统计时间间隔，默认1秒。

## 输出示例

### 过滤进程程序路径

此路径要求是全局路径，否则过滤不生效。

```bash
$ sudo ./observe/syscall-stat -f /usr/bin/ls
filter: 
        pid: -1, pathhash: -1920808975, comm: 

Syscall stats in 1 second:

SYSCALL                     CALL-CNT   ERROR      SECONDS   
--------------------------- ---------- ---------- ----------
sys_rt_sigaction            36         0          0.000000
sys_mmap                    18         0          0.000007
sys_statx                   11         0          0.000002
sys_close                   9          0          0.000001
sys_newfstatat              8          0          0.000001
sys_openat                  7          0          0.000005
sys_mprotect                5          0          0.000005
sys_write                   4          0          0.000003
sys_brk                     3          0          0.000001
sys_ioctl                   3          0          0.000001
sys_statfs                  2          2          0.000005
sys_getdents64              2          0          0.000008
sys_access                  2          2          0.000003
sys_pread64                 2          0          0.000001
sys_arch_prctl              1          0          0.000000
sys_set_tid_address         1          0          0.000000
sys_set_robust_list         1          0          0.000000
sys_prlimit64               1          0          0.000001
sys_getrandom               1          0          0.000001
sys_munmap                  1          0          0.000010
sys_rseq                    1          0          0.000000

total: 119
```

字段说明：

- SYSCALL：系统调用的名字。
- CALL-CNT：在当前统计时间间隔内，该系统调用被调用的次数。
- ERROR：在当前统计时间间隔内，该系统调用返回报错的次数。
- SECONDS：在当前统计时间间隔内，该系统调用的平均时间占用。

### 过滤PID

如果同时指定了pid过滤条件和进程路径或comm，则仅pid过滤条件生效。

```bash
$ sudo ./observe/syscall-stat -p 835202
filter: 
        pid: 835202, pathhash: 0, comm: 

Syscall stats in 1 second:

SYSCALL                     CALL-CNT   ERROR      SECONDS   
--------------------------- ---------- ---------- ----------
sys_rt_sigaction            42         0          0.000000
sys_ioctl                   20         0          0.000001
sys_write                   8          0          0.000002
sys_rt_sigprocmask          8          0          0.000000
sys_fcntl                   2          0          0.000001
sys_pselect6                1          0          0.164128

total: 81
```

### 过滤进程名

该方式较为简单，因此也存在缺陷，系统中可以有多个重名进程，这会导致统计结果属于这多个进程，当然，也可以利用这个特点，将多个进程修改命名至相同，然后去统计这几个进程的系统调用。

```shell
sudo ./observe/syscall-stat -c ls
filter: 
        pid: -1, pathhash: 0, comm: ls

Syscall stats in 1 second:

SYSCALL                     CALL-CNT   ERROR      SECONDS   
--------------------------- ---------- ---------- ----------
sys_rt_sigaction            36         0          0.000000
sys_mmap                    18         0          0.000004
sys_statx                   11         0          0.000001
sys_close                   9          0          0.000000
sys_newfstatat              8          0          0.000000
sys_openat                  7          0          0.000003
sys_mprotect                5          0          0.000002
sys_write                   4          0          0.000002
sys_brk                     3          0          0.000001
sys_ioctl                   3          0          0.000001
sys_statfs                  2          2          0.000002
sys_getdents64              2          0          0.000004
sys_access                  2          2          0.000002
sys_pread64                 2          0          0.000000
sys_arch_prctl              1          0          0.000000
sys_set_tid_address         1          0          0.000000
sys_set_robust_list         1          0          0.000000
sys_prlimit64               1          0          0.000001
sys_getrandom               1          0          0.000000
sys_munmap                  1          0          0.000005
sys_rseq                    1          0          0.000000

total: 119
```
