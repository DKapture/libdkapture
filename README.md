# DKapture

DKapture（Deepin Kernel Capture）是一个用户空间工具集和动态库，用于观察和操作内核的数据对象或行为。对标业界标杆工具sysdig和systemtap，但实现的方式截然不同，DKapture是基于Linux内核新兴的eBPF技术，相对sysdig和systemtap基于内核模块的技术，eBPF技术更安全。

# 功能特性

## 信息采集

1. 网络信息采集：每进程套接字使用信息，套接字元组信息，每进程网络流量统计。
2. 文件系统信息采集：文件vfs事件跟踪，文件描述符IO内容跟踪，挂载事件监听。
3. 进程信息采集：procfs节点信息访问优化，提供高性能的进程信息访问接口，相对procfs节点接口提升超过1个数量级。
4. IO信息采集：每设备IO流量，每进程IO流量。
5. 系统调用信息采集。
6. 调度信息采集：进程切换跟踪，进程唤醒，运行队列等信息采集。
7. 中断信息采集：缺页中断，软中断，tasklet，及部分硬中断。
8. 内存信息采集：内核内存泄漏。

## 行为拦截

1. 网络包过滤：支持按网络4元组信息对网络数据包进行过滤。
2. 文件管控：支持监控和限制系统用户对文件的访问、删除。

# 目录结构

- build: 动态生成，存放项目构建过程中生成的文件。
- docs: 存放文档。
- kmodules：内核模块代码，只用于少数只有模块能实现的功能。
- include: 存放编译时使用的源代码头文件。
- filter: 存放作为过滤器的 eBPF 源代码。
- observe: 存放作为观察器的 eBPF 源代码。
- policy: 存放策略相关代码。
- script: 存放用于提高工作效率的脚本。
- test：单元测试用例代码。
- so：动态库核心代码。
- demo：示例使用libdkapture.so动态库查询系统信息的例子。
- tools：工具目录，用于完成单元测试需要的功能。

# 命名规则

- 内核 bpf 代码：[名称].bpf.c
- 用户空间代码：[名称].cpp
- 头文件：文件名前加大写字符，后跟全小写的文件名。大写字符必须是 'K' 或 'U'，以 'K' 开头的头文件只能在 bpf 程序中包含，以 'U' 开头的头文件只能在用户程序中包含。没有前置大写字符的头文件可以在 bpf 和用户程序中都包含。

只需将这两个源文件放在同一目录中（filter、observe 或 policy）

# 编译构建

## 环境要求

- 系统: Deepin 23, Deepin 25, UOS 25 专业版
- 内核：6.6.0以上，且编译选项开启BPF、BTF相关配置：
  ```conf
  CONFIG_DEBUG_INFO_BTF=y
  CONFIG_BPF=y
  CONFIG_HAVE_EBPF_JIT=y
  CONFIG_BPF_SYSCALL=y
  CONFIG_BPF_JIT=y
  CONFIG_BPF_LSM=y
  CONFIG_CGROUP_BPF=y
  CONFIG_NETFILTER_BPF_LINK=y
  CONFIG_BPF_EVENTS=y
  ```
- 架构：x86_64、ARM64、Loong64、sw64。
- 编译工具：`sudo apt install build-essential clang llvm libbpf-dev bpftool`

## 构建流程

### 完整构建

```bash
# 克隆项目
git clone <repository-url>
cd dkapture

# 完整构建所有模块
make all
```

### 分模块构建

```bash
# 构建内核头文件（必需的第一步）
make include

# 构建观察工具模块
make observe

# 构建过滤器模块
make filter

# 构建策略模块
make policy

# 构建动态库
make so

# 构建示例程序
make demo

# 构建测试程序
make test
```

### 构建特定工具

```bash
# 构建单个观察工具
make observe/bio-stat
make observe/lsock
make observe/trace-file

# 构建单个过滤器
make filter/net-filter
make filter/rm-forbid

# 构建单个策略
make policy/frtp
```

## 构建产物

### 可执行文件

构建完成后，以下目录包含可执行文件：

- `build/observe/` - 系统观察工具
- `build/filter/` - 网络和文件过滤器
- `build/policy/` - 访问控制策略工具

### 动态库

- `build/so/libdkapture.so` - 核心动态库，提供 API 接口

### 示例程序

- `build/demo/demo` - 演示如何使用 libdkapture.so

## 清理构建

```bash
# 清楚所有非生存头文件构建产物
make clean

# 清理所有构建产物
make distclean

# 清理特定模块
make observe/clean
make filter/clean
make so/clean
```

## 打包部署

### 构建 DEB 包

```bash
# 使用提供的脚本构建 DEB 包
./script/build-deb.sh

# 生成的包文件：dkapture_1.0.0_<arch>.deb
```

### 安装 DEB 包

```bash
# 安装
sudo dpkg -i dkapture_1.0.0_<arch>.deb

# 修复依赖问题
sudo apt-get install -f

# 卸载
sudo dpkg -r dkapture
```

## 验证安装

```bash
# 检查可执行文件
ls -la /usr/bin/dk-*

# 测试动态库
ldd /lib/libdkapture.so

# 运行示例程序
dk-demo

# 测试单个工具
sudo dk-bio-stat
sudo dk-lsock
```

# 功能对比

| 名称            | 功能简述                                                                   | 独占功能<br />（30%） | 与sysdig交叉功能<br />（60%）                                                                                                       | 与systemtap交叉功能<br />（40%）                                                                                            |
| --------------- | -------------------------------------------------------------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| bio-stat        | 统计每进程每磁盘的块IO请求数、字节数、平均耗时等                           |                       | v_io_by_type.lua<br />v_slow_io.lua<br />fdtime_by.lua<br />fdbytes_by.lua                                                          | io_submit.stp<br />ioblktime.stp<br />iodevstats.stp<br />iostats.stp<br />iotime.stp<br />iotop.stp<br />biolatency-nd.stp |
| ext4snoop       | 跟踪ext4文件系统的操作事件（如创建、删除、写入等）                         |                       |                                                                                                                                     |                                                                                                                             |
| lsof | 查询指定文件当前被哪些进程/线程占用                                        | 部分独占              | lsof.lua                                                                                                                            |                                                                                                                             |
| hrtimer         | 跟踪高精度定时器相关的系统调用和事件                                       | 独占                  |                                                                                                                                     |                                                                                                                             |
| irqsnoop        | 跟踪中断件事件，包括软中断和设备中断                                       | 部分独占              |                                                                                                                                     | interrupts-by-dev.stp                                                                                                       |
| lscgroup        | 展示cgroup（控制组）的层级、属性和进程归属关系                             | 独占                  |                                                                                                                                     |                                                                                                                             |
| lsock           | 跟踪和展示进程socket的创建、连接、关闭等操作                               | 部分独占              | netstat.lua<br />topconns.lua<br />v_incoming_connections.lua<br />v_port_bindings.lua                                              | connect_stat.stp<br />socktop<br />tcp_connections.stp<br />tcp_trace.stp<br />tcpdumplike.stp<br />tcpipstat.stp           |
| mountsnoop      | 跟踪mount、umount、fs相关系统调用及参数                                    | 部分独占              |                                                                                                                                     | enospc.stp<br />fslatency-nd.stp                                                                                            |
| net-traffic     | 统计和跟踪进程/系统的网络流量                                              |                       | spy_ip.lua<br />spy_port.lua                                                                                                        | nettop.stp<br />accept2close-nd.stp                                                                                         |
| peek-fd         | 监控进程文件描述符的读写数据                                               |                       | iobytes_file.lua<br />iobytes_net.lua<br />iobytes.lua<br />stderr.lua<br />stdin.lua<br />stdout.lua                               |                                                                                                                             |
| proc-info       | 采集进程的stat、io、fd、traffic等/proc相关信息                             | 部分独占              | proc_exec_time.lua<br />v_procs_cpu.lua<br />v_procs_errors.lua<br />v_procs_fd_usage.lua<br />v_procs.lua<br />v_syscall_procs.lua | chng_cpu.stp<br />proc_snoop.stp<br />proctop.stp                                                                           |
| ps              | 类似ps命令，展示进程/线程的详细状态信息                                    |                       | ps.lua                                                                                                                              |                                                                                                                             |
| run-queue       | 展示每个CPU的运行队列及其上的进程                                          | 部分独占              | v_threads.lua                                                                                                                       |                                                                                                                             |
| spinlock_ob     | 跟踪内核自旋锁的获取与释放，分析锁竞争                                     |                       |                                                                                                                                     | bkl_stats.stp<br />schedtimes.stp                                                                                           |
| switch_count    | 统计进程/线程的上下文切换次数                                              |                       |                                                                                                                                     | sched-latency.stp                                                                                                           |
| syscall-stat    | 统计进程/系统的系统调用频率、耗时、错误等                                  |                       | v_syscalls.lua<br />bottlenecks.lua                                                                                                 | syscallbypid-nd.stp<br />syscalls_by_pid.stp<br />syscalls_by_proc.stp                                                      |
| trace-exec      | 跟踪进程的exec链，分析进程启动关系                                         |                       |                                                                                                                                     | execsnoop-nd.stp<br />forktracker.stp<br />pstrace_exec.stp                                                                 |
| trace-file      | 跟踪文件操作（如open/close/read/write等）及其详细参数                      |                       | spy_file.lua<br />v_file_opens.lua<br />v_files.lua                                                                                 | inodewatch.stp<br />opensnoop-nd.stp<br />rwtime-nd.stp                                                                     |
| trace-signal    | 跟踪信号的发送、接收、处理过程                                             |                       |                                                                                                                                     | killsnoop-nd.stp<br />sig_by_pid.stp<br />sig_by_proc.stp<br />sigkill.stp<br />sigmon.stp                                  |
| urblat          | 跟踪USB请求块（URB）的延迟                                                 | 独占                  |                                                                                                                                     |                                                                                                                             |
| usb_ob          | 跟踪USB子系统相关事件和统计信息                                            | 独占                  |                                                                                                                                     |                                                                                                                             |
| wakeup_count    | 统计进程/线程的唤醒次数                                                    | 独占                  |                                                                                                                                     |                                                                                                                             |
| xhci-snoop      | 跟踪xHCI（USB 3.0控制器）相关的内核事件和操作                              | 独占                  |                                                                                                                                     |                                                                                                                             |
| kmemleak        | 检测和分析内核内存泄漏，打印可疑点函数调用堆栈                             |                       |                                                                                                                                     | gmalloc_watch.stp                                                                                                           |
| pagefault       | 跟踪和统计进程/系统的缺页异常事件                                          |                       | v_page_faults.lua                                                                                                                   | pfaults.stp                                                                                                                 |
| net-filter      | 网络包过滤与抓包工具，<br />支持基于协议、IP、端口、进程名等多维度规则过滤 |                       | udp_extract.lua                                                                                                                     | netfilter_drop.stp<br />who_sent_it.stp<br />packet_contents.stp                                                            |
| rm-forbid       | 文件误删防护工具，禁止删除被占用的文件。                                   | 独占                  |                                                                                                                                     |                                                                                                                             |
| frtp            | 文件访问权限策略工具，基于eBPF实现细粒度的文件操作权限控制与审计           | 独占                  |                                                                                                                                     |                                                                                                                             |

# 性能对比

## 进程信息读取

**测试条件**

1. 仅遍历读取/proc/[pid]/stat信息，作为示例。
2. 循环遍历100次，间隔500us。
3. 遍历的是系统的所有线程（非进程）。

**遍历procfs文件节点**（例如ps/top工具）

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
  0.00    0.000000           0        37           others
------ ----------- ----------- --------- --------- ----------------
100.00    2.879984           2    996708         4 total
```

**dkapture优化方式**

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
  0.00    0.000000           0        37           others
------ ----------- ----------- --------- --------- ----------------
100.00    0.135814          65      2060         5 total
```

## 文件跟踪

**测试参数**

- 文件操作次数: 1000
- 预期总事件数: 2000 (每次操作产生一个read和一个write事件)

**测试结果**

| 工具      | 总耗时(秒) | 收集事件数 | 事件采集率 | 每秒处理事件数 | 每秒文件操作数 |
| --------- | ---------- | ---------- | ---------- | -------------- | -------------- |
| dkapture  | 6.13       | 1992       | 0.99x      | 324.80         | 163.13         |
| sysdig    | 7.94       | 1984       | 0.99x      | 249.89         | 125.94         |
| systemtap | 11.75      | 2000       | 1.00x      | 170.21         | 85.10          |

**指标说明**

- 事件采集率：实际收集的事件数/预期事件数
- 每秒处理事件数：实际收集的事件数/总耗时
- 每秒文件操作数：完成的文件操作次数/总耗时
