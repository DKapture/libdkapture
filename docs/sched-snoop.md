# sched-snoop - 调度器事件跟踪工具

## 概述

sched-snoop 是一个基于 eBPF 的实时调度器事件监控工具，用于深度分析 Linux 内核调度器的行为。它能够捕获各种调度事件，包括上下文切换、进程唤醒、进程迁移、生命周期事件以及详细的性能统计信息，帮助系统管理员和开发者诊断性能问题、理解调度行为。

## 功能特性

sched-snoop 支持跟踪以下调度器事件：

### 基础调度事件
- **SWITCH** - 进程上下文切换
- **WAKEUP** - 进程唤醒事件  
- **WAKEUP_NEW** - 新进程唤醒事件
- **MIGRATE** - 进程在 CPU 间迁移

### 进程生命周期事件
- **FORK** - 进程创建
- **EXIT** - 进程退出
- **EXEC** - 进程执行

### 性能统计事件
- **STAT_RUNTIME** - 进程运行时间统计
- **STAT_WAIT** - 进程等待时间统计
- **STAT_SLEEP** - 进程睡眠时间统计
- **STAT_BLOCKED** - 进程阻塞时间统计
- **STAT_IOWAIT** - IO 等待时间统计

## 系统要求

### 前提条件
- Linux 内核版本 ≥ 5.8 (支持 eBPF 和调度器 tracepoints)
- 已安装 libbpf 开发库
- 编译工具链 (gcc, clang, make)
- **重要**: 需要启用内核调度器统计功能

### 启用调度器统计

性能统计事件需要启用内核的调度器统计功能：

```bash
# 临时启用（重启后失效）
sudo bash -c 'echo 1 > /proc/sys/kernel/sched_schedstats'

# 永久启用（重启后仍有效）
echo 'kernel.sched_schedstats = 1' | sudo tee -a /etc/sysctl.conf
```

## 编译和安装

### 编译步骤

```bash
# 进入项目目录
cd dkapture/observe

# 编译 sched-snoop
make sched-snoop
```

编译成功后会生成以下文件：
- `sched-snoop` - 可执行文件
- `sched-snoop.bpf.o` - BPF 对象文件
- `sched-snoop.skel.h` - BPF skeleton 头文件

## 使用方法

### 基本语法

```bash
sched-snoop [选项]
```

### 命令行选项

| 选项 | 参数 | 描述 |
|------|------|------|
| `-h` | - | 显示帮助信息 |
| `-e` | EVENTS | 指定要跟踪的事件类型 |
| `-p` | PID | 只跟踪指定进程ID |
| `-c` | CPU | 只跟踪指定CPU核心 |
| `-C` | COMM | 只跟踪包含指定字符串的命令名 |

### 事件类型说明

**基础事件**:
- `switch` - 上下文切换
- `wakeup` - 进程唤醒
- `wakeup_new` - 新进程唤醒
- `migrate` - 进程迁移

**生命周期事件**:
- `fork` - 进程创建
- `exit` - 进程退出
- `exec` - 进程执行

**性能统计事件**:
- `stat_runtime` - 运行时间统计
- `stat_wait` - 等待时间统计
- `stat_sleep` - 睡眠时间统计
- `stat_blocked` - 阻塞时间统计
- `stat_iowait` - IO等待时间统计

**特殊值**:
- `all` - 所有事件类型

多个事件可用逗号分隔，例如: `-e switch,wakeup,fork`

## 使用示例

### 1. 基本跟踪
跟踪所有调度事件：

```bash
sudo ./sched-snoop -e all
```

### 2. 跟踪上下文切换
只跟踪进程上下文切换：

```bash
sudo ./sched-snoop -e switch
```

### 3. 跟踪性能统计
查看进程运行时间统计：

```bash
sudo ./sched-snoop -e stat_runtime
```

### 4. 跟踪特定进程
只跟踪 PID 为 1234 的进程：

```bash
sudo ./sched-snoop -p 1234 -e all
```

### 5. 跟踪特定CPU
只跟踪 CPU 0 的调度事件：

```bash
sudo ./sched-snoop -c 0 -e switch
```

### 6. 跟踪特定命令
只跟踪包含 "bash" 的命令：

```bash
sudo ./sched-snoop -C bash -e all
```

### 7. 组合多种事件
跟踪上下文切换和进程唤醒：

```bash
sudo ./sched-snoop -e switch,wakeup
```

### 8. 生命周期事件分析
跟踪进程创建和退出：

```bash
sudo ./sched-snoop -e fork,exit,exec
```

### 9. 性能分析组合
跟踪所有性能统计事件：

```bash
sudo ./sched-snoop -e stat_runtime,stat_wait,stat_sleep,stat_blocked,stat_iowait
```

## 输出格式

### 输出列说明

```
TIME     CPU   EVENT   DETAILS
-------- ----- ------- -------
```

- **TIME**: 事件发生时间（HH:MM:SS 格式）
- **CPU**: 发生事件的 CPU 核心编号
- **EVENT**: 事件类型
- **DETAILS**: 事件详细信息

### 事件详细信息格式

#### 上下文切换 (SWITCH)
```
prev_comm:prev_pid [prev_prio] -> next_comm:next_pid [next_prio] state=prev_state
```

#### 进程唤醒 (WAKEUP/WAKEUP_NEW)
```
comm:pid [prio] target_cpu=cpu success=1/0
```

#### 进程迁移 (MIGRATE)
```
comm:pid [prio] orig_cpu=cpu dest_cpu=cpu
```

#### 进程创建 (FORK)
```
parent_comm:parent_pid -> child_comm:child_pid
```

#### 进程退出 (EXIT)
```
comm:pid [prio]
```

#### 进程执行 (EXEC)
```
comm:pid filename="/path/to/executable"
```

#### 性能统计 (STAT_*)
```
comm:pid [prio] delay_type=delay_value ns
```

### 示例输出

```bash
$ sudo ./sched-snoop -e switch,wakeup,stat_runtime
TIME     CPU   EVENT   DETAILS
-------- ----- ------- -------
13:45:15 [002] SWITCH              swapper/2:0 [120] -> kworker/2:1:71 [120] state=0
13:45:15 [002] SWITCH              kworker/2:1:71 [120] -> swapper/2:0 [120] state=1
13:45:15 [003] WAKEUP              kworker/3:2:469 [120] target_cpu=3 success=1
13:45:15 [003] SWITCH              swapper/3:0 [120] -> kworker/3:2:469 [120] state=0
13:45:15 [001] STAT_RUNTIME        sudo:34027 [120] runtime_delay=15000 ns
13:45:15 [002] STAT_RUNTIME        kworker/2:1:71 [120] runtime_delay=8500 ns
```

## 故障排除

### 常见问题

#### 1. 权限不足
```bash
错误: Failed to load and verify BPF skeleton
解决: 使用 sudo 运行程序
```

#### 2. 性能统计事件无输出
```bash
现象: stat_* 事件类型无任何输出
原因: 调度器统计功能未启用
解决: 启用调度器统计功能
```

```bash
# 检查当前状态
cat /proc/sys/kernel/sched_schedstats

# 如果显示 0，则启用它
sudo bash -c 'echo 1 > /proc/sys/kernel/sched_schedstats'
```

#### 3. 内核版本不支持
```bash
错误: BPF program load failed
解决: 确认内核版本 ≥ 5.8 且支持调度器 tracepoints
```

#### 4. 缺少依赖库
```bash
错误: Failed to open BPF skeleton
解决: 安装 libbpf-dev 包
```

#### 5. 无调度事件输出
可能原因：
- 过滤条件过于严格（如指定的 PID 不存在或无活动）
- 系统负载很低，调度事件较少
- 指定的 CPU 核心处于空闲状态

解决方法：
- 放宽过滤条件或移除过滤
- 在系统负载较高时测试
- 使用 `stress` 等工具生成负载进行测试

### 性能测试命令

生成调度事件用于测试：

```bash
# 生成 CPU 负载
stress-ng --cpu 4 --timeout 30s

# 生成 IO 负载  
stress-ng --io 2 --timeout 30s

# 生成内存压力
stress-ng --vm 2 --vm-bytes 1G --timeout 30s

# 简单的并发测试
for i in {1..10}; do sleep 1 & done; wait
```

## 性能影响

sched-snoop 使用 eBPF 技术，具有以下特点：

- **极低开销**: eBPF 程序在内核空间运行，最小化性能影响
- **零拷贝**: 使用环形缓冲区实现高效的数据传输
- **安全性**: BPF 验证器确保程序安全可靠
- **实时性**: 事件实时捕获和报告，延迟极低

**注意**: 启用调度器统计功能会产生轻微的系统开销，因为内核需要维护额外的统计信息。在生产环境中使用时请权衡性能影响。

## 应用场景

1. **性能调优**: 分析进程调度延迟和上下文切换开销
2. **故障诊断**: 定位调度相关的性能问题
3. **负载分析**: 理解系统负载分布和 CPU 利用率
4. **应用优化**: 优化多线程应用的调度行为
5. **系统监控**: 实时监控关键进程的调度状态
6. **研究学习**: 深入理解 Linux 内核调度器工作原理 