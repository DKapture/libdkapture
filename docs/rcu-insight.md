# rcu-insight

## 功能描述

rcu-insight是一个专门用于监控Linux内核RCU（Read-Copy-Update）子系统活动的eBPF工具。它能够实时捕获和分析RCU子系统的关键事件，帮助开发者深入了解RCU的运行状态、性能特征和潜在问题。

该工具基于内核tracepoint机制，监控两种主要的RCU事件：
- **RCU利用率事件 (rcu_utilization)**: 监控RCU上下文切换、调度器行为、RCU核心操作等
- **RCU停顿警告事件 (rcu_stall_warning)**: 检测RCU停顿异常，帮助诊断性能问题

RCU是Linux内核中的高性能同步机制，广泛应用于内核数据结构的并发访问。通过监控RCU活动，可以深入了解系统的并发性能特征、识别潜在的性能瓶颈和调试RCU相关问题。

## 参数说明

```bash
$ sudo ./observe/rcu-insight --help
Usage: rcu-insight [OPTION...]
Monitor RCU (Read-Copy-Update) subsystem activity.

USAGE: rcu-insight [--help] [-v] [-i INTERVAL] [-d DURATION] [-p PID] [-c CPU]
[--utilization-only] [--stall-only]

EXAMPLES:
    rcu-insight                     # Monitor all RCU events
    rcu-insight -p 1234             # Monitor RCU events for PID 1234
    rcu-insight -c 2                # Monitor RCU events for CPU 2
    rcu-insight --utilization-only  # Monitor only utilization events
    rcu-insight --stall-only        # Monitor only stall warning events

  -c, --cpu=CPU              CPU to trace
  -d, --duration=DURATION    Duration of trace (seconds)
  -i, --interval=INTERVAL    Summary interval (seconds)
  -p, --pid=PID              Process ID to trace
  -s, --stall-only           Monitor only stall warning events
  -T, --timestamp            Include timestamp on output
  -u, --utilization-only     Monitor only utilization events
  -v, --verbose              Verbose debug output
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version
```

**参数详细说明：**

- **-p, --pid**: 过滤指定进程ID的RCU事件。当指定此参数时，只显示该进程相关的RCU活动。
- **-c, --cpu**: 过滤指定CPU的RCU事件。当指定此参数时，只显示该CPU上的RCU活动。
- **-T, --timestamp**: 在输出中包含精确的时间戳信息，格式为HH:MM:SS.mmm。
- **-v, --verbose**: 启用详细调试输出，显示更多运行时信息和统计数据。
- **-d, --duration**: 指定监控持续时间（秒），到达指定时间后自动退出。
- **-i, --interval**: 设置统计间隔（秒），用于未来的聚合统计功能。
- **-u, --utilization-only**: 仅监控RCU利用率事件，过滤掉停顿警告事件。
- **-s, --stall-only**: 仅监控RCU停顿警告事件，过滤掉利用率事件。

## 字段说明

rcu-insight工具的输出包含以下字段：

- **TIME**: 事件发生的精确时间戳（当使用-T参数时显示），格式为HH:MM:SS.mmm
- **PID**: 触发该RCU事件的进程ID，0表示内核线程
- **CPU**: 发生该RCU事件的CPU编号
- **EVENT_TYPE**: RCU事件类型，主要包括：
  - `UTILIZATION`: RCU利用率事件，显示RCU子系统的各种活动
  - `STALL_WARNING`: RCU停顿警告事件，表示检测到RCU停顿异常
- **DETAILS**: 事件的详细信息，根据事件类型显示不同内容：
  - 对于UTILIZATION事件：显示具体的RCU活动描述，如"Start context s"、"End context swi"、"Start scheduler"、"Start RCU core"等
  - 对于STALL_WARNING事件：显示RCU名称和详细的警告消息

## 统计信息说明

程序结束时（Ctrl+C或达到指定持续时间），会显示统计信息：

- **Total events**: 捕获的RCU事件总数
- **Utilization events**: RCU利用率事件数量
- **Stall warning events**: RCU停顿警告事件数量
- **Duration**: 实际监控持续时间（秒）
- **Event rate**: 平均事件捕获率（events/second）

## 使用示例

### 基本监控

监控所有RCU事件，按Ctrl+C停止：

```bash
$ sudo ./observe/rcu-insight
PID      CPU  EVENT_TYPE    DETAILS
0        1    UTILIZATION   Start context s
0        1    UTILIZATION   End context swi
1234     2    UTILIZATION   Start scheduler
1234     2    UTILIZATION   End scheduler-t
0        3    UTILIZATION   Start RCU core
0        3    UTILIZATION   End RCU core
```

### 带时间戳监控

启用时间戳显示，监控5秒钟：

```bash
$ sudo ./observe/rcu-insight -T -d 5
TIME          PID      CPU  EVENT_TYPE    DETAILS
05:06:04.682  2855266  1    UTILIZATION   End context swi
05:06:04.682  0        1    UTILIZATION   Start context s
05:06:04.682  0        1    UTILIZATION   End context swi
05:06:04.682  1428211  3    UTILIZATION   Start context s
05:06:04.684  1426955  0    UTILIZATION   Start scheduler
05:06:04.684  1426955  0    UTILIZATION   End scheduler-t
05:06:04.684  1426955  0    UTILIZATION   Start RCU core
05:06:04.684  1426955  0    UTILIZATION   End RCU core

=== RCU Monitoring Statistics ===
Total events: 65298
Utilization events: 65298
Stall warning events: 0
Duration: 5 seconds
Event rate: 13059.60 events/second
```

### 过滤特定进程

只监控进程ID为1234的RCU事件：

```bash
$ sudo ./observe/rcu-insight -p 1234 -T
TIME          PID      CPU  EVENT_TYPE    DETAILS
05:10:15.123  1234     2    UTILIZATION   Start context s
05:10:15.123  1234     2    UTILIZATION   End context swi
05:10:15.124  1234     1    UTILIZATION   Start scheduler
05:10:15.124  1234     1    UTILIZATION   End scheduler-t
```

### 过滤特定CPU

只监控CPU 2上的RCU事件：

```bash
$ sudo ./observe/rcu-insight -c 2 -T
TIME          PID      CPU  EVENT_TYPE    DETAILS
05:12:30.456  2911638  2    UTILIZATION   Start context s
05:12:30.456  2911638  2    UTILIZATION   End context swi
05:12:30.457  2904316  2    UTILIZATION   Start scheduler
05:12:30.457  2904316  2    UTILIZATION   End scheduler-t
```

### 只监控利用率事件

过滤掉停顿警告事件，只显示利用率事件：

```bash
$ sudo ./observe/rcu-insight --utilization-only -v
PID      CPU  EVENT_TYPE    DETAILS
0        1    UTILIZATION   Start context s
0        1    UTILIZATION   End context swi
1234     2    UTILIZATION   Start RCU core
1234     2    UTILIZATION   End RCU core

=== RCU Monitoring Statistics ===
Total events: 1024
Utilization events: 1024
Stall warning events: 0
Duration: 3 seconds
Event rate: 341.33 events/second
```

### 只监控停顿警告事件

专门监控RCU停顿问题：

```bash
$ sudo ./observe/rcu-insight --stall-only -T -v
TIME          PID      CPU  EVENT_TYPE    DETAILS
05:15:45.789  0        0    STALL_WARNING rcuname=rcu_preempt msg=INFO: rcu_preempt detected stalls on CPUs/tasks...

=== RCU Monitoring Statistics ===
Total events: 1
Utilization events: 0
Stall warning events: 1
Duration: 10 seconds
Event rate: 0.10 events/second
```

## 应用场景

### 性能分析

RCU insight工具适用于以下性能分析场景：

1. **系统并发性能评估**: 通过监控RCU事件频率和模式，了解系统的并发访问特征
2. **上下文切换分析**: 观察RCU上下文切换的频率和时机，识别潜在的性能瓶颈
3. **调度器行为分析**: 监控RCU与调度器的交互，优化调度策略

### 问题诊断

1. **RCU停顿检测**: 及时发现RCU停顿警告，诊断可能的死锁或性能问题
2. **CPU热点分析**: 通过CPU过滤功能，识别RCU活动密集的CPU核心
3. **进程级RCU分析**: 针对特定进程分析其RCU使用模式，优化程序设计

### 内核开发

1. **RCU机制验证**: 验证RCU机制在特定工作负载下的行为是否符合预期
2. **内核补丁测试**: 评估内核补丁对RCU性能的影响
3. **并发算法优化**: 为依赖RCU的并发算法提供性能数据支持

## 注意事项

1. **权限要求**: 该工具需要root权限运行，因为它需要访问内核tracepoint
2. **性能影响**: 在高负载系统中，大量的RCU事件可能会影响监控性能，建议适当使用过滤参数
3. **内核版本**: 工具依赖于内核的RCU tracepoint，建议在较新的内核版本上使用（Linux 4.18+）
4. **存储空间**: 长时间监控可能产生大量输出，注意重定向输出时的存储空间管理 