# power-snoop

电源管理子系统观测工具，用于实时监控和分析系统电源管理事件。

## 功能描述

`power-snoop` 是一个基于eBPF的电源管理监控工具，能够深度观测内核电源管理子系统的运行状态。它通过监控内核中的power tracepoint事件，提供全面的CPU频率调节、电源状态切换、设备电源管理和PM QoS请求的可观测性。

### 主要功能特性

- **CPU频率监控**：实时跟踪CPU频率变化事件和调频策略
- **CPU空闲状态监控**：监控CPU进入/退出空闲状态的事件和持续时间
- **设备电源管理**：跟踪设备的电源状态切换和回调函数执行
- **PM QoS监控**：监控电源管理服务质量请求的添加和更新
- **时钟管理**：观测系统时钟的启用和禁用事件
- **运行时电源管理**：跟踪设备的运行时电源状态变化
- **多维度过滤**：支持基于进程、CPU核心、事件类型、频率范围等的灵活过滤
- **统计分析**：提供电源事件的统计信息和性能汇总
- **实时流式输出**：支持时间戳、详细信息和统计模式

## 监控的电源事件类型

| 事件类型 | 描述 | 触发场景 |
|---------|------|----------|
| CPU_FREQ | CPU频率变化 | 系统调整CPU频率时 |
| CPU_IDLE | CPU空闲状态变化 | CPU进入或退出空闲状态时 |
| DEVICE_PM_START | 设备电源管理开始 | 设备电源回调函数开始执行时 |
| DEVICE_PM_END | 设备电源管理结束 | 设备电源回调函数执行完成时 |
| PM_QOS_ADD | PM QoS请求添加 | 添加新的电源管理服务质量请求时 |
| PM_QOS_UPDATE | PM QoS请求更新 | 更新现有的PM QoS请求时 |
| CLOCK_ENABLE | 时钟启用 | 系统启用特定时钟时 |
| CLOCK_DISABLE | 时钟禁用 | 系统禁用特定时钟时 |
| RPM_SUSPEND | 运行时电源挂起 | 设备进入运行时挂起状态时 |
| RPM_RESUME | 运行时电源恢复 | 设备从运行时挂起状态恢复时 |

## 命令行参数

### 基本过滤选项

```bash
-p, --pid PID
    按进程ID过滤事件
    
-c, --cpu CPU
    按CPU核心ID过滤事件
    
-C, --comm COMM
    按进程名过滤事件
```

### 事件类型过滤

```bash
-e, --events MASK
    按事件类型过滤（位掩码）
    支持十进制、十六进制（0x前缀）或八进制（0前缀）
    
    事件掩码对应关系：
    1    CPU_FREQ        CPU频率变化
    2    CPU_IDLE        CPU空闲状态变化  
    4    DEVICE_PM       设备电源管理
    8    PM_QOS          PM QoS请求
    16   CLOCK           时钟启用/禁用
    32   RPM             运行时电源管理
    
    示例：
    0x03 = 监控CPU频率和空闲事件
    0x0F = 监控所有CPU和设备相关事件
    0xFF = 监控所有电源事件（默认）
```

### 频率和持续时间过滤

```bash
--min-freq FREQ
    最小CPU频率过滤（Hz）
    
--max-freq FREQ  
    最大CPU频率过滤（Hz）
    
--min-idle NS
    最小空闲持续时间过滤（纳秒）
    
--max-idle NS
    最大空闲持续时间过滤（纳秒）
```

### 输出控制选项

```bash
-v, --verbose
    详细输出模式，显示完整的事件信息
    
-t, --timestamp  
    显示时间戳
    
-s, --stats
    显示实时统计信息
    
-S, --summary
    程序结束时显示汇总统计
```

## 使用示例

### 基本使用

```bash
# 监控所有电源管理事件
sudo ./power-snoop

# 监控特定进程的电源事件
sudo ./power-snoop -p 1234

# 监控特定CPU核心的事件
sudo ./power-snoop -c 0

# 详细输出模式，带时间戳
sudo ./power-snoop -v -t
```

### 事件类型过滤

```bash
# 只监控CPU频率变化事件
sudo ./power-snoop -e 0x01

# 监控CPU频率和空闲状态事件
sudo ./power-snoop -e 0x03

# 监控设备电源管理事件
sudo ./power-snoop -e 0x04

# 监控PM QoS相关事件
sudo ./power-snoop -e 0x08
```

### 频率范围过滤

```bash
# 监控频率变化大于等于1GHz的事件
sudo ./power-snoop --min-freq 1000000000

# 监控特定频率范围的变化
sudo ./power-snoop --min-freq 800000000 --max-freq 2000000000

# 监控较长时间的空闲事件（大于1ms）
sudo ./power-snoop --min-idle 1000000
```

### 统计和分析

```bash
# 显示实时统计信息
sudo ./power-snoop -s

# 程序结束时显示汇总
sudo ./power-snoop -S

# 详细模式，包含统计信息
sudo ./power-snoop -v -t -S
```

## 输出格式

### 标准模式输出

```
CPU0 frequency: 800000 -> 1600000Hz
CPU1 idle state: 1
Device PM: acpi event=1
PM QoS: type=1 value=2000
```

### 详细模式输出（-v）

```
10:45:24 [CPU_FREQ] CPU0: 800000 -> 1600000Hz (pid=1234 comm=stress)
10:45:24 [CPU_IDLE] CPU1: state=1 (pid=0 comm=swapper/1)
10:45:24 [DEVICE_PM_START] Device: acpi event=1 duration=0ns ret=0 (pid=2345 comm=kworker/0:1)
10:45:24 [PM_QOS_ADD] PM QoS: type=1 value=2000 requestor=NetworkManager (pid=1000 comm=NetworkManager)
```

### 统计信息输出（-S）

```
Power Management Statistics:
============================
Total events:     15432
CPU freq events:  8234
CPU idle events:  6120
Device PM events: 892
PM QoS events:    152
Clock events:     28
RPM events:       6
```

## 性能和资源使用

### 系统开销

- **CPU开销**：低（< 1% CPU使用率）
- **内存开销**：约2-4MB（包含BPF程序和用户态缓冲区）
- **内核影响**：最小化，仅在事件发生时触发
- **存储开销**：无持久化存储需求

### 适用场景

- **电源管理调试**：诊断电源策略问题和性能优化
- **系统性能分析**：了解CPU频率调节和空闲状态对性能的影响
- **设备驱动调试**：观测设备电源管理回调的执行情况
- **节能优化**：分析系统的电源使用模式和优化机会
- **QoS监控**：跟踪电源管理服务质量请求的变化

## 技术原理

### eBPF架构

```
用户空间:  power-snoop (用户态程序)
           ↑ (ring buffer)
内核空间:  BPF程序 → tracepoints
           ↓
追踪点:    power:cpu_frequency
          power:cpu_idle  
          power:device_pm_callback_start
          power:device_pm_callback_end
          power:pm_qos_add_request
          power:pm_qos_update_request
```

### 数据流程

1. **事件捕获**：BPF程序附加到power子系统的tracepoints
2. **数据过滤**：在内核空间进行高效过滤，减少数据传输
3. **数据传输**：通过ring buffer将事件数据传递给用户空间
4. **事件处理**：用户态程序解析事件并格式化输出
5. **统计汇总**：实时统计和分析电源管理指标

### 关键特性

- **零拷贝数据传输**：使用ring buffer避免不必要的内存拷贝
- **内核态过滤**：减少用户态处理开销和数据传输量
- **事件聚合**：支持连接级别的统计和分析
- **低延迟监控**：实时捕获和报告电源管理事件

## 故障排除

### 常见问题

**问题1**: `failed to open BPF object`
```bash
# 解决方案：检查是否有足够权限
sudo ./power-snoop
```

**问题2**: `failed to attach BPF programs`
```bash
# 解决方案：检查内核是否支持相应的tracepoints
ls /sys/kernel/debug/tracing/events/power/
```

**问题3**: 没有输出数据
```bash
# 解决方案：检查过滤条件是否过于严格
./power-snoop -v -t  # 使用详细模式查看所有事件
```

**问题4**: `Permission denied`
```bash
# 解决方案：确保以root权限运行
sudo ./power-snoop
# 或配置适当的capability
setcap cap_sys_admin+ep ./power-snoop
```
