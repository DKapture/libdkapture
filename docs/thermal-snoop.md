## thermal-snoop

## 功能描述

thermal-snoop用于实时监控系统thermal管理子系统的活动，包括温度变化、trip point触发、冷却设备状态更新以及电源管理事件。该工具通过eBPF技术捕获内核thermal tracepoints，提供详细的thermal事件信息和统计数据。

## 参数说明

```bash
# ./observe/thermal-snoop -h
Usage: thermal-snoop [OPTION...]
thermal-snoop - Thermal management subsystem observation tool

USAGE: thermal-snoop [OPTIONS]

EXAMPLES:
    thermal-snoop                           # Trace all thermal events
    thermal-snoop -p 1234                   # Trace specific process
    thermal-snoop -c 0                      # Trace specific CPU
    thermal-snoop -e 0x03                   # Trace temp updates and trips
    thermal-snoop --min-temp 50000          # Trace temperatures >= 50°C
    thermal-snoop -z 1                      # Trace specific thermal zone
    thermal-snoop -v -t                     # Verbose output with timestamps
    thermal-snoop -s                        # Show statistics

Event types (for -e bitmask):
    1   TEMP_UPDATE     Temperature updates
    2   TRIP_TRIGGER    Trip point triggers
    4   CDEV_UPDATE     Cooling device updates
    8   POWER_ALLOC     Power allocator events
    16  POWER_PID       PID power control events

      --celsius              Display temperatures in Celsius (default)
  -c, --cpu=CPU              CPU ID to trace
  -C, --comm=COMM            Process name to trace
  -e, --events=MASK          Event types to trace (bitmask)
      --max-temp=TEMP        Maximum temperature to trace (millicelsius)
      --min-temp=TEMP        Minimum temperature to trace (millicelsius)
  -p, --pid=PID              Process ID to trace
  -s, --stats                Show statistics
  -t, --timestamp            Show timestamps
  -v, --verbose              Verbose output
  -z, --zone=ZONE            Thermal zone ID to trace
  -?, --help                 Give this help list
      --usage                Give a short usage message
```

- -p：过滤指定的进程ID。
- -C：过滤指定的进程名。
- -c：过滤指定的CPU编号。
- -e：指定要监控的事件类型（位掩码）。
- --min-temp：设置最小温度阈值（毫摄氏度）。
- --max-temp：设置最大温度阈值（毫摄氏度）。
- -z：过滤指定的thermal zone ID。
- -t：显示时间戳。
- -v：详细输出模式。
- -s：显示统计信息。
- --celsius：以摄氏度显示温度（默认）。

## 事件类型说明

thermal-snoop监控以下类型的thermal事件：

1. **TEMP_UPDATE** - 温度更新事件
   - 监控thermal zone温度读取
   - 显示当前温度和之前温度的变化

2. **TRIP_TRIGGER** - Trip point触发事件
   - 监控thermal zone trip point触发
   - 显示trip类型（ACTIVE、PASSIVE、HOT、CRITICAL）

3. **CDEV_UPDATE** - 冷却设备更新事件
   - 监控cooling device状态变化
   - 显示冷却设备类型和目标状态

4. **POWER_ALLOC** - 电源分配事件
   - 监控devfreq功率获取操作
   - 显示设备功率分配信息

5. **POWER_PID** - PID功率控制事件
   - 监控devfreq功率限制操作
   - 显示功率控制参数

## 字段说明

- **TIME**：事件发生时间戳
- **PID**：触发事件的进程ID
- **COMM**：触发事件的进程名
- **CPU**：事件发生的CPU编号
- **EVENT**：事件类型
- **ZONE/DEV**：thermal zone或cooling device标识
- **TEMP**：温度值（摄氏度）
- **PREV_TEMP**：之前的温度值
- **TRIP_TYPE**：trip point类型
- **TARGET**：冷却设备目标状态
- **POWER**：功率值

## 使用示例

### 基本监控
```bash
# sudo ./observe/thermal-snoop
thermal-snoop: Tracing thermal management events... Ctrl-C to end.
15:42:31.123 PID:1234  COMM:sensors     CPU:2  EVENT:TEMP_UPDATE    ZONE:acpi_thermal_zone  TEMP:45.0°C  PREV:44.5°C
15:42:31.124 PID:0     COMM:swapper/2   CPU:2  EVENT:CDEV_UPDATE    DEV:Processor           TARGET:1
15:42:31.125 PID:1234  COMM:sensors     CPU:2  EVENT:TRIP_TRIGGER   ZONE:acpi_thermal_zone  TRIP:ACTIVE
```

### 监控特定CPU
```bash
# sudo ./observe/thermal-snoop -c 0
thermal-snoop: Tracing thermal management events on CPU 0... Ctrl-C to end.
```

### 设置温度阈值
```bash
# sudo ./observe/thermal-snoop --min-temp 50000
thermal-snoop: Tracing thermal events with temperature >= 50.0°C... Ctrl-C to end.
```

### 监控特定事件类型
```bash
# sudo ./observe/thermal-snoop -e 0x03
thermal-snoop: Tracing TEMP_UPDATE and TRIP_TRIGGER events... Ctrl-C to end.
```

### 显示统计信息
```bash
# sudo ./observe/thermal-snoop -s

Thermal Monitoring Statistics:
==============================
Total Events:           42
├─ Temperature Updates: 28 (66.7%)
├─ Trip Triggers:       8 (19.0%)
├─ Cooling Dev Updates: 4 (9.5%)
├─ Power Allocator:     2 (4.8%)
└─ Power PID Control:   0 (0.0%)
```

### 详细输出带时间戳
```bash
# sudo ./observe/thermal-snoop -v -t
thermal-snoop: Verbose tracing with timestamps... Ctrl-C to end.
[15:42:31.123456] PID:1234 (sensors) CPU:2 triggered TEMP_UPDATE event
  └─ Thermal Zone: acpi_thermal_zone (ID:0)
  └─ Temperature: 45.0°C (was 44.5°C, delta: +0.5°C)
  └─ Zone Status: Normal operation
```

## 性能说明

- **低开销**：使用eBPF技术，对系统性能影响极小
- **实时监控**：零延迟捕获thermal事件
- **高效过滤**：内核级别的事件过滤，减少用户空间开销
- **内存优化**：使用union结构和LRU maps优化内存使用

## 注意事项

1. **权限要求**：需要root权限运行
2. **内核支持**：需要内核支持thermal tracepoints
3. **事件频率**：thermal事件通常频率较低，可能需要等待或创建负载来观察事件
4. **虚拟化环境**：在虚拟机中thermal事件可能较少或不完整

## 故障排除

### 没有事件输出
```bash
# 检查thermal tracepoints是否可用
sudo ls /sys/kernel/debug/tracing/events/thermal/

# 检查系统thermal zones
ls /sys/class/thermal/

# 手动触发thermal活动
sensors  # 如果安装了lm-sensors
```

### 权限错误
```bash
# 确保以root权限运行
sudo ./observe/thermal-snoop

# 检查debugfs挂载
mount | grep debugfs
```

### BPF加载失败
```bash
# 检查内核BPF支持
zcat /proc/config.gz | grep BPF

# 检查libbpf版本
ldd ./observe/thermal-snoop
``` 