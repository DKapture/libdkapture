## graphics-snoop

## 功能描述

graphics-snoop用于监控图形系统事件，包括DRM垂直同步事件和DMA围栏事件。该工具基于eBPF技术，提供对GPU和显示驱动程序的实时监控，帮助分析图形系统性能和调试显示相关问题。

## 参数说明

```bash
# ./observe/graphics-snoop --help
Usage: graphics-snoop [OPTION...] 
graphics-snoop - Monitor graphics system events

USAGE: graphics-snoop [OPTIONS]

EXAMPLES:
    graphics-snoop                    # Monitor all graphics events
    graphics-snoop -p 1234            # Monitor process 1234 only
    graphics-snoop -e 1               # Monitor VBlank events only
    graphics-snoop -E                 # Show error events only
    graphics-snoop -v -t              # Verbose output with timestamps
    graphics-snoop -s -i 5            # Print statistics every 5 seconds

Options:
  -p, --pid=PID              Trace process with this PID only
  -c, --cpu=CPU              Trace events on this CPU only
  -C, --comm=COMM            Trace process with this command name only
  -e, --events=MASK          Event type mask (1=vblank, 2=fence)
  -r, --crtc=CRTC            Trace specific CRTC only
  -v, --verbose              Verbose output
  -t, --timestamp            Print timestamp
  -s, --stats                Print statistics
  -E, --errors-only          Show error events only
  -i, --interval=INTERVAL    Summary interval in seconds
  -T, --times=TIMES          Number of intervals to run
  -?, --help                 Give this help list
```

- -p：过滤指定的进程ID。
- -c：过滤指定的CPU。
- -C：过滤指定的进程名。
- -e：事件类型掩码，1=垂直同步事件，2=围栏事件。
- -r：过滤指定的CRTC（显示控制器）。
- -v：详细输出模式。
- -t：显示时间戳。
- -s：显示统计信息。
- -E：仅显示错误事件。
- -i：统计时间间隔。
- -T：运行次数。
- -h：打印此帮助信息。

## 事件类型说明

graphics-snoop监控以下类型的图形事件：

### DRM垂直同步事件
- **VBLANK**: DRM垂直同步事件，表示显示器完成一帧的扫描
- **VBLANK_Q**: DRM垂直同步队列事件，表示垂直同步事件被加入队列

### DMA围栏事件
- **FENCE_INIT**: DMA围栏初始化，标记GPU操作的开始
- **FENCE_DEST**: DMA围栏销毁，表示围栏生命周期结束
- **FENCE_EN**: DMA围栏信号启用，准备信号通知
- **FENCE_SIG**: DMA围栏信号完成，标记GPU操作完成

## 字段说明

### 标准输出格式
- **CPU**: 事件发生的CPU编号
- **COMM**: 触发事件的进程名
- **PID**: 触发事件的进程ID
- **EVENT**: 事件类型（VBLANK、FENCE_INIT等）
- **DETAILS**: 事件详细信息

### VBlank事件字段
- **crtc**: CRTC（显示控制器）ID
- **seq**: 垂直同步序列号
- **timestamp**: 硬件时间戳（可选）
- **device**: DRM设备名称

### DMA围栏事件字段
- **fence**: 围栏对象指针（十六进制）
- **ctx**: 围栏上下文ID
- **seq**: 围栏序列号
- **err**: 错误代码（非零表示错误）
- **driver**: 驱动程序名称
- **timeline**: 时间线名称

### 详细输出格式（-v选项）
详细模式显示所有可用字段，包括：
- 完整的时间戳信息
- 硬件特定的详细信息
- 驱动程序和设备信息
- 性能相关的数据

## 使用示例

### 基本监控
```bash
# 监控所有图形事件
sudo ./observe/graphics-snoop
Tracing graphics events... Hit Ctrl-C to end.
[0] Xorg[1234]: VBLANK crtc=0 seq=12345
[1] chrome[5678]: FENCE_INIT fence=0x12ab34cd seq=678
[0] Xorg[1234]: FENCE_SIG fence=0x12ab34cd seq=678
```

### 详细输出模式
```bash
# 详细输出，包含时间戳
sudo ./observe/graphics-snoop -v -t
15:30:45 [0] Xorg[1234]: VBLANK crtc=0 seq=12345 timestamp=1234567890 device=drm
15:30:45 [1] chrome[5678]: FENCE_INIT fence=0x12ab34cd ctx=100 seq=678 err=0 driver=i915 timeline=gfx
15:30:45 [0] Xorg[1234]: FENCE_SIG fence=0x12ab34cd ctx=100 seq=678 err=0 driver=i915 timeline=gfx
```

### 进程过滤
```bash
# 仅监控指定进程
sudo ./observe/graphics-snoop -p 1234
Filter settings:
  PID: 1234, CPU: -1, COMM: 
  Event mask: 0x3f, CRTC: 0, Errors only: no

[0] Xorg[1234]: VBLANK crtc=0 seq=12346
[0] Xorg[1234]: VBLANK crtc=1 seq=54321
```

### 事件类型过滤
```bash
# 仅监控VBlank事件（掩码1）
sudo ./observe/graphics-snoop -e 1
[0] Xorg[1234]: VBLANK crtc=0 seq=12347
[0] Xorg[1234]: VBLANK_Q crtc=0 seq=12348

# 仅监控DMA围栏事件（掩码60，二进制111100）
sudo ./observe/graphics-snoop -e 60
[1] chrome[5678]: FENCE_INIT fence=0x12ab34ce seq=679
[1] chrome[5678]: FENCE_SIG fence=0x12ab34ce seq=679
```

### 错误监控
```bash
# 仅显示错误事件
sudo ./observe/graphics-snoop -E
[2] glxgears[9999]: FENCE_SIG fence=0xdeadbeef seq=999 (ERROR)
```

### 统计信息
```bash
# 显示统计信息
sudo ./observe/graphics-snoop -s -i 5
Tracing graphics events... Hit Ctrl-C to end.
[运行5秒后]

Graphics Events Statistics:
==========================
Total Events:      245
VBlank Events:     180 (73.5%)
Fence Events:      65 (26.5%)
Error Events:      2 (0.8%)

DRM Statistics:
Total VBlanks:     180
Active CRTCs:      2

DMA Fence Statistics:
Fences Created:    32
Fences Destroyed:  30
Fences Signaled:   33
Fence Timeouts:    2
```

### CRTC过滤
```bash
# 仅监控CRTC 0的事件
sudo ./observe/graphics-snoop -r 0
[0] Xorg[1234]: VBLANK crtc=0 seq=12349
[0] Xorg[1234]: VBLANK_Q crtc=0 seq=12350
```

## 性能说明

graphics-snoop基于eBPF技术实现，具有以下特点：

- **零拷贝**: 使用BPF ring buffer高效传输事件数据
- **低开销**: 在内核空间进行事件过滤，减少用户空间负载
- **实时监控**: 无需轮询，事件驱动的实时监控
- **安全性**: BPF验证器确保程序安全性，不会影响系统稳定性

## 注意事项

1. **权限要求**: 需要root权限才能加载BPF程序和访问tracepoint
2. **内核版本**: 需要Linux 4.4+内核，建议5.0+以获得最佳兼容性
3. **图形驱动**: 依赖DRM驱动程序提供的tracepoint，某些旧驱动可能不支持
4. **事件频率**: 在高刷新率显示器上，VBlank事件频率可能很高，建议使用过滤选项

## 故障排除

### 常见问题

**1. 权限被拒绝**
```bash
Error: failed to open BPF object
```
解决方案：使用sudo运行程序

**2. 没有捕获到事件**
```bash
Tracing graphics events... (无输出)
```
可能原因：
- 系统没有图形活动
- 图形驱动不支持相关tracepoint
- 过滤条件过于严格

解决方案：
- 启动图形应用程序（如浏览器、游戏）
- 检查系统的图形驱动程序
- 移除过滤条件进行测试

**3. BPF程序加载失败**
```bash
Error: failed to load BPF object
```
可能原因：
- 内核版本过旧
- BPF功能未启用
- 内核配置不支持

解决方案：
- 升级到支持eBPF的内核版本
- 检查内核配置中的BPF支持

### 调试技巧

1. **使用详细模式**: `-v`选项显示更多调试信息
2. **检查可用tracepoint**: 
   ```bash
   sudo ls /sys/kernel/debug/tracing/events/drm/
   sudo ls /sys/kernel/debug/tracing/events/dma_fence/
   ```
3. **测试基本功能**: 先不使用任何过滤选项进行测试
4. **查看系统日志**: `dmesg`命令检查相关错误信息 