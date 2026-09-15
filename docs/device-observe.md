# device-observe

## 功能描述

device-observe 是基于 eBPF 的外设使用实时监控工具，能够记录系统中摄像头（V4L2）和麦克风（ALSA 录音设备）的打开、关闭、流启停等操作，输出调用进程 PID、时间戳、设备路径等完整信息。

## 使用方式

```bash
$ sudo ./build/observe/device-observe -h
Usage: device-observe [OPTION...]
device-observe - Monitor camera and microphone device access

USAGE: device-observe [OPTIONS]

EXAMPLES:
    device-observe                    # Monitor all camera and mic events
    device-observe -c                 # Monitor camera only
    device-observe -m                 # Monitor microphone only
    device-observe -p 1234            # Monitor process 1234 only
    device-observe -t -v              # Timestamp + verbose output

  -p, --pid=PID              Trace process with this PID only
  -c, --camera               Monitor camera devices (default: on)
  -C, --no-camera            Disable camera monitoring
  -m, --microphone           Monitor microphone devices (default: on)
  -M, --no-microphone        Disable microphone monitoring
  -t, --timestamp            Include timestamp in output
  -v, --verbose              Verbose output (show all ioctl events)
  -?, --help                 Give this help list
```

## 参数说明

- `-p, --pid=PID`：只跟踪指定 PID 的进程。
- `-c, --camera`：启用摄像头监控（默认开启）。
- `-C, --no-camera`：关闭摄像头监控。
- `-m, --microphone`：启用麦克风监控（默认开启）。
- `-M, --no-microphone`：关闭麦克风监控。
- `-t, --timestamp`：在输出中包含时间戳。
- `-v, --verbose`：详细模式，显示所有 ioctl 事件（默认仅显示 STREAM_ON/OFF）。

## 使用示例

### 示例输出

1) 监控所有摄像头和麦克风事件（默认）：

```bash
$ sudo ./build/observe/device-observe
DEVICE        EVENT       IOCTL                    PID    COMM             UID    PATH
Tracing device access... Hit Ctrl-C to end.
CAMERA        OPEN                                 1234   wechat           1000  /dev/video0 fd=3
CAMERA        STREAM_ON   VIDIOC_STREAMON          1234   wechat           1000  /dev/video0 fd=3
CAMERA        STREAM_OFF  VIDIOC_STREAMOFF         1234   wechat           1000  /dev/video0 fd=3
CAMERA        CLOSE                                1234   wechat           1000  /dev/video0 fd=3
MIC           OPEN                                 5678   pipewire         0     /dev/snd/pcmC0D0c fd=12
MIC           STREAM_ON   SNDRV_PCM_IOCTL_START    5678   pipewire         0     /dev/snd/pcmC0D0c fd=12
```

2) 仅监控摄像头，带时间戳：

```bash
$ sudo ./build/observe/device-observe -C -t
TIME     DEVICE        EVENT       IOCTL                    PID    COMM             UID    PATH
10:23:45 CAMERA        OPEN                                 1234   wechat           1000  /dev/video0 fd=3
```

3) 跟踪指定进程的麦克风使用：

```bash
$ sudo ./build/observe/device-observe -C -p 19876
```

## 技术原理

### 整体架构

```
  用户进程
      |
      | openat(/dev/video0)  openat(/dev/snd/pcmC0D0c)  ioctl(VIDIOC_STREAMON)
      v
  ---- Linux Kernel ----
  +--------------------+     +------------------+     +------------------+
  | sys_enter_openat  |---->| sys_enter_ioctl  |     | sys_enter_close |
  |   (tracepoint)     |     |   (tracepoint)   |     |   (tracepoint)   |
  +--------------------+     +------------------+     +------------------+
           |                          |                          |
           v                          v                          v
  +--------------------------------------------------------------+
  |                    eBPF Programs                        |
  |  - openat enter: 读 filename，匹配设备路径前缀            |
  |  - openat exit:  取 fd，发 DEV_EVT_OPEN，注册 fd_table |
  |  - ioctl enter:  查 fd_table，匹配 STREAM_ON/OFF cmd  |
  |  - close enter:  查 fd_table，发 DEV_EVT_CLOSE，清理      |
  +--------------------------------------------------------------+
           |
           v  bpf_ringbuf
  +------------------+
  |   用户空间程序    |  格式化输出到终端
  +------------------+
```

### 设备识别方式

| 设备   | 设备文件路径模式                | 内核子系统 | Major 号 |
|--------|-------------------------------|-----------|----------|
| 摄像头 | `/dev/video*`                   | V4L2      | 81       |
| 麦克风 | `/dev/snd/pcmC<card>D<dev>c` | ALSA PCM  | 116      |

- 摄像头：匹配路径前缀 `/dev/video`（V4L2 设备，major=81）
- 麦克风：匹配路径前缀 `/dev/snd/pcmC` 且路径末尾字符为 `c`（capture 设备，playback 为 `p`）

### 关键 ioctl 命令

| 设备   | 命令                      | 值        | 含义             |
|--------|--------------------------|-----------|------------------|
| 摄像头 | VIDIOC_STREAMON         | 0x40045612 | 开始视频采集     |
| 摄像头 | VIDIOC_STREAMOFF        | 0x40045613 | 停止视频采集     |
| 麦克风 | SNDRV_PCM_IOCTL_START  | 0x00004142 | 开始录音         |
| 麦克风 | SNDRV_PCM_IOCTL_DROP   | 0x00004143 | 停止录音         |

### BPF 数据流

1. **openat enter**：读用户空间 filename，匹配设备路径前缀，将设备类型和路径存入 `open_pending` map（key: pid_tgid）
2. **openat exit**：取返回值作为 fd，查 `open_pending` 获取设备信息，发送 DEV_EVT_OPEN 事件，将 (tgid, fd) → device_type 存入 `fd_table`
3. **ioctl enter**：查 `fd_table` 判断 fd 是否为已知设备，匹配关键 ioctl 命令，发送 DEV_EVT_STREAM_ON/DEV_EVT_STREAM_OFF 事件
4. **close enter**：查 `fd_table` 判断 fd 是否为已知设备，发送 DEV_EVT_CLOSE 事件，清理 `fd_table`

### BPF Maps

| Map 名称      | 类型                   | Key               | Value             | 用途                  |
|---------------|------------------------|-------------------|-------------------|----------------------|
| open_pending  | BPF_MAP_TYPE_HASH     | pid_tgid          | open_info struct  | openat enter→exit 传参 |
| fd_table      | BPF_MAP_TYPE_HASH     | (tgid<<32 \| fd) | u32 device_type   | ioctl/close 时查询 |
| events        | BPF_MAP_TYPE_RINGBUF  | -                 | devobs_event      | 事件输出到用户空间    |

### 事件结构体

```c
struct devobs_event
{
    __u64 timestamp_ns;   // 纳秒级时间戳
    __u32 pid;           // 进程 ID
    __u32 tid;           // 线程 ID
    __u32 uid;           // 用户 ID
    __u32 device_type;    // DEV_TYPE_CAMERA / DEV_TYPE_MICROPHONE
    __u32 event_type;     // DEV_EVT_OPEN / CLOSE / STREAM_ON / STREAM_OFF
    int   fd;             // 文件描述符
    __u32 ioctl_cmd;     // ioctl 命令码
    char  comm[16];      // 进程名
    char  device_path[64]; // 设备路径
};
```

### 用户空间过滤

通过 BPF skeleton 的 rodata 机制，用户空间在 BPF 加载前写入过滤条件：

| rodata 变量         | 类型 | 默认值 | 说明                       |
|---------------------|------|--------|---------------------------|
| filter_camera       | bool | true   | 是否启用摄像头监控         |
| filter_microphone   | bool | true   | 是否启用麦克风监控         |
| target_pid          | int  | 0      | 过滤指定 PID（0 表示不过滤）|

### PipeWire 场景说明

在 Deepin/UOS 等现代 Linux 桌面上，应用通常不直接打开 ALSA/V4L2 设备节点，而是通过 PipeWire（或旧版 PulseAudio）代理访问。此时：

- 本工具会记录 **pipewire 守护进程** 打开设备节点的行为
- PipeWire 作为中间层，打开 `/dev/video0` 或 `/dev/snd/pcmC0D0c` 进行实际的硬件交互
- 若需追溯最终请求应用，需结合 PipeWire 的 D-Bus 接口或 `pw-cli` 命令进一步查询

## 已知限制

1. 仅识别通过标准设备路径打开的设备（`/dev/video*`、`/dev/snd/pcmC*D*c`），不识别通过符号链接或 `/dev/v4l/by-path/` 等路径的打开
2. PipeWire 代理场景下记录的是 pipewire 进程而非最终应用
3. 不追踪通过 dup/dup2 继承的 fd
4. 不追踪通过 sendmsg/SCM_RIGHTS 传递的 fd
