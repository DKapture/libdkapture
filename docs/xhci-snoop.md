# xhci-snoop - xHCI USB 3.0 控制器操作跟踪工具

## 概述

xhci-snoop 是一个基于 eBPF 的工具，用于实时跟踪 xHCI (USB 3.0) 主机控制器的各种操作。它通过监听内核中的 xhci_hcd tracepoint 来收集 USB 设备操作信息，可以帮助系统管理员和开发者调试 USB 设备问题、分析 USB 性能和理解 xHCI 控制器行为。

## 功能特性

xhci-snoop 可以跟踪以下 xHCI 控制器操作：

### 设备管理事件
- **设备分配/释放** (`xhci_alloc_dev`, `xhci_free_dev`) - 设备槽位分配和释放
- **虚拟设备管理** (`xhci_alloc_virt_device`, `xhci_free_virt_device`) - 虚拟设备结构管理
- **设备设置** (`xhci_setup_device`, `xhci_setup_addressable_virt_device`) - 设备初始化和地址配置
- **设备槽位配置** (`xhci_setup_device_slot`) - 设备槽位上下文设置

### 端点管理事件
- **端点操作** (`xhci_add_endpoint`, `xhci_configure_endpoint`) - 端点添加和配置
- **端点控制上下文** (`xhci_configure_endpoint_ctrl_ctx`) - 端点控制上下文管理

### USB 请求块 (URB) 事件
- **URB 生命周期** (`xhci_urb_enqueue`, `xhci_urb_giveback`, `xhci_urb_dequeue`) - URB 入队、完成和出队
- **数据传输跟踪** - 包含传输长度、端点信息、状态码等

### 环形缓冲区事件
- **环形缓冲区管理** (`xhci_ring_alloc`, `xhci_ring_free`) - 环形缓冲区分配和释放
- **队列指针操作** (`xhci_inc_deq`, `xhci_inc_enq`) - 出队和入队指针递增
- **环形缓冲区扩展** (`xhci_ring_expansion`) - 动态扩展环形缓冲区

### 命令处理事件
- **xHCI 命令** (`xhci_handle_command`) - 通用命令处理
- **设备地址命令** (`xhci_handle_cmd_addr_dev`) - 设备地址分配命令
- **端点配置命令** (`xhci_handle_cmd_config_ep`) - 端点配置命令
- **设备槽位控制** (`xhci_handle_cmd_disable_slot`) - 设备槽位禁用
- **设备重置** (`xhci_handle_cmd_reset_dev`, `xhci_handle_cmd_reset_ep`) - 设备和端点重置
- **队列指针设置** (`xhci_handle_cmd_set_deq`, `xhci_handle_cmd_set_deq_ep`) - 队列指针设置
- **端点停止** (`xhci_handle_cmd_stop_ep`) - 端点停止命令

### 事件处理
- **事件处理** (`xhci_handle_event`, `xhci_handle_transfer`) - xHCI 事件和传输完成事件
- **TRB 队列** (`xhci_queue_trb`) - 传输请求块队列操作

### 门铃机制
- **端点门铃** (`xhci_ring_ep_doorbell`) - 端点门铃通知
- **主机门铃** (`xhci_ring_host_doorbell`) - 主机控制器门铃

### 地址上下文管理
- **地址上下文** (`xhci_address_ctx`, `xhci_address_ctrl_ctx`) - 设备地址上下文管理

### 端口状态
- **端口状态** (`xhci_get_port_status`, `xhci_handle_port_status`) - USB 端口状态查询和处理
- **集线器状态** (`xhci_hub_status_data`) - USB 集线器状态数据

### 调试事件
- **调试信息** (`xhci_dbg_address`, `xhci_dbg_*`) - 各种调试跟踪点
- **设备发现** (`xhci_discover_or_reset_device`) - 设备发现和重置
- **设备停止** (`xhci_stop_device`) - 设备停止操作

### USB 调试能力 (DBC) 事件
- **DBC 请求管理** (`xhci_dbc_alloc_request`, `xhci_dbc_free_request`) - DBC 请求分配释放
- **DBC 数据传输** (`xhci_dbc_handle_event`, `xhci_dbc_handle_transfer`) - DBC 事件和传输处理

## 编译和安装

### 前提条件

- Linux 内核版本 ≥ 4.18 (支持 eBPF)
- 已安装 libbpf 开发库
- 已安装 bpftool
- 编译工具链 (gcc, clang)
- 系统具有 xHCI 控制器和相关 tracepoint

### 编译步骤

```bash
# 进入项目目录
cd dkapture/observe

# 编译 xhci-snoop
make xhci-snoop
```

编译成功后会生成以下文件：
- `xhci-snoop` - 可执行文件
- `xhci-snoop.bpf.o` - BPF 对象文件
- `xhci-snoop.skel.h` - BPF skeleton 头文件

## 使用方法

### 基本语法

```bash
xhci-snoop [选项]
```

### 命令行选项

| 选项 | 参数 | 描述 |
|------|------|------|
| `-h` | - | 显示帮助信息 |
| `-v` | - | 详细输出（调试模式） |
| `-t` | - | 包含时间戳 |
| `-p` | PID | 只跟踪指定进程ID |
| `-T` | TID | 只跟踪指定线程ID |
| `-c` | COMM | 只跟踪包含指定字符串的命令 |
| `-D` | DURATION | 跟踪持续时间（秒） |

### 使用示例

#### 1. 基本跟踪
跟踪所有 xHCI 控制器操作：

```bash
sudo ./xhci-snoop
```

#### 2. 带时间戳跟踪
包含时间戳信息：

```bash
sudo ./xhci-snoop -t
```

#### 3. 跟踪特定进程
只跟踪 PID 为 1234 的进程：

```bash
sudo ./xhci-snoop -p 1234
```

#### 4. 跟踪特定命令
只跟踪包含 "usb" 的命令：

```bash
sudo ./xhci-snoop -c usb
```

#### 5. 限时跟踪
跟踪 60 秒后自动退出：

```bash
sudo ./xhci-snoop -D 60
```

#### 6. 组合选项
带时间戳跟踪特定进程 30 秒：

```bash
sudo ./xhci-snoop -t -p 1234 -D 30
```

## 输出格式

### 输出列说明

```
TIME(s)        COMM            PID     TID     EVENT                DETAILS
```

- **TIME(s)**: 时间戳（使用 -t 选项时显示）
- **COMM**: 进程命令名
- **PID**: 进程ID
- **TID**: 线程ID
- **EVENT**: 事件类型
- **DETAILS**: 事件详细信息

### 主要事件类型说明

| 事件类型 | 描述 | 详细信息格式 |
|----------|------|--------------|
| `xhci_alloc_dev` | 分配设备槽位 | info=上下文信息 info2=附加信息 tt_info=TT信息 state=状态 |
| `xhci_free_dev` | 释放设备槽位 | info=上下文信息 info2=附加信息 tt_info=TT信息 state=状态 |
| `xhci_urb_enqueue` | URB入队 | urb=URB地址 ep{N}{in/out}-{type} slot=槽位 len=长度 stream=流ID |
| `xhci_urb_giveback` | URB完成 | urb=URB地址 ep{N}{in/out}-{type} slot=槽位 len=长度 status=状态 |
| `xhci_urb_dequeue` | URB出队 | urb=URB地址 ep{N}{in/out}-{type} slot=槽位 len=长度 status=状态 |
| `xhci_setup_device` | 设备设置 | vdev=虚拟设备 devnum=设备号 state=状态 speed=速度 port=端口 slot=槽位 |
| `xhci_ring_alloc` | 环形缓冲区分配 | type=类型 ring=环形缓冲区地址 segs=段数 stream=流ID |
| `xhci_ring_free` | 环形缓冲区释放 | type=类型 ring=环形缓冲区地址 segs=段数 stream=流ID |
| `xhci_add_endpoint` | 添加端点 | info=端点信息 deq=出队指针 tx_info=传输信息 |
| `xhci_ring_ep_doorbell` | 端点门铃 | slot=槽位号 doorbell=门铃值 |
| `xhci_handle_event` | 事件处理 | type=事件类型 trb=TRB字段 |
| `xhci_queue_trb` | TRB队列 | type=TRB类型 trb=TRB字段 |

### USB 传输类型说明

- **control**: 控制传输
- **bulk**: 批量传输  
- **intr**: 中断传输
- **isoc**: 等时传输

### 示例输出

```
TIME(s)        COMM            PID     TID     EVENT                DETAILS
142.123456     kworker/0:2     12345   12345   xhci_alloc_dev       info=0x80000000 info2=0x12345678 tt_info=0x0 state=0x0
142.123467     usb-storage     54321   54321   xhci_urb_enqueue     urb=0xffff888012345678 ep1out-bulk slot=2 len=0/31 stream=0
142.123478     kworker/0:2     12345   12345   xhci_handle_event    type=1 trb=0x12345678,0x0,0x1000,0x1
142.123489     usb-storage     54321   54321   xhci_urb_giveback    urb=0xffff888012345678 ep1out-bulk slot=2 len=31/31 status=0
```

## 应用场景

### USB 设备调试
- 跟踪 USB 设备插拔事件
- 分析设备枚举过程
- 调试设备初始化问题

### 性能分析
- 监控 USB 传输性能
- 分析传输延迟和吞吐量
- 识别性能瓶颈

### 驱动程序开发
- 调试 USB 驱动程序
- 验证驱动程序行为
- 分析驱动程序与 xHCI 交互

### 系统故障排除
- 诊断 USB 相关系统问题
- 分析 USB 设备故障
- 监控系统 USB 活动

## 故障排除

### 常见问题

1. **权限不足**
   ```
   错误: Failed to load and verify BPF skeleton
   解决: 使用 sudo 运行程序
   ```

2. **内核版本不支持**
   ```
   错误: BPF program load failed
   解决: 确认内核版本 ≥ 4.18 且支持 eBPF
   ```

3. **缺少依赖**
   ```
   错误: Failed to open BPF skeleton
   解决: 安装 libbpf-dev 包
   ```

4. **无 xHCI 控制器**
   ```
   错误: 无法找到 xhci_hcd tracepoint
   解决: 确认系统有 USB 3.0 控制器且驱动已加载
   ```

5. **无输出**
   - 确认系统有 USB 设备活动
   - 检查过滤条件是否过于严格
   - 尝试插拔 USB 设备触发事件

### 调试模式

使用 `-v` 选项启用详细输出：

```bash
sudo ./xhci-snoop -v
```

### 检查 tracepoint 可用性

```bash
# 检查 xhci_hcd tracepoint 是否可用
ls /sys/kernel/debug/tracing/events/xhci_hcd/

# 查看具体 tracepoint 格式
cat /sys/kernel/debug/tracing/events/xhci_hcd/xhci_urb_enqueue/format
```

## 性能影响

xhci-snoop 使用 eBPF 技术，具有以下特点：

- **低开销**: eBPF 程序在内核空间运行，开销极小
- **安全性**: BPF 验证器确保程序安全性
- **实时性**: 零拷贝环形缓冲区提供高性能数据传输

建议在生产环境中：
- 使用过滤选项减少数据量
- 避免长时间运行
- 监控系统性能指标

## 相关工具

- **usb_ob**: 统计 USB 操作次数
- **urblat**: 分析 URB 延迟
- **lsusb**: 列出 USB 设备
- **usbmon**: 内核 USB 监控
- **wireshark**: 可配合 usbmon 进行 USB 协议分析

## 许可证

GPL 许可证

## 参考资料

- [xHCI 规范](https://www.intel.com/content/www/us/en/standards/usb-xhci-specification.html)
- [USB 3.0 规范](https://www.usb.org/documents)
- [eBPF 文档](https://ebpf.io/)
- [Linux USB 子系统文档](https://www.kernel.org/doc/html/latest/driver-api/usb/index.html) 