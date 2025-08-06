# wakeup_count 进程唤醒统计工具

## 功能描述
本工具通过 eBPF 技术实现：
- 跟踪系统中进程调度唤醒事件
- 统计指定进程/PID/cgroup 的唤醒次数
- 生成 ASCII 直方图展示唤醒频率分布
- 支持实时数据刷新和动态过滤

## 参数说明

| 参数 | 简写 | 说明 |
|------|------|-----|
| `--pid` | `-p` | 仅跟踪指定 PID 的进程 (默认: 所有进程) |
| `--cgroup` | `-c` | 跟踪指定 cgroup 路径下的进程 (需绝对路径) |
| `--verbose` | `-v` | 启用详细调试输出 |
| `--help` | `-h` | 显示完整帮助信息 |

## 字段说明

- max_count：最大次数
- pid：进程pid
- comm：进程名
- count：调用次数

## 使用示例
```bash
sudo ./wakeup_count
max_wakeup_count = 117
pid       comm                  count     
31        ksoftirqd/2           2          |                                        |
22945     kworker/u16:0         3          |*                                       |
1223      QThread               1          |                                        |
507       kworker/4:3           9          |***                                     |
21526     kworker/6:0           2          |                                        |
725       Xorg                  9          |***                                     |
770       Xorg:cs0              3          |*                                       |
1056      DetectThread          114        |**************************************  |
650       wpa_supplicant        2          |                                        |
974       lightdm               11         |***                                     |
23293     kworker/u16:2         12         |****                                    |
17        rcu_preempt           17         |*****                                   |
779       kworker/0:2           23         |*******                                 |
