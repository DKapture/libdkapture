# switch_count - 进程上下文切换监控工具

## 功能描述

本工具基于eBPF技术实现Linux系统进程上下文切换的实时监控分析，主要特性包括：

- **精准追踪**：通过`sched_switch`跟踪点捕获完整的上下文切换事件
- **动态过滤**：支持PID过滤和cgroup分组监控（v2子系统）
- **智能可视化**：自适应比例直方图展示切换频率分布

## 参数说明

```bash
Usage: switch_count [OPTIONS]
Options:
  -p, --pid <PID>        监控指定PID及其线程（支持逗号分隔列表）
  -c, --cgroup <PATH>    指定cgroup v2挂载路径（默认：/sys/fs/cgroup）
  -m, --mode <MODE>      统计模式 [basic|advanced]（默认：basic）
  -i, --interval <SEC>  刷新间隔秒数（默认：动态自适应）
  -v, --verbose          启用BPF验证器调试输出
  -h, --help             显示帮助信息
```

## 字段说明

- max_count：最大次数
- pid：进程pid
- comm：进程名
- count：调用次数

## 使用示例

```bash
sudo ./switch_count
max_count = 322
pid       comm                  count     
16        ksoftirqd/0      3          |                                        |
55        ksoftirqd/6      1          |                                        |
725       Xorg             3          |                                        |
23293     kworker/u16:2    7          |                                        |
733       dde-system-daem  3          |                                        |
747       dde-system-daem  2          |                                        |
648       NetworkManager   5          |                                        |
770       Xorg:cs0         1          |                                        |
1106      wb[UOS-PC]       1          |                                        |
1520      sudo             7          |                                        |
734       dde-system-daem  2          |                                        |
1056      DetectThread     46         |*****                                   |
24944     curl             3          |                                        |
1217      sshd             27         |***                                     |
673       QThread          9          |*                                       |
21526     kworker/6:0      11         |*                                       |
1223      QThread          1          |                                        |
618       gmain            1          |                                        |
208       gfx              2          |                                        |
923       QThread          1          |                                        |
24941     switch_count     1          |                                        |
727       dde-system-daem  1          |                                        |
61        ksoftirqd/7      7          |                                        |
17        rcu_preempt      60         |*******                                 |
24942     QThread          6          |                                        |
72        kcompactd0       1          |                                        |
16423     kworker/2:0      12         |*                                       |
469       kworker/3:2      10         |*                                       |
320       systemd-journal  1          |                                        |
4290      kworker/7:1      50         |******                                  |
0         swapper/1        358        |****************************************+|
```
