# trace-signal

## 功能描述

trace-signal用于追踪进程间的信号通信，能够实时追踪信号的来源和去向，以及信号的取值，甚至追踪一些违法的信号操作（信号发送失败）。可以通过命令行参数设置过滤选项，例如，来源进程的pid、exe路径，去向进程的pid、exe路径，以及信号值。本工具在一些问题排查场景中，非常有效，以下是使用场景：

1. 在日常研发和维护工作中，我们经常会碰到自己的业务进程莫名收到信号而异常退出，这时我们想知道是谁给我们业务进程发送了信号，以便进一步排查问题，但是传统的工具一般无法提供此类功能。
2. 统计指定信号在系统中的使用频率。
3. 统计指定进程在与其他哪些进程进行信号通信。

## 命令选项说明

```bash
./trace-signal -h
Usage: ./observe/trace-signal [option]
  Trace signal communication between processes.

Options:
  -P, --sender-pid <sender-pid>
        Sender process ID to filter

  -p, --recv-pid <recv-pid>
        Receiver process ID to filter

  -s, --sender-prog <sender-prog>
        Filter by sender program

  -r, --recv-prog <recv-prog>
        Filter by receiver program

  -S, --sig <sig>
        Signal number to filter

  -R, --res <res>
        Signal number to filter

  -h, --help 
        print this help message
```

- -P：指定发送进程的pid，用于过滤信号的发送方。
- -p：指定接收进程的pid，用于过滤信号的目的地。
- -s：指定发送进程的exe路径，用于使用路径来代表需过滤的发送进程。过滤时使用的路径与/proc/[pid]/exe的链接路径相同。请使用者自行注意，作为过滤使用的路径参数是否包含软链接，本工具不会对软链接进行解引用。
- -r：指定发送进程的exe路径，用于使用路径来代表需过滤的发送进程。过滤时使用的路径与/proc/[pid]/exe的链接路径相同。请使用者自行注意，作为过滤使用的路径参数是否包含软链接，本工具不会对软链接进行解引用。
- -S：需要过滤的信号，整数值。
- -R：过滤信号通信操作的结果，可以理解为kill系统调用的操作结果。
- -h：打印本帮助信息。

## 运行示例

```bash
sudo ./trace-signal -s /usr/bin/kill

=============== filter =================

        sender_pid = 0
        sender_phash = 0
        recv_pid = 0
        recv_phash = 1120940906
        signal = 0
        return = 0

========================================

SENDER          S-COMM      RCVER          R-COMM       SIGNAL   RESULT
 96077            kill       2683            bash            0        0
 96144            kill          0                            0       -1
 96454            kill      23287        cpptools    Continued        0
```

本示例中，使用该工具跟踪来/usr/bin/kill程序的信号发送，命名执行后，首先输出的过滤器相关的信息，然后是信号捕获输出列表，各字段含义如下：

- SENDER：发送者pid.
- S-COMM：发送者进程名。
- RCVER：接收者pid。
- R-COMM：接收者程序名。
- SIGNAL：信号。
- RESULT：通信结果。0表示成功。