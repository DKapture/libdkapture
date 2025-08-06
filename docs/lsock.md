# lsock

## 功能描述

类似netstat工具，提供获取系统中所有网络套接字信息的功能，但是效率要比netstat高。

## 使用方法

```bash
$ sudo ./observe/lsock -h
Usage: ./observe/lsock [option]
  list the sockets that the system is using

Options:
  -i, --sip <source ip>
        process name to filter

  -I, --dip <dest ip>
        process id to filter

  -p, --sport <source port>
        remote ip to filter

  -P, --dport <dest port>
        remote port to filter

  -t, --tcp 
        filter tcp socket

  -u, --udp 
        filter udp socket

  -x, --unix 
        filter unix socket

  -4, --ipv4 
        filter ipv4 socket

  -6, --ipv6 
        filter ipv6 socket

  -l, --listen 
        filter socket in state LISTENING

  -h, --help 
        print this help message
```

- -i：指定需要过滤的源端ip，可以通过‘-’符号指定范围，例如-i 127.0.0.1-127.0.0.255。
- -I：同-i，但是是指定源端ip。
- -p：指定需要过滤的源端端口，可以通过‘-’符号指定范围，例如-p 1000-2000。
- -P：同-p,但是是指定远端端口。
- -t：过滤tcp协议的套接字。
- -u：过滤udp协议的套接字。
- -x：过滤unix本地协议套接字。
- -4：过滤使用ipv4协议的套接字。
- -6：过滤使用ipv6协议的套接字。
- -l：过滤处于监听状态的套接字。

## 使用示例

### proc格式输出（默认)

工具的输出内容格式与procfs文件系统下的 `/proc/net/udp、/proc/net/udp6、/proc/net/tcp、/proc/net/tcp6、/proc/net/unix`的格式相同。

1. 查看unix套接字信息

```bash
$ sudo ./observe/lsock -x | head -20
trace thread created
Num               RefCount Protocol Flags    Type St    Inode Path
00000000b7dd9f84: 00000004 00000000 00000000 0001 03    38935 
00000000b16861ac: 00000004 00000000 00000000 0001 03    23930 /run/user/1000/bus
00000000fd369a09: 00000004 00000000 00000000 0001 03    20678 
00000000a781acbd: 00000004 00000000 00000000 0001 03    13045 /run/dbus/system_bus_socket
000000007a04d9dd: 00000004 00000000 00000000 0001 03    20441 
00000000314d3dee: 00000004 00000000 00000000 0001 03    17107 /run/systemd/journal/stdout
000000009903e50a: 00000004 00000000 00000000 0001 03    15965 /run/user/1000/bus
00000000c2779113: 00000004 00000000 00000000 0001 03  9491237 /tmp/.ZEYQYQ/s
```

    其中Path列表明该socket关联的文件系统的文件。

3. 查看tcp4套接字信息

```bash
$ sudo ./observe/lsock -t4 | head -10
trace thread created
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 017AA8C0:0035 00000000:0000 0A 00000000:00000000 02:00000000 00000000     0        0 2321 2 00000000756611ba 100 0 0 10 5
   0: 0100007F:170C 00000000:0000 0A 00000000:00000000 02:00000000 00000000 64055        0 14655 2 00000000a19d853f 100 0 0 10 0
   0: 0100007F:907B 00000000:0000 0A 00000000:00000000 02:00000000 00000000  1000        0 38921 2 0000000097f8c2fb 100 0 0 10 0
   0: 0100007F:B235 00000000:0000 0A 00000000:00000000 02:00000000 00000000  1000        0 23192 2 0000000015707367 100 0 0 10 0
   0: 0100007F:9E0D 00000000:0000 0A 00000000:00000000 02:00000000 00000000  1000        0 14433438 2 00000000e2551ee2 100 0 0 10 0
   0: 0100007F:A5B7 00000000:0000 0A 00000000:00000000 02:00000000 00000000  1000        0 14397338 2 00000000a1740049 100 0 0 10 0
   0: 0100007F:C35A 00000000:0000 0A 00000000:00000000 02:00000000 00000000  1000        0 36545 2 000000001c5e3511 100 0 0 10 0
   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 02:00000000 00000000     0        0 18873 2 00000000197c6d86 100 0 0 10 0
```

3. 查看udp6套接字信息

```bash
$ sudo ./observe/lsock -u6
trace thread created
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
    0: 000080FE00000000559F849CCFA10159:0222 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 11985 3 000000005cd1584a 0
    0: 00000000000000000000000000000000:14E9 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   107        0 14513 3 00000000c48b540e 0
    0: 00000000000000000000000000000000:006F 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 4710 3 00000000c3036f01 0
    0: 00000000000000000000000000000000:8753 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   107        0 14515 3 0000000002ed86ce 0
```

### netstat格式输出

TODO
