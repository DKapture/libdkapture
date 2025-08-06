# rm-forbid

## 功能描述

提供类似windows的“占用文件不可删除"的行为。在目前linux上，如果我们打开一个文件（占用它)，然后在另一个进程中去删除它，这个操作是被系统允许的，但是，在windows上，这个行为是不被允许的。本工具提供类windows文件删除行为的特性，给予用户更多选择。

## 使用方法

```c
sudo ./filter/rm-forbid -h
Usage: ./filter/rm-forbid [option]
  To query who are occupying the specified file.

Options:
  -p, --path [path]
        path of the file to watch on

  -u, --uuid [uuid]
        the uuid of filesystem to which the inode belong.
        you can get the uuid by running command 'blkid'

  -i, --inode [inode]
        inode of the file to watch on

  -h, --help 
        print this help message
```

- -p：可以指定某个路径的文件不允许在占用时被删除，不指定则涵括全系统文件。
- -u：-p的延伸版本，指定文件系统的uuid（可通过blkid命令查询)，所有在该指定文件系统上的文件不允许在占用时被删除。
- -i：指定文件inode号，建议结合-u选项使用，文件inode编号为指定值的文。件不允许在占用时被删除。

## 使用示例

```bash
$ blkid | grep n1p5
/dev/nvme0n1p5: UUID="8db1a478-0787-44f5-a0ac-3c5cd51d9271" BLOCK_SIZE="4096" TYPE="ext4" PARTUUID="66f2ede8-62cc-4a5a-9903-2b37b516c41c"
$ sudo ./filter/rm-forbid -u 8db1a478-0787-44f5-a0ac-3c5cd51d9271 &
[1] 1035650
$ echo 111 > /tmp/111
$ tail -f /tmp/111 &
[2] 1035664
111
$ rm -f /tmp/111 
rm: 无法删除 '/tmp/111': 设备或资源忙
$ kill %1
$ rm -f /tmp/111 
[1]-  已终止               sudo ./filter/rm-forbid -u 8db1a478-0787-44f5-a0ac-3c5cd51d9271
$
```

1. 首先我们通过blkid命令找一个需要保护的文件系统，例如他nvme0n1p5。
2. 然后将它的UUID传递给工具 `./filter/rm-forbid -u 8db1a478-0787-44f5-a0ac-3c5cd51d9271`。
3. 然后用任意编辑器占用一个文件，例如 `tail -f file`。
4. 然后尝试删除刚占用的文件，可以看到结果是“无法删除"。
5. 最后我们取消保护，将bpf程序退出 `kill %1`。
6. 再次删除，可以成功删除。
