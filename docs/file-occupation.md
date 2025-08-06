# file-occupation

## 功能描述

该工具用于查询一个指定路径的文件被哪些进程占用了，其输出结果和lsof的输出有异曲同工之效。与lsof不同的地方在于，file-occupation除了可以通过路径查询外，还可以通过文件inode进行查询，这个方式在路径不可信场景下使用时，尤为有效。当然，代价就是需要root权限使用。

## 使用方式

`sudo ./file-occupation -<p|i|u> <file path|inode number>`

* -p: 指定查询文件路径。使用更便捷，但唯一性较差，相同路径，可能在不同时间段，指向不同的文件（文件被删除、重命名，或再重建）。
* -i: 指定查询文件inode编号。注意不同分区可能使用相同inode编号，请结合-u选项使用
* -u：指定分区的UUID。因为inode编号仅针对分区唯一，不同分区可能存在相同的inode编号，因此可以指定该选项来使得前面指定的inode编号唯一化。

注意，指定文件路径时，如果该文件是一个软链接，那么查询的则是该软链接文件本身，而不是其链接的文件，也就是说，file-occupation不会跟踪软链接。

## 使用示例

```bash
$ sudo ./observe/file-occupation -p /usr/lib/x86_64-linux-gnu/libz.so.1.3.1
Scanning for file /usr/lib/x86_64-linux-gnu/libz.so.1.3.1...
            COMM    UID      PID   FD
--------------------------------------------
 accounts-daemon      0      686   vma(5)
         polkitd    987      695   vma(5)
         udisksd      0      700   vma(5)
           cupsd      0      829   vma(5)
         lightdm      0      837   vma(5)
         upowerd      0      904   vma(5)
            nmbd      0      990   vma(5)
            smbd      0     1006   vma(5)
            Xorg      0     1021   vma(5)
[...]

$ sudo ./observe/file-occupation -p /dev/pts/7
Scanning for file /dev/pts/7...
            COMM    UID      PID   FD
--------------------------------------------
            sudo   1000   835200   11 
              su      0   835201   0 1 2 
            bash      0   835202   0 1 2 255
```

在上面示例中，FD一览表示该文件被指定进程引用的方式，其中，vma(n)是指文件隐式被打开的方式，诸如执行文件，动态库引用文件等，n指被隐式引用的次数；其他空格分隔的纯数字则是表示文件描述符，是显式被引用的方式，一般通过open操作。
