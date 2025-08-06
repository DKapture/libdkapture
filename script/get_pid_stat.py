#!/usr/bin/env python3
import os
import sys

def read_stat_file(stat_path):
    """读取并解析stat文件"""
    try:
        with open(stat_path, 'r') as f:
            content = f.read().strip()
            if not content:
                return None
                
            # 处理包含空格的进程名
            if content.startswith('('):
                first_paren = content.find('(')
                last_paren = content.rfind(')')
                if first_paren != -1 and last_paren != -1 and last_paren > first_paren:
                    # PID在第一个括号之前
                    pid_part = content[:first_paren].strip()
                    # 进程名在括号内
                    comm = content[first_paren+1:last_paren]
                    # 剩余字段在第二个括号之后
                    remaining = content[last_paren+2:].strip()
                    
                    if pid_part and remaining:
                        fields = remaining.split()
                        # 在开头插入PID和进程名
                        fields.insert(0, comm)  # COMM
                        fields.insert(0, pid_part)  # PID
                        return fields
            else:
                # 简单情况：没有括号包围的进程名
                return content.split()
    except Exception as e:
        return None
    return None

def main():
    print(f"{'PID':>8} {'TGID':>8} {'UTIME':>10} {'STIME':>10} {'COMMAND'}")
    print("-" * 50)
    
    proc_dir = '/proc'
    
    if not os.path.exists(proc_dir):
        print(f"错误: {proc_dir} 目录不存在", file=sys.stderr)
        sys.exit(1)
    
    # 遍历所有进程目录
    for entry in os.listdir(proc_dir):
        if not entry.isdigit():
            continue
            
        pid = int(entry)
        task_dir = os.path.join(proc_dir, entry, 'task')
        
        if not os.path.exists(task_dir):
            continue
            
        # 遍历该进程的所有线程
        try:
            for task_entry in os.listdir(task_dir):
                if not task_entry.isdigit():
                    continue
                    
                task_stat_path = os.path.join(task_dir, task_entry, 'stat')
                
                if not os.path.exists(task_stat_path):
                    continue
                    
                stat_fields = read_stat_file(task_stat_path)
                
                # stat文件字段说明（从0开始索引）：
                # 0: pid, 1: comm, 2: state, 3: ppid, 4: pgrp, 5: session, 
                # 6: tty_nr, 7: tpgid, 8: flags, 9: minflt, 10: cminflt, 
                # 11: majflt, 12: cmajflt, 13: utime, 14: stime, 15: cutime, 
                # 16: cstime, 17: priority, 18: nice, 19: num_threads, 
                # 20: itrealvalue, 21: starttime, 22: vsize, 23: rss, ...
                
                if stat_fields and len(stat_fields) >= 17:
                    try:
                        task_pid = stat_fields[0]           # PID
                        task_name = stat_fields[1]          # COMM
                        task_utime = stat_fields[13]        # UTIME
                        task_stime = stat_fields[14]        # STIME
                        
                        # 对于task目录下的stat文件，TGID应该是线程组的PID
                        # 但在某些情况下，我们需要从进程目录获取正确的TGID
                        task_tgid = pid  # 默认使用进程PID作为TGID
                        
                        print(f"{task_pid:>8} {task_tgid:>8} {task_utime:>10} {task_stime:>10} {task_name}")
                        
                    except (IndexError, ValueError) as e:
                        continue
                        
        except PermissionError:
            continue
        except Exception as e:
            continue

if __name__ == '__main__':
    main()
