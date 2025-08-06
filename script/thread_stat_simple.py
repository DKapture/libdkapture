#!/usr/bin/env python3
"""
简化版线程统计信息分析器
只显示统计结果，不显示详细线程列表
"""

import os
import sys
from pathlib import Path

def parse_proc_stat(stat_content):
    """
    解析/proc/pid/task/tid/stat文件内容
    返回(utime, stime)元组
    """
    try:
        fields = stat_content.strip().split()
        if len(fields) < 15:
            return None, None
        
        # utime是第14个字段(索引13)，stime是第15个字段(索引14)
        utime = int(fields[13])
        stime = int(fields[14])
        return utime, stime
    except (ValueError, IndexError) as e:
        return None, None

def analyze_thread_stats():
    """
    分析所有进程的线程统计信息
    """
    proc_path = Path("/proc")
    total_threads = 0
    utime_zero_count = 0
    stime_zero_count = 0
    both_zero_count = 0
    
    print("正在分析线程统计信息...")
    
    # 遍历所有进程目录
    for pid_dir in proc_path.iterdir():
        if not pid_dir.is_dir() or not pid_dir.name.isdigit():
            continue
            
        task_dir = pid_dir / "task"
        
        if not task_dir.exists():
            continue
            
        # 遍历进程的所有线程
        for tid_dir in task_dir.iterdir():
            if not tid_dir.is_dir() or not tid_dir.name.isdigit():
                continue
                
            stat_file = tid_dir / "stat"
            
            if not stat_file.exists():
                continue
                
            try:
                with open(stat_file, 'r') as f:
                    stat_content = f.read()
                    
                utime, stime = parse_proc_stat(stat_content)
                
                if utime is None or stime is None:
                    continue
                    
                total_threads += 1
                
                # 统计utime为0的线程
                if utime == 0:
                    utime_zero_count += 1
                
                # 统计stime为0的线程
                if stime == 0:
                    stime_zero_count += 1
                
                # 统计utime和stime都为0的线程
                if utime == 0 and stime == 0:
                    both_zero_count += 1
                    
            except (IOError, OSError):
                # 忽略权限不足或文件不存在的错误
                continue
    
    # 打印统计结果
    print(f"\n=== 线程统计信息分析结果 ===")
    print(f"总线程数: {total_threads}")
    print(f"utime为0的线程数: {utime_zero_count} ({utime_zero_count/total_threads*100:.1f}%)")
    print(f"stime为0的线程数: {stime_zero_count} ({stime_zero_count/total_threads*100:.1f}%)")
    print(f"utime和stime都为0的线程数: {both_zero_count} ({both_zero_count/total_threads*100:.1f}%)")

def main():
    """
    主函数
    """
    print("简化版线程统计信息分析器")
    print("=" * 50)
    
    try:
        analyze_thread_stats()
    except KeyboardInterrupt:
        print("\n用户中断操作")
        sys.exit(1)
    except Exception as e:
        print(f"发生错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 