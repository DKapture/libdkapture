#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1

import sys
import argparse
from collections import defaultdict
import time
import re
import select
import shutil

class IRQStat:
    def __init__(self):
        # Data structure to store IRQ statistics
        self.irq_stats = defaultdict(lambda: {
            'count': 0, 
            'total_latency': 0.0, 
            'max_latency': 0.0,
            'name': '',
            'min_latency': float('inf'),
            'last_update': 0  # Last update time
        })
        self.softirq_stats = defaultdict(lambda: {
            'count': 0, 
            'total_latency': 0.0, 
            'max_latency': 0.0,
            'name': '',
            'min_latency': float('inf'),
            'last_update': 0  # Last update time
        })
        self.process_stats = defaultdict(lambda: {
            'count': 0, 
            'total_latency': 0.0,
            'max_latency': 0.0,
            'min_latency': float('inf'),
            'last_update': 0  # Last update time
        })
        self.start_time = time.time()
        self.last_print = 0  # Last time statistics were printed
        self.update_interval = 1  # Real-time update interval (seconds)
        self.terminal_width = shutil.get_terminal_size().columns
        
        # Add delay threshold constants
        self.MAX_REASONABLE_LATENCY_NS = 1000000000  # 1 second
        self.MIN_LATENCY_NS = 0
        self.WARN_THRESHOLD_NS = 100000000  # 100 milliseconds
        
        # Add delay trend analysis
        self.TREND_WINDOW = 10  # Keep the last 10 samples
        self.trend_data = defaultdict(lambda: {'samples': [], 'timestamps': []})
        
        # System load related
        self.last_load_check = 0
        self.load_check_interval = 1  # Check load every second
        
    def get_system_load(self):
        """Get system load information"""
        try:
            with open('/proc/loadavg', 'r') as f:
                loadavg = f.read().split()
                return {
                    'load1': float(loadavg[0]),
                    'load5': float(loadavg[1]),
                    'load15': float(loadavg[2])
                }
        except Exception as e:
            print(f"Cannot read system load: {e}", file=sys.stderr)
            return None
            
    def check_trend_anomaly(self, irq_type, irq_num, latency_us):
        """Check if the delay trend is anomalous"""
        key = f"{irq_type}_{irq_num}"
        trend = self.trend_data[key]
        
        # Update trend data
        trend['samples'].append(latency_us)
        trend['timestamps'].append(time.time())
        
        # Maintain window size
        if len(trend['samples']) > self.TREND_WINDOW:
            trend['samples'].pop(0)
            trend['timestamps'].pop(0)
            
        # At least 3 samples are needed to analyze the trend
        if len(trend['samples']) < 3:
            return False
            
        # Calculate the recent change rate
        recent_changes = [
            (trend['samples'][i] - trend['samples'][i-1]) / 
            (trend['timestamps'][i] - trend['timestamps'][i-1])
            for i in range(1, len(trend['samples']))
        ]
        
        # If the recent change rate is significantly higher than the average, it is considered anomalous
        avg_change = sum(recent_changes[:-1]) / len(recent_changes[:-1])
        latest_change = recent_changes[-1]
        
        return latest_change > avg_change * 5  # Change rate exceeds average by 5 times is considered anomalous

    def validate_latency(self, latency_ns, source):
        """Validate the rationality of the delay value, return the effective delay value in microseconds"""
        try:
            latency_ns = int(latency_ns)
            latency_us = float(latency_ns) / 1000.0

            # Check system load
            now = time.time()
            if now - self.last_load_check >= self.load_check_interval:
                load_info = self.get_system_load()
                self.last_load_check = now

            if latency_ns < self.MIN_LATENCY_NS:
                return 0
                
            if latency_ns > self.MAX_REASONABLE_LATENCY_NS:
                return self.MAX_REASONABLE_LATENCY_NS / 1000.0
                
            # Check trend anomalies but do not output prompts
            irq_type, irq_num = source.split()[0:2]
            self.check_trend_anomaly(irq_type, irq_num, latency_us)
                
            return latency_us
            
        except (ValueError, TypeError) as e:
            return 0

    def update_stats(self, irq_type, irq_num, latency_ns, process_name, irq_name=''):
        # Validate and convert delay value (nanoseconds to microseconds)
        latency_us = self.validate_latency(latency_ns, f"{irq_type} {irq_num} ({process_name})")
        
        stats = self.irq_stats if irq_type == 'IRQ' else self.softirq_stats
        
        # Update interrupt statistics
        stats[irq_num]['count'] += 1
        stats[irq_num]['total_latency'] += latency_us
        stats[irq_num]['max_latency'] = max(stats[irq_num]['max_latency'], latency_us)
        stats[irq_num]['min_latency'] = min(stats[irq_num]['min_latency'], latency_us) if stats[irq_num]['min_latency'] != float('inf') else latency_us
        stats[irq_num]['last_update'] = time.time()
        if irq_name:
            stats[irq_num]['name'] = irq_name
            
        # Update process statistics
        self.process_stats[process_name]['count'] += 1
        self.process_stats[process_name]['total_latency'] += latency_us
        self.process_stats[process_name]['max_latency'] = max(self.process_stats[process_name]['max_latency'], latency_us)
        self.process_stats[process_name]['min_latency'] = min(self.process_stats[process_name]['min_latency'], latency_us) if self.process_stats[process_name]['min_latency'] != float('inf') else latency_us
        self.process_stats[process_name]['last_update'] = time.time()

    def parse_line(self, line):
        try:
            # Parse irqsnoop output line using regular expressions
            if '[IRQ]' in line or '[SOFTIRQ]' in line:
                irq_type = 'IRQ' if '[IRQ]' in line else 'SOFTIRQ'
                
                # Parse pid and process name
                pid_match = re.search(r'pid=(\d+)', line)
                comm_match = re.search(r'comm=(\S+)', line)
                
                # Parse interrupt number/vector and delay
                if irq_type == 'IRQ':
                    irq_match = re.search(r'irq=(\d+)', line)
                    name_match = re.search(r'name=(\S+)', line)
                else:
                    irq_match = re.search(r'vec=(\S+)', line)
                    name_match = None
                    
                delta_match = re.search(r'delta=(\d+)ns', line)
                
                if all(m is not None for m in [pid_match, comm_match, irq_match, delta_match]):
                    process_name = comm_match.group(1)
                    irq_num = irq_match.group(1)
                    try:
                        latency_ns = int(delta_match.group(1))
                        irq_name = name_match.group(1) if name_match else ''
                        self.update_stats(irq_type, irq_num, latency_ns, process_name, irq_name)
                    except (ValueError, TypeError) as e:
                        print(f"Warning: Error parsing delay value: {e}, line: {line}", file=sys.stderr)
        except Exception as e:
            print(f"Parse error: {e}, line: {line}", file=sys.stderr)

    def print_progress(self):
        """Print real-time progress and statistics"""
        elapsed = time.time() - self.start_time
        total_time = float(self.interval) if self.interval else 0
        
        if total_time > 0:
            progress = min(elapsed / total_time * 100, 100)
            bar_width = self.terminal_width - 30
            filled = int(bar_width * progress / 100)
            bar = '=' * filled + '-' * (bar_width - filled)
            
            # Clear current line and print progress bar
            print(f'\r[{bar}] {progress:5.1f}% {elapsed:5.1f}/{total_time:5.1f}s', end='')
            
            # Print brief statistics every 5 seconds
            if int(elapsed) % 5 == 0 and elapsed - int(elapsed) < 0.1:
                self.print_brief_stats()
        else:
            # If no total time is set, only show running time
            print(f'\rRunning time: {elapsed:5.1f}s', end='')
            
            # Print brief statistics every 5 seconds
            if int(elapsed) % 5 == 0 and elapsed - int(elapsed) < 0.1:
                self.print_brief_stats()

    def print_brief_stats(self):
        """Print brief statistical information"""
        print("\n\n=== Real-time Statistics ===")
        elapsed = time.time() - self.start_time
        
        # Show the most active interrupts
        print("\nMost Active Hard Interrupts:")
        active_irqs = sorted(self.irq_stats.items(), 
                           key=lambda x: x[1]['count']/elapsed, 
                           reverse=True)[:3]
        for irq_num, stats in active_irqs:
            rate = stats['count'] / elapsed
            avg_latency = stats['total_latency'] / stats['count'] if stats['count'] > 0 else 0
            print(f"IRQ {irq_num:>3} ({stats['name']:<10}): {rate:6.1f}/s, Avg Latency: {avg_latency:6.1f}us")
            
        # Show the most active soft interrupts
        print("\nMost Active Soft Interrupts:")
        active_softirqs = sorted(self.softirq_stats.items(), 
                               key=lambda x: x[1]['count']/elapsed, 
                               reverse=True)[:3]
        for vec, stats in active_softirqs:
            rate = stats['count'] / elapsed
            avg_latency = stats['total_latency'] / stats['count'] if stats['count'] > 0 else 0
            print(f"SOFTIRQ {vec:<10}: {rate:6.1f}/s, Avg Latency: {avg_latency:6.1f}us")
            
        # Show the most active processes
        print("\nMost Active Processes:")
        active_procs = sorted(self.process_stats.items(), 
                            key=lambda x: x[1]['count']/elapsed, 
                            reverse=True)[:3]
        for proc, stats in active_procs:
            rate = stats['count'] / elapsed
            avg_latency = stats['total_latency'] / stats['count'] if stats['count'] > 0 else 0
            print(f"{proc:<15}: {rate:6.1f}/s, Avg Latency: {avg_latency:6.1f}us")
        
        # Move the cursor to the progress bar position
        print("\n", end='')

    def get_sorted_stats(self, stats, sort_by, elapsed):
        """Sort statistical data according to the specified sorting method"""
        def get_sort_key(item):
            irq_num, data = item
            count = data['count']
            if count == 0:
                return 0
                
            if sort_by == 'rate':
                return count / elapsed
            elif sort_by == 'avg':
                return data['total_latency'] / count
            elif sort_by == 'max':
                return data['max_latency']
            elif sort_by == 'min':
                return data['min_latency'] if data['min_latency'] != float('inf') else 0
            else:  # count
                return count
                
        return sorted(stats.items(), key=get_sort_key, reverse=True)

    def print_report(self, interval=None, filter_process=None, filter_irq=None, 
                    latency_threshold=None, sort_by='count'):
        """Print final detailed report"""
        print("\n\n" + "="*self.terminal_width)
        elapsed = time.time() - self.start_time if interval is None else interval
        
        print("\n=== IRQ Statistics Report ===")
        print(f"Time period: {elapsed:.2f} seconds")
        print(f"Sort by: {sort_by}\n")
        
        # Define column widths
        col_widths = {
            'type': 10,      # Type column
            'irq': 10,       # IRQ number column
            'name': 15,      # Name column
            'count': 12,     # Count column
            'rate': 12,      # Rate column
            'avg': 12,       # Average column
            'min': 12,       # Min column
            'max': 12        # Max column
        }
        
        # Print header
        header_format = "{type:<{w[type]}} {irq:<{w[irq]}} {name:<{w[name]}} {count:>{w[count]}} {rate:>{w[rate]}} {avg:>{w[avg]}} {min:>{w[min]}} {max:>{w[max]}}".format(
            type="Type",
            irq="IRQ",
            name="Name",
            count="Count",
            rate="Rate/s",
            avg="Avg(us)",
            min="Min(us)",
            max="Max(us)",
            w=col_widths
        )
        print(header_format)
        
        # Print separator line
        total_width = sum(col_widths.values()) + len(col_widths) - 1
        print("-" * total_width)
        
        # Get sorted hardware interrupt statistics
        sorted_irqs = self.get_sorted_stats(self.irq_stats, sort_by, elapsed)
        for irq_num, stats in sorted_irqs:
            if filter_irq and irq_num != filter_irq:
                continue
            if latency_threshold and stats['max_latency'] < latency_threshold:
                continue
                
            rate = stats['count'] / elapsed
            avg_latency = stats['total_latency'] / stats['count'] if stats['count'] > 0 else 0
            min_latency = stats['min_latency'] if stats['min_latency'] != float('inf') else 0
            
            row_format = "{type:<{w[type]}} {irq:<{w[irq]}} {name:<{w[name]}} {count:>{w[count]}d} {rate:>{w[rate]}.2f} {avg:>{w[avg]}.2f} {min:>{w[min]}.2f} {max:>{w[max]}.2f}".format(
                type="IRQ",
                irq=irq_num,
                name=stats['name'][:col_widths['name']-3],
                count=stats['count'],
                rate=rate,
                avg=avg_latency,
                min=min_latency,
                max=stats['max_latency'],
                w=col_widths
            )
            print(row_format)
        
        # Get sorted software interrupt statistics
        sorted_softirqs = self.get_sorted_stats(self.softirq_stats, sort_by, elapsed)
        for vector, stats in sorted_softirqs:
            if filter_irq and vector != filter_irq:
                continue
            if latency_threshold and stats['max_latency'] < latency_threshold:
                continue
                
            rate = stats['count'] / elapsed
            avg_latency = stats['total_latency'] / stats['count'] if stats['count'] > 0 else 0
            min_latency = stats['min_latency'] if stats['min_latency'] != float('inf') else 0
            
            row_format = "{type:<{w[type]}} {irq:<{w[irq]}} {name:<{w[name]}} {count:>{w[count]}d} {rate:>{w[rate]}.2f} {avg:>{w[avg]}.2f} {min:>{w[min]}.2f} {max:>{w[max]}.2f}".format(
                type="SOFTIRQ",
                irq=vector,
                name=stats['name'][:col_widths['name']-3],
                count=stats['count'],
                rate=rate,
                avg=avg_latency,
                min=min_latency,
                max=stats['max_latency'],
                w=col_widths
            )
            print(row_format)
        
        # Print process statistics
        if not filter_irq:
            print("\n=== Process Statistics ===")
            
            # Define process statistics column widths
            proc_widths = {
                'proc': 20,    # Process name column
                'count': 12,   # Count column
                'avg': 12,     # Average column
                'min': 12,     # Min column
                'max': 12      # Max column
            }
            
            # Print process statistics header
            proc_header = "{proc:<{w[proc]}} {count:>{w[count]}} {avg:>{w[avg]}} {min:>{w[min]}} {max:>{w[max]}}".format(
                proc="Process",
                count="Count",
                avg="Avg(us)",
                min="Min(us)",
                max="Max(us)",
                w=proc_widths
            )
            print(proc_header)
            print("-" * (sum(proc_widths.values()) + len(proc_widths) - 1))
            
            # Get sorted process statistics
            sorted_procs = self.get_sorted_stats(self.process_stats, sort_by, elapsed)
            for proc, stats in sorted_procs:
                if filter_process and filter_process not in proc:
                    continue
                if latency_threshold and stats['max_latency'] < latency_threshold:
                    continue
                    
                avg_latency = stats['total_latency'] / stats['count'] if stats['count'] > 0 else 0
                min_latency = stats['min_latency'] if stats['min_latency'] != float('inf') else 0
                
                proc_row = "{proc:<{w[proc]}} {count:>{w[count]}d} {avg:>{w[avg]}.2f} {min:>{w[min]}.2f} {max:>{w[max]}.2f}".format(
                    proc=proc[:proc_widths['proc']-1],
                    count=stats['count'],
                    avg=avg_latency,
                    min=min_latency,
                    max=stats['max_latency'],
                    w=proc_widths
                )
                print(proc_row)

def main():
    parser = argparse.ArgumentParser(description='Analyze irqsnoop output')
    parser.add_argument('-i', '--interval', type=int, help='Statistics interval (seconds)')
    parser.add_argument('-p', '--process', help='Filter by process name')
    parser.add_argument('-n', '--irq', help='Filter by interrupt number or vector')
    parser.add_argument('-t', '--threshold', type=float, help='Filter by delay threshold (microseconds)')
    parser.add_argument('-s', '--sort', choices=['rate', 'avg', 'max', 'min', 'count'],
                      default='count', help='Sort by: rate (frequency), avg (average delay), max (max delay), min (min delay), count (count)')
    args = parser.parse_args()

    stats = IRQStat()
    stats.interval = args.interval  # Save interval time for progress display
    start_time = time.time()
    
    try:
        # Set stdin to non-blocking mode
        if args.interval:
            while time.time() - start_time < args.interval:
                # Use select to wait for input, timeout is 0.1 seconds
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    line = sys.stdin.readline()
                    if not line:  # EOF
                        break
                    stats.parse_line(line)
                # Check if the timeout has been reached
                if args.interval and time.time() - start_time >= args.interval:
                    break
        else:
            # If no time interval is set, keep reading until EOF
            for line in sys.stdin:
                stats.parse_line(line)
            
        # Print final report
        stats.print_report(
            interval=args.interval,
            filter_process=args.process,
            filter_irq=args.irq,
            latency_threshold=args.threshold,
            sort_by=args.sort
        )
    except KeyboardInterrupt:
        # Ensure final report is printed
        stats.print_report(
            interval=args.interval,
            filter_process=args.process,
            filter_irq=args.irq,
            latency_threshold=args.threshold,
            sort_by=args.sort
        )
    
    # Exit after completing statistics
    sys.exit(0)

if __name__ == '__main__':
    main()