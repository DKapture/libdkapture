#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1

"""
Event Processor for DKapture File Monitoring
Part of file-monitor.sh event stream fusion tool
"""

import sys
import json
import re
import argparse
import signal
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from collections import defaultdict, deque
from dataclasses import dataclass, asdict


@dataclass
class Event:
    """Base event structure"""
    timestamp: str
    tool: str
    raw_data: str
    event_type: str = ""
    pid: int = 0
    path: str = ""
    operation: str = ""
    details: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


class EventParser:
    """Base class for tool-specific event parsers"""
    
    def __init__(self):
        self.patterns = {}
        self.setup_patterns()
    
    def setup_patterns(self):
        """Setup regex patterns for parsing tool output"""
        pass
    
    def parse(self, raw_line: str) -> Optional[Event]:
        """Parse raw line into Event object"""
        return None
    
    def extract_timestamp(self, line: str) -> Optional[str]:
        """Extract timestamp from line"""
        timestamp_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})'
        match = re.search(timestamp_pattern, line)
        return match.group(1) if match else None


class TraceFileParser(EventParser):
    """Parser for trace-file tool output"""
    
    def setup_patterns(self):
        # Sample trace-file output patterns
        self.patterns = {
            'file_op': re.compile(
                r'(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)'
            ),
            'vfs_op': re.compile(
                r'VFS_(\w+):\s+pid=(\d+)\s+path=(\S+)\s+(.+)'
            )
        }
    
    def parse(self, raw_line: str) -> Optional[Event]:
        """Parse trace-file output line"""
        # Extract basic info
        timestamp = self.extract_timestamp(raw_line)
        if not timestamp:
            return None
        
        # Remove timestamp and tool tag from line
        clean_line = re.sub(r'^\[.*?\] \[trace-file\] ', '', raw_line)
        
        # Try different patterns
        for pattern_name, pattern in self.patterns.items():
            match = pattern.search(clean_line)
            if match:
                return self._create_event_from_match(
                    timestamp, pattern_name, match, clean_line
                )
        
        # Return generic event if no pattern matches
        return Event(
            timestamp=timestamp,
            tool="trace-file",
            raw_data=clean_line,
            event_type="unknown"
        )
    
    def _create_event_from_match(self, timestamp: str, pattern_name: str, 
                                match, raw_line: str) -> Event:
        """Create Event from regex match"""
        if pattern_name == 'file_op':
            return Event(
                timestamp=timestamp,
                tool="trace-file",
                raw_data=raw_line,
                event_type="file_operation",
                pid=int(match.group(1)) if match.group(1).isdigit() else 0,
                operation=match.group(2),
                path=match.group(5),
                details={
                    'comm': match.group(3),
                    'flags': match.group(4)
                }
            )
        elif pattern_name == 'vfs_op':
            return Event(
                timestamp=timestamp,
                tool="trace-file",
                raw_data=raw_line,
                event_type="vfs_operation",
                pid=int(match.group(2)),
                operation=match.group(1),
                path=match.group(3),
                details={'extra': match.group(4)}
            )
        
        return Event(
            timestamp=timestamp,
            tool="trace-file",
            raw_data=raw_line,
            event_type="parsed"
        )


class Ext4SnoopParser(EventParser):
    """Parser for ext4snoop tool output"""
    
    def setup_patterns(self):
        self.patterns = {
            'ext4_op': re.compile(
                r'^(\S+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S*)\s+(.*)$'
            ),
            'header': re.compile(
                r'^COMM\s+PID\s+TID\s+EVENT\s+DEV\s+DETAILS$'
            )
        }
    
    def parse(self, raw_line: str) -> Optional[Event]:
        """Parse ext4snoop output line"""
        # Skip empty lines or header lines
        if not raw_line.strip() or raw_line.strip().startswith('COMM'):
            return None
            
        timestamp = self.extract_timestamp(raw_line)
        if not timestamp:
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        
        clean_line = re.sub(r'^\[.*?\] \[ext4snoop\] ', '', raw_line).strip()
        
        for pattern_name, pattern in self.patterns.items():
            match = pattern.search(clean_line)
            if match:
                event = self._create_event_from_match(
                    timestamp, pattern_name, match, clean_line
                )
                if event:  # Only return non-None events
                    return event
        
        # For lines that don't match patterns, still create an event
        if clean_line:
            return Event(
                timestamp=timestamp,
                tool="ext4snoop",
                raw_data=clean_line,
                event_type="unknown"
            )
        
        return None
    
    def _create_event_from_match(self, timestamp: str, pattern_name: str,
                                match, raw_line: str) -> Event:
        """Create Event from regex match"""
        if pattern_name == 'ext4_op':
            return Event(
                timestamp=timestamp,
                tool="ext4snoop",
                raw_data=raw_line,
                event_type="filesystem_operation",
                pid=int(match.group(2)) if match.group(2).isdigit() else 0,
                operation=match.group(4),
                details={
                    'comm': match.group(1),
                    'tid': match.group(3),
                    'device': match.group(5) if match.group(5) else "",
                    'extra': match.group(6).strip() if match.group(6) else ""
                }
            )
        elif pattern_name == 'header':
            # Skip header lines
            return None
        
        return Event(
            timestamp=timestamp,
            tool="ext4snoop",
            raw_data=raw_line,
            event_type="parsed"
        )


class MountSnoopParser(EventParser):
    """Parser for mountsnoop tool output"""
    
    def setup_patterns(self):
        self.patterns = {
            'mount_op': re.compile(
                r'(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)'
            )
        }
    
    def parse(self, raw_line: str) -> Optional[Event]:
        """Parse mountsnoop output line"""
        timestamp = self.extract_timestamp(raw_line)
        if not timestamp:
            return None
        
        clean_line = re.sub(r'^\[.*?\] \[mountsnoop\] ', '', raw_line)
        
        mount_match = self.patterns['mount_op'].search(clean_line)
        if mount_match:
            return Event(
                timestamp=timestamp,
                tool="mountsnoop",
                raw_data=clean_line,
                event_type="mount_operation",
                pid=int(mount_match.group(1)) if mount_match.group(1).isdigit() else 0,
                operation=mount_match.group(3),
                path=mount_match.group(6),
                details={
                    'comm': mount_match.group(2),
                    'source': mount_match.group(4),
                    'fstype': mount_match.group(5)
                }
            )
        
        return Event(
            timestamp=timestamp,
            tool="mountsnoop",
            raw_data=clean_line,
            event_type="unknown"
        )


class FileOccupationParser(EventParser):
    """Parser for lsof tool output"""
    
    def setup_patterns(self):
        self.patterns = {
            'occupation': re.compile(
                r'(\d+)\s+(\S+)\s+(\S+)\s+(.+)'
            )
        }
    
    def parse(self, raw_line: str) -> Optional[Event]:
        """Parse lsof output line"""
        timestamp = self.extract_timestamp(raw_line)
        if not timestamp:
            return None
        
        clean_line = re.sub(r'^\[.*?\] \[lsof\] ', '', raw_line)
        
        occ_match = self.patterns['occupation'].search(clean_line)
        if occ_match:
            return Event(
                timestamp=timestamp,
                tool="lsof",
                raw_data=clean_line,
                event_type="lsof",
                pid=int(occ_match.group(1)) if occ_match.group(1).isdigit() else 0,
                path=occ_match.group(4),
                details={
                    'comm': occ_match.group(2),
                    'type': occ_match.group(3)
                }
            )
        
        return Event(
            timestamp=timestamp,
            tool="lsof",
            raw_data=clean_line,
            event_type="unknown"
        )


class EventProcessor:
    """Main event processing engine"""
    
    def __init__(self, args):
        self.args = args
        self.parsers = {
            'trace-file': TraceFileParser(),
            'ext4snoop': Ext4SnoopParser(),
            'mountsnoop': MountSnoopParser(),
            'lsof': FileOccupationParser()
        }
        
        self.event_buffer = deque(maxlen=1000)
        self.correlation_window = args.correlation_window
        self.running = True
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle cleanup signals"""
        self.running = False
    
    def detect_tool(self, line: str, pipe_path: str = None) -> Optional[str]:
        """Detect which tool generated the line"""
        # First try tool pattern tags
        tool_patterns = {
            'trace-file': r'\[trace-file\]',
            'ext4snoop': r'\[ext4snoop\]',
            'mountsnoop': r'\[mountsnoop\]',
            'lsof': r'\[lsof\]'
        }
        
        for tool, pattern in tool_patterns.items():
            if re.search(pattern, line):
                return tool
        
        # If no pattern found, infer from pipe path
        if pipe_path:
            if 'trace-file' in pipe_path:
                return 'trace-file'
            elif 'ext4snoop' in pipe_path:
                return 'ext4snoop'
            elif 'mountsnoop' in pipe_path:
                return 'mountsnoop'
            elif 'lsof' in pipe_path:
                return 'lsof'
        
        return None
    
    def parse_event(self, line: str, pipe_path: str = None) -> Optional[Event]:
        """Parse a single event line"""
        tool = self.detect_tool(line, pipe_path)
        if not tool or tool not in self.parsers:
            return None
        
        return self.parsers[tool].parse(line)
    
    def process_events(self):
        """Main event processing loop"""
        import threading
        import select
        import os
        
        # Collect all pipe paths
        pipes = []
        if self.args.trace_file_pipe and self.args.trace_file_pipe != 'none':
            pipes.append(self.args.trace_file_pipe)
        if self.args.ext4snoop_pipe and self.args.ext4snoop_pipe != 'none':
            pipes.append(self.args.ext4snoop_pipe)
        if self.args.mountsnoop_pipe and self.args.mountsnoop_pipe != 'none':
            pipes.append(self.args.mountsnoop_pipe)
        if self.args.lsof_pipe and self.args.lsof_pipe != 'none':
            pipes.append(self.args.lsof_pipe)
        
        try:
            while self.running:
                for pipe_path in pipes:
                    try:
                        # Check if pipe exists and has data
                        if os.path.exists(pipe_path):
                            with open(pipe_path, 'r', encoding='utf-8', errors='replace', buffering=1) as pipe:
                                line = pipe.readline()
                                if line:
                                    line = line.strip()
                                    if line:
                                        event = self.parse_event(line, pipe_path)
                                        if event:
                                            self.handle_event(event)
                    except (OSError, IOError) as e:
                        continue
                
                # Small delay to avoid busy waiting
                import time
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"Error processing events: {e}", file=sys.stderr)
    
    def handle_event(self, event: Event):
        """Handle a parsed event"""
        self.event_buffer.append(event)
        
        if self.args.output_format == 'json':
            self.output_json_event(event)
        else:
            self.output_text_event(event)
    
    def output_json_event(self, event: Event):
        """Output event in JSON format"""
        event_dict = asdict(event)
        print(json.dumps(event_dict, ensure_ascii=False))
        sys.stdout.flush()
    
    def output_text_event(self, event: Event):
        """Output event in human-readable text format"""
        output = f"[{event.timestamp}] {event.tool}: {event.event_type}"
        if event.pid:
            output += f" PID={event.pid}"
        if event.path:
            output += f" PATH={event.path}"
        if event.operation:
            output += f" OP={event.operation}"
        
        print(output)
        sys.stdout.flush()


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Event processor for file monitoring tools'
    )
    
    parser.add_argument(
        '--format', '--output-format',
        choices=['json', 'text'],
        default='text',
        dest='output_format',
        help='Output format (default: text)'
    )
    
    parser.add_argument(
        '--correlation-window',
        type=int,
        default=5,
        help='Event correlation window in seconds (default: 5)'
    )
    
    parser.add_argument(
        '--main-pipe',
        type=str,
        help='Main communication pipe path'
    )
    
    parser.add_argument(
        '--trace-file-pipe',
        type=str,
        help='trace-file tool pipe path'
    )
    
    parser.add_argument(
        '--ext4snoop-pipe',
        type=str,
        help='ext4snoop tool pipe path'
    )
    
    parser.add_argument(
        '--mountsnoop-pipe',
        type=str,
        help='mountsnoop tool pipe path'
    )
    
    parser.add_argument(
        '--lsof-pipe',
        type=str,
        help='lsof tool pipe path'
    )
    
    parser.add_argument(
        '--filter-pid',
        type=int,
        help='Filter events by process ID'
    )
    
    parser.add_argument(
        '--filter-comm',
        type=str,
        help='Filter events by process name'
    )
    
    parser.add_argument(
        '--filter-path',
        type=str,
        help='Filter events by file path'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_arguments()
    processor = EventProcessor(args)
    processor.process_events()


if __name__ == '__main__':
    main() 