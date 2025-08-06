#!/usr/bin/env python3
"""
Network Data Processor - Python processing component for network analyzer
Author: dkapture project
Version: 1.0

This script provides advanced data processing capabilities for the network analyzer.
It's designed to be called by the main shell script to handle complex data analysis,
JSON/CSV export, and statistical computations.
"""

import sys
import os
import json
import csv
import argparse
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import re
import statistics
import subprocess


@dataclass
class ConnectionInfo:
    """Data class for network connection information"""
    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    pid: Optional[int] = None
    process_name: Optional[str] = None
    timestamp: Optional[str] = None


@dataclass
class TrafficInfo:
    """Data class for network traffic information"""
    timestamp: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    process_name: Optional[str] = None
    pid: Optional[int] = None


@dataclass
class AnalysisResult:
    """Data class for analysis results"""
    timestamp: str
    total_connections: int
    protocol_distribution: Dict[str, int]
    top_ports: List[Tuple[int, int]]
    connection_states: Dict[str, int]
    anomalies: List[str]
    security_alerts: List[str]
    traffic_summary: Dict[str, Any]


class NetworkDataProcessor:
    """Main class for processing network data"""
    
    def __init__(self, config_file: str = None, verbose: bool = False):
        """Initialize the network data processor"""
        self.config = self._load_config(config_file)
        self.verbose = verbose
        self.logger = self._setup_logging()
        
        # Data storage
        self.connections: List[ConnectionInfo] = []
        self.traffic_data: List[TrafficInfo] = []
        self.analysis_results: List[AnalysisResult] = []
        
        # Analysis parameters
        self.anomaly_threshold = float(self.config.get('anomaly_threshold', 3.0))
        self.port_scan_threshold = int(self.config.get('port_scan_threshold', 50))
        self.suspicious_threshold = int(self.config.get('suspicious_threshold', 200))
        
        self.logger.info("Network data processor initialized")
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from file"""
        config = {}
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            config[key.strip()] = value.strip()
            except Exception as e:
                print(f"Warning: Could not load config file {config_file}: {e}")
        return config
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('NetworkProcessor')
        logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        
        logger.addHandler(console_handler)
        return logger
    
    def parse_lsock_output(self, input_file: str) -> List[ConnectionInfo]:
        """Parse lsock output file and extract connection information"""
        connections = []
        self.logger.info(f"Parsing lsock output from {input_file}")
        
        try:
            with open(input_file, 'r') as f:
                current_timestamp = None
                for line in f:
                    line = line.strip()
                    
                    # Check for timestamp markers
                    if line.startswith('=== ') and line.endswith(' ==='):
                        # Extract timestamp from marker
                        timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                        if timestamp_match:
                            current_timestamp = timestamp_match.group(1)
                        continue
                    
                    # Parse connection lines
                    if line and not line.startswith('==='):
                        conn_info = self._parse_connection_line(line, current_timestamp)
                        if conn_info:
                            connections.append(conn_info)
            
            self.logger.info(f"Parsed {len(connections)} connections from lsock output")
            
        except Exception as e:
            self.logger.error(f"Error parsing lsock output: {e}")
        
        return connections
    
    def _parse_connection_line(self, line: str, timestamp: str) -> Optional[ConnectionInfo]:
        """Parse a single connection line from lsock output"""
        try:
            # This is a simplified parser - actual implementation depends on lsock output format
            # Expected format: protocol local_addr:port remote_addr:port state [pid/process]
            
            parts = line.split()
            if len(parts) < 4:
                return None
            
            protocol = parts[0].lower()
            
            # Parse local address
            local_parts = parts[1].split(':')
            if len(local_parts) < 2:
                return None
            local_address = ':'.join(local_parts[:-1])
            local_port = int(local_parts[-1])
            
            # Parse remote address
            remote_parts = parts[2].split(':')
            if len(remote_parts) < 2:
                remote_address = remote_parts[0]
                remote_port = 0
            else:
                remote_address = ':'.join(remote_parts[:-1])
                remote_port = int(remote_parts[-1])
            
            # Parse state
            state = parts[3] if len(parts) > 3 else "UNKNOWN"
            
            # Parse PID and process name if available
            pid = None
            process_name = None
            if len(parts) > 4:
                pid_match = re.search(r'(\d+)', parts[4])
                if pid_match:
                    pid = int(pid_match.group(1))
                
                proc_match = re.search(r'/([^/]+)$', parts[4])
                if proc_match:
                    process_name = proc_match.group(1)
            
            return ConnectionInfo(
                protocol=protocol,
                local_address=local_address,
                local_port=local_port,
                remote_address=remote_address,
                remote_port=remote_port,
                state=state,
                pid=pid,
                process_name=process_name,
                timestamp=timestamp
            )
            
        except Exception as e:
            self.logger.debug(f"Could not parse connection line: {line} - {e}")
            return None
    
    def parse_traffic_output(self, input_file: str) -> List[TrafficInfo]:
        """Parse network traffic output file"""
        traffic_data = []
        self.logger.info(f"Parsing traffic output from {input_file}")
        
        try:
            with open(input_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('==='):
                        traffic_info = self._parse_traffic_line(line)
                        if traffic_info:
                            traffic_data.append(traffic_info)
            
            self.logger.info(f"Parsed {len(traffic_data)} traffic events")
            
        except Exception as e:
            self.logger.error(f"Error parsing traffic output: {e}")
        
        return traffic_data
    
    def _parse_traffic_line(self, line: str) -> Optional[TrafficInfo]:
        """Parse a single traffic line from net-traffic output"""
        try:
            # This is a simplified parser - actual implementation depends on net-traffic format
            # Expected format varies based on net-traffic output
            
            # Extract timestamp
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Parse IP addresses and ports
            ip_match = re.findall(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
            if len(ip_match) < 2:
                return None
            
            source_ip, source_port = ip_match[0]
            dest_ip, dest_port = ip_match[1]
            
            # Extract protocol
            protocol = "tcp"  # Default
            if "udp" in line.lower():
                protocol = "udp"
            
            # Extract bytes information
            bytes_sent = 0
            bytes_received = 0
            
            bytes_match = re.search(r'(\d+)\s*bytes', line)
            if bytes_match:
                bytes_sent = int(bytes_match.group(1))
            
            return TrafficInfo(
                timestamp=timestamp,
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=int(source_port),
                dest_port=int(dest_port),
                protocol=protocol,
                bytes_sent=bytes_sent,
                bytes_received=bytes_received
            )
            
        except Exception as e:
            self.logger.debug(f"Could not parse traffic line: {line} - {e}")
            return None
    
    def analyze_connections(self, connections: List[ConnectionInfo]) -> AnalysisResult:
        """Analyze network connections for patterns and anomalies"""
        self.logger.info("Analyzing network connections")
        
        # Basic statistics
        total_connections = len(connections)
        protocol_distribution = Counter(conn.protocol for conn in connections)
        connection_states = Counter(conn.state for conn in connections)
        
        # Top ports analysis
        port_counter = Counter()
        for conn in connections:
            if conn.local_port:
                port_counter[conn.local_port] += 1
        top_ports = port_counter.most_common(10)
        
        # Anomaly detection
        anomalies = self._detect_anomalies(connections)
        
        # Security analysis
        security_alerts = self._detect_security_issues(connections)
        
        # Traffic summary
        traffic_summary = self._summarize_traffic(connections)
        
        result = AnalysisResult(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_connections=total_connections,
            protocol_distribution=dict(protocol_distribution),
            top_ports=top_ports,
            connection_states=dict(connection_states),
            anomalies=anomalies,
            security_alerts=security_alerts,
            traffic_summary=traffic_summary
        )
        
        self.logger.info(f"Analysis complete: {total_connections} connections analyzed")
        return result
    
    def _detect_anomalies(self, connections: List[ConnectionInfo]) -> List[str]:
        """Detect anomalies in network connections"""
        anomalies = []
        
        # Port usage anomalies
        port_counts = Counter(conn.local_port for conn in connections if conn.local_port)
        if port_counts:
            port_values = list(port_counts.values())
            if len(port_values) > 1:
                mean_usage = statistics.mean(port_values)
                std_usage = statistics.stdev(port_values) if len(port_values) > 1 else 0
                
                for port, count in port_counts.items():
                    if std_usage > 0 and count > mean_usage + (self.anomaly_threshold * std_usage):
                        anomalies.append(f"Unusual port usage detected: port {port} with {count} connections")
        
        # Connection state anomalies
        state_counts = Counter(conn.state for conn in connections)
        total_conns = len(connections)
        
        for state, count in state_counts.items():
            if count > total_conns * 0.8:  # More than 80% in one state
                anomalies.append(f"High concentration of {state} connections: {count}/{total_conns}")
        
        return anomalies
    
    def _detect_security_issues(self, connections: List[ConnectionInfo]) -> List[str]:
        """Detect potential security issues"""
        alerts = []
        
        # Port scan detection
        remote_ips = defaultdict(set)
        for conn in connections:
            if conn.remote_address and conn.remote_address != '0.0.0.0':
                remote_ips[conn.remote_address].add(conn.local_port)
        
        for ip, ports in remote_ips.items():
            if len(ports) > self.port_scan_threshold:
                alerts.append(f"Possible port scan from {ip}: {len(ports)} different ports accessed")
        
        # Suspicious connection patterns
        connection_rates = defaultdict(int)
        for conn in connections:
            if conn.remote_address:
                connection_rates[conn.remote_address] += 1
        
        for ip, count in connection_rates.items():
            if count > self.suspicious_threshold:
                alerts.append(f"High connection rate from {ip}: {count} connections")
        
        return alerts
    
    def _summarize_traffic(self, connections: List[ConnectionInfo]) -> Dict[str, Any]:
        """Summarize traffic patterns"""
        summary = {
            'total_unique_remote_ips': len(set(conn.remote_address for conn in connections if conn.remote_address)),
            'total_unique_local_ports': len(set(conn.local_port for conn in connections if conn.local_port)),
            'protocol_breakdown': dict(Counter(conn.protocol for conn in connections)),
            'top_remote_ips': []
        }
        
        # Top remote IPs
        ip_counter = Counter(conn.remote_address for conn in connections if conn.remote_address)
        summary['top_remote_ips'] = [{'ip': ip, 'count': count} for ip, count in ip_counter.most_common(10)]
        
        return summary
    
    def export_to_json(self, data: Any, output_file: str) -> None:
        """Export data to JSON format"""
        self.logger.info(f"Exporting data to JSON: {output_file}")
        
        try:
            with open(output_file, 'w') as f:
                if hasattr(data, '__dict__'):
                    json.dump(asdict(data), f, indent=2, default=str)
                else:
                    json.dump(data, f, indent=2, default=str)
            
            self.logger.info(f"JSON export completed: {output_file}")
            
        except Exception as e:
            self.logger.error(f"Error exporting to JSON: {e}")
    
    def export_to_csv(self, connections: List[ConnectionInfo], output_file: str) -> None:
        """Export connections to CSV format"""
        self.logger.info(f"Exporting connections to CSV: {output_file}")
        
        try:
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([
                    'timestamp', 'protocol', 'local_address', 'local_port',
                    'remote_address', 'remote_port', 'state', 'pid', 'process_name'
                ])
                
                # Write data
                for conn in connections:
                    writer.writerow([
                        conn.timestamp, conn.protocol, conn.local_address, conn.local_port,
                        conn.remote_address, conn.remote_port, conn.state, conn.pid, conn.process_name
                    ])
            
            self.logger.info(f"CSV export completed: {output_file}")
            
        except Exception as e:
            self.logger.error(f"Error exporting to CSV: {e}")


def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description='Network Data Processor')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--input', required=True, help='Input data file')
    parser.add_argument('--output-dir', default='/tmp/network_analysis', help='Output directory')
    parser.add_argument('--format', choices=['json', 'csv', 'both'], default='both', help='Output format')
    parser.add_argument('--type', choices=['lsock', 'traffic'], default='lsock', help='Input data type')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Create processor instance
    processor = NetworkDataProcessor(config_file=args.config, verbose=args.verbose)
    
    # Process input based on type
    if args.type == 'lsock':
        connections = processor.parse_lsock_output(args.input)
        if connections:
            # Analyze connections
            analysis_result = processor.analyze_connections(connections)
            
            # Export results
            if args.format in ['json', 'both']:
                json_file = os.path.join(args.output_dir, 'analysis_result.json')
                processor.export_to_json(analysis_result, json_file)
                
                connections_json = os.path.join(args.output_dir, 'connections.json')
                processor.export_to_json(connections, connections_json)
            
            if args.format in ['csv', 'both']:
                csv_file = os.path.join(args.output_dir, 'connections.csv')
                processor.export_to_csv(connections, csv_file)
            
            # Print summary
            print(f"Processed {len(connections)} connections")
            print(f"Found {len(analysis_result.anomalies)} anomalies")
            print(f"Found {len(analysis_result.security_alerts)} security alerts")
            
    elif args.type == 'traffic':
        traffic_data = processor.parse_traffic_output(args.input)
        if traffic_data:
            # Export traffic data
            if args.format in ['json', 'both']:
                json_file = os.path.join(args.output_dir, 'traffic_data.json')
                processor.export_to_json(traffic_data, json_file)
            
            print(f"Processed {len(traffic_data)} traffic events")


if __name__ == '__main__':
    main() 