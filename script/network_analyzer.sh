#!/bin/bash

# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1

# Network Analyzer - Advanced network connection analysis tool
# Based on dkapture observe tools (lsock, net-traffic)
# Author: dkapture project
# Version: 1.0

set -euo pipefail

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="$SCRIPT_DIR/network_config.conf"
OUTPUT_DIR="/tmp/network_analysis"
LOG_FILE="/var/log/network_analyzer.log"
PID_FILE="/var/run/network_analyzer.pid"

# Default configuration
LSOCK_INTERVAL=5
TRAFFIC_INTERVAL=5
ANALYSIS_DURATION=300
AUTO_START=true
MAX_CONNECTIONS=10000
CONNECTION_THRESHOLD=1000
TRAFFIC_THRESHOLD_MB=100
ANOMALY_THRESHOLD=3.0
PORT_SCAN_THRESHOLD=50
SUSPICIOUS_THRESHOLD=200
LOG_LEVEL="INFO"
EXPORT_FORMAT="both"
GENERATE_GRAPHS=true
KEEP_HISTORY_DAYS=7

# Security settings
ENABLE_ANOMALY_DETECTION=true
ENABLE_PORT_SCAN_DETECTION=true
ENABLE_SUSPICIOUS_TRAFFIC_DETECTION=true
ENABLE_PATTERN_ANALYSIS=true
SECURITY_LOG="/var/log/network_security.log"

# Tool paths
LSOCK_PATH="$PROJECT_ROOT/observe/lsock"
TRAFFIC_PATH="$PROJECT_ROOT/observe/net-traffic"
FILTER_PATH="$PROJECT_ROOT/observe/net-filter"
SS_PATH="/usr/bin/ss"
NETSTAT_PATH="/usr/bin/netstat"
PROCESSOR_SCRIPT="$SCRIPT_DIR/network_processor.py"

# Control flags
VERBOSE=false
DEBUG=false
DAEMON=false
STOP_REQUESTED=false

# Process IDs for cleanup
LSOCK_PID=""
TRAFFIC_PID=""
MONITOR_PIDS=()

# Show help information
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Network Analyzer - Advanced network connection analysis tool

Options:
  -c, --config FILE       Use custom configuration file
  -o, --output DIR        Output directory for results
  -i, --interval SEC      Monitoring interval in seconds
  -d, --duration SEC      Analysis duration in seconds (0 = unlimited)
  -t, --threshold COUNT   Connection threshold for alerts
  -f, --format FORMAT     Export format: json,csv,both,txt
  
  Analysis Options:
  --anomaly-detection     Enable anomaly detection (default: enabled)
  --port-scan-detection   Enable port scan detection (default: enabled)
  --no-graphs            Disable graph generation
  --security-only        Run security analysis only
  
  Control Options:
  --daemon               Run as daemon
  --stop                 Stop running daemon
  --status               Show daemon status
  --cleanup              Clean up old data
  
  Debug Options:
  -v, --verbose          Verbose output
  --debug                Debug mode
  -l, --log-level LEVEL  Log level: DEBUG, INFO, WARN, ERROR
  
  Help:
  -h, --help             Show this help message
  --version              Show version information

Examples:
  $0                                    # Run with default settings
  $0 -d 600 -i 10                     # Run for 10 minutes with 10s interval
  $0 --daemon                          # Run as daemon
  $0 --security-only                   # Security analysis only
  $0 --stop                            # Stop daemon
  $0 --cleanup                         # Clean old data

Configuration:
  Edit $CONFIG_FILE to customize default settings

Log Files:
  Main log: $LOG_FILE
  Security log: $SECURITY_LOG

EOF
}

# Show version information
show_version() {
    echo "Network Analyzer v1.0"
    echo "Part of dkapture project"
    echo "Based on eBPF observe tools"
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -i|--interval)
                LSOCK_INTERVAL="$2"
                TRAFFIC_INTERVAL="$2"
                shift 2
                ;;
            -d|--duration)
                ANALYSIS_DURATION="$2"
                shift 2
                ;;
            -t|--threshold)
                CONNECTION_THRESHOLD="$2"
                shift 2
                ;;
            -f|--format)
                EXPORT_FORMAT="$2"
                shift 2
                ;;
            --anomaly-detection)
                ENABLE_ANOMALY_DETECTION=true
                shift
                ;;
            --port-scan-detection)
                ENABLE_PORT_SCAN_DETECTION=true
                shift
                ;;
            --no-graphs)
                GENERATE_GRAPHS=false
                shift
                ;;
            --security-only)
                ENABLE_ANOMALY_DETECTION=true
                ENABLE_PORT_SCAN_DETECTION=true
                ENABLE_SUSPICIOUS_TRAFFIC_DETECTION=true
                ENABLE_PATTERN_ANALYSIS=true
                shift
                ;;
            --daemon)
                DAEMON=true
                shift
                ;;
            --stop)
                stop_daemon
                exit 0
                ;;
            --status)
                show_daemon_status
                exit 0
                ;;
            --cleanup)
                cleanup_old_data
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                LOG_LEVEL="INFO"
                shift
                ;;
            --debug)
                DEBUG=true
                VERBOSE=true
                LOG_LEVEL="DEBUG"
                shift
                ;;
            -l|--log-level)
                LOG_LEVEL="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            --version)
                show_version
                exit 0
                ;;
            *)
                echo "Error: Unknown option $1" >&2
                echo "Use -h or --help for usage information" >&2
                exit 1
                ;;
        esac
    done
}

# Log message with timestamp and level
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Log level priority: DEBUG=0, INFO=1, WARN=2, ERROR=3
    local current_priority=1
    case "$LOG_LEVEL" in
        "DEBUG") current_priority=0 ;;
        "INFO") current_priority=1 ;;
        "WARN") current_priority=2 ;;
        "ERROR") current_priority=3 ;;
    esac
    
    local msg_priority=1
    case "$level" in
        "DEBUG") msg_priority=0 ;;
        "INFO") msg_priority=1 ;;
        "WARN") msg_priority=2 ;;
        "ERROR") msg_priority=3 ;;
    esac
    
    # Only log if message priority >= current log level priority
    if [[ $msg_priority -ge $current_priority ]]; then
        echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
        
        # Also output to console if verbose or important message
        if [[ "$VERBOSE" == "true" ]] || [[ "$level" == "WARN" ]] || [[ "$level" == "ERROR" ]]; then
            echo "[$level] $message" >&2
        fi
    fi
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_message "ERROR" "This script must be run as root"
        echo "Error: This script requires root privileges" >&2
        echo "Please run with sudo: sudo $0" >&2
        exit 1
    fi
}

# Validate required tools are available
check_prerequisites() {
    log_message "INFO" "Checking prerequisites..."
    
    local missing_tools=()
    
    # Check observe tools
    if [[ ! -x "$LSOCK_PATH" ]]; then
        missing_tools+=("lsock")
    fi
    
    if [[ ! -x "$TRAFFIC_PATH" ]]; then
        missing_tools+=("net-traffic")
    fi
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        missing_tools+=("python3")
    fi
    
    # Check system tools (fallback)
    if [[ ! -x "$SS_PATH" ]] && [[ ! -x "$NETSTAT_PATH" ]]; then
        missing_tools+=("ss or netstat")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_message "ERROR" "Missing required tools: ${missing_tools[*]}"
        echo "Error: Missing required tools: ${missing_tools[*]}" >&2
        echo "Please install missing tools or check tool paths in configuration" >&2
        exit 1
    fi
    
    log_message "INFO" "Prerequisites check passed"
}

# Stop daemon if running
stop_daemon() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log_message "INFO" "Stopping network analyzer daemon (PID: $pid)"
            kill -TERM "$pid"
            sleep 2
            if kill -0 "$pid" 2>/dev/null; then
                kill -KILL "$pid"
            fi
            rm -f "$PID_FILE"
            echo "Daemon stopped"
        else
            log_message "WARN" "PID file exists but process not running"
            rm -f "$PID_FILE"
            echo "Daemon not running"
        fi
    else
        echo "Daemon not running"
    fi
}

# Show daemon status
show_daemon_status() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "Network analyzer daemon is running (PID: $pid)"
            return 0
        else
            echo "Network analyzer daemon is not running (stale PID file)"
            rm -f "$PID_FILE"
            return 1
        fi
    else
        echo "Network analyzer daemon is not running"
        return 1
    fi
}

# Cleanup old data files
cleanup_old_data() {
    log_message "INFO" "Cleaning up old data files..."
    
    if [[ -d "$OUTPUT_DIR" ]]; then
        find "$OUTPUT_DIR" -type f -mtime +"$KEEP_HISTORY_DAYS" -delete
        echo "Cleaned up data files older than $KEEP_HISTORY_DAYS days"
    fi
    
    # Rotate log files if they're too large (>100MB)
    if [[ -f "$LOG_FILE" ]] && [[ $(stat -c%s "$LOG_FILE") -gt 104857600 ]]; then
        mv "$LOG_FILE" "${LOG_FILE}.old"
        touch "$LOG_FILE"
        chmod 640 "$LOG_FILE"
        log_message "INFO" "Rotated log file"
    fi
}

# Signal handlers for cleanup
cleanup_and_exit() {
    STOP_REQUESTED=true
    log_message "INFO" "Received termination signal, cleaning up..."
    stop_monitors
    rm -f "$PID_FILE"
    exit 0
}

# Set up signal handlers
trap cleanup_and_exit SIGTERM SIGINT SIGQUIT

# Load configuration from INI-style config file
load_config() {
    log_message "DEBUG" "Loading configuration from $CONFIG_FILE"
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_message "WARN" "Configuration file not found: $CONFIG_FILE"
        log_message "INFO" "Using default configuration"
        return 0
    fi
    
    local section=""
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip comments and empty lines
        if [[ "$line" =~ ^[[:space:]]*# ]] || [[ "$line" =~ ^[[:space:]]*$ ]]; then
            continue
        fi
        
        # Check for section headers
        if [[ "$line" =~ ^\[([^]]+)\] ]]; then
            section="${BASH_REMATCH[1]}"
            continue
        fi
        
        # Parse key=value pairs
        if [[ "$line" =~ ^[[:space:]]*([^=]+)=(.*)$ ]]; then
            local key="${BASH_REMATCH[1]// /}"
            local value="${BASH_REMATCH[2]}"
            
            # Remove leading/trailing whitespace from value
            value="${value#"${value%%[![:space:]]*}"}"
            value="${value%"${value##*[![:space:]]}"}"
            
            case "$section" in
                "monitoring")
                    case "$key" in
                        "lsock_interval") LSOCK_INTERVAL="$value" ;;
                        "traffic_interval") TRAFFIC_INTERVAL="$value" ;;
                        "analysis_duration") ANALYSIS_DURATION="$value" ;;
                        "auto_start") AUTO_START="$value" ;;
                        "max_connections") MAX_CONNECTIONS="$value" ;;
                    esac
                    ;;
                "thresholds")
                    case "$key" in
                        "connection_threshold") CONNECTION_THRESHOLD="$value" ;;
                        "traffic_threshold_mb") TRAFFIC_THRESHOLD_MB="$value" ;;
                        "anomaly_threshold") ANOMALY_THRESHOLD="$value" ;;
                        "port_scan_threshold") PORT_SCAN_THRESHOLD="$value" ;;
                        "suspicious_threshold") SUSPICIOUS_THRESHOLD="$value" ;;
                    esac
                    ;;
                "output")
                    case "$key" in
                        "output_dir") OUTPUT_DIR="$value" ;;
                        "log_level") LOG_LEVEL="$value" ;;
                        "export_format") EXPORT_FORMAT="$value" ;;
                        "generate_graphs") GENERATE_GRAPHS="$value" ;;
                        "keep_history_days") KEEP_HISTORY_DAYS="$value" ;;
                    esac
                    ;;
                "security")
                    case "$key" in
                        "enable_anomaly_detection") ENABLE_ANOMALY_DETECTION="$value" ;;
                        "enable_port_scan_detection") ENABLE_PORT_SCAN_DETECTION="$value" ;;
                        "enable_suspicious_traffic_detection") ENABLE_SUSPICIOUS_TRAFFIC_DETECTION="$value" ;;
                        "enable_pattern_analysis") ENABLE_PATTERN_ANALYSIS="$value" ;;
                        "security_log") SECURITY_LOG="$value" ;;
                    esac
                    ;;
                "tools")
                    case "$key" in
                        "lsock_path") LSOCK_PATH="$value" ;;
                        "traffic_path") TRAFFIC_PATH="$value" ;;
                        "filter_path") FILTER_PATH="$value" ;;
                        "ss_path") SS_PATH="$value" ;;
                        "netstat_path") NETSTAT_PATH="$value" ;;
                        "processor_script") PROCESSOR_SCRIPT="$value" ;;
                    esac
                    ;;
            esac
        fi
    done < "$CONFIG_FILE"
    
    log_message "INFO" "Configuration loaded successfully"
}

# Validate configuration values
validate_config() {
    log_message "DEBUG" "Validating configuration"
    
    local errors=()
    
    # Validate numeric values
    if ! [[ "$LSOCK_INTERVAL" =~ ^[0-9]+$ ]] || [[ "$LSOCK_INTERVAL" -lt 1 ]]; then
        errors+=("lsock_interval must be a positive integer")
    fi
    
    if ! [[ "$TRAFFIC_INTERVAL" =~ ^[0-9]+$ ]] || [[ "$TRAFFIC_INTERVAL" -lt 1 ]]; then
        errors+=("traffic_interval must be a positive integer")
    fi
    
    if ! [[ "$ANALYSIS_DURATION" =~ ^[0-9]+$ ]] || [[ "$ANALYSIS_DURATION" -lt 0 ]]; then
        errors+=("analysis_duration must be a non-negative integer")
    fi
    
    if ! [[ "$MAX_CONNECTIONS" =~ ^[0-9]+$ ]] || [[ "$MAX_CONNECTIONS" -lt 1 ]]; then
        errors+=("max_connections must be a positive integer")
    fi
    
    if ! [[ "$CONNECTION_THRESHOLD" =~ ^[0-9]+$ ]] || [[ "$CONNECTION_THRESHOLD" -lt 1 ]]; then
        errors+=("connection_threshold must be a positive integer")
    fi
    
    if ! [[ "$TRAFFIC_THRESHOLD_MB" =~ ^[0-9]+$ ]] || [[ "$TRAFFIC_THRESHOLD_MB" -lt 1 ]]; then
        errors+=("traffic_threshold_mb must be a positive integer")
    fi
    
    if ! [[ "$PORT_SCAN_THRESHOLD" =~ ^[0-9]+$ ]] || [[ "$PORT_SCAN_THRESHOLD" -lt 1 ]]; then
        errors+=("port_scan_threshold must be a positive integer")
    fi
    
    if ! [[ "$SUSPICIOUS_THRESHOLD" =~ ^[0-9]+$ ]] || [[ "$SUSPICIOUS_THRESHOLD" -lt 1 ]]; then
        errors+=("suspicious_threshold must be a positive integer")
    fi
    
    if ! [[ "$KEEP_HISTORY_DAYS" =~ ^[0-9]+$ ]] || [[ "$KEEP_HISTORY_DAYS" -lt 1 ]]; then
        errors+=("keep_history_days must be a positive integer")
    fi
    
    # Validate anomaly threshold (float)
    if ! [[ "$ANOMALY_THRESHOLD" =~ ^[0-9]+\.?[0-9]*$ ]] || (( $(echo "$ANOMALY_THRESHOLD <= 0" | bc -l) )); then
        errors+=("anomaly_threshold must be a positive number")
    fi
    
    # Validate log level
    if [[ ! "$LOG_LEVEL" =~ ^(DEBUG|INFO|WARN|ERROR)$ ]]; then
        errors+=("log_level must be one of: DEBUG, INFO, WARN, ERROR")
    fi
    
    # Validate boolean values
    if [[ ! "$AUTO_START" =~ ^(true|false)$ ]]; then
        errors+=("auto_start must be true or false")
    fi
    
    if [[ ! "$GENERATE_GRAPHS" =~ ^(true|false)$ ]]; then
        errors+=("generate_graphs must be true or false")
    fi
    
    if [[ ! "$ENABLE_ANOMALY_DETECTION" =~ ^(true|false)$ ]]; then
        errors+=("enable_anomaly_detection must be true or false")
    fi
    
    if [[ ! "$ENABLE_PORT_SCAN_DETECTION" =~ ^(true|false)$ ]]; then
        errors+=("enable_port_scan_detection must be true or false")
    fi
    
    if [[ ! "$ENABLE_SUSPICIOUS_TRAFFIC_DETECTION" =~ ^(true|false)$ ]]; then
        errors+=("enable_suspicious_traffic_detection must be true or false")
    fi
    
    if [[ ! "$ENABLE_PATTERN_ANALYSIS" =~ ^(true|false)$ ]]; then
        errors+=("enable_pattern_analysis must be true or false")
    fi
    
    # Validate export format
    if [[ ! "$EXPORT_FORMAT" =~ ^(json|csv|txt)(,(json|csv|txt))*$ ]]; then
        errors+=("export_format must be comma-separated list of: json, csv, txt")
    fi
    
    # Validate paths
    if [[ ! -d "$(dirname "$OUTPUT_DIR")" ]]; then
        errors+=("output_dir parent directory does not exist: $(dirname "$OUTPUT_DIR")")
    fi
    
    if [[ ! -d "$(dirname "$LOG_FILE")" ]]; then
        errors+=("log_file parent directory does not exist: $(dirname "$LOG_FILE")")
    fi
    
    if [[ -n "$SECURITY_LOG" ]] && [[ ! -d "$(dirname "$SECURITY_LOG")" ]]; then
        errors+=("security_log parent directory does not exist: $(dirname "$SECURITY_LOG")")
    fi
    
    # Convert relative paths to absolute paths
    if [[ "$LSOCK_PATH" =~ ^\. ]]; then
        LSOCK_PATH="$PROJECT_ROOT/${LSOCK_PATH#./}"
    fi
    
    if [[ "$TRAFFIC_PATH" =~ ^\. ]]; then
        TRAFFIC_PATH="$PROJECT_ROOT/${TRAFFIC_PATH#./}"
    fi
    
    if [[ "$FILTER_PATH" =~ ^\. ]]; then
        FILTER_PATH="$PROJECT_ROOT/${FILTER_PATH#./}"
    fi
    
    if [[ "$PROCESSOR_SCRIPT" =~ ^\. ]]; then
        PROCESSOR_SCRIPT="$PROJECT_ROOT/${PROCESSOR_SCRIPT#./}"
    fi
    
    # Report validation errors
    if [[ ${#errors[@]} -gt 0 ]]; then
        log_message "ERROR" "Configuration validation failed:"
        for error in "${errors[@]}"; do
            log_message "ERROR" "  - $error"
        done
        exit 1
    fi
    
    log_message "INFO" "Configuration validation passed"
}

# Start lsock monitoring in background
start_lsock_monitor() {
    log_message "DEBUG" "Starting lsock monitor"
    
    local lsock_output="$OUTPUT_DIR/lsock_output.txt"
    local lsock_log="$OUTPUT_DIR/lsock.log"
    
    # Build lsock command based on configuration
    local lsock_cmd="$LSOCK_PATH"
    
    # Add common options for comprehensive monitoring
    lsock_cmd="$lsock_cmd -t -u -x -4 -6"  # tcp, udp, unix, ipv4, ipv6
    
    log_message "INFO" "Starting lsock monitor: $lsock_cmd"
    
    # Start lsock in background with output redirection
    (
        while [[ "$STOP_REQUESTED" != "true" ]]; do
            echo "=== $(date '+%Y-%m-%d %H:%M:%S') ===" >> "$lsock_output"
            timeout "$LSOCK_INTERVAL" "$lsock_cmd" >> "$lsock_output" 2>> "$lsock_log"
            
            # Add a small delay between collections
            sleep 1
        done
    ) &
    
    LSOCK_PID=$!
    MONITOR_PIDS+=($LSOCK_PID)
    
    log_message "INFO" "Lsock monitor started (PID: $LSOCK_PID)"
    log_message "DEBUG" "Lsock output: $lsock_output"
    log_message "DEBUG" "Lsock log: $lsock_log"
}

# Start net-traffic monitoring in background
start_traffic_monitor() {
    log_message "DEBUG" "Starting traffic monitor"
    
    local traffic_output="$OUTPUT_DIR/traffic_output.txt"
    local traffic_log="$OUTPUT_DIR/traffic.log"
    
    # Build net-traffic command
    local traffic_cmd="$TRAFFIC_PATH"
    
    log_message "INFO" "Starting traffic monitor: $traffic_cmd"
    
    # Start net-traffic in background with output redirection
    (
        echo "=== Traffic monitoring started at $(date '+%Y-%m-%d %H:%M:%S') ===" >> "$traffic_output"
        "$traffic_cmd" >> "$traffic_output" 2>> "$traffic_log"
    ) &
    
    TRAFFIC_PID=$!
    MONITOR_PIDS+=($TRAFFIC_PID)
    
    log_message "INFO" "Traffic monitor started (PID: $TRAFFIC_PID)"
    log_message "DEBUG" "Traffic output: $traffic_output"
    log_message "DEBUG" "Traffic log: $traffic_log"
}

# Start system fallback monitoring (using ss or netstat)
start_fallback_monitor() {
    log_message "DEBUG" "Starting fallback system monitor"
    
    local fallback_output="$OUTPUT_DIR/fallback_output.txt"
    local fallback_log="$OUTPUT_DIR/fallback.log"
    
    # Determine which system tool to use
    local fallback_cmd=""
    if [[ -x "$SS_PATH" ]]; then
        fallback_cmd="$SS_PATH -tuln"
        log_message "INFO" "Using ss as fallback monitor"
    elif [[ -x "$NETSTAT_PATH" ]]; then
        fallback_cmd="$NETSTAT_PATH -tuln"
        log_message "INFO" "Using netstat as fallback monitor"
    else
        log_message "WARN" "No fallback monitoring tool available"
        return 1
    fi
    
    # Start fallback monitoring in background
    (
        while [[ "$STOP_REQUESTED" != "true" ]]; do
            echo "=== $(date '+%Y-%m-%d %H:%M:%S') ===" >> "$fallback_output"
            $fallback_cmd >> "$fallback_output" 2>> "$fallback_log"
            sleep "$LSOCK_INTERVAL"
        done
    ) &
    
    local fallback_pid=$!
    MONITOR_PIDS+=($fallback_pid)
    
    log_message "INFO" "Fallback monitor started (PID: $fallback_pid)"
    log_message "DEBUG" "Fallback output: $fallback_output"
}

# Check if a process is running
is_process_running() {
    local pid="$1"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Monitor the health of observe tools
monitor_tool_health() {
    log_message "DEBUG" "Monitoring tool health"
    
    local unhealthy_tools=()
    
    # Check lsock monitor
    if [[ -n "$LSOCK_PID" ]] && ! is_process_running "$LSOCK_PID"; then
        unhealthy_tools+=("lsock")
        log_message "WARN" "Lsock monitor stopped unexpectedly"
    fi
    
    # Check traffic monitor
    if [[ -n "$TRAFFIC_PID" ]] && ! is_process_running "$TRAFFIC_PID"; then
        unhealthy_tools+=("net-traffic")
        log_message "WARN" "Traffic monitor stopped unexpectedly"
    fi
    
    # Check for output file growth (basic health check)
    local lsock_output="$OUTPUT_DIR/lsock_output.txt"
    local traffic_output="$OUTPUT_DIR/traffic_output.txt"
    
    if [[ -f "$lsock_output" ]]; then
        local lsock_size=$(stat -c%s "$lsock_output" 2>/dev/null || echo "0")
        if [[ "$lsock_size" -eq 0 ]]; then
            log_message "WARN" "Lsock output file is empty"
        fi
    fi
    
    if [[ -f "$traffic_output" ]]; then
        local traffic_size=$(stat -c%s "$traffic_output" 2>/dev/null || echo "0")
        if [[ "$traffic_size" -eq 0 ]]; then
            log_message "WARN" "Traffic output file is empty"
        fi
    fi
    
    # Return status
    if [[ ${#unhealthy_tools[@]} -gt 0 ]]; then
        log_message "ERROR" "Unhealthy monitoring tools: ${unhealthy_tools[*]}"
        return 1
    else
        log_message "DEBUG" "All monitoring tools healthy"
        return 0
    fi
}

# Restart a failed monitor
restart_monitor() {
    local monitor_type="$1"
    
    log_message "INFO" "Restarting $monitor_type monitor"
    
    case "$monitor_type" in
        "lsock")
            if [[ -n "$LSOCK_PID" ]]; then
                kill -TERM "$LSOCK_PID" 2>/dev/null || true
                wait "$LSOCK_PID" 2>/dev/null || true
            fi
            start_lsock_monitor
            ;;
        "traffic")
            if [[ -n "$TRAFFIC_PID" ]]; then
                kill -TERM "$TRAFFIC_PID" 2>/dev/null || true
                wait "$TRAFFIC_PID" 2>/dev/null || true
            fi
            start_traffic_monitor
            ;;
        *)
            log_message "ERROR" "Unknown monitor type: $monitor_type"
            return 1
            ;;
    esac
}

# Stop all monitoring processes
stop_monitors() {
    log_message "DEBUG" "Stopping all monitors"
    
    STOP_REQUESTED=true
    
    # Stop individual monitors by PID
    if [[ -n "$LSOCK_PID" ]]; then
        log_message "INFO" "Stopping lsock monitor (PID: $LSOCK_PID)"
        kill -TERM "$LSOCK_PID" 2>/dev/null || true
    fi
    
    if [[ -n "$TRAFFIC_PID" ]]; then
        log_message "INFO" "Stopping traffic monitor (PID: $TRAFFIC_PID)"
        kill -TERM "$TRAFFIC_PID" 2>/dev/null || true
    fi
    
    # Stop all monitor processes
    for pid in "${MONITOR_PIDS[@]}"; do
        if [[ -n "$pid" ]] && is_process_running "$pid"; then
            log_message "DEBUG" "Stopping monitor process (PID: $pid)"
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    
    # Wait for processes to terminate gracefully
    sleep 2
    
    # Force kill any remaining processes
    for pid in "${MONITOR_PIDS[@]}"; do
        if [[ -n "$pid" ]] && is_process_running "$pid"; then
            log_message "WARN" "Force killing monitor process (PID: $pid)"
            kill -KILL "$pid" 2>/dev/null || true
        fi
    done
    
    # Clear PID variables
    LSOCK_PID=""
    TRAFFIC_PID=""
    MONITOR_PIDS=()
    
    log_message "INFO" "All monitors stopped"
}

# Start all monitors
start_monitors() {
    log_message "INFO" "Starting all monitors"
    
    # Try to start primary observe tools
    local started_tools=()
    
    if [[ -x "$LSOCK_PATH" ]]; then
        start_lsock_monitor
        started_tools+=("lsock")
    else
        log_message "WARN" "Lsock tool not available: $LSOCK_PATH"
    fi
    
    if [[ -x "$TRAFFIC_PATH" ]]; then
        start_traffic_monitor
        started_tools+=("net-traffic")
    else
        log_message "WARN" "Net-traffic tool not available: $TRAFFIC_PATH"
    fi
    
    # Start fallback monitor if primary tools failed
    if [[ ${#started_tools[@]} -eq 0 ]]; then
        log_message "WARN" "No primary observe tools available, starting fallback monitor"
        start_fallback_monitor
        started_tools+=("fallback")
    fi
    
    if [[ ${#started_tools[@]} -eq 0 ]]; then
        log_message "ERROR" "Failed to start any monitoring tools"
        return 1
    fi
    
    log_message "INFO" "Started monitors: ${started_tools[*]}"
    
    # Give monitors time to initialize
    sleep 2
    
    # Initial health check
    monitor_tool_health
}

# Collect network data from monitoring tools
collect_network_data() {
    log_message "INFO" "Collecting and processing network data"
    
    local lsock_output="$OUTPUT_DIR/lsock_output.txt"
    local traffic_output="$OUTPUT_DIR/traffic_output.txt"
    local fallback_output="$OUTPUT_DIR/fallback_output.txt"
    
    # Check which data sources are available
    local available_sources=()
    
    if [[ -f "$lsock_output" ]] && [[ -s "$lsock_output" ]]; then
        available_sources+=("lsock")
        log_message "INFO" "Lsock data available: $(wc -l < "$lsock_output") lines"
    fi
    
    if [[ -f "$traffic_output" ]] && [[ -s "$traffic_output" ]]; then
        available_sources+=("traffic")
        log_message "INFO" "Traffic data available: $(wc -l < "$traffic_output") lines"
    fi
    
    if [[ -f "$fallback_output" ]] && [[ -s "$fallback_output" ]]; then
        available_sources+=("fallback")
        log_message "INFO" "Fallback data available: $(wc -l < "$fallback_output") lines"
    fi
    
    if [[ ${#available_sources[@]} -eq 0 ]]; then
        log_message "ERROR" "No network data available for processing"
        return 1
    fi
    
    log_message "INFO" "Available data sources: ${available_sources[*]}"
    
    # Process socket data
    if [[ " ${available_sources[*]} " =~ " lsock " ]]; then
        collect_socket_data "$lsock_output"
    elif [[ " ${available_sources[*]} " =~ " fallback " ]]; then
        collect_socket_data "$fallback_output"
    fi
    
    # Process traffic data
    if [[ " ${available_sources[*]} " =~ " traffic " ]]; then
        collect_traffic_data "$traffic_output"
    fi
    
    # Generate summary statistics
    generate_data_summary
}

# Process socket connection data
collect_socket_data() {
    local input_file="$1"
    log_message "DEBUG" "Processing socket data from $input_file"
    
    local socket_summary="$OUTPUT_DIR/socket_summary.txt"
    local connection_stats="$OUTPUT_DIR/connection_stats.txt"
    
    # Create socket summary
    {
        echo "=== Socket Connection Summary ==="
        echo "Generated at: $(date)"
        echo "Source file: $input_file"
        echo
        
        # Count total connections by type
        echo "Connection counts by protocol:"
        if grep -q "tcp" "$input_file"; then
            local tcp_count=$(grep -c "tcp" "$input_file" || echo "0")
            echo "TCP connections: $tcp_count"
        fi
        
        if grep -q "udp" "$input_file"; then
            local udp_count=$(grep -c "udp" "$input_file" || echo "0")
            echo "UDP connections: $udp_count"
        fi
        
        if grep -q "unix" "$input_file"; then
            local unix_count=$(grep -c "unix" "$input_file" || echo "0")
            echo "UNIX connections: $unix_count"
        fi
        
        echo
        echo "Top listening ports:"
        # Extract listening ports (this is a simplified extraction)
        grep -E "(LISTEN|LISTENING)" "$input_file" 2>/dev/null | \
        awk '{for(i=1;i<=NF;i++) if($i ~ /:[0-9]+$/) print $i}' | \
        cut -d: -f2 | sort | uniq -c | sort -nr | head -10 || echo "No listening ports found"
        
    } > "$socket_summary"
    
    # Create detailed connection statistics
    {
        echo "=== Detailed Connection Statistics ==="
        echo "Timestamp: $(date)"
        echo
        
        # Process each timestamp section
        awk '
        /^=== [0-9-]+ [0-9:]+ ===$/ { 
            timestamp = $2 " " $3
            print "Snapshot at " timestamp ":"
            getline
        }
        /tcp|udp|unix/ && !/^===/ { 
            connections++
            protocol = $1
            state = $NF
            if (protocol_count[protocol] == "") protocol_count[protocol] = 0
            if (state_count[state] == "") state_count[state] = 0
            protocol_count[protocol]++
            state_count[state]++
        }
        END {
            print "Total connections processed: " connections
            print "\nProtocol distribution:"
            for (p in protocol_count) print "  " p ": " protocol_count[p]
            print "\nConnection states:"
            for (s in state_count) print "  " s ": " state_count[s]
        }
        ' "$input_file"
        
    } > "$connection_stats"
    
    log_message "INFO" "Socket data processed"
    log_message "DEBUG" "Socket summary: $socket_summary"
    log_message "DEBUG" "Connection stats: $connection_stats"
}

# Process network traffic data
collect_traffic_data() {
    local input_file="$1"
    log_message "DEBUG" "Processing traffic data from $input_file"
    
    local traffic_summary="$OUTPUT_DIR/traffic_summary.txt"
    local traffic_stats="$OUTPUT_DIR/traffic_stats.txt"
    
    # Create traffic summary
    {
        echo "=== Network Traffic Summary ==="
        echo "Generated at: $(date)"
        echo "Source file: $input_file"
        echo
        
        # Count traffic events
        local total_events=$(grep -E "\[(to|from)\]" "$input_file" 2>/dev/null | wc -l || echo "0")
        echo "Total traffic events: $total_events"
        
        # Top traffic sources/destinations
        echo
        echo "Top traffic destinations:"
        grep -E "to [0-9]+\." "$input_file" 2>/dev/null | \
        awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) print $i}' | \
        sort | uniq -c | sort -nr | head -10 || echo "No traffic destinations found"
        
        echo
        echo "Top traffic sources:"
        grep -E "from [0-9]+\." "$input_file" 2>/dev/null | \
        awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) print $i}' | \
        sort | uniq -c | sort -nr | head -10 || echo "No traffic sources found"
        
    } > "$traffic_summary"
    
    # Create detailed traffic statistics
    {
        echo "=== Detailed Traffic Statistics ==="
        echo "Timestamp: $(date)"
        echo
        
        # Analyze traffic patterns
        awk '
        /traffic:/ {
            traffic_count++
            # Extract traffic volume
            for(i=1; i<=NF; i++) {
                if($i == "traffic:") {
                    volume = $(i+1)
                    total_volume += volume
                    if(volume > max_volume) max_volume = volume
                    if(min_volume == 0 || volume < min_volume) min_volume = volume
                }
            }
        }
        END {
            print "Traffic events analyzed: " traffic_count
            if(traffic_count > 0) {
                print "Total volume: " total_volume " bytes"
                print "Average volume: " int(total_volume/traffic_count) " bytes"
                print "Maximum volume: " max_volume " bytes"
                print "Minimum volume: " min_volume " bytes"
            }
        }
        ' "$input_file"
        
    } > "$traffic_stats"
    
    log_message "INFO" "Traffic data processed"
    log_message "DEBUG" "Traffic summary: $traffic_summary"
    log_message "DEBUG" "Traffic stats: $traffic_stats"
}

# Generate overall data summary
generate_data_summary() {
    log_message "DEBUG" "Generating overall data summary"
    
    local summary_file="$OUTPUT_DIR/analysis_summary.txt"
    
    {
        echo "========================================"
        echo "    Network Analysis Summary Report"
        echo "========================================"
        echo "Generated at: $(date)"
        echo "Analysis period: $ANALYSIS_DURATION seconds"
        echo "Output directory: $OUTPUT_DIR"
        echo
        
        # Include socket summary if available
        if [[ -f "$OUTPUT_DIR/socket_summary.txt" ]]; then
            echo "--- Socket Information ---"
            tail -n +4 "$OUTPUT_DIR/socket_summary.txt"
            echo
        fi
        
        # Include traffic summary if available
        if [[ -f "$OUTPUT_DIR/traffic_summary.txt" ]]; then
            echo "--- Traffic Information ---"
            tail -n +4 "$OUTPUT_DIR/traffic_summary.txt"
            echo
        fi
        
        # Configuration summary
        echo "--- Configuration Used ---"
        echo "Lsock interval: ${LSOCK_INTERVAL}s"
        echo "Traffic interval: ${TRAFFIC_INTERVAL}s"
        echo "Connection threshold: $CONNECTION_THRESHOLD"
        echo "Traffic threshold: ${TRAFFIC_THRESHOLD_MB}MB"
        echo "Anomaly detection: $ENABLE_ANOMALY_DETECTION"
        echo "Port scan detection: $ENABLE_PORT_SCAN_DETECTION"
        echo
        
        # File inventory
        echo "--- Generated Files ---"
        find "$OUTPUT_DIR" -name "*.txt" -type f -exec basename {} \; | sort
        
    } > "$summary_file"
    
    log_message "INFO" "Analysis summary generated: $summary_file"
    
    # Display summary to console if verbose
    if [[ "$VERBOSE" == "true" ]]; then
        echo
        echo "=== Analysis Summary ==="
        cat "$summary_file"
    fi
}

# Run advanced analysis using Python processor
run_advanced_analysis() {
    log_message "INFO" "Running advanced analysis with Python processor"
    
    local lsock_output="$OUTPUT_DIR/lsock_output.txt"
    local traffic_output="$OUTPUT_DIR/traffic_output.txt"
    local fallback_output="$OUTPUT_DIR/fallback_output.txt"
    
    # Determine which data files to process
    local input_files=()
    local analysis_types=()
    
    if [[ -f "$lsock_output" ]] && [[ -s "$lsock_output" ]]; then
        input_files+=("$lsock_output")
        analysis_types+=("lsock")
    elif [[ -f "$fallback_output" ]] && [[ -s "$fallback_output" ]]; then
        input_files+=("$fallback_output")
        analysis_types+=("lsock")
    fi
    
    if [[ -f "$traffic_output" ]] && [[ -s "$traffic_output" ]]; then
        input_files+=("$traffic_output")
        analysis_types+=("traffic")
    fi
    
    # Process each data file
    for i in "${!input_files[@]}"; do
        local input_file="${input_files[$i]}"
        local analysis_type="${analysis_types[$i]}"
        
        log_message "INFO" "Processing $analysis_type data: $input_file"
        
        # Build Python processor command
        local python_cmd="python3 $PROCESSOR_SCRIPT"
        python_cmd="$python_cmd --input $input_file"
        python_cmd="$python_cmd --output-dir $OUTPUT_DIR"
        python_cmd="$python_cmd --type $analysis_type"
        python_cmd="$python_cmd --format $EXPORT_FORMAT"
        
        if [[ -f "$CONFIG_FILE" ]]; then
            python_cmd="$python_cmd --config $CONFIG_FILE"
        fi
        
        if [[ "$VERBOSE" == "true" ]]; then
            python_cmd="$python_cmd --verbose"
        fi
        
        # Run Python processor
        log_message "DEBUG" "Running: $python_cmd"
        
        if eval "$python_cmd"; then
            log_message "INFO" "Advanced analysis completed for $analysis_type data"
        else
            log_message "ERROR" "Advanced analysis failed for $analysis_type data"
        fi
    done
    
    # Run security analysis if enabled
    if [[ "$ENABLE_ANOMALY_DETECTION" == "true" ]] || [[ "$ENABLE_PORT_SCAN_DETECTION" == "true" ]]; then
        run_security_analysis
    fi
}

# Run security-focused analysis
run_security_analysis() {
    log_message "INFO" "Running security analysis"
    
    local security_report="$OUTPUT_DIR/security_report.txt"
    
    {
        echo "========================================"
        echo "       Network Security Analysis"
        echo "========================================"
        echo "Generated at: $(date)"
        echo
        
        # Analyze connection patterns for security issues
        echo "--- Connection Pattern Analysis ---"
        
        if [[ -f "$OUTPUT_DIR/connections.json" ]]; then
            # Use jq to analyze JSON data if available
            if command -v jq &> /dev/null; then
                echo "Top remote IP addresses:"
                jq -r '.[] | .remote_address' "$OUTPUT_DIR/connections.json" 2>/dev/null | \
                grep -v "null" | sort | uniq -c | sort -nr | head -10
                
                echo
                echo "Unusual port usage:"
                jq -r '.[] | .local_port' "$OUTPUT_DIR/connections.json" 2>/dev/null | \
                grep -v "null" | sort | uniq -c | sort -nr | head -10
            fi
        fi
        
        echo
        echo "--- Port Scan Detection ---"
        
        # Simple port scan detection using shell tools
        if [[ -f "$OUTPUT_DIR/lsock_output.txt" ]]; then
            # Count unique local ports per remote IP
            awk '/tcp|udp/ && $3 !~ /^127\./ && $3 !~ /^0\.0\.0\.0/ {
                split($2, local, ":");
                split($3, remote, ":");
                if (remote[1] != "0.0.0.0") {
                    ports[remote[1]][local[2]] = 1;
                }
            }
            END {
                for (ip in ports) {
                    count = 0;
                    for (port in ports[ip]) count++;
                    if (count > 20) {
                        print ip ": " count " different ports accessed - POSSIBLE PORT SCAN";
                    }
                }
            }' "$OUTPUT_DIR/lsock_output.txt"
        fi
        
        echo
        echo "--- Connection Rate Analysis ---"
        
        # Analyze connection rates
        if [[ -f "$OUTPUT_DIR/connection_stats.txt" ]]; then
            echo "High connection rate sources:"
            grep -E "^[0-9]+\." "$OUTPUT_DIR/lsock_output.txt" 2>/dev/null | \
            awk '{print $3}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -10
        fi
        
        echo
        echo "--- Anomaly Detection ---"
        
        # Check for unusual patterns
        if [[ -f "$OUTPUT_DIR/analysis_result.json" ]]; then
            if command -v jq &> /dev/null; then
                echo "Detected anomalies:"
                jq -r '.anomalies[]' "$OUTPUT_DIR/analysis_result.json" 2>/dev/null || echo "No anomalies file found"
                
                echo
                echo "Security alerts:"
                jq -r '.security_alerts[]' "$OUTPUT_DIR/analysis_result.json" 2>/dev/null || echo "No security alerts found"
            fi
        fi
        
    } > "$security_report"
    
    log_message "INFO" "Security analysis completed: $security_report"
    
    # Log security report to security log if configured
    if [[ -n "$SECURITY_LOG" ]]; then
        {
            echo "=== Security Analysis Report $(date) ==="
            cat "$security_report"
            echo
        } >> "$SECURITY_LOG"
    fi
}

# Export data in requested formats
export_data() {
    log_message "INFO" "Exporting data in requested formats: $EXPORT_FORMAT"
    
    # Parse export format list
    IFS=',' read -ra FORMATS <<< "$EXPORT_FORMAT"
    
    for format in "${FORMATS[@]}"; do
        format=$(echo "$format" | tr -d ' ')  # Remove spaces
        
        case "$format" in
            "json")
                export_json_data
                ;;
            "csv")
                export_csv_data
                ;;
            "txt")
                export_text_data
                ;;
            *)
                log_message "WARN" "Unknown export format: $format"
                ;;
        esac
    done
    
    # Generate graphs if requested
    if [[ "$GENERATE_GRAPHS" == "true" ]]; then
        generate_graphs
    fi
    
    log_message "INFO" "Data export completed"
}

# Export data in JSON format
export_json_data() {
    log_message "DEBUG" "Exporting JSON data"
    
    # Create a comprehensive JSON export
    local json_export="$OUTPUT_DIR/network_analysis_export.json"
    
    {
        echo "{"
        echo "  \"analysis_info\": {"
        echo "    \"timestamp\": \"$(date)\","
        echo "    \"duration\": $ANALYSIS_DURATION,"
        echo "    \"configuration\": {"
        echo "      \"lsock_interval\": $LSOCK_INTERVAL,"
        echo "      \"traffic_interval\": $TRAFFIC_INTERVAL,"
        echo "      \"connection_threshold\": $CONNECTION_THRESHOLD,"
        echo "      \"anomaly_detection\": $ENABLE_ANOMALY_DETECTION"
        echo "    }"
        echo "  },"
        
        # Include file list
        echo "  \"generated_files\": ["
        local first=true
        for file in "$OUTPUT_DIR"/*.{txt,json,csv}; do
            if [[ -f "$file" ]]; then
                if [[ "$first" == "true" ]]; then
                    first=false
                else
                    echo ","
                fi
                echo -n "    \"$(basename "$file")\""
            fi
        done
        echo
        echo "  ]"
        echo "}"
    } > "$json_export"
    
    log_message "INFO" "JSON export created: $json_export"
}

# Export data in CSV format
export_csv_data() {
    log_message "DEBUG" "Exporting CSV data"
    
    # Create CSV summary
    local csv_export="$OUTPUT_DIR/network_summary.csv"
    
    {
        echo "metric,value,timestamp"
        echo "total_connections,$(grep -c "tcp\|udp" "$OUTPUT_DIR/lsock_output.txt" 2>/dev/null || echo 0),$(date)"
        echo "tcp_connections,$(grep -c "tcp" "$OUTPUT_DIR/lsock_output.txt" 2>/dev/null || echo 0),$(date)"
        echo "udp_connections,$(grep -c "udp" "$OUTPUT_DIR/lsock_output.txt" 2>/dev/null || echo 0),$(date)"
        echo "analysis_duration,$ANALYSIS_DURATION,$(date)"
        echo "monitoring_interval,$LSOCK_INTERVAL,$(date)"
    } > "$csv_export"
    
    log_message "INFO" "CSV export created: $csv_export"
}

# Export data in text format
export_text_data() {
    log_message "DEBUG" "Exporting text data"
    
    # Create readable text report
    local text_export="$OUTPUT_DIR/network_analysis_report.txt"
    
    {
        echo "========================================"
        echo "    Network Analysis Report"
        echo "========================================"
        echo "Generated: $(date)"
        echo "Duration: $ANALYSIS_DURATION seconds"
        echo "Configuration file: $CONFIG_FILE"
        echo "Output directory: $OUTPUT_DIR"
        echo
        
        # Include summaries from other files
        if [[ -f "$OUTPUT_DIR/analysis_summary.txt" ]]; then
            echo "--- Analysis Summary ---"
            cat "$OUTPUT_DIR/analysis_summary.txt"
            echo
        fi
        
        if [[ -f "$OUTPUT_DIR/security_report.txt" ]]; then
            echo "--- Security Report ---"
            cat "$OUTPUT_DIR/security_report.txt"
            echo
        fi
        
        echo "--- File Inventory ---"
        ls -la "$OUTPUT_DIR"
        
    } > "$text_export"
    
    log_message "INFO" "Text export created: $text_export"
}

# Generate graphs (placeholder for future implementation)
generate_graphs() {
    log_message "INFO" "Graph generation requested"
    
    # Check if graphing tools are available
    if command -v gnuplot &> /dev/null; then
        log_message "INFO" "Gnuplot available - could generate graphs"
        # TODO: Implement actual graph generation
    else
        log_message "WARN" "Gnuplot not available - cannot generate graphs"
    fi
}

# Main function
main() {
    log_message "INFO" "Starting Network Analyzer"
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Check prerequisites
    check_root
    check_prerequisites
    
    # Load and validate configuration
    load_config
    validate_config
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    chmod 755 "$OUTPUT_DIR"
    
    # If daemon mode, fork to background
    if [[ "$DAEMON" == "true" ]]; then
        if [[ -f "$PID_FILE" ]]; then
            local existing_pid=$(cat "$PID_FILE")
            if kill -0 "$existing_pid" 2>/dev/null; then
                echo "Error: Daemon already running (PID: $existing_pid)" >&2
                exit 1
            else
                rm -f "$PID_FILE"
            fi
        fi
        
        echo $$ > "$PID_FILE"
        log_message "INFO" "Starting as daemon (PID: $$)"
    fi
    
    log_message "INFO" "Network analyzer initialized successfully"
    log_message "INFO" "Configuration: interval=${LSOCK_INTERVAL}s, duration=${ANALYSIS_DURATION}s"
    log_message "INFO" "Output directory: $OUTPUT_DIR"
    
    # Start monitoring tools
    if ! start_monitors; then
        log_message "ERROR" "Failed to start monitoring tools"
        exit 1
    fi
    
    # Main monitoring loop
    local start_time=$(date +%s)
    local end_time=$((start_time + ANALYSIS_DURATION))
    local health_check_interval=30
    local last_health_check=$start_time
    
    log_message "INFO" "Starting main monitoring loop"
    log_message "INFO" "Analysis will run for $ANALYSIS_DURATION seconds"
    
    while [[ "$STOP_REQUESTED" != "true" ]]; do
        local current_time=$(date +%s)
        
        # Check if analysis duration has been reached (if not unlimited)
        if [[ "$ANALYSIS_DURATION" -gt 0 ]] && [[ "$current_time" -ge "$end_time" ]]; then
            log_message "INFO" "Analysis duration reached, stopping monitors"
            break
        fi
        
        # Periodic health check
        if [[ $((current_time - last_health_check)) -ge $health_check_interval ]]; then
            if ! monitor_tool_health; then
                log_message "WARN" "Some monitors are unhealthy, attempting restart"
                # Could implement selective restart logic here
            fi
            last_health_check=$current_time
        fi
        
        # Sleep for a short interval
        sleep 5
    done
    
    log_message "INFO" "Stopping monitors"
    stop_monitors
    
    # Collect and process data
    collect_network_data
    
    # Run advanced analysis using Python processor
    if [[ -x "$PROCESSOR_SCRIPT" ]]; then
        run_advanced_analysis
    fi
    
    # Export data in requested formats
    export_data
    
    log_message "INFO" "Network analyzer completed"
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi 