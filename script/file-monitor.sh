#!/bin/bash

# File Monitor Script - Event Stream Fusion Engine
# Combined monitoring with trace-file, ext4snoop, mountsnoop, file-occupation
# Version: 1.0

set -e
set -o pipefail

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="$SCRIPT_DIR/file-monitor.conf"
TOOLS_DIR="$PROJECT_ROOT/observe"
PYTHON_PROCESSOR="$SCRIPT_DIR/event-processor.py"

# Process tracking
TOOL_PIDS=()
MONITOR_PIDS=()
CLEANUP_DONE=false

# Named pipes
MAIN_PIPE="/tmp/file-monitor-main-$$"
TRACE_FILE_PIPE="/tmp/file-monitor-trace-file-$$"
EXT4SNOOP_PIPE="/tmp/file-monitor-ext4snoop-$$"
MOUNTSNOOP_PIPE="/tmp/file-monitor-mountsnoop-$$"
FILE_OCCUPATION_PIPE="/tmp/file-monitor-file-occupation-$$"

# Default configuration
ENABLE_TRACE_FILE=true
ENABLE_EXT4SNOOP=true
ENABLE_MOUNTSNOOP=true
ENABLE_FILE_OCCUPATION=true
OUTPUT_FORMAT="text"
OUTPUT_FILE=""
CORRELATION_WINDOW=5
FILTER_PID=""
FILTER_COMM=""
FILTER_PATH=""
VERBOSE=false
DRY_RUN=false

# Function to display help
show_help() {
    cat << EOF
File Monitor Script - Event Stream Fusion Engine

USAGE:
    $0 [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -c, --config FILE       Configuration file (default: $CONFIG_FILE)
    -o, --output FILE       Output file (default: stdout)
    -f, --format FORMAT     Output format: text|json (default: text)
    -p, --pid PID           Filter by process ID
    -n, --comm COMM         Filter by process name
    -P, --path PATH         Filter by file path
    -v, --verbose           Enable verbose output
    -d, --dry-run           Show what would be executed without running
    --enable-trace-file     Enable trace-file tool
    --disable-trace-file    Disable trace-file tool
    --enable-ext4snoop      Enable ext4snoop tool
    --disable-ext4snoop     Disable ext4snoop tool
    --enable-mountsnoop     Enable mountsnoop tool
    --disable-mountsnoop    Disable mountsnoop tool
    --enable-file-occupation Enable file-occupation tool
    --disable-file-occupation Disable file-occupation tool

EXAMPLES:
    $0                                    # Run with default configuration
    $0 -p 1234 -f json                  # Monitor PID 1234, output JSON
    $0 -n firefox -o /tmp/monitor.log   # Monitor firefox, save to file
    $0 --disable-trace-file -v          # Run without trace-file, verbose mode

CONFIGURATION:
    The script reads configuration from $CONFIG_FILE
    Command line options override configuration file settings.

TOOLS MONITORED:
    - trace-file:      VFS operations monitoring
    - ext4snoop:       ext4 filesystem events
    - mountsnoop:      Mount/unmount operations
    - file-occupation: File descriptor snapshots

REQUIREMENTS:
    - Root privileges
    - Compiled monitoring tools in $TOOLS_DIR
    - Python 3 with json module
    - Named pipe support

EOF
}

# Function to log messages
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    case "$level" in
        ERROR)
            echo "[$timestamp] ERROR: $message" >&2
            ;;
        WARN)
            echo "[$timestamp] WARN: $message" >&2
            ;;
        INFO)
            if [[ "$VERBOSE" == true ]]; then
                echo "[$timestamp] INFO: $message" >&2
            fi
            ;;
        DEBUG)
            if [[ "$VERBOSE" == true ]]; then
                echo "[$timestamp] DEBUG: $message" >&2
            fi
            ;;
    esac
}

# Function to validate dependencies
check_dependencies() {
    local missing_deps=()
    
    log INFO "Starting dependency check"
    
    # Check for root privileges (skip in dry-run mode)
    if [[ $EUID -ne 0 ]] && [[ "$DRY_RUN" != true ]]; then
        log ERROR "This script requires root privileges"
        exit 1
    fi
    if [[ "$DRY_RUN" == true ]]; then
        log INFO "Dry-run mode: skipping root privileges check"
    else
        log INFO "Root privileges confirmed"
    fi
    
    # Check for Python
    if ! command -v python3 >/dev/null 2>&1; then
        missing_deps+=("python3")
        log WARN "python3 not found"
    else
        log INFO "python3 found"
    fi
    
    # Check for monitoring tools
    local tools=()
    [[ "$ENABLE_TRACE_FILE" == true ]] && tools+=("trace-file")
    [[ "$ENABLE_EXT4SNOOP" == true ]] && tools+=("ext4snoop")
    [[ "$ENABLE_MOUNTSNOOP" == true ]] && tools+=("mountsnoop")
    [[ "$ENABLE_FILE_OCCUPATION" == true ]] && tools+=("file-occupation")
    
    log INFO "Checking ${#tools[@]} enabled tools: ${tools[*]}"
    
    for tool in "${tools[@]}"; do
        log DEBUG "Checking tool: $TOOLS_DIR/$tool"
        if [[ ! -x "$TOOLS_DIR/$tool" ]]; then
            log WARN "Tool $tool not found or not executable at $TOOLS_DIR/$tool"
            missing_deps+=("$tool")
        else
            log INFO "Tool $tool verified at $TOOLS_DIR/$tool"
        fi
    done
    
    # Check Python processor
    if [[ ! -f "$PYTHON_PROCESSOR" ]]; then
        missing_deps+=("event-processor.py")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log ERROR "Missing dependencies: ${missing_deps[*]}"
        echo "Please ensure all tools are compiled and available." >&2
        exit 1
    fi
    
    log INFO "All dependencies verified"
}

# Function to load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        log INFO "Loading configuration from $CONFIG_FILE"
        
        # Source the config file in a subshell to avoid polluting current environment
        while IFS='=' read -r key value; do
            # Skip empty lines and comments
            [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
            
            # Remove quotes and whitespace
            key=$(echo "$key" | tr -d '[:space:]')
            value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed 's/^"\(.*\)"$/\1/')
            
            case "$key" in
                ENABLE_TRACE_FILE) ENABLE_TRACE_FILE="$value" ;;
                ENABLE_EXT4SNOOP) ENABLE_EXT4SNOOP="$value" ;;
                ENABLE_MOUNTSNOOP) ENABLE_MOUNTSNOOP="$value" ;;
                ENABLE_FILE_OCCUPATION) ENABLE_FILE_OCCUPATION="$value" ;;
                OUTPUT_FORMAT) OUTPUT_FORMAT="$value" ;;
                CORRELATION_WINDOW) CORRELATION_WINDOW="$value" ;;
                VERBOSE) VERBOSE="$value" ;;
            esac
        done < "$CONFIG_FILE"
        
        log INFO "Configuration loaded successfully"
    else
        log WARN "Configuration file $CONFIG_FILE not found, using defaults"
    fi
}

# Function to parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -f|--format)
                OUTPUT_FORMAT="$2"
                if [[ "$OUTPUT_FORMAT" != "text" && "$OUTPUT_FORMAT" != "json" ]]; then
                    log ERROR "Invalid output format: $OUTPUT_FORMAT (must be text or json)"
                    exit 1
                fi
                shift 2
                ;;
            -p|--pid)
                FILTER_PID="$2"
                if ! [[ "$FILTER_PID" =~ ^[0-9]+$ ]]; then
                    log ERROR "Invalid PID: $FILTER_PID (must be numeric)"
                    exit 1
                fi
                shift 2
                ;;
            -n|--comm)
                FILTER_COMM="$2"
                shift 2
                ;;
            -P|--path)
                FILTER_PATH="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            --enable-trace-file)
                ENABLE_TRACE_FILE=true
                shift
                ;;
            --disable-trace-file)
                ENABLE_TRACE_FILE=false
                shift
                ;;
            --enable-ext4snoop)
                ENABLE_EXT4SNOOP=true
                shift
                ;;
            --disable-ext4snoop)
                ENABLE_EXT4SNOOP=false
                shift
                ;;
            --enable-mountsnoop)
                ENABLE_MOUNTSNOOP=true
                shift
                ;;
            --disable-mountsnoop)
                ENABLE_MOUNTSNOOP=false
                shift
                ;;
            --enable-file-occupation)
                ENABLE_FILE_OCCUPATION=true
                shift
                ;;
            --disable-file-occupation)
                ENABLE_FILE_OCCUPATION=false
                shift
                ;;
            *)
                log ERROR "Unknown option: $1"
                echo "Use $0 --help for usage information" >&2
                exit 1
                ;;
        esac
    done
}

# Function to validate configuration
validate_config() {
    local enabled_tools=0
    
    log DEBUG "Checking tool enable flags:"
    log DEBUG "ENABLE_TRACE_FILE=$ENABLE_TRACE_FILE"
    log DEBUG "ENABLE_EXT4SNOOP=$ENABLE_EXT4SNOOP"
    log DEBUG "ENABLE_MOUNTSNOOP=$ENABLE_MOUNTSNOOP"
    log DEBUG "ENABLE_FILE_OCCUPATION=$ENABLE_FILE_OCCUPATION"
    
    [[ "$ENABLE_TRACE_FILE" == true ]] && enabled_tools=$((enabled_tools + 1))
    [[ "$ENABLE_EXT4SNOOP" == true ]] && enabled_tools=$((enabled_tools + 1))
    [[ "$ENABLE_MOUNTSNOOP" == true ]] && enabled_tools=$((enabled_tools + 1))
    [[ "$ENABLE_FILE_OCCUPATION" == true ]] && enabled_tools=$((enabled_tools + 1))
    
    log DEBUG "Total enabled tools: $enabled_tools"
    
    if [[ $enabled_tools -eq 0 ]]; then
        log ERROR "No monitoring tools enabled"
        exit 1
    fi
    
    log DEBUG "Checking correlation window: $CORRELATION_WINDOW"
    if [[ ! "$CORRELATION_WINDOW" =~ ^[0-9]+$ ]] || [[ $CORRELATION_WINDOW -lt 1 ]]; then
        log ERROR "Invalid correlation window: $CORRELATION_WINDOW (must be positive integer)"
        exit 1
    fi
    
    log INFO "Configuration validated: $enabled_tools tools enabled"
}

# Function to create named pipes
create_pipes() {
    log INFO "Creating named pipes"
    
    local pipes=("$MAIN_PIPE")
    [[ "$ENABLE_TRACE_FILE" == true ]] && pipes+=("$TRACE_FILE_PIPE")
    [[ "$ENABLE_EXT4SNOOP" == true ]] && pipes+=("$EXT4SNOOP_PIPE")
    [[ "$ENABLE_MOUNTSNOOP" == true ]] && pipes+=("$MOUNTSNOOP_PIPE")
    [[ "$ENABLE_FILE_OCCUPATION" == true ]] && pipes+=("$FILE_OCCUPATION_PIPE")
    
    for pipe in "${pipes[@]}"; do
        if [[ -e "$pipe" ]]; then
            rm -f "$pipe"
        fi
        mkfifo "$pipe"
        log DEBUG "Created pipe: $pipe"
    done
}

# Function to cleanup resources
cleanup() {
    if [[ "$CLEANUP_DONE" == true ]]; then
        return
    fi
    CLEANUP_DONE=true
    
    log INFO "Cleaning up resources"
    
    # Stop monitoring processes
    for pid in "${MONITOR_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            log DEBUG "Stopping monitor process: $pid"
            kill "$pid" 2>/dev/null || true
        fi
    done
    
    # Stop tool processes
    for pid in "${TOOL_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            log DEBUG "Stopping tool process: $pid"
            kill "$pid" 2>/dev/null || true
            sleep 1
            if kill -0 "$pid" 2>/dev/null; then
                log DEBUG "Force killing tool process: $pid"
                kill -9 "$pid" 2>/dev/null || true
            fi
        fi
    done
    
    # Remove named pipes
    local pipes=("$MAIN_PIPE" "$TRACE_FILE_PIPE" "$EXT4SNOOP_PIPE" "$MOUNTSNOOP_PIPE" "$FILE_OCCUPATION_PIPE")
    for pipe in "${pipes[@]}"; do
        if [[ -e "$pipe" ]]; then
            rm -f "$pipe"
            log DEBUG "Removed pipe: $pipe"
        fi
    done
    
    log INFO "Cleanup completed"
}

# Function to setup signal handlers
setup_signal_handlers() {
    trap cleanup SIGINT SIGTERM EXIT
}

# Function to start monitoring tool
start_tool() {
    local tool="$1"
    local pipe="$2"
    shift 2
    local tool_args=("$@")
    
    log INFO "Starting $tool with args: ${tool_args[*]}"
    
    if [[ "$DRY_RUN" == true ]]; then
        echo "Would run: $TOOLS_DIR/$tool ${tool_args[*]} > $pipe"
        return
    fi
    
    # Start tool and redirect output to pipe
    "$TOOLS_DIR/$tool" "${tool_args[@]}" > "$pipe" &
    local tool_pid=$!
    TOOL_PIDS+=("$tool_pid")
    
    log DEBUG "$tool started with PID: $tool_pid"
    
    # Monitor tool process
    (
        while kill -0 "$tool_pid" 2>/dev/null; do
            sleep 1
        done
        log WARN "$tool process $tool_pid terminated"
    ) &
    MONITOR_PIDS+=($!)
}

# Function to start event router
start_event_router() {
    log INFO "Starting event router"
    
    if [[ "$DRY_RUN" == true ]]; then
        echo "Would start event router with Python processor"
        return
    fi
    
    # Start Python event processor
    local python_args=(
        "$PYTHON_PROCESSOR"
        "--format" "$OUTPUT_FORMAT"
        "--correlation-window" "$CORRELATION_WINDOW"
        "--main-pipe" "$MAIN_PIPE"
    )
    
    [[ "$ENABLE_TRACE_FILE" == true ]] && python_args+=("--trace-file-pipe" "$TRACE_FILE_PIPE")
    [[ "$ENABLE_EXT4SNOOP" == true ]] && python_args+=("--ext4snoop-pipe" "$EXT4SNOOP_PIPE")
    [[ "$ENABLE_MOUNTSNOOP" == true ]] && python_args+=("--mountsnoop-pipe" "$MOUNTSNOOP_PIPE")
    [[ "$ENABLE_FILE_OCCUPATION" == true ]] && python_args+=("--file-occupation-pipe" "$FILE_OCCUPATION_PIPE")
    [[ -n "$FILTER_PID" ]] && python_args+=("--filter-pid" "$FILTER_PID")
    [[ -n "$FILTER_COMM" ]] && python_args+=("--filter-comm" "$FILTER_COMM")
    [[ -n "$FILTER_PATH" ]] && python_args+=("--filter-path" "$FILTER_PATH")
    [[ "$VERBOSE" == true ]] && python_args+=("--verbose")
    
    if [[ -n "$OUTPUT_FILE" ]]; then
        python3 "${python_args[@]}" > "$OUTPUT_FILE" &
    else
        python3 "${python_args[@]}" &
    fi
    
    local processor_pid=$!
    TOOL_PIDS+=("$processor_pid")
    log DEBUG "Event processor started with PID: $processor_pid"
}

# Function to build tool arguments
build_tool_args() {
    local tool="$1"
    local args=()
    
    case "$tool" in
        trace-file)
            [[ -n "$FILTER_PID" ]] && args+=("-p" "$FILTER_PID")
            [[ -n "$FILTER_COMM" ]] && args+=("-c" "$FILTER_COMM")
            ;;
        ext4snoop)
            [[ -n "$FILTER_PID" ]] && args+=("-p" "$FILTER_PID")
            [[ -n "$FILTER_COMM" ]] && args+=("-c" "$FILTER_COMM")
            ;;
        mountsnoop)
            # mountsnoop uses different argument format
            [[ -n "$FILTER_PATH" ]] && args+=("$FILTER_PATH")
            ;;
        file-occupation)
            [[ -n "$FILTER_PATH" ]] && args+=("-p" "$FILTER_PATH")
            ;;
    esac
    
    echo "${args[@]}"
}

# Function to start file-occupation snapshots
start_file_occupation_monitor() {
    if [[ "$ENABLE_FILE_OCCUPATION" != true ]]; then
        return
    fi
    
    log INFO "Starting file-occupation snapshot monitor"
    
    if [[ "$DRY_RUN" == true ]]; then
        echo "Would start file-occupation monitor with 5-second intervals"
        return
    fi
    
    (
        while true; do
            local args=($(build_tool_args "file-occupation"))
            echo "SNAPSHOT_START:$(date '+%Y-%m-%d %H:%M:%S')" > "$FILE_OCCUPATION_PIPE"
            "$TOOLS_DIR/file-occupation" "${args[@]}" >> "$FILE_OCCUPATION_PIPE" 2>/dev/null || true
            echo "SNAPSHOT_END:$(date '+%Y-%m-%d %H:%M:%S')" >> "$FILE_OCCUPATION_PIPE"
            sleep 5
        done
    ) &
    
    local monitor_pid=$!
    TOOL_PIDS+=("$monitor_pid")
    log DEBUG "File-occupation monitor started with PID: $monitor_pid"
}

# Main function
main() {
    log INFO "File Monitor Script starting"
    
    # Parse command line arguments first
    log INFO "Parsing command line arguments"
    parse_arguments "$@"
    log INFO "Arguments parsed successfully"
    
    # Load configuration
    log INFO "Loading configuration"
    load_config
    log INFO "Configuration loaded"
    
    # Validate configuration
    log INFO "Validating configuration"
    validate_config
    log INFO "Configuration validated"
    
    # Check dependencies
    log INFO "Checking dependencies"
    check_dependencies
    log INFO "Dependencies checked"
    
    # Show configuration if dry run
    if [[ "$DRY_RUN" == true ]]; then
        echo "=== CONFIGURATION ==="
        echo "trace-file: $ENABLE_TRACE_FILE"
        echo "ext4snoop: $ENABLE_EXT4SNOOP"
        echo "mountsnoop: $ENABLE_MOUNTSNOOP"
        echo "file-occupation: $ENABLE_FILE_OCCUPATION"
        echo "Output format: $OUTPUT_FORMAT"
        echo "Output file: ${OUTPUT_FILE:-stdout}"
        echo "Correlation window: $CORRELATION_WINDOW seconds"
        [[ -n "$FILTER_PID" ]] && echo "Filter PID: $FILTER_PID"
        [[ -n "$FILTER_COMM" ]] && echo "Filter COMM: $FILTER_COMM"
        [[ -n "$FILTER_PATH" ]] && echo "Filter PATH: $FILTER_PATH"
        echo "===================="
        echo ""
    fi
    
    # Setup signal handlers
    setup_signal_handlers
    
    # Create named pipes
    create_pipes
    
    # Start monitoring tools
    if [[ "$ENABLE_TRACE_FILE" == true ]]; then
        local args=($(build_tool_args "trace-file"))
        start_tool "trace-file" "$TRACE_FILE_PIPE" "${args[@]}"
    fi
    
    if [[ "$ENABLE_EXT4SNOOP" == true ]]; then
        local args=($(build_tool_args "ext4snoop"))
        start_tool "ext4snoop" "$EXT4SNOOP_PIPE" "${args[@]}"
    fi
    
    if [[ "$ENABLE_MOUNTSNOOP" == true ]]; then
        local args=($(build_tool_args "mountsnoop"))
        start_tool "mountsnoop" "$MOUNTSNOOP_PIPE" "${args[@]}"
    fi
    
    # Start file-occupation monitor
    start_file_occupation_monitor
    
    # Start event router
    start_event_router
    
    if [[ "$DRY_RUN" == true ]]; then
        log INFO "Dry run completed"
        cleanup
        exit 0
    fi
    
    log INFO "All tools started successfully"
    log INFO "Press Ctrl+C to stop monitoring"
    
    # Wait for processes
    wait
}

# Run main function with all arguments
main "$@" 