#!/bin/bash

# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1

# Help information
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "Monitor and analyze IRQ statistics"
    echo ""
    echo "Options:"
    echo "  -i, --interval SECONDS    Statistics interval (seconds)"
    echo "  -p, --process NAME        Filter by process name"
    echo "  -n, --irq NUMBER         Filter by IRQ number or vector"
    echo "  -t, --threshold MICROS    Filter by latency threshold (microseconds)"
    echo "  -s, --sort TYPE          Sort by: rate, avg(average latency), max(maximum latency),"
    echo "                           min(minimum latency), count(occurrence count)"
    echo "  -h, --help               Show this help message"
}

# Cleanup function
cleanup() {
    local pids=$(jobs -p)
    if [ ! -z "$pids" ]; then
        kill $pids 2>/dev/null
    fi
    exit 0
}

# Register cleanup function
trap cleanup EXIT INT TERM

# Default values
INTERVAL=10
PROCESS=""
IRQ=""
THRESHOLD=""
SORT="count"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--interval)
            INTERVAL="$2"
            shift 2
            ;;
        -p|--process)
            PROCESS="$2"
            shift 2
            ;;
        -n|--irq)
            IRQ="$2"
            shift 2
            ;;
        -t|--threshold)
            THRESHOLD="$2"
            shift 2
            ;;
        -s|--sort)
            SORT="$2"
            if [[ ! "$SORT" =~ ^(rate|avg|max|min|count)$ ]]; then
                echo "Error: Invalid sort type '$SORT'"
                echo "Valid sort types: rate, avg, max, min, count"
                exit 1
            fi
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Check for root user
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Check required tools
if ! command -v python3 &> /dev/null; then
    echo "Python3 is required"
    exit 1
fi

# Build statistics script arguments
STAT_ARGS=""
[ ! -z "$INTERVAL" ] && STAT_ARGS="$STAT_ARGS -i $INTERVAL"
[ ! -z "$PROCESS" ] && STAT_ARGS="$STAT_ARGS -p $PROCESS"
[ ! -z "$IRQ" ] && STAT_ARGS="$STAT_ARGS -n $IRQ"
[ ! -z "$THRESHOLD" ] && STAT_ARGS="$STAT_ARGS -t $THRESHOLD"
[ ! -z "$SORT" ] && STAT_ARGS="$STAT_ARGS -s $SORT"

# Run irqsnoop and pipe to statistics script
echo "Starting IRQ monitoring... (will run for ${INTERVAL} seconds)"
echo "Interval: ${INTERVAL} seconds"
[ ! -z "$PROCESS" ] && echo "Process filter: $PROCESS"
[ ! -z "$IRQ" ] && echo "IRQ filter: $IRQ"
[ ! -z "$THRESHOLD" ] && echo "Latency threshold: ${THRESHOLD}us"
[ ! -z "$SORT" ] && echo "Sort by: $SORT"
echo ""

# Start irqsnoop and pipe output to statistics script
/home/rwen/dkapture/observe/irqsnoop | python3 /home/rwen/dkapture/script/irq_stat.py $STAT_ARGS