#!/bin/bash

# Script to generate EXT4 tracepoint structure definitions
# Usage: ./generate_ext4_structs.sh

EXT4_DIR="../ext4"
OUTPUT_FILE="../docs/ext4_all_structures.h"

echo "Generating EXT4 tracepoint structures..."

# Write header
cat > $OUTPUT_FILE << 'EOF'
/*
 * Auto-generated EXT4 tracepoint structures
 * Generated from /sys/kernel/debug/tracing/events/ext4/*/format files
 */

#ifndef _EXT4_TRACEPOINT_STRUCTS_H
#define _EXT4_TRACEPOINT_STRUCTS_H

#include <linux/types.h>

/* Common tracepoint fields */
struct tp_common {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
};

EOF

# Process each tracepoint directory
for tp_dir in $(find $EXT4_DIR -maxdepth 1 -type d | sort); do
    if [[ ! -f "$tp_dir/format" ]]; then
        continue
    fi
    
    tp_name=$(basename $tp_dir)
    echo "Processing $tp_name..."
    
    # Extract structure name
    struct_name="struct tp_$tp_name"
    
    echo "" >> $OUTPUT_FILE
    echo "/* $tp_name tracepoint */" >> $OUTPUT_FILE
    echo "$struct_name {" >> $OUTPUT_FILE
    echo "    unsigned short common_type;" >> $OUTPUT_FILE
    echo "    unsigned char common_flags;" >> $OUTPUT_FILE
    echo "    unsigned char common_preempt_count;" >> $OUTPUT_FILE
    echo "    int common_pid;" >> $OUTPUT_FILE
    
    # Parse format file and extract field definitions
    grep "^[[:space:]]*field:" "$tp_dir/format" | grep -v common_ | while read line; do
        # Extract field type and name
        field_type=$(echo "$line" | sed 's/.*field:\([^;]*\).*/\1/' | sed 's/[[:space:]]*$//')
        field_name=$(echo "$field_type" | awk '{print $NF}' | sed 's/\*//g')
        field_type_clean=$(echo "$field_type" | sed "s/[[:space:]]*${field_name}[[:space:]]*$//")
        
        # Handle pointer types
        if [[ "$field_type" == *"*"* ]]; then
            field_type_clean="${field_type_clean} *"
        fi
        
        echo "    $field_type_clean $field_name;" >> $OUTPUT_FILE
    done
    
    echo "};" >> $OUTPUT_FILE
done

# Write footer
cat >> $OUTPUT_FILE << 'EOF'

#endif /* _EXT4_TRACEPOINT_STRUCTS_H */
EOF

echo "Structures generated in $OUTPUT_FILE"

# Generate a summary of all tracepoints
echo ""
echo "Generating tracepoint summary..."

cat > ../docs/ext4_tracepoint_summary.txt << 'EOF'
EXT4 Tracepoint Summary
======================

This file lists all available EXT4 tracepoints and their categories.

EOF

echo "Total tracepoints found: $(find $EXT4_DIR -maxdepth 1 -type d -name 'ext4_*' | wc -l)" >> ../docs/ext4_tracepoint_summary.txt
echo "" >> ../docs/ext4_tracepoint_summary.txt

# Categorize tracepoints
echo "## Inode Operations" >> ../docs/ext4_tracepoint_summary.txt
find $EXT4_DIR -maxdepth 1 -type d -name '*inode*' | sort | sed 's/.*\///g' | sed 's/^/- /' >> ../docs/ext4_tracepoint_summary.txt

echo "" >> ../docs/ext4_tracepoint_summary.txt
echo "## Write Operations" >> ../docs/ext4_tracepoint_summary.txt
find $EXT4_DIR -maxdepth 1 -type d -name '*write*' | sort | sed 's/.*\///g' | sed 's/^/- /' >> ../docs/ext4_tracepoint_summary.txt

echo "" >> ../docs/ext4_tracepoint_summary.txt
echo "## Block Allocation" >> ../docs/ext4_tracepoint_summary.txt
find $EXT4_DIR -maxdepth 1 -type d -name '*alloc*' -o -name '*block*' -o -name '*mballoc*' | sort | sed 's/.*\///g' | sed 's/^/- /' >> ../docs/ext4_tracepoint_summary.txt

echo "" >> ../docs/ext4_tracepoint_summary.txt
echo "## Journal Operations" >> ../docs/ext4_tracepoint_summary.txt
find $EXT4_DIR -maxdepth 1 -type d -name '*journal*' | sort | sed 's/.*\///g' | sed 's/^/- /' >> ../docs/ext4_tracepoint_summary.txt

echo "" >> ../docs/ext4_tracepoint_summary.txt
echo "## Fast Commit" >> ../docs/ext4_tracepoint_summary.txt
find $EXT4_DIR -maxdepth 1 -type d -name '*fc_*' | sort | sed 's/.*\///g' | sed 's/^/- /' >> ../docs/ext4_tracepoint_summary.txt

echo "" >> ../docs/ext4_tracepoint_summary.txt
echo "## Extent Operations" >> ../docs/ext4_tracepoint_summary.txt
find $EXT4_DIR -maxdepth 1 -type d -name '*ext_*' -o -name '*es_*' | sort | sed 's/.*\///g' | sed 's/^/- /' >> ../docs/ext4_tracepoint_summary.txt

echo "" >> ../docs/ext4_tracepoint_summary.txt
echo "## File Operations" >> ../docs/ext4_tracepoint_summary.txt
find $EXT4_DIR -maxdepth 1 -type d -name '*sync*' -o -name '*truncate*' -o -name '*fallocate*' -o -name '*unlink*' | sort | sed 's/.*\///g' | sed 's/^/- /' >> ../docs/ext4_tracepoint_summary.txt

echo "" >> ../docs/ext4_tracepoint_summary.txt
echo "## All Tracepoints" >> ../docs/ext4_tracepoint_summary.txt
find $EXT4_DIR -maxdepth 1 -type d -name 'ext4_*' | sort | sed 's/.*\///g' | nl -w3 -s'. '>> ../docs/ext4_tracepoint_summary.txt

echo "Summary generated in ../docs/ext4_tracepoint_summary.txt"
echo "Done!" 