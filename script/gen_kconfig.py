#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1-only

"""
Script to generate kconfig.h from /proc/config.gz
Usage: python3 gen_kconfig.py [output_file]
       If output_file is not specified, output to stdout
"""

import os
import gzip
import re
import sys

def main():
    # Parse command line arguments
    if len(sys.argv) > 1:
        OUTPUT_FILE = sys.argv[1]
        output_to_stdout = False
    else:
        OUTPUT_FILE = None
        output_to_stdout = True
    
    CONFIG_SOURCE = "/proc/config.gz"
    
    if output_to_stdout:
        print(f"Generating kconfig.h from {CONFIG_SOURCE} to stdout...", file=sys.stderr)
    else:
        print(f"Generating kconfig.h from {CONFIG_SOURCE} to {OUTPUT_FILE}...")
    
    # Check if config.gz exists
    if not os.path.exists(CONFIG_SOURCE):
        print(f"Error: {CONFIG_SOURCE} not found!", file=sys.stderr)
        print("Make sure you have CONFIG_IKCONFIG_PROC enabled in your kernel.", file=sys.stderr)
        sys.exit(1)
    
    # Write header
    header_content = '''/*
 * Auto-generated kernel configuration header
 * Generated from /proc/config.gz
 * 
 * This file contains kernel configuration options as preprocessor definitions.
 * Each option is prefixed with KCONFIG_ to avoid conflicts with other macros.
 */

#pragma once

/* Kernel configuration options */
'''

    if output_to_stdout:
        print(header_content, end='')
    else:
        with open(OUTPUT_FILE, 'w') as f:
            f.write(header_content)

    if not output_to_stdout:
        print("Processing kernel configuration...")

    # Process config.gz and generate definitions
    try:
        with gzip.open(CONFIG_SOURCE, 'rt') as config_file:
            for line in config_file:
                line = line.strip()

                # Skip comments and empty lines
                if line.startswith('#') or not line:
                    continue

                # Skip lines that don't look like config options
                if not line.startswith('CONFIG_'):
                    continue

                # Extract config name and value
                match = re.match(r'^\s*(CONFIG_[^=]*)=(.*)$', line)
                if not match:
                    continue

                config_name = match.group(1).strip()
                config_value = match.group(2).strip()
                
                # Handle different value types
                if config_value == 'y':
                    # Boolean option set to yes
                    definition = f"#define {config_name} 1"
                elif config_value == 'm':
                    # Boolean option set to module
                    definition = f"#define {config_name} 2"
                elif config_value == 'n':
                    # Boolean option set to no
                    definition = f"#define {config_name} 0"
                elif config_value.isdigit():
                    # Numeric value
                    definition = f"#define {config_name} {config_value}"
                elif config_value.startswith('"'):
                    # String value (quoted)
                    definition = f"#define {config_name} {config_value}"
                else:
                    # Other string value
                    definition = f'#define {config_name} "{config_value}"'

                # Output definition
                if output_to_stdout:
                    print(definition)
                else:
                    # Append to file
                    with open(OUTPUT_FILE, 'a') as f:
                        f.write(definition + '\n')

    except Exception as e:
        print(f"Error processing {CONFIG_SOURCE}: {e}", file=sys.stderr)
        sys.exit(1)

    if not output_to_stdout:
        print(f"kconfig.h generated in {OUTPUT_FILE}")

if __name__ == "__main__":
    main() 