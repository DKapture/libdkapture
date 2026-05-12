#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
#
# SPDX-License-Identifier: LGPL-2.1

"""Helpers for parsing /proc/[pid]/stat style files."""


def parse_stat_content(stat_content):
    """Return (comm, utime, stime) parsed from /proc stat content.

    The comm field is wrapped in parentheses and may itself contain spaces or
    right parentheses, so splitting the whole line on whitespace is unsafe.
    """
    open_paren = stat_content.find("(")
    close_paren = stat_content.rfind(")")

    if open_paren < 0 or close_paren <= open_paren:
        raise ValueError("missing process name parentheses")

    comm = stat_content[open_paren + 1:close_paren]
    fields = stat_content[close_paren + 1:].strip().split()

    # fields[0] is state, so utime/stime (proc fields 14/15) are 11/12 here.
    if len(fields) < 13:
        raise ValueError("not enough stat fields")

    return comm, int(fields[11]), int(fields[12])
