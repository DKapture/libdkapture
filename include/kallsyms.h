// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1

#pragma once
#include <stdio.h>
#include <string.h>

static void *kallsyms_lookup(const char *symbol_name)
{
	FILE *fp;
	char line[256];
	unsigned long address = 0;
	char sym[256] = {};
	char type;

	fp = fopen("/proc/kallsyms", "r");
	if (!fp)
	{
		perror("fopen");
		return NULL;
	}

	while (fgets(line, sizeof(line), fp))
	{
		if (sscanf(line, "%lx %c %s", &address, &type, sym) == 3)
		{
			if (strcmp(sym, symbol_name) == 0)
			{
				fclose(fp);
				return (void *)address;
			}
		}
	}

	fclose(fp);
	return NULL;
}