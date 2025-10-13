// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once
#include <stdio.h>
#include <stdarg.h>

class Log
{
  public:
	enum Level
	{
		ERROR = 0,
		WARN,
		INFO,
		DEBUG,
		MAX,
	};
	static void set_level(int level);
	static void set_file(FILE *file);
	static void info(const char *fmt, ...);
	static void debug(const char *fmt, ...);
	static void warn(const char *fmt, ...);
	static void error(const char *fmt, ...);

  private:
	static int m_level;
	static FILE *m_file;
};

#define LOG_PREFIX "[DKapture]"

#define pr_info(fmt, ...)                                                      \
	Log::info(                                                                 \
		LOG_PREFIX "[%s:%d][info] " fmt "\n",                                  \
		__FILE_NAME__,                                                         \
		__LINE__,                                                              \
		##__VA_ARGS__                                                          \
	)
#define pr_debug(fmt, ...)                                                     \
	Log::debug(                                                                \
		"\033[1;90m" LOG_PREFIX "[%s:%d][debug] " fmt "\033[0m\n",             \
		__FILE_NAME__,                                                         \
		__LINE__,                                                              \
		##__VA_ARGS__                                                          \
	)
#define pr_warn(fmt, ...)                                                      \
	Log::warn(                                                                 \
		"\033[1;33m" LOG_PREFIX "[%s:%d][warn] " fmt "\033[0m\n",              \
		__FILE_NAME__,                                                         \
		__LINE__,                                                              \
		##__VA_ARGS__                                                          \
	)
#define pr_error(fmt, ...)                                                     \
	Log::error(                                                                \
		"\033[1;31m" LOG_PREFIX "[%s:%d][error] " fmt "\033[0m\n",             \
		__FILE_NAME__,                                                         \
		__LINE__,                                                              \
		##__VA_ARGS__                                                          \
	)
