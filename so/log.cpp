#include "Ulog.h"

void Log::set_level(int level)
{
	if (level < ERROR || level > MAX)
		level = WARN;
	m_level = level;
}
void Log::set_file(FILE *file)
{
	if (file == nullptr)
		file = stderr;
	m_file = file;
}
void Log::info(const char *fmt, ...)
{
	if (m_level < INFO)
		return;
	va_list args;
	va_start(args, fmt);
	vfprintf(m_file, fmt, args);
	va_end(args);
}
void Log::debug(const char *fmt, ...)
{
	if (m_level < DEBUG)
		return;
	va_list args;
	va_start(args, fmt);
	vfprintf(m_file, fmt, args);
	va_end(args);
}
void Log::warn(const char *fmt, ...)
{
	if (m_level < WARN)
		return;
	va_list args;
	va_start(args, fmt);
	vfprintf(m_file, fmt, args);
	va_end(args);
}
void Log::error(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(m_file, fmt, args);
	va_end(args);
}

int Log::m_level = INFO;
FILE *Log::m_file = stdout;