#ifndef _STDIO_H_

#define _STDIO_H_

#include <stdarg.h>
#include <stddef.h>

int printf(const char *format, ...);
int vsnprintf(char *s, size_t n, const char *format, va_list arg);

#endif