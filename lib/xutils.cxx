
#include "include/xdefines.h"
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>

static void vlog(const char *fmt, va_list ap)
{
	char buf[1024], *p = buf;
	size_t len, max = 1024;
	struct timeval tv;
	struct tm tm;
	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tm);
	len = strftime(p, max, "%Y-%m-%d %H:%M:%S", &tm);
	assert(len < max);
	p += len; max -= len;
	len = snprintf(p, max, ".%06lu ", tv.tv_usec);
	assert(len < max);
	p += len; max -= len;

	len = vsnprintf(p, max - 1, fmt, ap);
	if (len > max - 1) {
		len = max - 1;
	}
	p += len;
	*p++ = '\n';
	write(2, buf, p - buf);
}

void x_dbg(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vlog(fmt, ap);
	va_end(ap);
}

void x_panic(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vlog(fmt, ap);
	va_end(ap);
	abort();
}

