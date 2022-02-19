
#include "include/xdefines.h"
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>

static void vlog(const char *name, const char *fmt, va_list ap)
{
	char buf[8 * 1024], *p = buf;
	size_t len, max = sizeof buf;
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

	if (name) {
		len = snprintf(p, max - 1, "%s ", name);
		if (len > max - 1) {
			len = max - 1;
		}
		p += len; max -= len;
	}

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
	return;
	va_list ap;
	va_start(ap, fmt);
	vlog(nullptr, fmt, ap);
	va_end(ap);
}

void x_panic(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vlog(nullptr, fmt, ap);
	va_end(ap);
	abort();
}

int x_loglevel = X_LOG_LEVEL_DBG;

static const char *x_loglevel_names[] = {
#define X_LOG_DECL(x) #x,
	X_LOG_ENUM
#undef X_LOG_DECL
};

void x_log(int level, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vlog(x_loglevel_names[level], fmt, ap);
	va_end(ap);
}


