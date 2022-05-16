
#include "include/xdefines.h"
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>

int x_loglevel = X_LOG_LEVEL_DBG;
int x_logfd = 2; // stderr

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
	write(x_logfd, buf, p - buf);
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

int x_log_init(const char *log_level, const char *log_name)
{
	int loglevel = X_LOG_LEVEL_DBG; // TODO set to INFO
	if (log_level) {
		int l;
		for (l = 0; l < X_LOG_LEVEL_MAX; ++l) {
			if (strcmp(log_level, x_loglevel_names[l]) == 0) {
				break;
			}
		}
		if (l == X_LOG_LEVEL_MAX) {
			x_log(X_LOG_LEVEL_ERR, "invalid log_level %s", log_level);
			return -1;
		}
		loglevel = l;
	}
	int logfd = -1;
	if (strcmp(log_name, "stderr") == 0) {
		logfd = 2;
	} else {
		logfd = open(log_name, O_WRONLY | O_APPEND | O_CREAT, 0644);
		if (logfd == -1) {
			x_log(X_LOG_LEVEL_ERR, "fail to open log_name %s, errno=%d",
					log_name, errno);
			return -1;
		}
	}
	if (x_logfd != 2) {
		close(x_logfd);
	}
	x_logfd = logfd;
	x_loglevel = loglevel;
	x_log(X_LOG_LEVEL_NOTICE, "init log %s:%s logfd %d",
			log_name, x_loglevel_names[loglevel],
			logfd);
	return 0;
}

