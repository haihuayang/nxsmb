
#include "include/utils.hxx"
#include <memory>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <libgen.h>

struct x_logger_t
{
	x_logger_t(int dirfd, int fd, uint64_t filesize, std::string base)
		: dirfd(dirfd), fd(fd), filesize(filesize), base(std::move(base))
	{
	}

	~x_logger_t()
	{
		if (is_file()) {
			X_ASSERT(0 == close(fd));
			if (dirfd >= 0) {
				X_ASSERT(0 == close(dirfd));
			}
		}
	}

	bool is_file() const
	{
		return dirfd != -1;
	}

	int dirfd;
	const int fd;
	uint64_t filesize;
	const std::string base;
};

static std::shared_ptr<x_logger_t> log_init_stderr()
{
	return std::make_shared<x_logger_t>(-1, 2, 0ul, "");
}

unsigned int x_loglevel = X_LOG_LEVEL_DBG;
static std::shared_ptr<x_logger_t> g_logger = log_init_stderr();

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

	len = snprintf(p, max - 1, "%s ", name);
	if (len > max - 1) {
		len = max - 1;
	}
	p += len; max -= len;

	len = vsnprintf(p, max - 1, fmt, ap);
	if (len > max - 1) {
		len = max - 1;
	}
	p += len;
	*p++ = '\n';

	auto logger = g_logger;
	write(logger->fd, buf, p - buf);
}

void x_dbg(const char *fmt, ...)
{
	return;
	va_list ap;
	va_start(ap, fmt);
	vlog("DBG", fmt, ap);
	va_end(ap);
}

void x_panic(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vlog("PANIC", fmt, ap);
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

static int open_base(int dirfd, const char *base)
{
	struct timeval tv;
	struct tm tm;
	gettimeofday(&tv, NULL);
	gmtime_r(&tv.tv_sec, &tm);
	char tmbuf[32];
	strftime(tmbuf, sizeof tmbuf, "%Y%m%d-%H%M%S", &tm);
	char name[PATH_MAX];
	snprintf(name, sizeof name, "%s-%s", base, tmbuf);
	int fd = openat(dirfd, name, O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (fd >= 0) {
		unlinkat(dirfd, base, 0);
		symlinkat(name, dirfd, base);
	}
	return fd;
}

static int open_dir(int &dirfd, int &fd, std::string &basebuf, char *path)
{
	char *base = basename(path);
	char *dir = dirname(path);
	int tmp_dirfd = open(dir, O_RDONLY);
	if (tmp_dirfd == -1) {
		return -errno;
	}

	int ret = 0;
	int tmp_fd = open_base(tmp_dirfd, base);
	if (tmp_fd == -1) {
		ret = -errno;
		close(tmp_dirfd);
		return ret;
	}
	dirfd = tmp_dirfd;
	fd = tmp_fd;
	basebuf = base;
	return ret;
}

static std::shared_ptr<x_logger_t> log_init_file(const char *log_name, uint64_t filesize)
{
	char *tmp = strdup(log_name);
	if (!tmp) {
		X_LOG_ERR("fail allocate memory");
		return nullptr;
	}

	int dirfd, logfd;
	std::string base;
	int err = open_dir(dirfd, logfd, base, tmp);
	free(tmp);

	if (err != 0) {
		X_LOG_ERR("open_dir %s, err=%d", log_name, err);
		return nullptr;
	}
	return std::make_shared<x_logger_t>(dirfd, logfd, filesize, base);
}

int x_log_init(const char *log_name, unsigned int loglevel, uint64_t filesize)
{
	X_ASSERT(loglevel < X_LOG_LEVEL_MAX);
	x_loglevel = loglevel;

	if (!log_name) {
		g_logger->filesize = filesize;
		return 0;
	}

	std::shared_ptr<x_logger_t> logger;
	if (strcmp(log_name, "stderr") == 0) {
		logger = log_init_stderr();
	} else {
		logger = log_init_file(log_name, filesize);
	}

	if (!logger) {
		return -1;
	}

	g_logger = logger;
	X_LOG_NOTICE("init log %s:%s logfd=%d filesize=%ld",
			log_name, x_loglevel_names[loglevel],
			logger->fd, filesize);
	return 0;
}

/* should be called by at most 1 thread concurrently */
void x_log_check_size()
{
	auto logger = g_logger;
	if (logger->is_file()) {
		struct stat st;
		int err = fstat(logger->fd, &st);
		X_ASSERT(err == 0);
		if (uint64_t(st.st_size) > logger->filesize) {
			int logfd = open_base(logger->dirfd, logger->base.c_str());
			if (logfd == -1) {
				X_LOG_ERR("fail open new log, errno=%d", errno);
			}
			auto new_logger = std::make_shared<x_logger_t>(logger->dirfd,
					logfd, logger->filesize,
					logger->base);
			logger->dirfd = -2;
			g_logger = new_logger;
		}
	}
}
