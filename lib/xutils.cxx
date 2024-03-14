
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

static std::shared_ptr<x_logger_t> g_logger = log_init_stderr();

static void vlog(const char *log_class_name,
		const char *log_level_name,
		const char *fmt, va_list ap)
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

	len = snprintf(p, max - 1, "%s %s ", log_class_name,
			log_level_name);
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
	vlog("OTHER", "DBG", fmt, ap);
	va_end(ap);
}

void x_panic(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vlog("OTHER", "PANIC", fmt, ap);
	va_end(ap);
	abort();
}

static const char *x_log_level_names[] = {
#define X_LOG_DECL(x) #x,
	X_LOG_ENUM
#undef X_LOG_DECL
};

#undef X_LOG_CLASS_DECL
#define X_LOG_CLASS_DECL(x) # x,
static const char *x_log_class_names[] = {
	X_LOG_CLASS_ENUM
};

#undef X_LOG_CLASS_DECL
#define X_LOG_CLASS_DECL(x) X_LOG_LEVEL_NOTICE,
unsigned int x_log_level[X_LOG_CLASS_MAX] = {
	X_LOG_CLASS_ENUM
};

void x_log(int log_class, int log_level, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vlog(x_log_class_names[log_class], x_log_level_names[log_level], fmt, ap);
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
	if (fd < 0) {
		return -errno;
	}
	unlinkat(dirfd, base, 0);
	symlinkat(name, dirfd, base);
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

	int tmp_fd = open_base(tmp_dirfd, base);
	if (tmp_fd < 0) {
		close(tmp_dirfd);
		return tmp_fd;
	}
	dirfd = tmp_dirfd;
	fd = tmp_fd;
	basebuf = base;
	return 0;
}

static std::shared_ptr<x_logger_t> log_init_file(const char *log_name, uint64_t filesize)
{
	char *tmp = strdup(log_name);
	if (!tmp) {
		X_LOG(UTILS, ERR, "fail allocate memory");
		return nullptr;
	}

	int dirfd = -1, logfd = -1;
	std::string base;
	int err = open_dir(dirfd, logfd, base, tmp);
	free(tmp);

	if (err != 0) {
		X_LOG(UTILS, ERR, "open_dir %s, err=%d", log_name, err);
		return nullptr;
	}
	return std::make_shared<x_logger_t>(dirfd, logfd, filesize, base);
}

static unsigned int map_name(const char *names[], unsigned int count,
		const char *p, const char *end)
{
	unsigned int i;
	for (i = 0; i < count; ++i) {
		if (strncmp(p, names[i], end - p) == 0 &&
				p + strlen(names[i]) == end) {
			break;
		}
	}
	return i;
}

static unsigned int map_log_level(unsigned long num)
{
	if (num > 10) {
		return X_LOG_LEVEL_VERB;
	} else if (num > 5) {
		return X_LOG_LEVEL_DBG;
	} else if (num > 3) {
		return X_LOG_LEVEL_OP;
	} else if (num > 1) {
		return X_LOG_LEVEL_NOTICE;
	} else if (num > 0) {
		return X_LOG_LEVEL_WARN;
	} else {
		return X_LOG_LEVEL_ERR;
	}
}

static unsigned int parse_log_level(const char *p, const char *end)
{
	char *te;
	unsigned long tmp = strtoul(p, &te, 0);
	if (te != end) {
		return map_name(x_log_level_names, X_LOG_LEVEL_MAX,
				p, end);
	}
	return map_log_level(tmp);
}

static std::array<unsigned int, 2> parse_log_class(const char *p, const char *end)
{
	const char *sep = strchr(p, ':');
	unsigned int ll, lc;
	if (sep && sep < end) {
		if (*p == '*' && sep == p + 1) {
			lc = X_LOG_CLASS_MAX;
		} else {
			lc = map_name(x_log_class_names, X_LOG_CLASS_MAX,
					p, sep);
			if (lc == X_LOG_CLASS_MAX) {
				return {X_LOG_CLASS_MAX, X_LOG_LEVEL_MAX};
			}
		}
		ll = parse_log_level(sep + 1, end);
		return { lc, ll };
	} else {
		return { X_LOG_CLASS_MAX, parse_log_level(p, end) };
	}
}

static bool foreach(const char *p, char sep, auto func)
{
	const char *pos;
	for (;;) {
		pos = strchr(p, ',');
		if (!pos) {
			break;
		}

		if (!func(p, pos)) {
			return false;
		}
		p = pos + 1;
	}
	return func(p, p + strlen(p));
}

static bool set_log_level(const char *log_level_param)
{
	unsigned int log_level[X_LOG_CLASS_MAX];
	unsigned int log_level_all = X_LOG_LEVEL_MAX;
	unsigned int i;
	for (i = 0; i < X_LOG_CLASS_MAX; ++i) {
		log_level[i] = X_LOG_LEVEL_MAX;
	}

	foreach(log_level_param, ',',
		[&log_level, &log_level_all](const char *b, const char *e) {
			auto [ lc, ll ] = parse_log_class(b, e);
			if (ll >= X_LOG_LEVEL_MAX) {
				X_LOG(UTILS, ERR, "Invalid log '%.*s'", int(e-b), b);
			} else if (lc == X_LOG_CLASS_MAX) {
				log_level_all = ll;
			} else {
				log_level[lc] = ll;
			}
			return true;
		});

	if (log_level_all != X_LOG_LEVEL_MAX) {
		for (i = 0; i < X_LOG_CLASS_MAX; ++i) {
			if (log_level[i] == X_LOG_LEVEL_MAX) {
				log_level[i] = log_level_all;
			}
		}
	}

	for (i = 0; i < X_LOG_CLASS_MAX; ++i) {
		if (log_level[i] != X_LOG_LEVEL_MAX) {
			x_log_level[i] = log_level[i];
		}
	}
	return true;
}

int x_log_init(const char *log_name, const char *log_level_param, uint64_t filesize)
{
	if (log_level_param && *log_level_param &&
			!set_log_level(log_level_param)) {
		return -1;
	}

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
	x_log(X_LOG_CLASS_UTILS, X_LOG_LEVEL_NOTICE,
			X_LOG_AT_FMT " init log %s logfd=%d filesize=%ld"
#undef X_LOG_CLASS_DECL
#define X_LOG_CLASS_DECL(x) " "#x":%u"
			X_LOG_CLASS_ENUM,
			X_LOG_AT_ARGS,
			log_name, logger->fd, filesize
#undef X_LOG_CLASS_DECL
#define X_LOG_CLASS_DECL(x) , x_log_level[X_LOG_CLASS_##x]
			X_LOG_CLASS_ENUM);
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
				X_LOG(UTILS, ERR, "fail open new log, errno=%d", errno);
			}
			auto new_logger = std::make_shared<x_logger_t>(logger->dirfd,
					logfd, logger->filesize,
					logger->base);
			logger->dirfd = -2;
			g_logger = new_logger;
		}
	}
}
