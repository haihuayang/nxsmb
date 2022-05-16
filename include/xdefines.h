
#ifndef __include__xdefines__h__
#define __include__xdefines__h__

#include <errno.h>

/* these macros gain us a few percent of speed on gcc */
#if (__GNUC__ >= 3)
/* the strange !! is to ensure that __builtin_expect() takes either 0 or 1
   as its first argument */
#define x_likely(x)   __builtin_expect(!!(x), 1)
#define x_unlikely(x) __builtin_expect(!!(x), 0)
#else
#define x_likely(x) (x)
#define x_unlikely(x) (x)
#endif

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#error "Not supported yet"
#endif

#define X_PANIC(fmt, ...) do { \
	x_panic("at %s:%d %s: " fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
} while (0)

#define X_ASSERT(cond) do { \
	if (x_likely(cond)) { \
	} else { \
		X_PANIC("!(%s)", #cond); \
	} \
} while (0)

#ifdef __X_DEVELOPER__
#define X_DEVEL_ASSERT X_ASSERT
#else
#define X_DEVEL_ASSERT(...) 
#endif

#define X_TODO_ASSERT(cond) do { \
	if (x_likely(cond)) { \
	} else { \
		X_PANIC("TODO !(%s)", #cond); \
	} \
} while (0)

#define X_TODO X_PANIC("TODO")

#define X_ASSERT_SYSCALL(call) do { \
	int __err = call; \
	if (x_likely(__err == 0)) { \
	} else { \
		X_PANIC("%s = %d,%d", #call, __err, errno); \
	} \
} while (0)

void x_panic(const char *fmt, ...);

#define X_DBG(fmt, ...) do { \
	x_dbg("at %s:%d %s: " fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
} while (0)

#define X_NODBG(...) do { } while (0)

void x_dbg(const char *fmt, ...);

#define X_LOG_ENUM \
	X_LOG_DECL(ERR) \
	X_LOG_DECL(WARN) \
	X_LOG_DECL(NOTICE) \
	X_LOG_DECL(CONN) \
	X_LOG_DECL(OP) \
	X_LOG_DECL(DBG) \
	X_LOG_DECL(VERB) \

enum {
#define X_LOG_DECL(x) X_LOG_LEVEL_##x,
	X_LOG_ENUM
#undef X_LOG_DECL
	X_LOG_LEVEL_MAX
};

extern int x_loglevel;
void x_log(int level, const char *fmt, ...);
int x_log_init(const char *log_level, const char *log_name);

#define X_LOG_L(level, fmt, ...) do { \
	if ((level) <= x_loglevel) { \
		x_log((level), "[%s:%d:%s] " fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
	} \
} while (0)

#define X_LOG_ERR(...) X_LOG_L(X_LOG_LEVEL_ERR, __VA_ARGS__)
#define X_LOG_WARN(...) X_LOG_L(X_LOG_LEVEL_WARN, __VA_ARGS__)
#define X_LOG_NOTICE(...) X_LOG_L(X_LOG_LEVEL_NOTICE, __VA_ARGS__)
#define X_LOG_CONN(...) X_LOG_L(X_LOG_LEVEL_CONN, __VA_ARGS__)
#define X_LOG_OP(...) X_LOG_L(X_LOG_LEVEL_OP, __VA_ARGS__)
#define X_LOG_DBG(...) X_LOG_L(X_LOG_LEVEL_DBG, __VA_ARGS__)
#define X_LOG_VERB(...) X_LOG_L(X_LOG_LEVEL_VERB, __VA_ARGS__)


/* these are used to mark symbols as local to a shared lib, or
 * publicly available via the shared lib API */
#ifndef _PUBLIC_
#ifdef HAVE_VISIBILITY_ATTR
#define _PUBLIC_ __attribute__((visibility("default")))
#else
#define _PUBLIC_
#endif
#endif

#define XSTR(s) #s
#define XSTR2(s) XSTR(s)

#ifndef __location__
#define __TALLOC_STRING_LINE1__(s)    #s
#define __TALLOC_STRING_LINE2__(s)   __TALLOC_STRING_LINE1__(s)
#define __TALLOC_STRING_LINE3__  __TALLOC_STRING_LINE2__(__LINE__)
#define __location__ __FILE__ ":" XSTR2(__LINE__)
#endif

#define X_NSEC_PER_SEC 1000000000ul
#define X_SEC_TO_NSEC(s) (X_NSEC_PER_SEC * s)

#define PROJECT_NAME XSTR2(PROJECT)

#define X_ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#define X_MALLOC malloc

#define X_IPQUAD_BE(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#ifdef __cplusplus
extern "C" {
#endif

extern const char __version__[];
extern const char __build__[];

#ifdef __cplusplus
}
#endif

#endif /* __include__xdefines__h__ */

