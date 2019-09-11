
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

#define X_PANIC(fmt, ...) do { \
	x_panic("at %s:%d %s: " fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
} while (0)

#define X_ASSERT(cond) do { \
	if (x_likely(cond)) { \
	} else { \
		X_PANIC("!(%s)", #cond); \
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

#define PROJECT_NAME XSTR2(PROJECT)

#ifdef __cplusplus
extern "C" {
#endif

extern const char __version__[];
extern const char __build__[];

#ifdef __cplusplus
}
#endif

#endif /* __include__xdefines__h__ */

