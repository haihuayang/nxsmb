
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
#define X_SEC_TO_NSEC(s) (X_NSEC_PER_SEC * (s))
#define X_MSEC_TO_NSEC(ms) (1000000ul * (ms))

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

