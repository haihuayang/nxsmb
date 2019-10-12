
#ifndef __nttime__hxx__
#define __nttime__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <sys/time.h>

#define TIME_FIXUP_CONSTANT 11644473600LL

typedef uint64_t x_nttime_t;
static inline x_nttime_t x_timeval_to_nttime(const struct timeval *tv)
{
	return 10*(tv->tv_usec +
			((TIME_FIXUP_CONSTANT + (uint64_t)tv->tv_sec) * 1000000));
}

static inline x_nttime_t x_nttime_current(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return x_timeval_to_nttime(&tv);
}

#endif /* __nttime__hxx__ */

