
#ifndef __nttime__hxx__
#define __nttime__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "librpc/ndr_smb.hxx"

static inline idl::NTTIME x_unix_to_nttime(time_t t)
{
	if (t == (time_t)-1) {
		return idl::NTTIME{(uint64_t)-1};
	}
	if (t == 0) {
		return idl::NTTIME{0};
	}
	if (t == (time_t)0x7fffffff) {
		return idl::NTTIME{0x7fffffffffffffffLL};
	}
	uint64_t v = t;
	return idl::NTTIME{(v + idl::NTTIME::TIME_FIXUP_CONSTANT) * 1000 * 1000 * 10};
}

static inline idl::NTTIME x_tick_to_nttime(x_tick_t tick)
{
	return idl::NTTIME{(tick / 100) + idl::NTTIME::TIME_FIXUP_CONSTANT * 1000 * 1000 * 10};
}

static inline idl::NTTIME x_timespec_to_nttime(const struct timespec &ts)
{
	uint64_t val = ts.tv_sec + idl::NTTIME::TIME_FIXUP_CONSTANT;
	val *= 1000 * 1000 * 10;
	val += ts.tv_nsec / 100;
	return idl::NTTIME{val};
}

static inline struct timespec x_nttime_to_timespec(idl::NTTIME nt)
{
	struct timespec ts;
	ts.tv_nsec = (nt.val % (1000 * 1000 * 10)) * 100;
	ts.tv_sec = nt.val / (1000 * 1000 * 10);
	ts.tv_sec -= idl::NTTIME::TIME_FIXUP_CONSTANT;
	return ts;
}


#endif /* __nttime__hxx__ */

