
#ifndef __misc__hxx__
#define __misc__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/librpc/ndr_nxsmb.hxx"

template <class T>
struct x_array_const_t
{
	template <std::size_t N>
	constexpr x_array_const_t(const T(&array)[N]) : data(array), size(N) { }
	const T *data;
	size_t size;
};
#if 0
template <class T, std::size_t N>
constexpr x_array_const_t<T> x_array_const(const T(&array)[N]){
	return x_array_const_t<T>{array, N};
}
#endif

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

#endif /* __misc__hxx__ */

