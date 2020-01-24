
#ifndef __misc__hxx__
#define __misc__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/utils.hxx"
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

static inline bool x_check_range(uint32_t offset, uint32_t length,
		uint32_t min_offset, uint32_t max_offset)
{
	if (length == 0) {
		return true;
	}
	if (offset < min_offset) {
		return false;
	}
	uint32_t end = offset + length;
	if (end < offset) {
		return false;
	}
	if (end > max_offset) {
		return false;
	}
	return true;
}

void x_smbd_report_nt_status(NTSTATUS status, unsigned int line, const char *file);

#define RETURN_ERR_NT_STATUS(status) do { \
	x_smbd_report_nt_status((status), __LINE__, __FILE__); \
	return (status); \
} while(0)


#endif /* __misc__hxx__ */

