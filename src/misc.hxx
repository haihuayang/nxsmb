
#ifndef __misc__hxx__
#define __misc__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "include/utils.hxx"
#include "include/librpc/ndr_smb.hxx"

template <class T>
struct x_array_const_t
{
	template <std::size_t N>
	constexpr x_array_const_t(const T(&array)[N]) : data(array), size(N) { }
	template <std::size_t N>
	constexpr x_array_const_t(const std::array<T, N> &array) : data(array.data()), size(N) { }
	const T *data;
	size_t size;
};

template <class T>
std::string idl_tostring(const T &obj)
{
	std::ostringstream os;
	idl::x_ndr_output(obj, os, 8, 3);
	std::string ret = os.str();
	return ret;
}

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

template <typename T>
static inline bool x_check_range(T offset, T length,
		T min_offset, T max_offset)
{
	if (length == 0) {
		return true;
	}
	if (offset < min_offset) {
		return false;
	}
	T end = offset + length;
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

NTSTATUS x_map_nt_error_from_unix(int unix_error);
NTSTATUS x_map_nt_error_from_ndr_err(idl::x_ndr_err_code_t ndr_err);


struct x_fnmatch_t;
bool x_fnmatch_match(const x_fnmatch_t &fnmatch, const char *name);
x_fnmatch_t *x_fnmatch_create(const std::u16string &pattern, bool icase);
void x_fnmatch_destroy(x_fnmatch_t *fnmatch);

#endif /* __misc__hxx__ */

