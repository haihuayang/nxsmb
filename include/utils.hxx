
#ifndef __utils__hxx__
#define __utils__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <string>
#include <array>
#include <cstring>
#include <sstream>

/* unit is nsec */

typedef int64_t x_tick_diff_t;

struct x_tick_t
{
	bool operator>(x_tick_t other) const {
		return int64_t(val - other.val) > 0;
	}
	x_tick_diff_t operator-(x_tick_t other) const {
		return int64_t(val - other.val);
	}
	x_tick_t operator+(x_tick_diff_t diff) const {
		return x_tick_t{val + diff};
	}
	x_tick_t operator-(x_tick_diff_t diff) const {
		return x_tick_t{val - diff};
	}
	uint64_t val;
};

static constexpr x_tick_diff_t x_tick_diff_max = INT64_MAX / 2;

static inline x_tick_diff_t x_tick_diff_from_ms(int ms)
{
	return {ms * 1000000l};
}

static inline x_tick_t x_tick_from_timespec(const struct timespec &ts)
{
	return x_tick_t{ts.tv_sec * 1000000000ul + ts.tv_nsec};
}

static inline x_tick_t x_tick_now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return x_tick_from_timespec(ts);
	// auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now());
}

template <typename T>
struct x_auto_ref_t
{
	explicit x_auto_ref_t(T *t = nullptr) : val{t} { }
	x_auto_ref_t(const x_auto_ref_t<T> &o) {
		val = o.val;
		val->incref();
	}
	x_auto_ref_t(x_auto_ref_t<T> &&o) {
		val = o.val;
		o.val = nullptr;
	}

	x_auto_ref_t<T> &operator=(const x_auto_ref_t<T> &o) = delete;
	x_auto_ref_t<T> &operator=(x_auto_ref_t<T> &&o) {
		if (val != o.val && val) {
			val->decref();
		}
		val = o.val;
		o.val = nullptr;
		return *this;
	}

	void set(T *t) {
		if (val == t) {
			return;
		}
		if (val) {
			val->decref();
		}
		val = t;
	}

	operator T*() const {
		return val;
	}
	T *operator->() const {
		return val;
	}
	~x_auto_ref_t() {
		if (val) {
			val->decref();
		}
	}
	T *val;
};

static inline size_t x_next_2_power(size_t num)
{
	size_t ret = 1;
	while (ret < num) {
		ret <<= 1;
	}
	return ret;
}

static inline const char16_t *x_skip_sep(const char16_t *in, const char16_t *end, char16_t sep)
{
	for ( ; in < end; ++in) {
		if (*in != sep) {
			break;
		}
	}
	return in;
}

static inline const char16_t *x_rskip_sep(const char16_t *in, const char16_t *end, char16_t sep)
{
	for ( ; in > end; --in) {
		if (in[-1] != sep) {
			break;
		}
	}
	return in;
}

static inline const char16_t *x_next_sep(const char16_t *in, const char16_t *end, char16_t sep)
{
	for ( ; in < end; ++in) {
		if (*in == sep) {
			break;
		}
	}
	return in;
}

std::string x_hex_dump(const void *data, size_t length, const char *prefix);

template <class T>
std::string x_tostr(const T &v)
{
	std::ostringstream os;
	os << v;
	return os.str();
}

void x_rand_bytes(void *buf, size_t size);

#define X_DEFINE_ENUM_FLAG_OPERATORS(T) \
inline T operator~ (T a) { return static_cast<T>( ~static_cast<std::underlying_type<T>::type>(a) ); } \
inline T operator| (T a, T b) { return static_cast<T>( static_cast<std::underlying_type<T>::type>(a) | static_cast<std::underlying_type<T>::type>(b) ); } \
inline T operator& (T a, T b) { return static_cast<T>( static_cast<std::underlying_type<T>::type>(a) & static_cast<std::underlying_type<T>::type>(b) ); } \
inline T operator^ (T a, T b) { return static_cast<T>( static_cast<std::underlying_type<T>::type>(a) ^ static_cast<std::underlying_type<T>::type>(b) ); } \
inline T& operator|= (T& a, T b) { return reinterpret_cast<T&>( reinterpret_cast<std::underlying_type<T>::type&>(a) |= static_cast<std::underlying_type<T>::type>(b) ); } \
inline T& operator&= (T& a, T b) { return reinterpret_cast<T&>( reinterpret_cast<std::underlying_type<T>::type&>(a) &= static_cast<std::underlying_type<T>::type>(b) ); } \
inline T& operator^= (T& a, T b) { return reinterpret_cast<T&>( reinterpret_cast<std::underlying_type<T>::type&>(a) ^= static_cast<std::underlying_type<T>::type>(b) ); }


#endif /* __utils__hxx__ */

