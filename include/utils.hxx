
#ifndef __utils__hxx__
#define __utils__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <string>

/* unit is nsec */
typedef uint64_t x_tick_t;

static inline x_tick_t x_tick_now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	unsigned long ns = ts.tv_sec;
	return ns * 1000000000 + ts.tv_nsec;
	// auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now());
}

static inline x_tick_t x_tick_add(x_tick_t t, long delta)
{
	return t + delta;
}

static inline long x_tick_cmp(x_tick_t t1, x_tick_t t2)
{
	return t1 - t2;
}

template <typename T>
struct x_auto_ref_t
{
	x_auto_ref_t(T *t = nullptr) : val{t} { }
	x_auto_ref_t(const x_auto_ref_t<T> &o) = delete;
	x_auto_ref_t(x_auto_ref_t<T> &&o) = delete;
	x_auto_ref_t<T> &operator=(const x_auto_ref_t<T> &o) = delete;
	x_auto_ref_t<T> &operator=(x_auto_ref_t<T> &&o) = delete;

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



#endif /* __utils__hxx__ */

