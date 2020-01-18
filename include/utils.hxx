
#ifndef __utils__hxx__
#define __utils__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <string>

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

