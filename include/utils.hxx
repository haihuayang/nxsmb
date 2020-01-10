
#ifndef __utils__hxx__
#define __utils__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <string>

template <typename T>
struct x_ref_t
{
	x_ref_t() : val{nullptr} { }
	x_ref_t(T *t) : val{t} { val->incref(); }
	x_ref_t(const x_ref_t<T> &o) = delete;
	x_ref_t(x_ref_t<T> &&o) = delete;
	x_ref_t<T> &operator=(const x_ref_t<T> &o) = delete;
	x_ref_t<T> &operator=(x_ref_t<T> &&o) = delete;
	operator T*() const {
		return val;
	}
	T *operator->() const {
		return val;
	}
	~x_ref_t() {
		if (val) {
			val->decref();
		}
	}
	T *val;
};



#endif /* __utils__hxx__ */

