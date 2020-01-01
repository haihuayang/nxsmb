
#ifndef __utils__hxx__
#define __utils__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <string>

std::u16string x_convert_utf8_to_utf16(const std::string &src);
std::string x_convert_utf16_to_utf8(const std::u16string &src);

template <typename T>
struct x_ref_t
{
	x_ref_t(T *t) :t(t) { X_ASSERT(t); }
	x_ref_t(x_ref_t &&other) {
		t = other.t;
		other.t = nullptr;
	}
	x_ref_t(const x_ref_t &) = delete;
	x_ref_t &operator=(const x_ref_t &) = delete;
	operator T*() const {
		return t;
	}
	~x_ref_t() {
		if (t) {
			t->decref();
		}
	}
	T *get() {
		return t;
	}
	T * const t;
};



#endif /* __utils__hxx__ */

