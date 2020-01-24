
#ifndef __common__h__
#define __common__h__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#include <iostream>

template <class T>
void verify(const uint8_t *data, size_t size, bool verify)
{
	T msg;
	idl::x_ndr_off_t ret = idl::x_ndr_pull(msg, data, size, 0);
	assert(ret > 0);
	idl::x_ndr_ostr(msg, std::cout, 8, 3);

	assert((size_t)ret == size);

	std::vector<uint8_t> out;
	ret = idl::x_ndr_push(msg, out, 0);

	if (verify) {
		assert(ret > 0);
		assert((size_t)ret == size);
		assert(memcmp(out.data(), data, size) == 0);
	}
}


#endif /* __common__h__ */

