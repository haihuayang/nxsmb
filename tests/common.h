
#ifndef __common__h__
#define __common__h__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

template <class T>
void verify(const uint8_t *data, size_t size, bool verify)
{
	T msg;
	idl::x_ndr_off_t ret = idl::x_ndr_pull(msg, data, size);
	assert(ret == size);

	std::vector<uint8_t> out;
	ret = idl::x_ndr_push(msg, out);

	if (verify) {
		assert(ret == size);
		assert(memcmp(out.data(), data, size) == 0);
	}
}


#endif /* __common__h__ */

