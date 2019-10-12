
#ifndef __asn1_wrap__hxx__
#define __asn1_wrap__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "xdefines.h"
#include <vector>
#include <stdint.h>

#define X_ASN1_METHOD(type_name) \
inline int x_asn1_encode(const type_name &arg, std::vector<uint8_t> &out) \
{ \
	size_t size = length_##type_name(&arg); \
	out.resize(size); \
	size_t consumed; \
	int ret = encode_##type_name(out.data() + size - 1, size, &arg, &consumed); \
	X_ASSERT(consumed == size); \
	return ret; \
} \
 \
inline int x_asn1_decode(type_name &arg, const uint8_t *data, size_t size, size_t *pconsumed) \
{ \
	return decode_##type_name(data, size, &arg, pconsumed); \
} \
inline void x_asn1_free(type_name &arg) \
{ \
	free_##type_name(&arg); \
}

#define X_ASN1_ALLOC(x) do { (x) = decltype(x)(calloc(1, sizeof *(x))); } while (0)

#endif /* __asn1_wrap__hxx__ */

