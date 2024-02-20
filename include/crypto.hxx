
#ifndef __crypto__hxx__
#define __crypto__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <openssl/evp.h>
#include <sys/uio.h>

unsigned int x_hmac(void *digest, unsigned int dlen,
		const EVP_MD *md,
		const void *KI, unsigned int KI_len,
		const struct iovec *vector, unsigned int count);

unsigned int x_hmac(void *digest, unsigned int dlen,
		const EVP_MD *md,
		const void *KI, unsigned int KI_len,
		const void *data, size_t size);

#endif /* __crypto__hxx__ */

