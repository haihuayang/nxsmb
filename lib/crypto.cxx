
#include "include/crypto.hxx"
#include <openssl/hmac.h>
#include <string.h>

static inline unsigned int hmac_digest(HMAC_CTX *ctx,
		void *digest, unsigned int dlen,
		const EVP_MD *md,
		const void *KI, unsigned int KI_len,
		const struct iovec *vector, unsigned int count)
{
	HMAC_Init_ex(ctx, KI, KI_len, md, nullptr);

	for (unsigned int i = 0; i < count; ++i) {
		HMAC_Update(ctx, (const uint8_t *)vector[i].iov_base, vector[i].iov_len);
	}
	uint8_t buf[HMAC_size(ctx)];
	unsigned int len;
	HMAC_Final(ctx, buf, &len);
	if (len > dlen) {
		len = dlen;
	}
	memcpy(digest, buf, len);
	return len;
}

unsigned int x_hmac(void *digest, unsigned int dlen,
		const EVP_MD *md,
		const void *KI, unsigned int KI_len,
		const struct iovec *vector, unsigned int count)
{
	unsigned int ret;
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	HMAC_CTX *ctx = HMAC_CTX_new();
	ret = hmac_digest(ctx, digest, dlen, md, KI, KI_len, vector, count);
	HMAC_CTX_free(ctx);
#else
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
	ret = hmac_digest(&ctx, digest, dlen, md, KI, KI_len, vector, count);
	HMAC_CTX_cleanup(&ctx);
#endif
	return ret;
}

unsigned int x_hmac(void *digest, unsigned int dlen,
		const EVP_MD *md,
		const void *KI, unsigned int KI_len,
		const void *data, size_t size)
{
	struct iovec vec = { (void *)data, size };
	return x_hmac(digest, dlen, md, KI, KI_len, &vec, 1);
}
