
#ifndef __crypto__hxx__
#define __crypto__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <openssl/evp.h>
#include <sys/uio.h>

int x_crypto_init();

void x_crypto_fini();

unsigned int x_hmac(void *digest, unsigned int dlen,
		const EVP_MD *md,
		const void *KI, unsigned int KI_len,
		const struct iovec *vector, unsigned int count);

unsigned int x_hmac(void *digest, unsigned int dlen,
		const EVP_MD *md,
		const void *KI, unsigned int KI_len,
		const void *data, size_t size);

void x_md5(uint8_t *digest, const struct iovec *iov, unsigned int count);

int x_rc4_crypt(const void *key, bool enc,
		const void *in, unsigned int inlen,
		void *out);

struct x_cipher_ctx_t
{
	~x_cipher_ctx_t()
	{
		if (ctx) {
			EVP_CIPHER_CTX_free(ctx);
		}
	}

	void cleanup()
	{
		if (ctx) {
			EVP_CIPHER_CTX_free(ctx);
			ctx = nullptr;
		}
	}

	bool init(const EVP_CIPHER *evp, const void *key, unsigned int keylen, bool enc);

	int update(const void *in, unsigned int inlen, void *out)
	{
		int outlen;
		int ret = EVP_CipherUpdate(ctx, (uint8_t *)out, &outlen,
				(const uint8_t *)in, (unsigned int)inlen);
		return (ret == 1) ? outlen : -1;
	}

	bool init_rc4(const void *key, unsigned int keylen, bool enc)
	{
		return init(EVP_rc4(), key, keylen, enc);
	}

	EVP_CIPHER_CTX *ctx = nullptr;
};

#endif /* __crypto__hxx__ */

