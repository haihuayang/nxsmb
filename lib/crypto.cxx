
#include "include/crypto.hxx"
#include "include/utils.hxx"
#include <openssl/hmac.h>
#include <openssl/md5.h>
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

void x_md5(uint8_t *digest, const struct iovec *iov, unsigned int count)
{
	MD5_CTX ctx;
	MD5_Init(&ctx);
	for (unsigned int i = 0; i < count; ++i) {
		MD5_Update(&ctx, (const uint8_t *)iov[i].iov_base, iov[i].iov_len);
	}
	MD5_Final(digest, &ctx);
}

int x_rc4_crypt(const void *key, bool enc,
		const void *in, unsigned int inlen,
		void *out)
{
	x_cipher_ctx_t ctx;
	auto ret = ctx.init_rc4(key, 16, enc);
	X_ASSERT(ret);
	int outlen = ctx.update(in, inlen, out);
	return outlen;
}

bool x_cipher_ctx_t::init(const EVP_CIPHER *evp, const void *key, unsigned int keylen, bool enc)
{
	if (!evp) {
		return false;
	}
	X_ASSERT(!ctx);
	ctx = EVP_CIPHER_CTX_new();
	EVP_CipherInit(ctx, evp, (const uint8_t *)key, nullptr, enc ? 1 : 0);
	return true;
}


#if OPENSSL_VERSION_NUMBER >= 0x30000000L

#include <openssl/provider.h>

static OSSL_PROVIDER *g_legacy_provider = nullptr;
static OSSL_PROVIDER *g_fips_provider = nullptr;
static OSSL_PROVIDER *g_default_provider =nullptr;
/*
 *  Initialize OpenSSL 3.x providers for FIPS and legacy algorithm support
 *  This replaces the deprecated FIPS_mode_set(0) call
 */
static int init_openssl_providers()
{
	X_LOG(UTILS, NOTICE, "Initializing OpenSSL 3.x providers for FIPS + legacy support...");

	// 1. Load default provider (always required)
	g_default_provider = OSSL_PROVIDER_load(NULL, "default");
	if (!g_default_provider) {
		X_LOG(UTILS, ERR, "Failed to load default provider");
		return -1;
	}
	X_LOG(UTILS, NOTICE, "Default provider loaded");

	// 2. Load legacy provider (for RC4 and other deprecated algorithms)
	g_legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
	if (!g_legacy_provider) {
		X_LOG(UTILS, ERR, "Failed to load legacy provider - RC4 will not work");
		return -1;
		//TODO: If RC4 is not required, alternative handling may be necessary.
	} else {
		X_LOG(UTILS, NOTICE, "Legacy provider loaded successfully");
	}

	// 3. Load FIPS provider (if available and needed) 
	g_fips_provider = OSSL_PROVIDER_load(NULL, "fips");
	if (!g_fips_provider) {
		X_LOG(UTILS, ERR, "Failed to load FIPS provider - initialization failed");
        return -1;
	} else {
		X_LOG(UTILS, NOTICE, "FIPS provider loaded successfully");
	}

	// 4. Verify RC4 availability
	const EVP_CIPHER *rc4 = EVP_rc4();
	X_ASSERT(rc4);
	X_LOG(UTILS, NOTICE, "RC4 algorithm is available: %s", EVP_CIPHER_name(rc4));


	return 0;
}
#endif

int x_crypto_init()
{
	OPENSSL_init();
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	return init_openssl_providers();
#else
	FIPS_mode_set(0);
	return 0;
#endif
}

void x_crypto_fini()
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (g_legacy_provider) {
		OSSL_PROVIDER_unload(g_legacy_provider);
		g_legacy_provider = nullptr;
		X_LOG(UTILS, NOTICE, "Legacy provider unloaded");
	}

	if (g_fips_provider) {
		OSSL_PROVIDER_unload(g_fips_provider);
		g_fips_provider = nullptr;
		X_LOG(UTILS, NOTICE, "FIPS provider unloaded");
	}
	if (g_default_provider) {
		OSSL_PROVIDER_unload(g_default_provider);
		g_default_provider = nullptr;
		X_LOG(UTILS, NOTICE, "Default provider unloaded");
	}
#endif
}
