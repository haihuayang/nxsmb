
#include "smbd.hxx"
extern "C" {
#include "samba/include/config.h"
#include "samba/lib/crypto/crypto.h"
}
#include <openssl/cmac.h>

void x_smb2_key_derivation(const uint8_t *KI, size_t KI_len,
		const void *Label, size_t Label_len,
		const void *Context, size_t Context_len,
		x_smb2_key_t &key)
{
	struct HMACSHA256Context ctx;
	uint8_t buf[4];
	static const uint8_t zero = 0;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	uint32_t i = 1;
	uint32_t L = 128;

	/*
	 * a simplified version of
	 * "NIST Special Publication 800-108" section 5.1
	 * using hmac-sha256.
	 */
	hmac_sha256_init(KI, KI_len, &ctx);

	RSIVAL(buf, 0, i);
	hmac_sha256_update(buf, sizeof(buf), &ctx);
	hmac_sha256_update((const uint8_t *)Label, Label_len, &ctx);
	hmac_sha256_update(&zero, 1, &ctx);
	hmac_sha256_update((const uint8_t *)Context, Context_len, &ctx);
	RSIVAL(buf, 0, L);
	hmac_sha256_update(buf, sizeof(buf), &ctx);

	hmac_sha256_final(digest, &ctx);

	memcpy(key.data(), digest, 16);
}

/*
 * Compute AES-CMAC digest for the input data (https://tools.ietf.org/html/rfc4493).
 * Param res, output, the digest will be stored and caller must ensure it has AES_CMAC_DIGEST_LENGTH bytes 
 * Param key_data, input, point to address where the AES key is stored.
 * Param key_length, input, the AES key size.
 * Param data1, input, point to the 1st fragment of input data.
 * Param len1, input, the length of the 1st fragment of input data.
 * Param data2, input, point to the 2nd fragment of input data.
 * Param len2, input, the length of the 2nd fragment of input data.
 * Param vector, input, the remain fragments of input data
 * Param count, input, the number of iovec in vector.
 */
static inline void cmac_digest_by_software(const x_smb2_key_t &key,
		void *digest,
		const struct iovec *vector, unsigned int count)
{
	struct aes_cmac_128_context ctx;
	aes_cmac_128_init(&ctx, key.data());

	for (unsigned int i=0; i < count; i++) {
		aes_cmac_128_update(&ctx,
				(const uint8_t *)vector[i].iov_base,
				vector[i].iov_len);
	}
	uint8_t tmp_digest[16];
	aes_cmac_128_final(&ctx, tmp_digest);
	memcpy(digest, tmp_digest, 16);
}
#if 0
static inline void cmac_digest(uint8_t *digest,
		const void *key_data, size_t key_length,
		const struct iovec *vector, int count)
{
	DEBUG(11,("cmac_digest len1=%d, len2=%d, count=%d\n", len1, len2, count));
	if (unlikely(!hardware_acceleration_enabled)) {
		cmac_digest_by_software(res, signing_key.data, signing_key.length,
				data1, len1, data2, len2, vector, count);
	} else {
		cmac_digest_by_ippcp(res, signing_key.data, signing_key.length,
				data1, len1, data2, len2, vector, count);
	}
}
#endif
static inline void hmac_sha256_digest(const x_smb2_key_t &key,
		void *digest,
		const struct iovec *vector, unsigned int count)
{
	struct HMACSHA256Context m;
	uint8_t sha256_digest[SHA256_DIGEST_LENGTH];

	ZERO_STRUCT(m);
	hmac_sha256_init(key.data(), 16, &m);
	for (unsigned int i = 0; i < count; ++i) {
		hmac_sha256_update((const uint8_t *)vector[i].iov_base, vector[i].iov_len, &m);
	}
	hmac_sha256_final(sha256_digest, &m);
	memcpy(digest, sha256_digest, 16);
}

NTSTATUS x_smb2_sign_msg(uint8_t *data, size_t length, uint16_t dialect,
		const x_smb2_key_t &key)
{
#if 0
	uint64_t session_id;
	session_id = BVAL(hdr, SMB2_HDR_SESSION_ID);
	if (session_id == 0) {
		/*
		 * do not sign messages with a zero session_id.
		 * See MS-SMB2 3.2.4.1.1
		 */
		return NT_STATUS_OK;
	}
#endif
	memset(data + SMB2_HDR_SIGNATURE, 0, 16);

	SIVAL(data, SMB2_HDR_FLAGS, IVAL(data, SMB2_HDR_FLAGS) | SMB2_HDR_FLAG_SIGNED);

	struct iovec vector = {
		.iov_base = data,
		.iov_len = length,
	};
	if (dialect >= SMB2_DIALECT_REVISION_224) {
		cmac_digest_by_software(key, data + SMB2_HDR_SIGNATURE, &vector, 1);
	} else {
		hmac_sha256_digest(key, data + SMB2_HDR_SIGNATURE, &vector, 1);
	}
	// DEBUG(5,("signed SMB2 message\n"));

	return NT_STATUS_OK;
}


