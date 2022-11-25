
#include "smb2.hxx"
extern "C" {
#include "samba/include/config.h"
#include "samba/lib/crypto/crypto.h"
}
#include <openssl/evp.h>
#include <openssl/cmac.h>

void x_smb2_key_derivation(const uint8_t *KI, size_t KI_len,
		const x_array_const_t<char> &label,
		const x_array_const_t<char> &context,
		x_smb2_key_t &key)
{
	struct HMACSHA256Context ctx;
	uint32_t buf;
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

#define HMAC_UPDATE(d, s, c) hmac_sha256_update((const uint8_t *)(d), (s), (c))

	buf = X_H2BE32(i);
	HMAC_UPDATE(&buf, sizeof(buf), &ctx);
	HMAC_UPDATE(label.data, label.size, &ctx);
	HMAC_UPDATE(&zero, 1, &ctx);
	HMAC_UPDATE(context.data, context.size, &ctx);
	buf = X_H2BE32(L);
	HMAC_UPDATE(&buf, sizeof(buf), &ctx);

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
	CMAC_CTX *ctx = CMAC_CTX_new();
	CMAC_Init(ctx, key.data(), 16, EVP_aes_128_cbc(), NULL);

	for (unsigned int i=0; i < count; i++) {
		CMAC_Update(ctx, 
				(const uint8_t *)vector[i].iov_base,
				vector[i].iov_len);
	}
	size_t dlen;
	CMAC_Final(ctx, (unsigned char *)digest, &dlen);
	CMAC_CTX_free(ctx);
}

static inline void gmac_digest_by_software(const x_smb2_key_t &key,
		void *digest,
		const struct iovec *vector, unsigned int count)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	X_ASSERT(ctx);
	int rc, unused;
	uint64_t iv[2];
	{
		const x_smb2_header_t *smb2hdr = (const x_smb2_header_t *)vector[0].iov_base;
		iv[0] = smb2hdr->mid;
		uint32_t flags = X_LE2H32(smb2hdr->flags);
		uint64_t high_bits = flags & SMB2_HDR_FLAG_REDIRECT;
		uint16_t opcode = X_LE2H16(smb2hdr->opcode);
		if (opcode == SMB2_OP_CANCEL) {
			high_bits |= SMB2_HDR_FLAG_ASYNC;
		}
		iv[1] = X_H2LE64(high_bits);
	}

	rc = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
	X_ASSERT(rc == 1);

	rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
	X_ASSERT(rc == 1);

	rc = EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), (uint8_t *)iv);
	X_ASSERT(rc == 1);

	for (unsigned int i=0; i < count; i++) {
		rc = EVP_EncryptUpdate(ctx, nullptr, &unused,
				(const uint8_t *)vector[i].iov_base,
				(int)vector[i].iov_len);
	}

	rc = EVP_EncryptFinal_ex(ctx, NULL, &unused);
	X_ASSERT(rc == 1);

	rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, digest);
	X_ASSERT(rc == 1);
#if 0
	printf("Calculated tag:\n  ");
	for(i = 0; i < sizeof(tag); i++)
	{
		printf("%02x", tag[i]);

		if(i == sizeof(tag) - 1) {
			printf("\n");
		}
	}

	printf("Expected tag:\n  ");
	for(i = 0; i < sizeof(exp); i++)
	{
		printf("%02x", exp[i]);

		if(i == sizeof(exp) - 1) {
			printf("\n");
		}
	}
#endif
	EVP_CIPHER_CTX_free(ctx);
}

static inline void hmac_sha256_digest(const x_smb2_key_t &key,
		void *digest,
		const struct iovec *vector, unsigned int count)
{
	struct HMACSHA256Context m;
	uint8_t sha256_digest[SHA256_DIGEST_LENGTH];

	memset(&m, 0, sizeof m);
	hmac_sha256_init(key.data(), 16, &m);
	for (unsigned int i = 0; i < count; ++i) {
		hmac_sha256_update((const uint8_t *)vector[i].iov_base, vector[i].iov_len, &m);
	}
	hmac_sha256_final(sha256_digest, &m);
	memcpy(digest, sha256_digest, 16);
}

static void x_smb2_digest(uint16_t algo,
		const x_smb2_key_t &key,
		x_bufref_t *buflist,
		uint8_t *digest)
{
	static const uint8_t zero_sig[16] = { 0, };
	struct iovec iov[8];
	unsigned int niov = 0;

	X_ASSERT(buflist->length >= SMB2_HDR_BODY);

	iov[niov].iov_base = buflist->get_data();
	iov[niov].iov_len = SMB2_HDR_SIGNATURE;
	++niov;
	iov[niov].iov_base = (void *)zero_sig;
	iov[niov].iov_len = sizeof(zero_sig);
	++niov;
	if (buflist->length > SMB2_HDR_BODY) {
		iov[niov].iov_base = buflist->get_data() + SMB2_HDR_BODY;
		iov[niov].iov_len = buflist->length - SMB2_HDR_BODY;
		++niov;
	}

	for (buflist = buflist->next ; buflist; buflist = buflist->next) {
		iov[niov].iov_base = buflist->get_data();
		iov[niov].iov_len = buflist->length;
		++niov;
	}

	if (algo == X_SMB2_SIGNING_AES128_GMAC) {
		gmac_digest_by_software(key, digest, iov, niov);
	} else if (algo == X_SMB2_SIGNING_AES128_CMAC) {
		cmac_digest_by_software(key, digest, iov, niov);
	} else {
		hmac_sha256_digest(key, digest, iov, niov);
	}
}

bool x_smb2_signing_check(uint16_t algo,
		const x_smb2_key_t *key,
		x_bufref_t *buflist)
{
	uint8_t digest[16];
	x_smb2_digest(algo, *key, buflist, digest);
	
	uint8_t *signature = buflist->get_data() + SMB2_HDR_SIGNATURE;
	return memcmp(digest, signature, 16) == 0;
}

void x_smb2_signing_sign(uint16_t algo,
		const x_smb2_key_t *key,
		x_bufref_t *buflist)
{
	uint8_t *signature = buflist->get_data() + SMB2_HDR_SIGNATURE;
	x_smb2_digest(algo, *key, buflist, signature);
}


