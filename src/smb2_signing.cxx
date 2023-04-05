
#include "smb2.hxx"
#include "include/crypto.hxx"
#include <openssl/evp.h>
#include <openssl/cmac.h>
#include <openssl/sha.h>

void x_smb2_key_derivation(const uint8_t *KI, size_t KI_len,
		const x_array_const_t<char> &label,
		const x_array_const_t<char> &context,
		uint8_t *key, uint32_t key_len)
{
	uint32_t buf1, buf2;
	static const uint8_t zero = 0;
	uint32_t i = 1;
	uint32_t L = key_len * 8;

	buf1 = X_H2BE32(i);
	buf2 = X_H2BE32(L);

	struct iovec iov[] = {
		{ &buf1, sizeof(buf1), },
		{ (void *)label.data, label.size, },
		{ (void *)&zero, 1, },
		{ (void *)context.data, context.size, },
		{ &buf2, sizeof(buf2), },
	};

	unsigned ret = x_hmac(key, key_len, EVP_sha256(),
			KI, x_convert_assert<unsigned int>(KI_len), iov, 5);
	X_ASSERT(ret == key_len);
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
static inline void cmac_aes_128_digest(const x_smb2_key_t &key,
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

static inline void gmac_aes_128_digest(const x_smb2_key_t &key,
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
		uint64_t high_bits = flags & X_SMB2_HDR_FLAG_REDIRECT;
		uint16_t opcode = X_LE2H16(smb2hdr->opcode);
		if (opcode == X_SMB2_OP_CANCEL) {
			high_bits |= X_SMB2_HDR_FLAG_ASYNC;
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
	unsigned int dlen = x_hmac(digest, 16, EVP_sha256(),
			key.data(), 16,
			vector, count);
	X_ASSERT(dlen == 16);
}

static void x_smb2_digest(uint16_t algo,
		const x_smb2_key_t &key,
		x_bufref_t *buflist,
		uint8_t *digest)
{
	static const uint8_t zero_sig[16] = { 0, };
	struct iovec iov[8];
	unsigned int niov = 0;

	X_ASSERT(buflist->length >= sizeof(x_smb2_header_t));

	iov[niov].iov_base = buflist->get_data();
	iov[niov].iov_len = offsetof(x_smb2_header_t, signature);
	++niov;
	iov[niov].iov_base = (void *)zero_sig;
	iov[niov].iov_len = sizeof(zero_sig);
	++niov;
	if (buflist->length > sizeof(x_smb2_header_t)) {
		iov[niov].iov_base = buflist->get_data() + sizeof(x_smb2_header_t);
		iov[niov].iov_len = buflist->length - sizeof(x_smb2_header_t);
		++niov;
	}

	for (buflist = buflist->next ; buflist; buflist = buflist->next) {
		iov[niov].iov_base = buflist->get_data();
		iov[niov].iov_len = buflist->length;
		++niov;
	}

	if (algo == X_SMB2_SIGNING_AES128_GMAC) {
		gmac_aes_128_digest(key, digest, iov, niov);
	} else if (algo == X_SMB2_SIGNING_AES128_CMAC) {
		cmac_aes_128_digest(key, digest, iov, niov);
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
	
	uint8_t *signature = buflist->get_data() + offsetof(x_smb2_header_t, signature);
	return memcmp(digest, signature, 16) == 0;
}

void x_smb2_signing_sign(uint16_t algo,
		const x_smb2_key_t *key,
		x_bufref_t *buflist)
{
	uint8_t *signature = buflist->get_data() + offsetof(x_smb2_header_t, signature);
	x_smb2_digest(algo, *key, buflist, signature);
}

static inline int aes_ccm_signing_decrypt(const EVP_CIPHER *evp_cipher,
		const x_smb2_cryption_key_t &key,
		const void *signature,
		const void *aad, int aad_len,
		const void *cdata, int cdata_len,
		void *pdata)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	X_ASSERT(ctx);

	int rc, out_len;
	int pdata_len = -1;

	rc = EVP_DecryptInit_ex(ctx, evp_cipher, NULL, NULL, NULL);
	X_ASSERT(rc == 1);

	rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 11, NULL);
	X_ASSERT(rc == 1);

	rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, (void *)signature);
	X_ASSERT(rc == 1);

	rc = EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), (uint8_t *)aad);
	X_ASSERT(rc == 1);

	rc = EVP_DecryptUpdate(ctx, nullptr, &out_len,
			nullptr, cdata_len);
	X_ASSERT(rc == 1);

	rc = EVP_DecryptUpdate(ctx, nullptr, &out_len,
			(const uint8_t *)aad, aad_len);
	X_ASSERT(rc == 1);

	rc = EVP_DecryptUpdate(ctx, (uint8_t *)pdata, &out_len,
			(const uint8_t *)cdata, cdata_len);
	X_ASSERT(rc == 1);

	pdata_len = out_len;

	rc = EVP_DecryptFinal_ex(ctx, (uint8_t *)pdata + pdata_len, &out_len);

	EVP_CIPHER_CTX_free(ctx);
	if (!rc) {
		return -1;
	}

	return pdata_len + out_len;
}

static inline int aes_ccm_signing_encrypt(const EVP_CIPHER *evp_cipher,
		const x_smb2_cryption_key_t &key,
		void *signature,
		const void *aad, int aad_len,
		x_bufref_t *buflist, int length,
		void *cdata)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	X_ASSERT(ctx);

	int rc, out_len;

	rc = EVP_EncryptInit_ex(ctx, evp_cipher, NULL, NULL, NULL);
	X_ASSERT(rc == 1);

	rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 11, NULL);
	X_ASSERT(rc == 1);

	rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, nullptr);
	X_ASSERT(rc == 1);

	rc = EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), (uint8_t *)aad);
	X_ASSERT(rc == 1);

	rc = EVP_EncryptUpdate(ctx, nullptr, &out_len,
			NULL, length);
	X_ASSERT(rc == 1);

	rc = EVP_EncryptUpdate(ctx, nullptr, &out_len,
			(const uint8_t *)aad, aad_len);
	X_ASSERT(rc == 1);

	uint8_t *cptr = (uint8_t *)cdata;
	/* looks like it has to encrypt all data once, so copy the
	 * fragments into one and encrypt
	 */
	if (buflist->next) {
		uint8_t *whole_data = (uint8_t *)malloc(length);
		uint8_t *p = whole_data;
		for (buflist = buflist; buflist; buflist = buflist->next) {
			memcpy(p, buflist->get_data(), buflist->length);
			p += buflist->length;
		}
		rc = EVP_EncryptUpdate(ctx, cptr, &out_len,
				whole_data, length);
		free(whole_data);
	} else {
		rc = EVP_EncryptUpdate(ctx, cptr, &out_len,
				buflist->get_data(), buflist->length);
	}
	X_ASSERT(rc == 1);
	cptr += out_len;

	rc = EVP_EncryptFinal_ex(ctx, cptr, &out_len);
	X_ASSERT(rc == 1);
	cptr += out_len;

	rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 16, (void *)signature);
	X_ASSERT(rc == 1);

	return x_convert<int>(cptr - (uint8_t *)cdata);
}

static inline int aes_gcm_signing_decrypt(const EVP_CIPHER *evp_cipher,
		const x_smb2_cryption_key_t &key,
		const void *signature,
		const void *aad, int aad_len,
		const void *cdata, int cdata_len,
		void *pdata)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	X_ASSERT(ctx);

	int rc, out_len;
	int pdata_len = -1;

	rc = EVP_DecryptInit_ex(ctx, evp_cipher, NULL, NULL, NULL);
	X_ASSERT(rc == 1);

	rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
	X_ASSERT(rc == 1);

	rc = EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), (uint8_t *)aad);
	X_ASSERT(rc == 1);

	rc = EVP_DecryptUpdate(ctx, nullptr, &out_len,
			(const uint8_t *)aad, aad_len);
	X_ASSERT(rc == 1);

	rc = EVP_DecryptUpdate(ctx, (uint8_t *)pdata, &out_len,
			(const uint8_t *)cdata, cdata_len);
	X_ASSERT(rc == 1);

	pdata_len = out_len;

	rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)signature);
	X_ASSERT(rc == 1);

	rc = EVP_DecryptFinal_ex(ctx, (uint8_t *)pdata + pdata_len, &out_len);

	EVP_CIPHER_CTX_free(ctx);
	if (!rc) {
		return -1;
	}

	return pdata_len + out_len;
}

static inline int aes_gcm_signing_encrypt(const EVP_CIPHER *evp_cipher,
		const x_smb2_cryption_key_t &key,
		void *signature,
		const void *aad, int aad_len,
		x_bufref_t *buflist,
		void *cdata)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	X_ASSERT(ctx);

	int rc, out_len;

	rc = EVP_EncryptInit_ex(ctx, evp_cipher, NULL, NULL, NULL);
	X_ASSERT(rc == 1);

	rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
	X_ASSERT(rc == 1);

	rc = EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), (uint8_t *)aad);
	X_ASSERT(rc == 1);

	rc = EVP_EncryptUpdate(ctx, nullptr, &out_len,
			(const uint8_t *)aad, aad_len);
	X_ASSERT(rc == 1);

	uint8_t *cptr = (uint8_t *)cdata;
	for (buflist = buflist; buflist; buflist = buflist->next) {
		rc = EVP_EncryptUpdate(ctx, cptr, &out_len,
				buflist->get_data(), buflist->length);
		X_ASSERT(rc == 1);
		cptr += out_len;
	}

	rc = EVP_EncryptFinal_ex(ctx, cptr, &out_len);
	X_ASSERT(rc == 1);
	cptr += out_len;

	rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, (void *)signature);
	X_ASSERT(rc == 1);

	return x_convert<int>(cptr - (uint8_t *)cdata);
}

int x_smb2_signing_decrypt(uint16_t algo,
		const x_smb2_cryption_key_t *key,
		const x_smb2_tf_header_t *tfhdr,
		const void *cdata, size_t cdata_len,
		void *pdata)
{
	int a_total = x_convert<int>(sizeof(x_smb2_tf_header_t) -
			offsetof(x_smb2_tf_header_t, nonce));

	if (algo == X_SMB2_ENCRYPTION_AES128_GCM) {
		return aes_gcm_signing_decrypt(EVP_aes_128_gcm(),
				*key, tfhdr->signature,
				tfhdr->nonce, a_total,
				cdata, x_convert<int>(cdata_len),
				pdata);
	} else if (algo == X_SMB2_ENCRYPTION_AES256_GCM) {
		return aes_gcm_signing_decrypt(EVP_aes_256_gcm(),
				*key, tfhdr->signature,
				tfhdr->nonce, a_total,
				cdata, x_convert<int>(cdata_len),
				pdata);
	} else if (algo == X_SMB2_ENCRYPTION_AES128_CCM) {
		return aes_ccm_signing_decrypt(EVP_aes_128_ccm(),
				*key, tfhdr->signature,
				tfhdr->nonce, a_total,
				cdata, x_convert<int>(cdata_len),
				pdata);
	} else if (algo == X_SMB2_ENCRYPTION_AES256_CCM) {
		return aes_ccm_signing_decrypt(EVP_aes_256_ccm(),
				*key, tfhdr->signature,
				tfhdr->nonce, a_total,
				cdata, x_convert<int>(cdata_len),
				pdata);
	}
	return -1;
}

int x_smb2_signing_encrypt(uint16_t algo,
		const x_smb2_cryption_key_t *key,
		x_smb2_tf_header_t *tfhdr,
		x_bufref_t *buflist,
		size_t length)
{
	int a_total = x_convert<int>(sizeof(x_smb2_tf_header_t) -
			offsetof(x_smb2_tf_header_t, nonce));

	if (algo == X_SMB2_ENCRYPTION_AES128_GCM) {
		return aes_gcm_signing_encrypt(EVP_aes_128_gcm(),
				*key, tfhdr->signature,
				tfhdr->nonce, a_total,
				buflist,
				tfhdr + 1);
	} else if (algo == X_SMB2_ENCRYPTION_AES256_GCM) {
		return aes_gcm_signing_encrypt(EVP_aes_256_gcm(),
				*key, tfhdr->signature,
				tfhdr->nonce, a_total,
				buflist,
				tfhdr + 1);
	} else if (algo == X_SMB2_ENCRYPTION_AES128_CCM) {
		return aes_ccm_signing_encrypt(EVP_aes_128_ccm(),
				*key, tfhdr->signature,
				tfhdr->nonce, a_total,
				buflist, x_convert<int>(length),
				tfhdr + 1);
	} else if (algo == X_SMB2_ENCRYPTION_AES256_CCM) {
		return aes_ccm_signing_encrypt(EVP_aes_256_ccm(),
				*key, tfhdr->signature,
				tfhdr->nonce, a_total,
				buflist, x_convert<int>(length),
				tfhdr + 1);
	}
	return -1;
}

int x_smb2_signing_get_nonce_size(uint16_t algo)
{
	switch (algo) {
	case X_SMB2_ENCRYPTION_AES128_GCM:
	case X_SMB2_ENCRYPTION_AES256_GCM:
		return 12;
	case X_SMB2_ENCRYPTION_AES128_CCM:
	case X_SMB2_ENCRYPTION_AES256_CCM:
		return 11;
	}
	return 0;
}

int x_smb2_signing_get_key_size(uint16_t algo)
{
	switch (algo) {
	case X_SMB2_ENCRYPTION_AES128_GCM:
	case X_SMB2_ENCRYPTION_AES128_CCM:
		return 16;
	case X_SMB2_ENCRYPTION_AES256_GCM:
	case X_SMB2_ENCRYPTION_AES256_CCM:
		return 32;
	}
	return 0;
}

