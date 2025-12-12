
#ifndef __ntlmssp__hxx__
#define __ntlmssp__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "xdefines.h"
#include "crypto.hxx"
#include "bits.hxx"
#include <vector>
#include <string>

static inline void x_ntlmssp_arcfour_crypt_sbox(x_cipher_ctx_t &cipher_ctx,
		void *data, size_t data_len)
{
	int outl = cipher_ctx.update(data, x_convert_assert<unsigned int>(data_len), data);
	X_ASSERT(outl == (int)data_len);
}

static inline void x_ntlmssp_arcfour_crypt(uint8_t *data, const void *key, size_t data_len)
{
	int outl = x_rc4_crypt(key, false, data,
			x_convert_assert<unsigned int>(data_len),
			data);
	X_ASSERT(outl == (int)data_len);
}

int x_ntlmssp_client_authenticate(std::vector<uint8_t> &out,
		const uint8_t *in_buf, size_t in_len,
		const uint8_t *client_challenge,
		uint8_t *exported_session_key,
		const std::string &user, const std::string &password,
		const std::string &domain, const std::string &hostname);


#endif /* __ntlmssp__hxx__ */

