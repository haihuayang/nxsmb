
#ifndef __ntlmssp__hxx__
#define __ntlmssp__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include <vector>
#include <string>

int x_ntlmssp_client_authenticate(std::vector<uint8_t> &out,
		const uint8_t *in_buf, size_t in_len,
		const uint8_t *client_challenge,
		uint8_t *exported_session_key,
		const std::string &user, const std::string &password,
		const std::string &domain, const std::string &hostname);


#endif /* __ntlmssp__hxx__ */

