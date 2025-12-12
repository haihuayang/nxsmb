
#include "include/ntlmssp.hxx"
#include <stdlib.h>
#include <string.h>

#undef max
#undef min

#include "include/librpc/ntlmssp.hxx"
#include "include/charset.hxx"
#include "include/nttime.hxx"

static inline void vector_append(std::vector<uint8_t> &vec, const void *b, const void *e)
{
	vec.insert(std::end(vec), (const uint8_t *)b, (const uint8_t *)e);
}

static inline void vector_append(std::vector<uint8_t> &vec, std::vector<uint8_t> &vec2)
{
	vec.insert(std::end(vec), std::begin(vec2), std::end(vec2));
}

static int NTOWFv2(uint8_t *digest, uint32_t dlen,
		const std::string &password, const std::string &user,
		const std::string &userdom)
{
	std::u16string password_u16;
	x_str_convert(password_u16, password);

	uint8_t nt_hash_passwd[16];
	uint32_t size = sizeof nt_hash_passwd;
	int ret = EVP_Digest(password_u16.data(), password_u16.size() * 2,
			nt_hash_passwd, &size, EVP_md4(), NULL);
	X_ASSERT(ret);

	std::u16string userdom_u16;
	x_str_convert(userdom_u16, user, x_toupper_t());
	x_str_convert(userdom_u16, userdom, x_toupper_t());

	struct iovec vec = { userdom_u16.data(), userdom_u16.size() * 2 };
	return x_hmac(digest, dlen, EVP_md5(), nt_hash_passwd, 16,
			&vec, 1);
}

struct NTLM_RESPONSE
{
	uint8_t resp_vers, hi_resp_vers;
	uint16_t reserved0;
	uint32_t reserved1;
	uint64_t time_stamp;
	uint8_t client_challenge[8];
};

static void ComputeResponsev2(uint8_t SessionBaseKey[],
		std::shared_ptr<idl::LM_RESPONSE> &LmChallengeResponse,
		std::shared_ptr<idl::DATA_BLOB> &NtChallengeResponse,
		const uint8_t ResponseKeyNT[],
		const uint8_t *ServerChallenge,
		const uint8_t *ClientChallenge, idl::NTTIME server_time,
		const idl::AV_PAIR_LIST &av_pair_list)
{
	NTLM_RESPONSE ntlm_resp;
	ntlm_resp.resp_vers = 1;
	ntlm_resp.hi_resp_vers = 1;
	ntlm_resp.reserved0 = 0;
	ntlm_resp.reserved1 = 0;
	ntlm_resp.time_stamp = X_H2LE64(server_time.val);
	memcpy(ntlm_resp.client_challenge, ClientChallenge, 8);
	uint8_t reserve[] = { 0, 0, 0, 0 };

	std::vector<uint8_t> target_info;
	idl::x_ndr_push(av_pair_list, target_info, 0);

	uint8_t NTProofStr[16];
	struct iovec vec[] = {
		{ (void *)ServerChallenge, 8, },
		{ &ntlm_resp, sizeof ntlm_resp, },
		{ reserve, sizeof reserve, },
		{ target_info.data(), target_info.size(), },
	};

	x_hmac(NTProofStr, sizeof(NTProofStr), EVP_md5(),
			ResponseKeyNT, 16, vec, 4);

	NtChallengeResponse = std::make_shared<idl::DATA_BLOB>();
	NtChallengeResponse->val.assign(NTProofStr, NTProofStr + 16);
	vector_append(NtChallengeResponse->val, 
			(const uint8_t *)&ntlm_resp, (const uint8_t *)(&ntlm_resp + 1));
	vector_append(NtChallengeResponse->val,
			reserve, reserve + 4);
	vector_append(NtChallengeResponse->val, target_info);

	LmChallengeResponse = std::make_shared<idl::LM_RESPONSE>();
	memset(LmChallengeResponse->Response.data(), 0, 24);

	x_hmac(SessionBaseKey, 16, EVP_md5(),
			ResponseKeyNT, 16, NTProofStr, sizeof NTProofStr);
}

int x_ntlmssp_client_authenticate(std::vector<uint8_t> &out,
		const uint8_t *in_buf, size_t in_len,
		const uint8_t *client_challenge,
		uint8_t *exported_session_key,
		const std::string &user, const std::string &password,
		const std::string &domain, const std::string &hostname)
{
	idl::CHALLENGE_MESSAGE chal_msg;
	idl::x_ndr_off_t err = x_ndr_pull(chal_msg, in_buf, in_len, 0);
	if (err < 0) {
		return -EBADMSG;
	}

	idl::NTTIME server_time{0};
	for (auto &pair : chal_msg.TargetInfo->pair) {
		if (pair.AvId == idl::MsvAvTimestamp) {
			server_time = pair.Value.AvTimestamp;
		}
	}
	if (server_time.val == 0) {
		server_time = x_tick_to_nttime(x_tick_now());
	}

	uint8_t session_base_key[16];
	idl::AUTHENTICATE_MESSAGE auth_msg;
	auth_msg.NegotiateFlags = idl::NTLMSSP_NEGOTIATE_UNICODE |
				  idl::NTLMSSP_REQUEST_TARGET |
				  idl::NTLMSSP_NEGOTIATE_NTLM |
				  idl::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
				  idl::NTLMSSP_NEGOTIATE_SIGN |
				  idl::NTLMSSP_NEGOTIATE_TARGET_INFO |
				  idl::NTLMSSP_NEGOTIATE_128 |
				  idl::NTLMSSP_NEGOTIATE_56 |
				  idl::NTLMSSP_TARGET_TYPE_DOMAIN |
				  idl::NTLMSSP_NEGOTIATE_KEY_EXCH;

	if (user.empty() && domain.empty()) {
		memset(session_base_key, 0, sizeof(session_base_key));
	} else {
		uint8_t nt_hash[16];
		NTOWFv2(nt_hash, sizeof(nt_hash), password,
				user, domain);
		ComputeResponsev2(session_base_key,
				auth_msg.LmChallengeResponse,
				auth_msg.NtChallengeResponse,
				nt_hash, chal_msg.ServerChallenge.data(),
				client_challenge, server_time,
				*chal_msg.TargetInfo);
	}

	auth_msg.DomainName = std::make_shared<std::string>(domain);
	auth_msg.UserName = std::make_shared<std::string>(user);
	auth_msg.Workstation = std::make_shared<std::string>(hostname);

	if (auth_msg.NegotiateFlags & idl::NTLMSSP_NEGOTIATE_VERSION) {
		auth_msg.Version = chal_msg.Version;
	} else {
		memset(&auth_msg.Version, 0, sizeof auth_msg.Version);
	}

	auth_msg.EncryptedRandomSessionKey = std::make_shared<idl::DATA_BLOB>();
	if (auth_msg.NegotiateFlags & idl::NTLMSSP_NEGOTIATE_KEY_EXCH) {
		uint8_t tmp[16];
		memcpy(tmp, exported_session_key, 16);
		x_ntlmssp_arcfour_crypt(tmp, session_base_key, 16);
		auth_msg.EncryptedRandomSessionKey->val.assign(tmp, tmp + 16);
	} else {
		memcpy(exported_session_key, session_base_key, 16);
	}

	memset(auth_msg.mic.MIC.data(), 0, 16);
	idl::x_ndr_off_t ret = idl::x_ndr_push(auth_msg, out, 0);
	X_ASSERT(ret > 0);

	return 0;
}


