
extern "C" {
#include "heimdal/lib/asn1/asn1-common.h"
#include "heimdal/lib/gssapi/gssapi/gssapi.h"
#include "heimdal/lib/gssapi/mech/gssapi_asn1.h"
#include "heimdal/lib/gssapi/spnego/spnego_locl.h"
#include "heimdal/lib/asn1/der.h"
#include "heimdal/lib/gssapi/spnego/spnego_asn1.h"
#include "heimdal/lib/ntlm/heimntlm.h"
#include "samba/libcli/util/hresult.h"
#include "samba/lib/util/samba_util.h"

// #include "samba/auth/gensec/gensec.h"
}

#include <stdlib.h>
#include <string.h>

#undef max
#undef min

#include "smbd.hxx"
#include <cctype>
#include <algorithm>
#include "include/asn1_wrap.hxx"
#include "librpc/idl/ntlmssp.h"
#include "include/utils.hxx"

struct x_gensec_ntlmssp_t : x_gensec_t
{
	x_gensec_ntlmssp_t(x_gensec_context_t *context) : x_gensec_t(context) {
		// gensec_ntlmssp_server_start
		allow_lm_response = lpcfg_lanman_auth();
		allow_lm_key = (allow_lm_response && lpcfg_param_bool(NULL, "ntlmssp_server", "allow_lm_key", false));
		force_old_spnego = lpcfg_param_bool(NULL, "ntlmssp_server", "force_old_spnego", false);

		neg_flags = idl::NTLMSSP_NEGOTIATE_NTLM | idl::NTLMSSP_NEGOTIATE_VERSION;
		if (lpcfg_param_bool(NULL, "ntlmssp_server", "128bit", true)) {
			neg_flags |= idl::NTLMSSP_NEGOTIATE_128;
		}

		if (lpcfg_param_bool(NULL, "ntlmssp_server", "56bit", true)) {
			neg_flags |= idl::NTLMSSP_NEGOTIATE_56;
		}

		if (lpcfg_param_bool(NULL, "ntlmssp_server", "keyexchange", true)) {
			neg_flags |= idl::NTLMSSP_NEGOTIATE_KEY_EXCH;
		}

		if (lpcfg_param_bool(NULL, "ntlmssp_server", "alwayssign", true)) {
			neg_flags |= idl::NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
		}

		if (lpcfg_param_bool(NULL, "ntlmssp_server", "ntlm2", true)) {
			neg_flags |= idl::NTLMSSP_NEGOTIATE_NTLM2;
		}

		if (allow_lm_key) {
			neg_flags |= idl::NTLMSSP_NEGOTIATE_LM_KEY;
		}

		if (lpcfg_param_bool(NULL, "ntlmssp_server", "keyexchange", true)) {
			neg_flags |= idl::NTLMSSP_NEGOTIATE_KEY_EXCH;
		}

		if (want_features & GENSEC_FEATURE_SESSION_KEY) {
			neg_flags |= idl::NTLMSSP_NEGOTIATE_SIGN;
		}
		if (want_features & GENSEC_FEATURE_SIGN) {
			neg_flags |= idl::NTLMSSP_NEGOTIATE_SIGN;
			/*
			 * We need to handle idl::NTLMSSP_NEGOTIATE_SIGN as
			 * idl::NTLMSSP_NEGOTIATE_SEAL if GENSEC_FEATURE_LDAP_STYLE
			 * is requested.
			 */
			force_wrap_seal = ((want_features & GENSEC_FEATURE_LDAP_STYLE) != 0);
		}

		if (want_features & GENSEC_FEATURE_SEAL) {
			neg_flags |= idl::NTLMSSP_NEGOTIATE_SIGN | idl::NTLMSSP_NEGOTIATE_SEAL;
		}

		/* TODO
		if (role == ROLE_STANDALONE) {
			ntlmssp_state->server.is_standalone = true;
		} else {
			ntlmssp_state->server.is_standalone = false;
		}
		*/
		is_standalone = false;
		netbios_name = u16string_from_utf8(lpcfg_netbios_name());
		netbios_domain = u16string_from_utf8(lpcfg_workgroup());

		dns_domain = u16string_from_utf8(lpcfg_dnsdomain());
		std::u16string tmp_dns_name = netbios_name;
		if (dns_domain.size()) {
			tmp_dns_name += u".";
			tmp_dns_name += dns_domain;
		}

		std::transform(tmp_dns_name.begin(), tmp_dns_name.end(), dns_name.begin(),
				[](unsigned char c) { return std::tolower(c); });
		/* TODO
		ntlmssp_state->neg_flags |= ntlmssp_state->required_flags;
		ntlmssp_state->conf_flags = ntlmssp_state->neg_flags;
		*/
	}

	NTSTATUS update(const uint8_t *in_buf, size_t in_len,
			std::vector<uint8_t> &out);
	virtual NTSTATUS check_packet(const uint8_t *data, size_t data_len,
			const uint8_t *sig, size_t sig_len) override {
		X_TODO;
	}
	virtual NTSTATUS sign_packet(const uint8_t *data, size_t data_len,
			std::vector<uint8_t> &sig) override {
		X_TODO;
	}
	enum state_position_t {
		S_NEGOTIATE,
		S_AUTHENTICATE,
		S_DONE
	} state_position{S_NEGOTIATE};

	// smbd_smb2_session_setup_send, should in base class
	uint32_t want_features = GENSEC_FEATURE_SESSION_KEY | GENSEC_FEATURE_UNIX_TOKEN;

	bool allow_lm_response;
	bool allow_lm_key;
	bool force_old_spnego;
	bool force_wrap_seal;
	bool is_standalone;
	bool unicode = false;
	uint32_t neg_flags;
	uint32_t required_flags = 0;

	std::array<uint8_t, 8> chal;
	struct timeval challenge_endtime;
	std::u16string netbios_name, netbios_domain, dns_name, dns_domain;
};
#if 0
const DATA_BLOB ntlmssp_version_blob(void)
{
	/*
	 * This is a simplified version of
	 *
	 * enum ndr_err_code err;
	 * struct ntlmssp_VERSION vers;
	 *
	 * ZERO_STRUCT(vers);
	 * vers.ProductMajorVersion = NTLMSSP_WINDOWS_MAJOR_VERSION_6;
	 * vers.ProductMinorVersion = NTLMSSP_WINDOWS_MINOR_VERSION_1;
	 * vers.ProductBuild = 0;
	 * vers.NTLMRevisionCurrent = NTLMSSP_REVISION_W2K3;
	 *
	 * err = ndr_push_struct_blob(&version_blob,
	 * 			ntlmssp_state,
	 * 			&vers,
	 * 			(ndr_push_flags_fn_t)ndr_push_ntlmssp_VERSION);
	 *
	 * if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
	 * 	data_blob_free(&struct_blob);
	 * 	return NT_STATUS_NO_MEMORY;
	 * }
	 */
	static const uint8_t version_buffer[8] = {
		NTLMSSP_WINDOWS_MAJOR_VERSION_6,
		NTLMSSP_WINDOWS_MINOR_VERSION_1,
		0x00, 0x00, /* product build */
		0x00, 0x00, 0x00, /* reserved */
		NTLMSSP_REVISION_W2K3
	};

	return data_blob_const(version_buffer, ARRAY_SIZE(version_buffer));
}
#endif
// ntlmssp_handle_neg_flags
static NTSTATUS handle_neg_flags(x_gensec_ntlmssp_t &gensec_ntlmssp,
		uint32_t flags, const char *name)
{
	uint32_t missing_flags = gensec_ntlmssp.required_flags;
	if (flags & idl::NTLMSSP_NEGOTIATE_UNICODE) {
		gensec_ntlmssp.neg_flags |= idl::NTLMSSP_NEGOTIATE_UNICODE;
		gensec_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_OEM;
		gensec_ntlmssp.unicode = true;
	} else {
		gensec_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_UNICODE;
		gensec_ntlmssp.neg_flags |= idl::NTLMSSP_NEGOTIATE_OEM;
		gensec_ntlmssp.unicode = false;
	}

        /*
         * NTLMSSP_NEGOTIATE_NTLM2 (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
         * has priority over NTLMSSP_NEGOTIATE_LM_KEY
         */
        if (!(flags & idl::NTLMSSP_NEGOTIATE_NTLM2)) {
                gensec_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_NTLM2;
        }

        if (gensec_ntlmssp.neg_flags & idl::NTLMSSP_NEGOTIATE_NTLM2) {
                gensec_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_LM_KEY;
        }

        if (!(flags & idl::NTLMSSP_NEGOTIATE_LM_KEY)) {
                gensec_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_LM_KEY;
        }

        if (!(flags & idl::NTLMSSP_NEGOTIATE_ALWAYS_SIGN)) {
                gensec_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
        }

        if (!(flags & idl::NTLMSSP_NEGOTIATE_128)) {
                gensec_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_128;
        }

        if (!(flags & idl::NTLMSSP_NEGOTIATE_56)) {
                gensec_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_56;
        }

        if (!(flags & idl::NTLMSSP_NEGOTIATE_KEY_EXCH)) {
                gensec_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_KEY_EXCH;
        }

        if (!(flags & idl::NTLMSSP_NEGOTIATE_SIGN)) {
                gensec_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_SIGN;
        }

        if (!(flags & idl::NTLMSSP_NEGOTIATE_SEAL)) {
                gensec_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_SEAL;
        }

        if ((flags & idl::NTLMSSP_REQUEST_TARGET)) {
                gensec_ntlmssp.neg_flags |= idl::NTLMSSP_REQUEST_TARGET;
        }

        missing_flags &= ~gensec_ntlmssp.neg_flags;
        if (missing_flags != 0) {
                HRESULT hres = HRES_SEC_E_UNSUPPORTED_FUNCTION;
                NTSTATUS status = NT_STATUS(HRES_ERROR_V(hres));
#if 0
                DEBUG(1, ("%s: Got %s flags[0x%08x] "
                          "- possible downgrade detected! "
                          "missing_flags[0x%08x] - %s\n",
                          __func__, name,
                          (unsigned)flags,
                          (unsigned)missing_flags,
                          nt_errstr(status)));
                debug_ntlmssp_flags_raw(1, missing_flags);
                DEBUGADD(4, ("neg_flags[0x%08x]\n",
                             (unsigned)ntlmssp_state->neg_flags));
                debug_ntlmssp_flags_raw(4, ntlmssp_state->neg_flags);
#endif
                return status;
        }
	return NT_STATUS_OK;
}

static inline NTSTATUS handle_negotiate(x_gensec_ntlmssp_t &gensec_ntlmssp,
		const uint8_t *in_buf, size_t in_len, std::vector<uint8_t> &out)
{
	idl::NEGOTIATE_MESSAGE nego_msg;
	idl::x_ndr_off_t ret = idl::x_ndr_pull(nego_msg, in_buf, in_len);

	if (ret < 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	NTSTATUS status = handle_neg_flags(gensec_ntlmssp, nego_msg.NegotiateFlags, "negotiate");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	uint32_t max_lifetime = 30 * 60;
	struct timeval tv_now = timeval_current();
	struct timeval tv_end = timeval_add(&tv_now, max_lifetime, 0);
	std::array<uint8_t, 8> cryptkey;
	generate_random_buffer(cryptkey.data(), cryptkey.size());

	gensec_ntlmssp.challenge_endtime = tv_end;

	uint32_t chal_flags = gensec_ntlmssp.neg_flags;
	std::u16string target_name;

        if (nego_msg.NegotiateFlags & idl::NTLMSSP_REQUEST_TARGET) {
                chal_flags |= idl::NTLMSSP_NEGOTIATE_TARGET_INFO |
			idl::NTLMSSP_REQUEST_TARGET;
                if (gensec_ntlmssp.is_standalone) {
                        chal_flags |= idl::NTLMSSP_TARGET_TYPE_SERVER;
                        target_name = gensec_ntlmssp.netbios_name;
                } else {
                        chal_flags |= idl::NTLMSSP_TARGET_TYPE_DOMAIN;
                        target_name = gensec_ntlmssp.netbios_domain;
                };
        }

	gensec_ntlmssp.chal = cryptkey;
	// TODO gensec_ntlmssp.internal_chal = cryptkey;

	idl::CHALLENGE_MESSAGE chal_msg;

	if (chal_flags & idl::NTLMSSP_NEGOTIATE_TARGET_INFO) {
		chal_msg.TargetInfo = std::make_shared<idl::AV_PAIR_LIST>();
		auto &av_pair_list = chal_msg.TargetInfo;
		idl::AV_PAIR pair;

		pair.set_AvId(idl::MsvAvNbDomainName);
		pair.Value.AvNbDomainName.val = target_name;
		av_pair_list->pair.push_back(pair);

		pair.set_AvId(idl::MsvAvNbComputerName);
		pair.Value.AvNbComputerName.val = gensec_ntlmssp.netbios_name;
		av_pair_list->pair.push_back(pair);

		pair.set_AvId(idl::MsvAvDnsDomainName);
		pair.Value.AvDnsDomainName.val = gensec_ntlmssp.dns_domain;
		av_pair_list->pair.push_back(pair);

		pair.set_AvId(idl::MsvAvDnsComputerName);
		pair.Value.AvDnsComputerName.val = gensec_ntlmssp.dns_name;
		av_pair_list->pair.push_back(pair);

		if (gensec_ntlmssp.force_old_spnego) {
			pair.set_AvId(idl::MsvAvTimestamp);
			pair.Value.AvTimestamp = timeval_to_nttime(&tv_now);
			av_pair_list->pair.push_back(pair);
		}

		pair.set_AvId(idl::MsvAvEOL);
		av_pair_list->pair.push_back(pair);
	}

	chal_msg.TargetName.val = target_name;
	chal_msg.NegotiateFlags = idl::NEGOTIATE(chal_flags);
	chal_msg.ServerChallenge = cryptkey;

	ret = idl::x_ndr_push(chal_msg, out);
#if 0
	{
                /* Marshal the packet in the right format, be it unicode or ASCII */
                const char *gen_string;
                const DATA_BLOB version_blob = ntlmssp_version_blob();

                if (ntlmssp_state->unicode) {
                        gen_string = "CdUdbddBb";
                } else {
                        gen_string = "CdAdbddBb";
                }

                status = msrpc_gen(out_mem_ctx, reply, gen_string,
                        "NTLMSSP",
                        idl::NTLMSSP_CHALLENGE,
                        target_name,
                        chal_flags,
                        cryptkey, 8,
                        0, 0,
                        struct_blob.data, struct_blob.length,
                        version_blob.data, version_blob.length);

                if (!NT_STATUS_IS_OK(status)) {
                        data_blob_free(&struct_blob);
                        return status;
                }

                if (DEBUGLEVEL >= 10) {
                        struct CHALLENGE_MESSAGE *challenge = talloc(
                                ntlmssp_state, struct CHALLENGE_MESSAGE);
                        if (challenge != NULL) {
                                challenge->NegotiateFlags = chal_flags;
                                status = ntlmssp_pull_CHALLENGE_MESSAGE(
                                        reply, challenge, challenge);
                                if (NT_STATUS_IS_OK(status)) {
                                        NDR_PRINT_DEBUG(CHALLENGE_MESSAGE,
                                                        challenge);
                                }
                                TALLOC_FREE(challenge);
                        }
                }
        }
#endif
        gensec_ntlmssp.state_position = x_gensec_ntlmssp_t::S_AUTHENTICATE;

        return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

static inline NTSTATUS handle_authenticate(x_gensec_ntlmssp_t &gensec_ntlmssp,
		const uint8_t *in_buf, size_t in_len, std::vector<uint8_t> &out)
{
	/* TODO ntlmssp.idl, version & mic may not present,s
	 * samba/auth/ntlmssp/ntlmssp_server.c ntlmssp_server_preauth try
	 * long format and fail back to short format */
	idl::AUTHENTICATE_MESSAGE msg;
	idl::x_ndr_off_t err = x_ndr_pull(msg, in_buf, in_len);
	if (err < 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	NTSTATUS status;
	if (msg.NegotiateFlags != 0) {
		status = handle_neg_flags(gensec_ntlmssp, msg.NegotiateFlags, "authenticate");
		if (!NT_STATUS_IS_OK(status)){
			return status;
		}
	}

#if 0 
	TODO
	if (msg.ntlmssp_NTLM_RESPONSE_type > 0x18) {
		uint32_t av_flags = 0;
		auto &v2_resp = msg.NtChallengeResponse.v2;
		if (v2_resp.Challenge.AvPairs.pair.size() < gensec_ntlmssp.server_av_pair_list.size()) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		for (auto &av: gensec_ntlmssp.server_av_pair_list) {
			if (av.AvId == idl::MsvAvEOL) {
				continue;
			}

			auto cpair = av_pairs_find(v2_resp.Challenge.AvPairs.pair);
			if (cpair == nullptr) {
				return NT_STATUS_INVALID_PARAMETER;
			}
			if (av.AvId == idl::MsvAvNbComputerName) {
				if (av.Value.AvNbComputerName != cpair->Value.AvNbComputerName) {
					return NT_STATUS_INVALID_PARAMETER;
				}
			} else if (av.AvId == idl::MsvAvTimestamp) {
				if (av.Value.AvTimestamp != cp->Value.AvTimestamp) {
					return NT_STATUS_INVALID_PARAMETER;
				}
			} else {
				/*
				 * This can't happen as we control
				 * ntlmssp_state->server.av_pair_list
				 */
				return NT_STATUS_INTERNAL_ERROR;
			}
		}

		for (auto &av: v2_resp.Challenge.AvPairs.pair) {
			if (av.AvId == idl::MsvAvEOL) {
				break;
			} else if (av.AvId == idl::MsvAvFlags) {
				av_flags = av.Value.AvFlags;
			}
		}
	}

	if (now > gensec_ntlmssp.challeng_endtime) {
		return NT_STATUS_INVALID_PARAMETER;
	}


        /* NTLM2 uses a 'challenge' that is made of up both the server challenge, and a
           client challenge

           However, the NTLM2 flag may still be set for the real NTLMv2 logins, be careful.
        */
	if (gensec_ntlmssp.neg_flags & idl::NTLMSSP_NEGOTIATE_NTLM2) {
		if (msg.ntlmssp_NTLM_RESPONSE_type == 0x18) {
			uint6_t session_nonce_hash[16];
			MD5_CTX md5_session_nonce_ctx;
			MD5Init(&md5_session_nonce_ctx);
			MD5Update();
			MD5Final(session_nonce_hash, &md5_session_nonce_ctx);
		}
	}
#endif


	X_TODO;
	return NT_STATUS_INVALID_PARAMETER;
}

NTSTATUS x_gensec_ntlmssp_t::update(const uint8_t *in_buf, size_t in_len, std::vector<uint8_t> &out)
{
	if (state_position == S_NEGOTIATE) {
		return handle_negotiate(*this, in_buf, in_len, out);
	} else if (state_position == S_AUTHENTICATE) {
		return handle_authenticate(*this, in_buf, in_len, out);
	} else {
		X_ASSERT(false);
		return NT_STATUS_INTERNAL_ERROR;
	}
}
#if 0
static x_gensec_t *x_gensec_ntlmssp_create(x_gensec_context_t *context)
{
	return new x_gensec_ntlmssp_t(context);
};

const struct x_gensec_mech_t x_gensec_mech_ntlmssp = {
	GSS_SPNEGO_MECHANISM,
	x_gensec_ntlmssp_create,
};
#endif
x_gensec_t *x_gensec_create_ntlmssp(x_gensec_context_t *context)
{
	return new x_gensec_ntlmssp_t(context);
}

