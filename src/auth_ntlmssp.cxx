
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
#include "samba/lib/crypto/md5.h"
#include "./samba/nsswitch/libwbclient/wbclient.h"

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
#include "include/librpc/ndr_ntlmssp.hxx"
#include "include/utils.hxx"

struct x_auth_ntlmssp_t
{
	x_auth_ntlmssp_t(x_auth_context_t *context, const x_auth_ops_t *ops);
#if 0
	NTSTATUS update(const uint8_t *in_buf, size_t in_len,
			std::vector<uint8_t> &out);

	virtual NTSTATUS check_packet(const uint8_t *data, size_t data_len,
			const uint8_t *sig, size_t sig_len) override {
		X_TODO;
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	virtual NTSTATUS sign_packet(const uint8_t *data, size_t data_len,
			std::vector<uint8_t> &sig) override {
		X_TODO;
		return NT_STATUS_NOT_IMPLEMENTED;
	}
#endif
	x_wbcli_t wbcli;
	x_wbrequ_t wbrequ;
	x_wbresp_t wbresp;

	enum state_position_t {
		S_NEGOTIATE,
		S_AUTHENTICATE,
		S_CHECK_TRUSTED_DOMAIN,
		S_CHECK_PASSWORD,
		S_DONE
	} state_position{S_NEGOTIATE};

	x_auth_t auth; // base class
	x_smbdsess_t *smbdsess;
	// x_auth_upcall_t *upcall;

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
	x_tick_t challenge_endtime;
	std::u16string netbios_name, netbios_domain, dns_name, dns_domain;
	std::shared_ptr<idl::AV_PAIR_LIST> server_av_pair_list;

	std::string client_domain;
	std::string client_user;
	std::string client_workstation;
	std::shared_ptr<idl::LM_RESPONSE> client_lm_resp;
	std::shared_ptr<idl::blob_t> client_nt_resp;
	std::vector<uint8_t> encrypted_session_key;
};

#define AUTHORITY_MASK	(~(0xffffffffffffULL))

/* Convert a character string to a binary SID */
static char *dom_sid_parse(idl::dom_sid &sid, const char *str, char end)
{
	const char *p;
	char *q;
	uint64_t x;

	/* Sanity check for either "S-" or "s-" */

	if (!str
	    || (str[0]!='S' && str[0]!='s')
	    || (str[1]!='-')) {
		return false;
	}

	/* Get the SID revision number */

	p = str+2;
	x = (uint64_t)strtoul(p, &q, 10);
	if (x==0 || x > UINT8_MAX || !q || *q!='-') {
		return false;
	}
	sid.sid_rev_num = (uint8_t)x;

	/*
	 * Next the Identifier Authority.  This is stored big-endian in a
	 * 6 byte array. If the authority value is >= UINT_MAX, then it should
	 * be expressed as a hex value, according to MS-DTYP.
	 */
	p = q+1;
	x = strtoull(p, &q, 0);
	if (!q || *q!='-' || (x & AUTHORITY_MASK)) {
		return false;
	}
	sid.id_auth[5] = (x & 0x0000000000ffULL);
	sid.id_auth[4] = (x & 0x00000000ff00ULL) >> 8;
	sid.id_auth[3] = (x & 0x000000ff0000ULL) >> 16;
	sid.id_auth[2] = (x & 0x0000ff000000ULL) >> 24;
	sid.id_auth[1] = (x & 0x00ff00000000ULL) >> 32;
	sid.id_auth[0] = (x & 0xff0000000000ULL) >> 40;

	/* now read the the subauthorities */
	p = q +1;
	sid.num_auths = 0;
	while (sid.num_auths < sid.sub_auths.size()) {
		x = strtoull(p, &q, 10);
		if (p == q)
			break;
		if (x > UINT32_MAX) {
			return nullptr;
		}
		sid.sub_auths[sid.num_auths++] = x;

		if (*q != '-') {
			break;
		}
		p = q + 1;
	}

	/* IF we ended early, then the SID could not be converted */

	if (q && *q != end) {
		return nullptr;
	}

	return q;
}

struct dom_sid_with_attrs_t
{
	idl::dom_sid sid;
	uint32_t attrs;
};

static dom_sid_with_attrs_t sid_attr_compose(
		const idl::dom_sid &d,
		uint32_t rid, uint32_t attrs)
{
	dom_sid_with_attrs_t s;
	X_ASSERT(d.num_auths < d.sub_auths.size() - 1);
	s.sid = d;
	s.sid.sub_auths[s.sid.num_auths++] = rid;
	s.attrs = attrs;
	return s;
}

struct AuthUserInfo_t {
	uint32_t user_flags;

	std::string account_name;
	std::string user_principal;
	std::string full_name;
	std::string domain_name;
	std::string dns_domain_name;

	uint32_t acct_flags;
	uint8_t user_session_key[16];
	uint8_t lm_session_key[8];

	uint16_t logon_count;
	uint16_t bad_password_count;

	uint64_t logon_time;
	uint64_t logoff_time;
	uint64_t kickoff_time;
	uint64_t pass_last_set_time;
	uint64_t pass_can_change_time;
	uint64_t pass_must_change_time;

	std::string logon_server;
	std::string logon_script;
	std::string profile_path;
	std::string home_directory;
	std::string home_drive;

	/*
	 * the 1st one is the account sid
	 * the 2nd one is the primary_group sid
	 * followed by the rest of the groups
	 */
	std::vector<dom_sid_with_attrs_t> sids;
};


static void ntlmssp_check_password_cb_reply(x_wbcli_t *wbcli, int err)
{
	x_auth_ntlmssp_t *ntlmssp = X_CONTAINER_OF(wbcli, x_auth_ntlmssp_t, wbcli);
	X_ASSERT(ntlmssp->state_position == x_auth_ntlmssp_t::S_CHECK_PASSWORD);

	x_ref_t<x_smbdsess_t> sess_decref{ntlmssp->smbdsess};
	ntlmssp->smbdsess = nullptr;
	if (err < 0) {
		std::vector<uint8_t> out_security;
		x_smbdsess_auth_updated(sess_decref.get(), NT_STATUS_INTERNAL_ERROR, 
				out_security);
		return;
	}

	AuthUserInfo_t userinfo;
	auto &auth = ntlmssp->wbresp.header.data.auth;
	if (auth.nt_status == 0) {
		userinfo.user_flags = auth.info3.user_flgs;
		userinfo.account_name = auth.info3.user_name;
		userinfo.full_name = auth.info3.full_name;
		userinfo.domain_name = auth.info3.logon_dom;
		userinfo.acct_flags = auth.info3.acct_flags;

		memcpy(userinfo.user_session_key,
				auth.user_session_key,
				sizeof(userinfo.user_session_key));
		memcpy(userinfo.lm_session_key,
				auth.first_8_lm_hash,
				sizeof(userinfo.lm_session_key));

		userinfo.logon_count		= auth.info3.logon_count;
		userinfo.bad_password_count	= auth.info3.bad_pw_count;

		userinfo.logon_time		= auth.info3.logon_time;
		userinfo.logoff_time		= auth.info3.logoff_time;
		userinfo.kickoff_time		= auth.info3.kickoff_time;
		userinfo.pass_last_set_time	= auth.info3.pass_last_set_time;
		userinfo.pass_can_change_time	= auth.info3.pass_can_change_time;
		userinfo.pass_must_change_time= auth.info3.pass_must_change_time;

		userinfo.logon_server	= auth.info3.logon_srv;
		userinfo.logon_script	= auth.info3.logon_script;
		userinfo.profile_path	= auth.info3.profile_path;
		userinfo.home_directory= auth.info3.home_dir;
		userinfo.home_drive	= auth.info3.dir_drive;

		idl::dom_sid domain_sid;
		if (!dom_sid_parse(domain_sid, auth.info3.dom_sid, '\0')) {
			X_TODO;
		}

		if (domain_sid.num_auths >= domain_sid.sub_auths.size() - 1) {
			X_TODO;
		}
		userinfo.sids.reserve(2 + auth.info3.num_groups + auth.info3.num_other_sids);
		userinfo.sids.push_back(sid_attr_compose(domain_sid, auth.info3.user_rid, 0));
		userinfo.sids.push_back(sid_attr_compose(domain_sid, auth.info3.group_rid, 0));

		const auto &extra = ntlmssp->wbresp.extra;
		if (extra.empty() || extra.back() != 0) {
			X_TODO;
		}
		const char *p = (const char *)extra.data(); 
		char *end;
		for (uint32_t j = 0; j < auth.info3.num_groups; ++j) {
			uint32_t rid = strtoul(p, &end, 0);
			if (!end || *end != ':') {
				X_TODO;
			}
			p = end + 1;
			uint32_t attrs = strtoul(p, &end, 0);
			if (!end || *end != '\n') {
				X_TODO;
			}
			p = end + 1;
			userinfo.sids.push_back(sid_attr_compose(domain_sid, rid, attrs));
		}

		for (uint32_t j=0; j < auth.info3.num_other_sids; j++) {
			dom_sid_with_attrs_t sid_attr;
			end = dom_sid_parse(sid_attr.sid, p, ':');
			if (!end) {
				X_TODO;
			}
			p = end + 1;
			sid_attr.attrs = strtoul(p, &end, 0);
			if (!end || *end != '\n') {
				X_TODO;
			}
			userinfo.sids.push_back(sid_attr);
		}

	}

	{
		/* TODO update userinfo */
		std::vector<uint8_t> out_security;
		x_smbdsess_auth_updated(sess_decref.get(), NT_STATUS_OK, 
				out_security);
	}
}

static const x_wb_cbs_t ntlmssp_check_password_cbs = {
	ntlmssp_check_password_cb_reply,
};

static void ntlmssp_check_password(x_auth_ntlmssp_t &ntlmssp, bool trusted, x_smbdsess_t *smbdsess)
{
	std::string domain;
	if (trusted) {
		domain = ntlmssp.client_domain;
	} else {
		domain = x_convert_utf16_to_utf8(ntlmssp.netbios_name);
	}
	ntlmssp.state_position = x_auth_ntlmssp_t::S_CHECK_PASSWORD;
	// ntlmssp->

	/* check_winbind_security */
	auto &wbrequ = ntlmssp.wbrequ;
	memset(&wbrequ.header, 0, sizeof(wbrequ.header));
	wbrequ.header.cmd = WINBINDD_PAM_AUTH_CRAP;
	wbrequ.header.flags = WBFLAG_PAM_INFO3_TEXT |
		WBFLAG_PAM_USER_SESSION_KEY |
		WBFLAG_PAM_LMKEY;

	/* wbcCtxAuthenticateUserEx */
	auto &auth_crap = wbrequ.header.data.auth_crap;
	strncpy(auth_crap.user, ntlmssp.client_user.c_str(),
			sizeof(auth_crap.user)-1);
	if (!domain.empty()) {
		strncpy(auth_crap.domain, domain.c_str(),
				sizeof(auth_crap.domain)-1);
	}
	if (!ntlmssp.client_workstation.empty()) {
		strncpy(auth_crap.workstation,
				ntlmssp.client_workstation.c_str(),
				sizeof(auth_crap.workstation)-1);
	}

	auth_crap.logon_parameters = WBC_MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT |
		WBC_MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT;

	memcpy(auth_crap.chal, ntlmssp.chal.data(),
			sizeof(auth_crap.chal));

	if (ntlmssp.client_lm_resp) {
		auth_crap.lm_resp_len =
			std::min(ntlmssp.client_lm_resp->Response.size(), 
					sizeof(auth_crap.lm_resp));
		if (auth_crap.lm_resp_len) {
			memcpy(auth_crap.lm_resp,
					ntlmssp.client_lm_resp->Response.data(),
					auth_crap.lm_resp_len);
		}
	}

	if (ntlmssp.client_nt_resp) {
		auth_crap.nt_resp_len = ntlmssp.client_nt_resp->val.size();
		if (auth_crap.nt_resp_len > sizeof(auth_crap.nt_resp)) {
			wbrequ.extra = ntlmssp.client_nt_resp->val;
			wbrequ.header.flags |= WBFLAG_BIG_NTLMV2_BLOB;
			wbrequ.header.extra_len = wbrequ.extra.size();
			wbrequ.header.extra_data.data = (char *)wbrequ.extra.data();
		} else if (auth_crap.nt_resp_len > 0) {
			memcpy(auth_crap.nt_resp,
					ntlmssp.client_nt_resp->val.data(),
					auth_crap.nt_resp_len);
		}
	}

	ntlmssp.wbcli.cbs = &ntlmssp_check_password_cbs;
	ntlmssp.smbdsess = smbdsess;
	smbdsess->incref();
	x_smbd_wbpool_request(&ntlmssp.wbcli);
}

static void ntlmssp_domain_info_cb_reply(x_wbcli_t *wbcli, int err)
{
	x_auth_ntlmssp_t *ntlmssp = X_CONTAINER_OF(wbcli, x_auth_ntlmssp_t, wbcli);
	X_ASSERT(ntlmssp->state_position == x_auth_ntlmssp_t::S_CHECK_TRUSTED_DOMAIN);

	x_ref_t<x_smbdsess_t> sess_decref{ntlmssp->smbdsess};
	ntlmssp->smbdsess = nullptr;

	if (err < 0) {
		std::vector<uint8_t> out_security;
		x_smbdsess_auth_updated(sess_decref.get(), NT_STATUS_INTERNAL_ERROR, 
				out_security);
		return;
	}

	const auto &domain_info = ntlmssp->wbresp.header.data.domain_info;
	X_DBG("err=%d, result=%d, name='%s', alt_name='%s', sid=%s, native_mode=%d, active_directory=%d, primary=%d", err, ntlmssp->wbresp.header.result,
			domain_info.name, domain_info.alt_name,
			domain_info.sid,
			domain_info.native_mode,
			domain_info.active_directory,
			domain_info.primary);

	bool is_trusted = err == 0 && ntlmssp->wbresp.header.result == WINBINDD_OK;

	ntlmssp_check_password(*ntlmssp, is_trusted, sess_decref.get());
}

static const x_wb_cbs_t ntlmssp_domain_info_cbs = {
	ntlmssp_domain_info_cb_reply,
};

static void x_ntlmssp_is_trusted_domain(x_auth_ntlmssp_t &ntlmssp, x_smbdsess_t *smbdsess)
{
	ntlmssp.state_position = x_auth_ntlmssp_t::S_CHECK_TRUSTED_DOMAIN;
	auto &requ = ntlmssp.wbrequ.header;
	requ.cmd = WINBINDD_DOMAIN_INFO;
	strncpy(requ.domain_name, ntlmssp.client_domain.c_str(), sizeof(requ.domain_name) - 1);

	ntlmssp.wbcli.cbs = &ntlmssp_domain_info_cbs;
	ntlmssp.smbdsess = smbdsess;
	smbdsess->incref();
	x_smbd_wbpool_request(&ntlmssp.wbcli);
}


x_auth_ntlmssp_t::x_auth_ntlmssp_t(x_auth_context_t *context, const x_auth_ops_t *ops)
	: auth{context, ops}
{
	wbcli.requ = &wbrequ;
	wbcli.resp = &wbresp;

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
	netbios_name = x_convert_utf8_to_utf16(lpcfg_netbios_name());
	netbios_domain = x_convert_utf8_to_utf16(lpcfg_workgroup());

	dns_domain = x_convert_utf8_to_utf16(lpcfg_dnsdomain());
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
static NTSTATUS handle_neg_flags(x_auth_ntlmssp_t &auth_ntlmssp,
		uint32_t flags, const char *name)
{
	uint32_t missing_flags = auth_ntlmssp.required_flags;
	if (flags & idl::NTLMSSP_NEGOTIATE_UNICODE) {
		auth_ntlmssp.neg_flags |= idl::NTLMSSP_NEGOTIATE_UNICODE;
		auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_OEM;
		auth_ntlmssp.unicode = true;
	} else {
		auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_UNICODE;
		auth_ntlmssp.neg_flags |= idl::NTLMSSP_NEGOTIATE_OEM;
		auth_ntlmssp.unicode = false;
	}

        /*
         * NTLMSSP_NEGOTIATE_NTLM2 (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
         * has priority over NTLMSSP_NEGOTIATE_LM_KEY
         */
        if (!(flags & idl::NTLMSSP_NEGOTIATE_NTLM2)) {
                auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_NTLM2;
        }

        if (auth_ntlmssp.neg_flags & idl::NTLMSSP_NEGOTIATE_NTLM2) {
                auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_LM_KEY;
        }

        if (!(flags & idl::NTLMSSP_NEGOTIATE_LM_KEY)) {
                auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_LM_KEY;
        }

        if (!(flags & idl::NTLMSSP_NEGOTIATE_ALWAYS_SIGN)) {
                auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
        }

        if (!(flags & idl::NTLMSSP_NEGOTIATE_128)) {
                auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_128;
        }

        if (!(flags & idl::NTLMSSP_NEGOTIATE_56)) {
                auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_56;
        }

        if (!(flags & idl::NTLMSSP_NEGOTIATE_KEY_EXCH)) {
                auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_KEY_EXCH;
        }

        if (!(flags & idl::NTLMSSP_NEGOTIATE_SIGN)) {
                auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_SIGN;
        }

        if (!(flags & idl::NTLMSSP_NEGOTIATE_SEAL)) {
                auth_ntlmssp.neg_flags &= ~idl::NTLMSSP_NEGOTIATE_SEAL;
        }

        if ((flags & idl::NTLMSSP_REQUEST_TARGET)) {
                auth_ntlmssp.neg_flags |= idl::NTLMSSP_REQUEST_TARGET;
        }

        missing_flags &= ~auth_ntlmssp.neg_flags;
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

static const uint32_t max_lifetime = 30 * 60 * 1000;
static inline NTSTATUS handle_negotiate(x_auth_ntlmssp_t &auth_ntlmssp,
		const uint8_t *in_buf, size_t in_len, std::vector<uint8_t> &out,
		x_smbdsess_t *smbdsess)
{
	// samba gensec_ntlmssp_server_negotiate
	idl::NEGOTIATE_MESSAGE nego_msg;
	idl::x_ndr_off_t ret = idl::x_ndr_pull(nego_msg, in_buf, in_len);

	if (ret < 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	NTSTATUS status = handle_neg_flags(auth_ntlmssp, nego_msg.NegotiateFlags, "negotiate");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	struct timeval tv_now = timeval_current();
	std::array<uint8_t, 8> cryptkey;
	generate_random_buffer(cryptkey.data(), cryptkey.size());

	auth_ntlmssp.challenge_endtime = x_tick_add(tick_now, max_lifetime);

	uint32_t chal_flags = auth_ntlmssp.neg_flags;
	std::u16string target_name;

        if (nego_msg.NegotiateFlags & idl::NTLMSSP_REQUEST_TARGET) {
                chal_flags |= idl::NTLMSSP_NEGOTIATE_TARGET_INFO |
			idl::NTLMSSP_REQUEST_TARGET;
                if (auth_ntlmssp.is_standalone) {
                        chal_flags |= idl::NTLMSSP_TARGET_TYPE_SERVER;
                        target_name = auth_ntlmssp.netbios_name;
                } else {
                        chal_flags |= idl::NTLMSSP_TARGET_TYPE_DOMAIN;
                        target_name = auth_ntlmssp.netbios_domain;
                };
        }

	auth_ntlmssp.chal = cryptkey;
	// TODO auth_ntlmssp.internal_chal = cryptkey;

	idl::CHALLENGE_MESSAGE chal_msg;

	if (chal_flags & idl::NTLMSSP_NEGOTIATE_TARGET_INFO) {
		chal_msg.TargetInfo.val = std::make_shared<idl::AV_PAIR_LIST>();
		auto &av_pair_list = chal_msg.TargetInfo.val;
		idl::AV_PAIR pair;

		pair.set_AvId(idl::MsvAvNbDomainName);
		pair.Value.AvNbDomainName.val = target_name;
		av_pair_list->pair.val.push_back(pair);

		pair.set_AvId(idl::MsvAvNbComputerName);
		pair.Value.AvNbComputerName.val = auth_ntlmssp.netbios_name;
		av_pair_list->pair.val.push_back(pair);

		pair.set_AvId(idl::MsvAvDnsDomainName);
		pair.Value.AvDnsDomainName.val = auth_ntlmssp.dns_domain;
		av_pair_list->pair.val.push_back(pair);

		pair.set_AvId(idl::MsvAvDnsComputerName);
		pair.Value.AvDnsComputerName.val = auth_ntlmssp.dns_name;
		av_pair_list->pair.val.push_back(pair);

		if (auth_ntlmssp.force_old_spnego) {
			pair.set_AvId(idl::MsvAvTimestamp);
			pair.Value.AvTimestamp.val = timeval_to_nttime(&tv_now);
			av_pair_list->pair.val.push_back(pair);
		}

		pair.set_AvId(idl::MsvAvEOL);
		av_pair_list->pair.val.push_back(pair);

		auth_ntlmssp.server_av_pair_list = chal_msg.TargetInfo.val;
	}

	chal_msg.TargetName.val = std::make_shared<idl::gstring>();
	chal_msg.TargetName.val->val = x_convert_utf16_to_utf8(target_name);
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
        auth_ntlmssp.state_position = x_auth_ntlmssp_t::S_AUTHENTICATE;

        return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

static const idl::AV_PAIR *av_pair_find(const idl::AV_PAIR_LIST &av_pair_list, idl::ntlmssp_AvId avid)
{
	for (const auto &p: av_pair_list.pair.val) {
		if (p.AvId == avid) {
			return &p;
		}
	}
	return nullptr;
}

static inline NTSTATUS handle_authenticate(x_auth_ntlmssp_t &auth_ntlmssp,
		const uint8_t *in_buf, size_t in_len, std::vector<uint8_t> &out,
		x_smbdsess_t *smbdsess)
{
	/* TODO ntlmssp.idl, version & mic may not present,
	 * samba/auth/ntlmssp/ntlmssp_server.c ntlmssp_server_preauth try
	 * long format and fail back to short format */
	idl::AUTHENTICATE_MESSAGE msg;
	idl::x_ndr_off_t err = x_ndr_pull(msg, in_buf, in_len);
	if (err < 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	NTSTATUS status;
	if (msg.NegotiateFlags != 0) {
		status = handle_neg_flags(auth_ntlmssp, msg.NegotiateFlags, "authenticate");
		if (!NT_STATUS_IS_OK(status)){
			return status;
		}
	}

	if (msg.NtChallengeResponse.val && msg.NtChallengeResponse.val->val.size() > 0x18) {
		idl::NTLMv2_RESPONSE v2_resp;
		err = x_ndr_pull(v2_resp, msg.NtChallengeResponse.val->val.data(),
				msg.NtChallengeResponse.val->val.size());
		if (err < 0) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		
		auto &server_av_pair_list = auth_ntlmssp.server_av_pair_list;
		if (server_av_pair_list) {
		       	if (v2_resp.Challenge.AvPairs.pair.val.size() < server_av_pair_list->pair.val.size()) {
				return NT_STATUS_INVALID_PARAMETER;
			}
			for (auto &av: auth_ntlmssp.server_av_pair_list->pair.val) {
				if (av.AvId == idl::MsvAvEOL) {
					continue;
				}

				auto cpair = av_pair_find(v2_resp.Challenge.AvPairs, av.AvId);
				if (cpair == nullptr) {
					return NT_STATUS_INVALID_PARAMETER;
				}

				if (false) {
				} else if (av.AvId == idl::MsvAvNbComputerName) {
					if (av.Value.AvNbComputerName != cpair->Value.AvNbComputerName) {
						return NT_STATUS_INVALID_PARAMETER;
					}
				} else if (av.AvId == idl::MsvAvNbDomainName) {
					if (av.Value.AvNbDomainName != cpair->Value.AvNbDomainName) {
						return NT_STATUS_INVALID_PARAMETER;
					}
				} else if (av.AvId == idl::MsvAvDnsComputerName) {
					if (av.Value.AvDnsComputerName != cpair->Value.AvDnsComputerName) {
						return NT_STATUS_INVALID_PARAMETER;
					}
				} else if (av.AvId == idl::MsvAvDnsDomainName) {
					if (av.Value.AvDnsDomainName != cpair->Value.AvDnsDomainName) {
						return NT_STATUS_INVALID_PARAMETER;
					}
				} else if (av.AvId == idl::MsvAvDnsTreeName) {
					if (av.Value.AvDnsTreeName != cpair->Value.AvDnsTreeName) {
						return NT_STATUS_INVALID_PARAMETER;
					}
				} else if (av.AvId == idl::MsvAvTimestamp) {
					if (av.Value.AvTimestamp.val != cpair->Value.AvTimestamp.val) {
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
		}

		uint32_t av_flags = 0;
		for (auto &av: v2_resp.Challenge.AvPairs.pair.val) {
			if (av.AvId == idl::MsvAvEOL) {
				break;
			} else if (av.AvId == idl::MsvAvFlags) {
				av_flags = av.Value.AvFlags;
			}
		}
		/* mic presents if flag NTLMSSP_AVFLAG_MIC_IN_AUTHENTICATE_MESSAGE,
		 * but in idl it is unconditional, since the server always send
		 * target_info, and client should send back. so the mic range is
		 * valid although it may not present */
		if (av_flags & idl::NTLMSSP_AVFLAG_MIC_IN_AUTHENTICATE_MESSAGE) {
			// ntlmssp_state->new_spnego = true;
		}
	}

	if (tick_now > auth_ntlmssp.challenge_endtime) {
		return NT_STATUS_INVALID_PARAMETER;
	}


        /* NTLM2 uses a 'challenge' that is made of up both the server challenge, and a
           client challenge

           However, the NTLM2 flag may still be set for the real NTLMv2 logins, be careful.
        */
	if (auth_ntlmssp.neg_flags & idl::NTLMSSP_NEGOTIATE_NTLM2) {
		if (msg.NtChallengeResponse.val && msg.NtChallengeResponse.val->val.size() == 0x18) {
			X_TODO; /*
			uint8_t session_nonce_hash[16];
			MD5_CTX md5_session_nonce_ctx;
			MD5Init(&md5_session_nonce_ctx);
			MD5Update();
			MD5Final(session_nonce_hash, &md5_session_nonce_ctx);
			*/
		}
	}

	/* ntlmssp_server_check_password */
	if (msg.DomainName.val) {
		auth_ntlmssp.client_domain = msg.DomainName.val->val;
	}
	if (msg.UserName.val) {
		auth_ntlmssp.client_user = msg.UserName.val->val;
	}
	if (msg.Workstation.val) {
		auth_ntlmssp.client_workstation = msg.Workstation.val->val;
	}
	if (msg.LmChallengeResponse.val) {
		auth_ntlmssp.client_lm_resp = msg.LmChallengeResponse.val;
	}
	if (msg.NtChallengeResponse.val) {
		auth_ntlmssp.client_nt_resp = msg.NtChallengeResponse.val;
	}

	auth_ntlmssp.encrypted_session_key = msg.EncryptedRandomSessionKey.val->val;
	bool upn_form = auth_ntlmssp.client_domain.empty() &&
		(auth_ntlmssp.client_user.find('@') != std::string::npos);

	if (!upn_form) {
		std::string netbios_name = x_convert_utf16_to_utf8(auth_ntlmssp.netbios_name);
		if (auth_ntlmssp.client_domain != netbios_name) {
			x_ntlmssp_is_trusted_domain(auth_ntlmssp, smbdsess);
			return NT_STATUS(2); // TODO introduce error
			return X_NT_STATUS_INTERNAL_BLOCKED;
		}
	}

	ntlmssp_check_password(auth_ntlmssp, false, smbdsess);
	return X_NT_STATUS_INTERNAL_BLOCKED;
}

static NTSTATUS ntlmssp_update(x_auth_t *auth, const uint8_t *in_buf, size_t in_len,
		std::vector<uint8_t> &out, x_smbdsess_t *smbdsess)
{
	x_auth_ntlmssp_t *ntlmssp = X_CONTAINER_OF(auth, x_auth_ntlmssp_t, auth);
	if (ntlmssp->state_position == x_auth_ntlmssp_t::S_NEGOTIATE) {
		return handle_negotiate(*ntlmssp, in_buf, in_len, out, smbdsess);
	} else if (ntlmssp->state_position == x_auth_ntlmssp_t::S_AUTHENTICATE) {
		return handle_authenticate(*ntlmssp, in_buf, in_len, out, smbdsess);
	} else {
		X_ASSERT(false);
		return NT_STATUS_INTERNAL_ERROR;
	}
}

static void ntlmssp_destroy(x_auth_t *auth)
{
	x_auth_ntlmssp_t *ntlmssp = X_CONTAINER_OF(auth, x_auth_ntlmssp_t, auth);
	delete ntlmssp;
}

static bool ntlmssp_have_feature(x_auth_t *auth, uint32_t feature)
{
	return false;
}

static NTSTATUS ntlmssp_check_packet(x_auth_t *auth, const uint8_t *data, size_t data_len,
		const uint8_t *sig, size_t sig_len)
{
	X_TODO;
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS ntlmssp_sign_packet(x_auth_t *auth, const uint8_t *data, size_t data_len,
		std::vector<uint8_t> &sig)
{
	X_TODO;
	return NT_STATUS_NOT_IMPLEMENTED;
}

static const x_auth_ops_t auth_ntlmssp_ops = {
	ntlmssp_update,
	ntlmssp_destroy,
	ntlmssp_have_feature,
	ntlmssp_check_packet,
	ntlmssp_sign_packet,
};


x_auth_t *x_auth_create_ntlmssp(x_auth_context_t *context)
{
	x_auth_ntlmssp_t *ntlmssp = new x_auth_ntlmssp_t(context, &auth_ntlmssp_ops);
	return &ntlmssp->auth;
}

int x_auth_ntlmssp_init(x_auth_context_t *ctx)
{
	return 0;
}

#if 0
static x_auth_t *x_auth_ntlmssp_create(x_auth_context_t *context)
{
	return new x_auth_ntlmssp_t(context);
};

const struct x_auth_mech_t x_auth_mech_ntlmssp = {
	GSS_SPNEGO_MECHANISM,
	x_auth_ntlmssp_create,
};
#endif

