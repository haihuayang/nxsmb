
#include <stdlib.h>
#include <string.h>

#undef max
#undef min

#include "smbd.hxx"
#include "smbd_conf.hxx"
#include "smbd_secrets.hxx"
#include <cctype>
#include <algorithm>
#include "include/asn1_wrap.hxx"
#include "include/krb5_wrap.hxx"
#include "include/charset.hxx"
#include <gssapi/gssapi_krb5.h>

/**
 * zero a structure
 */
#ifndef ZERO_STRUCT
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))
#endif

using x_krb5_principal_ptr_t = std::unique_ptr<Principal, std::function<void (Principal *)>>;
using x_krb5_principals_ptr_t = std::unique_ptr<Principals, std::function<void (Principals *)>>;
using x_gss_buffer_set_ptr_t = std::unique_ptr<gss_buffer_set_desc, std::function<void (gss_buffer_set_t)>>;

struct x_auth_krb5_t
{
	x_auth_krb5_t(x_auth_context_t *context, const x_auth_ops_t *ops);
	x_wbcli_t wbcli;
	x_wbrequ_t wbrequ;
	x_wbresp_t wbresp;

	enum state_position_t {
		S_START,
		S_GET_DOMAIN_INFO,
		S_CHECK_PASSWORD,
		S_DONE
	} state_position{S_START};

	x_auth_t auth; // base class
	x_auth_upcall_t *auth_upcall;

	std::string domain;
	std::string realm;
	std::string principal_string;
#if 0
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

	std::string client_user;
	std::string client_workstation;
	std::shared_ptr<idl::LM_RESPONSE> client_lm_resp;
	std::shared_ptr<idl::blob_t> client_nt_resp;
	std::vector<uint8_t> encrypted_session_key;
#endif

};

static void auth_krb5_post_domain_info(x_auth_krb5_t &auth)
{
	X_TODO;
}

static void auth_krb5_domain_info_cb_reply(x_wbcli_t *wbcli, int err)
{
	x_auth_krb5_t *auth = X_CONTAINER_OF(wbcli, x_auth_krb5_t, wbcli);
	X_ASSERT(auth->state_position == x_auth_krb5_t::S_GET_DOMAIN_INFO);

	if (err == 0) {
		const auto &domain_info = auth->wbresp.header.data.domain_info;
		X_LOG_DBG("err=%d, result=%d, name='%s', alt_name='%s', sid=%s, native_mode=%d, active_directory=%d, primary=%d",
				err, auth->wbresp.header.result,
				domain_info.name, domain_info.alt_name,
				domain_info.sid,
				domain_info.native_mode,
				domain_info.active_directory,
				domain_info.primary);
		auth->domain = domain_info.name;
	} else {
		DEBUG(3, ("Could not find short name: %s\n",
					wbcErrorString(wbc_status)));
		auth->domain = auth->realm;
	}

	auth_krb5_post_domain_info(*auth);
}

static const x_wb_cbs_t auth_krb5_domain_info_cbs = {
	auth_krb5_domain_info_cb_reply,
};

static void auth_krb5_get_domain_info(x_auth_krb5_t &auth)
{
	auth.state_position = x_auth_krb5_t::S_GET_DOMAIN_INFO;
	auto &requ = auth.wbrequ.header;
	requ.cmd = WINBINDD_DOMAIN_INFO;
	strncpy(requ.domain_name, auth.realm.c_str(), sizeof(requ.domain_name) - 1);

	auth.wbcli.cbs = &auth_krb5_domain_info_cbs;
	x_smbd_wbpool_request(&auth.wbcli);
}

#if 0
static void auth_krb5_getpwuid_cb_reply(x_wbcli_t *wbcli, int err)
{
	x_auth_krb5_t *auth_krb5 = X_CONTAINER_OF(wbcli, x_auth_krb5_t, wbcli);
	X_ASSERT(auth_krb5->state_position == x_auth_krb5_t::S_GETPWUID);

	if (err < 0) {
		auth_krb5->upcall->updated(NT_STATUS_INTERNAL_ERROR);
		return;
	}

	AuthUserInfo_t userinfo;
	auto &auth = auth_krb5->wbresp.header.data.auth;
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
	X_TODO;
}

static const x_wb_cbs_t ntlmssp_check_password_cbs = {
	ntlmssp_check_password_cb_reply,
};

static void ntlmssp_check_password(x_auth_krb5_t &ntlmssp, bool trusted)
{
	std::string domain;
	if (trusted) {
		domain = ntlmssp.client_domain;
	} else {
		domain = x_convert_utf16_to_utf8(ntlmssp.netbios_name);
	}
	ntlmssp.state_position = x_auth_krb5_t::S_CHECK_PASSWORD;
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
	x_smbsrv_wbpool_request(&ntlmssp.wbcli);
}

static void x_ntlmssp_is_trusted_domain(x_auth_krb5_t &ntlmssp)
{
	ntlmssp.state_position = x_auth_krb5_t::S_CHECK_TRUSTED_DOMAIN;
	auto &requ = ntlmssp.wbrequ.header;
	requ.cmd = WINBINDD_DOMAIN_INFO;
	strncpy(requ.domain_name, ntlmssp.client_domain.c_str(), sizeof(requ.domain_name) - 1);

	ntlmssp.wbcli.cbs = &ntlmssp_domain_info_cbs;
	x_smbsrv_wbpool_request(&ntlmssp.wbcli);
}
#endif

x_auth_krb5_t::x_auth_krb5_t(x_auth_context_t *context, const x_auth_ops_t *ops)
	: auth{context, ops}
{
	wbcli.requ = &wbrequ;
	wbcli.resp = &wbresp;
#if 0
	// auth_krb5_server_start
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
#endif
}
#if 0
static NTSTATUS gse_context_init(TALLOC_CTX *mem_ctx,
				 bool do_sign, bool do_seal,
				 const char *ccache_name,
				 uint32_t add_gss_c_flags,
				 struct gse_context **_gse_ctx)
{
	struct gse_context *gse_ctx;
	krb5_error_code k5ret;
	NTSTATUS status;

	gse_ctx = talloc_zero(mem_ctx, struct gse_context);
	if (!gse_ctx) {
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor((TALLOC_CTX *)gse_ctx, gse_context_destructor);

	gse_ctx->expire_time = GENSEC_EXPIRE_TIME_INFINITY;
	gse_ctx->max_wrap_buf_size = UINT16_MAX;

	memcpy(&gse_ctx->gss_mech, gss_mech_krb5, sizeof(gss_OID_desc));

	gse_ctx->gss_want_flags = GSS_C_MUTUAL_FLAG |
				GSS_C_DELEG_POLICY_FLAG |
				GSS_C_REPLAY_FLAG |
				GSS_C_SEQUENCE_FLAG;
	if (do_sign) {
		gse_ctx->gss_want_flags |= GSS_C_INTEG_FLAG;
	}
	if (do_seal) {
		gse_ctx->gss_want_flags |= GSS_C_INTEG_FLAG;
		gse_ctx->gss_want_flags |= GSS_C_CONF_FLAG;
	}

	gse_ctx->gss_want_flags |= add_gss_c_flags;

	/* Initialize Kerberos Context */
	initialize_krb5_error_table();

	k5ret = krb5_init_context(&gse_ctx->k5ctx);
	if (k5ret) {
		DEBUG(0, ("Failed to initialize kerberos context! (%s)\n",
			  error_message(k5ret)));
		status = NT_STATUS_INTERNAL_ERROR;
		goto err_out;
	}

	if (!ccache_name) {
		ccache_name = krb5_cc_default_name(gse_ctx->k5ctx);
	}
	k5ret = krb5_cc_resolve(gse_ctx->k5ctx, ccache_name,
				&gse_ctx->ccache);
	if (k5ret) {
		DEBUG(1, ("Failed to resolve credential cache! (%s)\n",
			  error_message(k5ret)));
		status = NT_STATUS_INTERNAL_ERROR;
		goto err_out;
	}

	/* TODO: Should we enforce a enc_types list ?
	ret = krb5_set_default_tgs_ktypes(gse_ctx->k5ctx, enc_types);
	*/

	*_gse_ctx = gse_ctx;
	return NT_STATUS_OK;

err_out:
	TALLOC_FREE(gse_ctx);
	return status;
}
#endif
struct auth_krb5_context_t
{
	~auth_krb5_context_t() {
		if (keytab) {
			krb5_kt_close(k5ctx, keytab);
		}
		if (k5ctx) {
			krb5_free_context(k5ctx);
		}
	}

	krb5_context k5ctx = nullptr;
	krb5_keytab keytab = nullptr;
};

static std::shared_ptr<auth_krb5_context_t> g_krb5_context;
#if 0
static NTSTATUS get_user_from_kerberos_info(
				     const char *cli_name,
				     const char *princ_name,
				     idl::PAC_LOGON_INFO *logon_info,
				     bool *is_mapped,
				     bool *mapped_to_guest,
				     char **ntuser,
				     char **ntdomain,
				     char **username,
				     struct passwd **_pw)
{
	NTSTATUS status;
	char *domain = NULL;
	char *realm = NULL;
	char *user = NULL;
	char *p;
	char *fuser = NULL;
	char *unixuser = NULL;
	struct passwd *pw = NULL;

	DEBUG(3, ("Kerberos ticket principal name is [%s]\n", princ_name));

	p = strchr_m(princ_name, '@');
	if (!p) {
		DEBUG(3, ("[%s] Doesn't look like a valid principal\n",
			  princ_name));
		return NT_STATUS_LOGON_FAILURE;
	}

	user = talloc_strndup(mem_ctx, princ_name, p - princ_name);
	if (!user) {
		return NT_STATUS_NO_MEMORY;
	}

	realm = talloc_strdup(talloc_tos(), p + 1);
	if (!realm) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!strequal(realm, lpcfg_realm())) {
		DEBUG(3, ("Ticket for foreign realm %s@%s\n", user, realm));
		if (!lp_allow_trusted_domains()) {
			return NT_STATUS_LOGON_FAILURE;
		}
	}

	if (logon_info && logon_info->info3.base.logon_domain.string) {
		domain = talloc_strdup(mem_ctx,
					logon_info->info3.base.logon_domain.string);
		if (!domain) {
			return NT_STATUS_NO_MEMORY;
		}
		DEBUG(10, ("Domain is [%s] (using PAC)\n", domain));
	} else {

		/* If we have winbind running, we can (and must) shorten the
		   username by using the short netbios name. Otherwise we will
		   have inconsistent user names. With Kerberos, we get the
		   fully qualified realm, with ntlmssp we get the short
		   name. And even w2k3 does use ntlmssp if you for example
		   connect to an ip address. */

		wbcErr wbc_status;
		struct wbcDomainInfo *info = NULL;

		DEBUG(10, ("Mapping [%s] to short name using winbindd\n",
			   realm));

		wbc_status = wbcDomainInfo(realm, &info);

		if (WBC_ERROR_IS_OK(wbc_status)) {
			domain = talloc_strdup(mem_ctx,
						info->short_name);
			wbcFreeMemory(info);
		} else {
			DEBUG(3, ("Could not find short name: %s\n",
				  wbcErrorString(wbc_status)));
			domain = talloc_strdup(mem_ctx, realm);
		}
		if (!domain) {
			return NT_STATUS_NO_MEMORY;
		}
		DEBUG(10, ("Domain is [%s] (using Winbind)\n", domain));
	}

	fuser = talloc_asprintf(mem_ctx,
				"%s%c%s",
				domain,
				*lp_winbind_separator(),
				user);
	if (!fuser) {
		return NT_STATUS_NO_MEMORY;
	}

	*is_mapped = map_username(mem_ctx, fuser, &fuser);
	if (!fuser) {
		return NT_STATUS_NO_MEMORY;
	}
	*mapped_to_guest = false;

	/* NUTANIX_DEV:
	 * First check if we can extract the passwd from info3. This will
	 * avoid the overhead of contacting DC to fill passwd info.
	 */
	if (parse_passwd_from_info3(fuser, &(logon_info->info3))) {
		DEBUG(10, ("Successfully parsed passwd from info3 and added to cache.\n"));
	}

	pw = smb_getpwnam(mem_ctx, fuser, &unixuser, true);
	if (pw) {
		if (!unixuser) {
			return NT_STATUS_NO_MEMORY;
		}
		/* if a real user check pam account restrictions */
		/* only really perfomed if "obey pam restriction" is true */
		/* do this before an eventual mapping to guest occurs */
		status = smb_pam_accountcheck(pw->pw_name, cli_name);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("PAM account restrictions prevent user "
				  "[%s] login\n", unixuser));
			return status;
		}
	}
	if (!pw) {

		/* this was originally the behavior of Samba 2.2, if a user
		   did not have a local uid but has been authenticated, then
		   map them to a guest account */

		if (lp_map_to_guest() == MAP_TO_GUEST_ON_BAD_UID) {
			*mapped_to_guest = true;
			fuser = talloc_strdup(mem_ctx, lp_guest_account());
			if (!fuser) {
				return NT_STATUS_NO_MEMORY;
			}
			pw = smb_getpwnam(mem_ctx, fuser, &unixuser, true);
		}

		/* extra sanity check that the guest account is valid */
		if (!pw) {
			DBG_NOTICE("Username %s is invalid on this system\n",
				  fuser);
			return NT_STATUS_LOGON_FAILURE;
		}
	}

	if (!unixuser) {
		return NT_STATUS_NO_MEMORY;
	}

	*username = talloc_strdup(mem_ctx, unixuser);
	if (!*username) {
		return NT_STATUS_NO_MEMORY;
	}
	*ntuser = user;
	*ntdomain = domain;
	*_pw = pw;

	return NT_STATUS_OK;
}


static NTSTATUS auth3_generate_session_info_pac(
						DATA_BLOB *pac_blob,
						const char *princ_name,
						const struct tsocket_address *remote_address,
						uint32_t session_info_flags,
						struct auth_session_info **session_info)
{
	TALLOC_CTX *tmp_ctx;
	struct PAC_LOGON_INFO *logon_info = NULL;
	struct netr_SamInfo3 *info3_copy = NULL;
	bool is_mapped;
	bool is_guest;
	char *ntuser;
	char *ntdomain;
	char *username;
	char *rhost;
	struct passwd *pw;
	NTSTATUS status;
	int rc;

	if (pac_blob) {
#ifdef HAVE_KRB5
		status = kerberos_pac_logon_info(tmp_ctx, *pac_blob, NULL, NULL,
						 NULL, NULL, 0, &logon_info);
#else
		status = NT_STATUS_ACCESS_DENIED;
#endif
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
	}

	rc = get_remote_hostname(remote_address,
				 &rhost,
				 tmp_ctx);
	if (rc < 0) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	if (strequal(rhost, "UNKNOWN")) {
		rhost = tsocket_address_inet_addr_string(remote_address,
							 tmp_ctx);
		if (rhost == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
	}

	status = get_user_from_kerberos_info(tmp_ctx, rhost,
					     princ_name, logon_info,
					     &is_mapped, &is_guest,
					     &ntuser, &ntdomain,
					     &username, &pw);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("Failed to map kerberos principal to system user "
			  "(%s)\n", nt_errstr(status));
		status = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	/* save the PAC data if we have it */
	if (logon_info) {
		status = create_info3_from_pac_logon_info(tmp_ctx,
					logon_info,
					&info3_copy);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
		netsamlogon_cache_store(ntuser, info3_copy);
	}

	/* setup the string used by %U */
	sub_set_smb_name(username);

	/* reload services so that the new %U is taken into account */
	lp_load_with_shares(get_dyn_CONFIGFILE());

	status = make_session_info_krb5(mem_ctx,
					ntuser, ntdomain, username, pw,
					info3_copy, is_guest, is_mapped, NULL /* No session key for now, caller will sort it out */,
					session_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to map kerberos pac to server info (%s)\n",
			  nt_errstr(status)));
		status = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	DEBUG(5, (__location__ "OK: user: %s domain: %s client: %s\n",
		  ntuser, ntdomain, rhost));

	status = NT_STATUS_OK;

done:
	TALLOC_FREE(tmp_ctx);
	return status;
}
#endif

/* The Heimdal OID for getting the PAC */
#define EXTRACT_PAC_AUTHZ_DATA_FROM_SEC_CONTEXT_OID_LENGTH 8
/* EXTRACTION OID		   AUTHZ ID */
#define EXTRACT_PAC_AUTHZ_DATA_FROM_SEC_CONTEXT_OID "\x2a\x85\x70\x2b\x0d\x03" "\x81\x00"

static inline OM_uint32 gssapi_obtain_pac_blob(OM_uint32 &gss_min,
		gss_ctx_id_t gss_ctx,
		gss_buffer_set_t &set)
{
	gss_OID_desc pac_data_oid = {
		.length = EXTRACT_PAC_AUTHZ_DATA_FROM_SEC_CONTEXT_OID_LENGTH,
		.elements = (void *)(EXTRACT_PAC_AUTHZ_DATA_FROM_SEC_CONTEXT_OID),
	};

	set = GSS_C_NO_BUFFER_SET;

	return gss_inquire_sec_context_by_oid(
			&gss_min, gss_ctx,
			&pac_data_oid, &set);
}

#ifndef GSS_KRB5_INQ_SSPI_SESSION_KEY_OID
#define GSS_KRB5_INQ_SSPI_SESSION_KEY_OID_LENGTH 11
#define GSS_KRB5_INQ_SSPI_SESSION_KEY_OID "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05"
#endif
// gssapi_get_session_key
static NTSTATUS auth_krb5_get_session_key(std::vector<uint8_t> &session_key,
		gss_ctx_id_t gss_ctx)
{
	gss_OID_desc gse_sesskey_inq_oid = {
		.length = GSS_KRB5_INQ_SSPI_SESSION_KEY_OID_LENGTH,
		.elements = (void *)(GSS_KRB5_INQ_SSPI_SESSION_KEY_OID)
	};

	OM_uint32 gss_min, gss_maj;
	gss_buffer_set_t set = GSS_C_NO_BUFFER_SET;

	gss_maj = gss_inquire_sec_context_by_oid(
				&gss_min, gss_ctx,
				&gse_sesskey_inq_oid, &set);
	if (gss_maj) {
		DEBUG(0, ("gss_inquire_sec_context_by_oid failed [%s]\n",
			  gssapi_error_string(mem_ctx, gss_maj, gss_min, gss_mech_krb5)));
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	if ((set == GSS_C_NO_BUFFER_SET) ||
	    (set->count == 0)) {
#ifdef HAVE_GSSKRB5_GET_SUBKEY
		krb5_keyblock *subkey;
		gss_maj = gsskrb5_get_subkey(&gss_min,
					     gss_ctx,
					     &subkey);
		if (gss_maj != 0) {
			DEBUG(1, ("NO session key for this mech\n"));
			return NT_STATUS_NO_USER_SESSION_KEY;
		}
		session_key.assign((const uint8_t *)KRB5_KEY_DATA(subkey),
				(const uint8_t *)KRB5_KEY_DATA(subkey) + KRB5_KEY_LENGTH(subkey));
#if 0
		if (keytype) {
			*keytype = KRB5_KEY_TYPE(subkey);
		}
#endif
		krb5_free_keyblock(NULL /* should be krb5_context */, subkey);
		return NT_STATUS_OK;
#else
		DEBUG(0, ("gss_inquire_sec_context_by_oid didn't return any session key (and no alternative method available)\n"));
		return NT_STATUS_NO_USER_SESSION_KEY;
#endif
	}

	session_key.assign((const uint8_t *)set->elements[0].value,
			(const uint8_t *)set->elements[0].value + set->elements[0].length);
#if 0
	if (keytype) {
		int diflen, i;
		const uint8_t *p;

		if (set->count < 2) {

#ifdef HAVE_GSSKRB5_GET_SUBKEY
			krb5_keyblock *subkey;
			gss_maj = gsskrb5_get_subkey(&gss_min,
						     gssapi_context,
						     &subkey);
			if (gss_maj == 0) {
				*keytype = KRB5_KEY_TYPE(subkey);
				krb5_free_keyblock(NULL /* should be krb5_context */, subkey);
			} else
#else
			{
				*keytype = 0;
			}
#endif
			gss_maj = gss_release_buffer_set(&gss_min, &set);
	
			return NT_STATUS_OK;

		} else if (memcmp(set->elements[1].value,
				  gse_sesskeytype_oid.elements,
				  gse_sesskeytype_oid.length) != 0) {
			/* Perhaps a non-krb5 session key */
			*keytype = 0;
			gss_maj = gss_release_buffer_set(&gss_min, &set);
			return NT_STATUS_OK;
		}
		p = (const uint8_t *)set->elements[1].value + gse_sesskeytype_oid.length;
		diflen = set->elements[1].length - gse_sesskeytype_oid.length;
		if (diflen <= 0) {
			gss_maj = gss_release_buffer_set(&gss_min, &set);
			return NT_STATUS_INVALID_PARAMETER;
		}
		*keytype = 0;
		for (i = 0; i < diflen; i++) {
			*keytype = (*keytype << 7) | (p[i] & 0x7f);
			if (i + 1 != diflen && (p[i] & 0x80) == 0) {
				gss_maj = gss_release_buffer_set(&gss_min, &set);
				return NT_STATUS_INVALID_PARAMETER;
			}
		}
	}
#endif
	gss_maj = gss_release_buffer_set(&gss_min, &set);
	return NT_STATUS_OK;
}

static x_dom_sid_with_attrs_t sid_attr_compose(
		const idl::dom_sid &d,
		uint32_t rid, uint32_t attrs)
{
	x_dom_sid_with_attrs_t s;
	X_ASSERT(d.num_auths < d.sub_auths.size() - 1);
	s.sid = d;
	s.sid.sub_auths[s.sid.num_auths++] = rid;
	s.attrs = attrs;
	return s;
}

static std::string safe_utf16_ptr_to_utf8(const std::shared_ptr<std::u16string> &u16s)
{
	std::string ret;
	if (u16s) {
		if (!x_convert_utf16_to_utf8_new(*u16s, ret)) {
			X_LOG_DBG("Invalid u16string");
		}
	}
	return ret;
}

static void auth_info_from_pac_logon_info(x_auth_info_t &auth_info, const idl::PAC_LOGON_INFO &logon_info)
{
	auth_info.logon_time = logon_info.info3.base.logon_time;
	auth_info.logoff_time = logon_info.info3.base.logoff_time;
	auth_info.kickoff_time = logon_info.info3.base.kickoff_time;
	auth_info.pass_last_set_time = logon_info.info3.base.last_password_change;
	auth_info.pass_can_change_time = logon_info.info3.base.allow_password_change;
	auth_info.pass_must_change_time = logon_info.info3.base.force_password_change;

	auth_info.account_name = logon_info.info3.base.account_name.string;
	auth_info.full_name = safe_utf16_ptr_to_utf8(logon_info.info3.base.full_name.string);
	auth_info.logon_script = safe_utf16_ptr_to_utf8(logon_info.info3.base.logon_script.string);
	auth_info.profile_path = safe_utf16_ptr_to_utf8(logon_info.info3.base.profile_path.string);
	auth_info.home_directory = safe_utf16_ptr_to_utf8(logon_info.info3.base.home_directory.string);
	auth_info.home_drive = safe_utf16_ptr_to_utf8(logon_info.info3.base.home_drive.string);

	auth_info.logon_count = logon_info.info3.base.logon_count;
	auth_info.bad_password_count = logon_info.info3.base.bad_password_count;
	auth_info.acct_flags = logon_info.info3.base.acct_flags;
	auth_info.user_flags = logon_info.info3.base.user_flags;

	auth_info.logon_server = safe_utf16_ptr_to_utf8(logon_info.info3.base.logon_server.string);
	auth_info.logon_domain = safe_utf16_ptr_to_utf8(logon_info.info3.base.logon_domain.string);

	// TODO should check if domain_sid is nullptr
	auth_info.domain_sid = *logon_info.info3.base.domain_sid;
	auth_info.rid = logon_info.info3.base.rid;
	auth_info.primary_gid = logon_info.info3.base.primary_gid;
	if (logon_info.info3.base.groups.rids) {
		auth_info.group_rids = *logon_info.info3.base.groups.rids;
	}

	if (logon_info.info3.sids) {
		for (const auto &sa: *logon_info.info3.sids) {
			auth_info.other_sids.push_back(x_dom_sid_with_attrs_t{*sa.sid, (uint32_t)sa.attributes});
		}
	}
	if (logon_info.resource_groups.domain_sid) {
		const idl::dom_sid &res_group_dom_sid = *logon_info.resource_groups.domain_sid;
		if (logon_info.resource_groups.groups.rids) {
			for (const auto &rid_with_attr : *logon_info.resource_groups.groups.rids) {
				auth_info.other_sids.push_back(sid_attr_compose(res_group_dom_sid,
							rid_with_attr.rid, rid_with_attr.attributes));
			}
		}
	}
}

// gensec_gse_session_info
static NTSTATUS auth_krb5_accepted(x_auth_krb5_t &auth, gss_ctx_id_t gss_ctx,
		gss_name_t client_name, x_auth_upcall_t *auth_upcall,
		std::shared_ptr<x_auth_info_t> &auth_info,
		uint32_t time_rec)
{
	OM_uint32 gss_maj, gss_min;
	gss_buffer_set_t pac_buffer_set = GSS_C_NO_BUFFER_SET;

	gss_maj = gssapi_obtain_pac_blob(gss_min, gss_ctx,
			pac_buffer_set);
	if (gss_maj == GSS_S_UNAVAILABLE) {
		X_LOG_DBG("unable to obtain a PAC against this GSSAPI library.  "
				"GSSAPI secured connections are available only with Heimdal or MIT Kerberos >= 1.8\n");
	} else if (gss_maj != 0) {
		DEBUG("obtaining PAC via GSSAPI gss_inqiure_sec_context_by_oid (Heimdal OID) failed: %s\n",
				gssapi_error_string(NULL, gss_maj, gss_min, gss_mech_krb5));
	} else if (pac_buffer_set == GSS_C_NO_BUFFER_SET) {
		X_LOG_DBG("gss_inquire_sec_context_by_oid returned unknown "
				"data in results.\n");
		return NT_STATUS_INTERNAL_ERROR;
	}
	auto unique_pac_buffer_set = x_gss_buffer_set_ptr_t(pac_buffer_set, [](gss_buffer_set_t p) {
			OM_uint32 min_stat;
			gss_release_buffer_set(&min_stat, &p);
		});

	const auto smbd_conf = x_smbd_conf_get();
	std::shared_ptr<idl::PAC_LOGON_INFO> logon_info;
	/* IF we have the PAC - otherwise we need to get this
	 * data from elsewere
	 */
	if (pac_buffer_set == GSS_C_NO_BUFFER_SET) {
		if (smbd_conf->gensec_require_pac) {
			DEBUG(1, ("Unable to find PAC in ticket from %s, failing to allow access\n",
				  principal_string));
			return NT_STATUS_ACCESS_DENIED;
		}
		DEBUG(1, ("Unable to find PAC for %s, resorting to local user lookup\n",
			  principal_string));
		X_TODO;
	} else {
		// auth3_generate_session_info_pac
		NTSTATUS status = kerberos_pac_logon_info(pac_buffer_set->elements, NULL, NULL,
				NULL, NULL, 0, logon_info);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	gss_buffer_desc name_token;
	gss_maj = gss_display_name(&gss_min,
			client_name,
			&name_token,
			NULL);
	if (GSS_ERROR(gss_maj)) {
		DEBUG(1, ("GSS display_name failed: %s\n",
			  gse_errstr(talloc_tos(), maj_stat, min_stat)));
		return NT_STATUS_FOOBAR;
	}

	auth.principal_string.assign((const char *)name_token.value, (const char *)name_token.value + name_token.length);
	gss_release_buffer(&gss_min, &name_token);

	auto pos = auth.principal_string.find('@');
	if (pos == std::string::npos) {
		DEBUG(3, ("[%s] Doesn't look like a valid principal\n",
					princ_name));
		return NT_STATUS_LOGON_FAILURE;
	}
	auth.realm = auth.principal_string.substr(pos + 1);
	if (auth.realm != smbd_conf->realm) { // TODO multibyte comparing
		if (!smbd_conf->allow_trusted_domains) {
			return NT_STATUS_LOGON_FAILURE;
		}
	}

	if (!logon_info/* TODO  || !logon_info->info3.base.logon_domain.string */) {
		auth_krb5_get_domain_info(auth);
	}

	std::vector<uint8_t> session_key;
	NTSTATUS status = auth_krb5_get_session_key(session_key, gss_ctx);
	if (NT_STATUS_IS_OK(status)) {
		auth_info = std::make_shared<x_auth_info_t>();
		auth_info_from_pac_logon_info(*auth_info, *logon_info);
		std::swap(auth_info->session_key, session_key);
		auth_info->time_rec = time_rec;
	}
	return status;

#if 0
	rc = get_remote_hostname(remote_address,
				 &rhost,
				 tmp_ctx);
	if (rc < 0) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	if (strequal(rhost, "UNKNOWN")) {
		rhost = tsocket_address_inet_addr_string(remote_address,
							 tmp_ctx);
		if (rhost == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
	}

	status = get_user_from_kerberos_info(tmp_ctx, rhost,
					     princ_name, logon_info,
					     &is_mapped, &is_guest,
					     &ntuser, &ntdomain,
					     &username, &pw);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("Failed to map kerberos principal to system user "
			  "(%s)\n", nt_errstr(status));
		status = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	/* save the PAC data if we have it */
	if (logon_info) {
		status = create_info3_from_pac_logon_info(tmp_ctx,
					logon_info,
					&info3_copy);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
		netsamlogon_cache_store(ntuser, info3_copy);
	}

	/* setup the string used by %U */
	sub_set_smb_name(username);

	/* reload services so that the new %U is taken into account */
	lp_load_with_shares(get_dyn_CONFIGFILE());

	status = make_session_info_krb5(mem_ctx,
					ntuser, ntdomain, username, pw,
					info3_copy, is_guest, is_mapped, NULL /* No session key for now, caller will sort it out */,
					session_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to map kerberos pac to server info (%s)\n",
			  nt_errstr(status)));
		status = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	DEBUG(5, (__location__ "OK: user: %s domain: %s client: %s\n",
		  ntuser, ntdomain, rhost));

	status = NT_STATUS_OK;

done:
	TALLOC_FREE(tmp_ctx);
	return status;
}

	gss_buffer_desc name_token;
	maj_stat = gss_display_name(&min_stat,
				    client_name,
				    &name_token,
				    NULL);
	if (GSS_ERROR(maj_stat)) {
		DEBUG(1, ("GSS display_name failed: %s\n",
			  gse_errstr(talloc_tos(), maj_stat, min_stat)));
		talloc_free(tmp_ctx);
		return NT_STATUS_FOOBAR;
	}

	gss_release_buffer(&min_stat, &name_token);

	gss_buffer_set_t pac_buffer_set = GSS_C_NO_BUFFER_SET;
	nt_status = gssapi_obtain_pac_blob(gss_ctx,
					   pac_buffer_set);

	uint32_t session_info_flags = 0;

	if (auth_krb5.want_features & GENSEC_FEATURE_UNIX_TOKEN) {
		session_info_flags |= AUTH_SESSION_INFO_UNIX_TOKEN;
	}

	session_info_flags |= AUTH_SESSION_INFO_DEFAULT_GROUPS;

	rc = get_remote_hostname(remote_address,
				 &rhost,
				 tmp_ctx);
	if (rc < 0) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	if (strequal(rhost, "UNKNOWN")) {
		rhost = tsocket_address_inet_addr_string(remote_address,
							 tmp_ctx);
		if (rhost == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
	}

	status = get_user_from_kerberos_info(tmp_ctx, rhost,
					     princ_name, logon_info,
					     &is_mapped, &is_guest,
					     &ntuser, &ntdomain,
					     &username, &pw);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("Failed to map kerberos principal to system user "
			  "(%s)\n", nt_errstr(status));
		status = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	/* save the PAC data if we have it */
	if (logon_info) {
		status = create_info3_from_pac_logon_info(tmp_ctx,
					logon_info,
					&info3_copy);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
		netsamlogon_cache_store(ntuser, info3_copy);
	}

	/* setup the string used by %U */
	sub_set_smb_name(username);

	/* reload services so that the new %U is taken into account */
	lp_load_with_shares(get_dyn_CONFIGFILE());

	status = make_session_info_krb5(mem_ctx,
					ntuser, ntdomain, username, pw,
					info3_copy, is_guest, is_mapped, NULL /* No session key for now, caller will sort it out */,
					session_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to map kerberos pac to server info (%s)\n",
			  nt_errstr(status)));
		status = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	DEBUG(5, (__location__ "OK: user: %s domain: %s client: %s\n",
		  ntuser, ntdomain, rhost));

	status = NT_STATUS_OK;

done:
	TALLOC_FREE(tmp_ctx);
	return status;
}

	return auth3_generate_session_info_pac(auth_krb5, pac_buffer_set,
			pac_blob,
			principal_string,
			remote_address,
			session_info_flags,
			session_info);


	nt_status = gensec_gse_session_key(gensec_security, session_info,
					   &session_info->session_key);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}

	*_session_info = talloc_move(mem_ctx, &session_info);
	talloc_free(tmp_ctx);
#endif
	return NT_STATUS_OK;
}

static NTSTATUS auth_krb5_update(x_auth_t *auth, const uint8_t *in_buf, size_t in_len,
		bool is_bind, uint8_t security_mode,
		std::vector<uint8_t> &out, x_auth_upcall_t *auth_upcall,
		std::shared_ptr<x_auth_info_t> &auth_info)
{
	x_auth_krb5_t *auth_krb5 = X_CONTAINER_OF(auth, x_auth_krb5_t, auth);
	NTSTATUS status;

	/* Hold a reference */
	auto auth_krb5_context = g_krb5_context;

	OM_uint32 gss_maj, gss_min;
	gss_buffer_desc in_data;
	gss_buffer_desc out_data;
	// DATA_BLOB blob = data_blob_null;
	OM_uint32 time_rec = 0;

	in_data.value = (void *)in_buf;
	in_data.length = in_len;

	gss_cred_id_t creds = nullptr;
	gss_maj = gss_krb5_import_cred(&gss_min, NULL, NULL, auth_krb5_context->keytab,
			&creds);
	X_ASSERT(gss_maj == 0);

	gss_ctx_id_t gssapi_context = nullptr;
	gss_cred_id_t delegated_cred_handle = nullptr;
	OM_uint32 /*gss_want_flags,*/ gss_got_flags;
	gss_name_t client_name;
	gss_OID ret_mech;

	gss_maj = gss_accept_sec_context(&gss_min,
					 &gssapi_context,
					 creds,
					 &in_data,
					 GSS_C_NO_CHANNEL_BINDINGS,
					 &client_name,
					 &ret_mech,
					 &out_data,
					 &gss_got_flags,
					 &time_rec,
					 &delegated_cred_handle);
	switch (gss_maj) {
	case GSS_S_COMPLETE:
		/* TODO should get end_time directly from gss context, instead the life_time
		 * see gss_accept_sec_context->_gsskrb5_accept_sec_context->gsskrb5_acceptor_start
		 */
		status = auth_krb5_accepted(*auth_krb5, gssapi_context, client_name, auth_upcall, auth_info, time_rec);
		if (NT_STATUS_IS_OK(status)) {
			out.assign((uint8_t *)out_data.value, (uint8_t *)out_data.value + out_data.length);
		}
		return status;

	case GSS_S_CONTINUE_NEEDED:
		/* we will need a third leg */
		out.assign((uint8_t *)out_data.value, (uint8_t *)out_data.value + out_data.length);
		return NT_STATUS_MORE_PROCESSING_REQUIRED;
	default:
		DEBUG(1, ("gss_accept_sec_context failed with [%s]\n",
			  gse_errstr(talloc_tos(), gss_maj, gss_min)));

		if (gssapi_context) {
			gss_delete_sec_context(&gss_min,
						&gssapi_context,
						GSS_C_NO_BUFFER);
		}

		/*
		 * If we got an output token, make Windows aware of it
		 * by telling it that more processing is needed
		 */
		if (out_data.length > 0) {
			status = NT_STATUS_MORE_PROCESSING_REQUIRED;
			/* Fall through to handle the out token */
		} else {
			return NT_STATUS_LOGON_FAILURE;
		}
	}

	X_TODO;
	return NT_STATUS_LOGON_FAILURE;
	/* we may be told to return nothing */
	if (out_data.length) {
		const uint8_t *p = (const uint8_t *)out_data.value;
		out.assign(p, p + out_data.length);
		gss_maj = gss_release_buffer(&gss_min, &out_data);
	}


	return X_NT_STATUS_INTERNAL_BLOCKED;
}

static void auth_krb5_destroy(x_auth_t *auth)
{
	x_auth_krb5_t *auth_krb5 = X_CONTAINER_OF(auth, x_auth_krb5_t, auth);
	delete auth_krb5;
}

static bool auth_krb5_have_feature(x_auth_t *auth, uint32_t feature)
{
	return false;
}

static NTSTATUS auth_krb5_check_packet(x_auth_t *auth, const uint8_t *data, size_t data_len,
		const uint8_t *whole_pdu, size_t pdu_length,
		const uint8_t *sig, size_t sig_len)
{
	X_TODO;
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS auth_krb5_sign_packet(x_auth_t *auth, const uint8_t *data, size_t data_len,
		const uint8_t *whole_pdu, size_t pdu_length,
		std::vector<uint8_t> &sig)
{
	X_TODO;
	return NT_STATUS_NOT_IMPLEMENTED;
}

static const x_auth_ops_t auth_krb5_ops = {
	auth_krb5_update,
	auth_krb5_destroy,
	auth_krb5_have_feature,
	auth_krb5_check_packet,
	auth_krb5_sign_packet,
};


x_auth_t *x_auth_create_krb5(x_auth_context_t *context)
{
	x_auth_krb5_t *auth_krb5 = new x_auth_krb5_t(context, &auth_krb5_ops);
	return &auth_krb5->auth;
}
#if 0
static bool strlower_m(char *s)
{
	for (; *s; ++s) {
		X_ASSERT((*s & 0x80) == 0); // TODO
		*s = x_convert<char>(std::tolower(*s));
	}
	return true;
}
#endif
// TODO smb_krb5_parse_name convert to utf8
#define x_krb5_parse_name krb5_parse_name
/**
* @brief Create a keyblock based on input parameters
*
* @param context	The krb5_context
* @param host_princ	The krb5_principal to use
* @param salt		The optional salt, if ommitted, salt is calculated with
*			the provided principal.
* @param password	The krb5_data containing the password
* @param enctype	The krb5_enctype to use for the keyblock generation
* @param key		The returned krb5_keyblock, caller needs to free with
*			krb5_free_keyblock().
*
* @return krb5_error_code
*/
// smb_krb5_create_key_from_string
static int x_krb5_create_key_from_string(krb5_context context,
				    krb5_const_principal host_princ,
				    krb5_data *salt,
				    krb5_data *password,
				    krb5_enctype enctype,
				    krb5_keyblock *key)
{
	int ret = 0;

	if (host_princ == NULL && salt == NULL) {
		return -1;
	}
	krb5_salt _salt;

	if (salt == NULL) {
		ret = krb5_get_pw_salt(context, host_princ, &_salt);
		if (ret) {
			DEBUG(1,("krb5_get_pw_salt failed (%s)\n", error_message(ret)));
			return ret;
		}
	} else {
		_salt.saltvalue = *salt;
		_salt.salttype = (krb5_salttype)KRB5_PW_SALT;
	}

	ret = krb5_string_to_key_salt(context, enctype, (const char *)password->data, _salt, key);
	if (salt == NULL) {
		krb5_free_salt(context, _salt);
	}
	return ret;
}

static krb5_principal kerberos_fetch_salt_princ_for_host_princ(
		const x_smbd_conf_t &smbd_conf,
		krb5_context context,
		krb5_principal host_princ,
		int enctype)
{
	krb5_principal ret_princ = NULL;

	/* lookup new key first */

#if 0
	char *unparsed_name = NULL, *salt_princ_s = NULL;
	if ( (salt_princ_s = kerberos_secrets_fetch_des_salt()) == NULL ) {

		/* look under the old key.  If this fails, just use the standard key */

		if (smb_krb5_unparse_name(talloc_tos(), context, host_princ, &unparsed_name) != 0) {
			return (krb5_principal)NULL;
		}
		if ((salt_princ_s = kerberos_secrets_fetch_salting_principal(unparsed_name, enctype)) == NULL) {
			/* fall back to host/machine.realm@REALM */
			salt_princ_s = kerberos_standard_des_salt();
		}
	}
#endif
	std::string salt_princ_s = "host/";
	salt_princ_s += smbd_conf.netbios_name;
	salt_princ_s += '.';
	for (auto c: smbd_conf.realm) {
		salt_princ_s += x_convert_assert<char>(std::tolower(c));
	}
	salt_princ_s += "@";
	salt_princ_s += smbd_conf.realm;

	if (x_krb5_parse_name(context, salt_princ_s.c_str(), &ret_princ) != 0) {
		ret_princ = NULL;
	}

	// TALLOC_FREE(unparsed_name);
	// SAFE_FREE(salt_princ_s);

	return ret_princ;
}

static krb5_error_code create_principal(krb5_context krbctx,
		krb5_principal *princ,
		const std::string &short_name,
		const std::string &domain,
		const std::string &realm)
{
	/* must be utf8 */
	std::string str = "cifs/" + short_name;
	if (domain.size()) {
		str += "." + domain;
	}
	str += "@" + realm;

	for (auto &c: str) {
		c = x_convert_assert<char>(std::tolower(c));
	}

	krb5_error_code ret = x_krb5_parse_name(krbctx, str.c_str(), princ);
	if (ret) {
		X_LOG_ERR("smb_krb5_parse_name(%s) failed (%s)",
			  str.c_str(), error_message(ret));
	}

	return ret;
}

static krb5_error_code get_alias_principals(
		const x_smbd_conf_t &smbd_conf,
		krb5_context krbctx,
		krb5_principals aliases)
{
	krb5_principal princ;
	krb5_error_code kerr = create_principal(krbctx, &princ, smbd_conf.netbios_name,
                        std::string(), smbd_conf.realm);
	if (kerr) {
		return kerr;
	}

	kerr = add_Principals(aliases, princ);
	if (kerr) {
		return kerr;
	}

	for (auto &node: smbd_conf.nodes) {
		kerr = create_principal(krbctx, &princ, node,
				smbd_conf.realm, smbd_conf.realm);
		if (kerr) {
			return kerr;
		}
		kerr = add_Principals(aliases, princ);
		if (kerr) {
			krb5_free_principal(krbctx, princ);
			return kerr;
		}
	}

	return 0;
}

static krb5_error_code get_host_principal(
		const x_smbd_conf_t &smbd_conf,
		krb5_context krbctx,
		krb5_principal *princ)
{
	return create_principal(krbctx, princ, smbd_conf.netbios_name, smbd_conf.realm,
			smbd_conf.realm);
}

static int kerberos_key_from_string(krb5_context context,
		const x_smbd_conf_t &smbd_conf,
		krb5_principal host_princ,
		krb5_data *password,
		krb5_keyblock *key,
		krb5_enctype enctype,
		bool no_salt)
{
	krb5_principal salt_princ = NULL;
	int ret;
	/*
	 * Check if we've determined that the KDC is salting keys for this
	 * principal/enctype in a non-obvious way.  If it is, try to match
	 * its behavior.
	 */
	if (no_salt) {
		KRB5_KEY_DATA(key) = (KRB5_KEY_DATA_CAST *)X_MALLOC(password->length);
		if (!KRB5_KEY_DATA(key)) {
			return ENOMEM;
		}
		memcpy(KRB5_KEY_DATA(key), password->data, password->length);
		KRB5_KEY_LENGTH(key) = password->length;
		KRB5_KEY_TYPE(key) = enctype;
		return 0;
	}
	salt_princ = kerberos_fetch_salt_princ_for_host_princ(smbd_conf, context, host_princ, enctype);
	ret = x_krb5_create_key_from_string(context,
					      salt_princ ? salt_princ : host_princ,
					      NULL,
					      password,
					      enctype,
					      key);
	if (salt_princ) {
		krb5_free_principal(context, salt_princ);
	}
	return ret;
}

/* TODO patch heimdal to add aliases */
static krb5_error_code fill_keytab_from_password(
		const x_smbd_conf_t &smbd_conf,
		krb5_context krbctx,
		krb5_keytab keytab,
		krb5_principal princ,
		krb5_principals aliases,
		krb5_kvno vno,
		const std::string &password)
{
	krb5_error_code ret;
	krb5_enctype *enctypes;
	krb5_keytab_entry kt_entry;
	unsigned int i;

	ret = krb5_get_permitted_enctypes(krbctx, &enctypes);
	if (ret) {
		X_LOG_ERR("Can't determine permitted enctypes!");
		return ret;
	}

	krb5_data pwd_data;
	pwd_data.data = (void *)password.data();
	pwd_data.length = password.size();

	for (i = 0; enctypes[i]; i++) {
		krb5_keyblock key;

		if (kerberos_key_from_string(krbctx, smbd_conf, princ,
						    &pwd_data, &key,
						    enctypes[i], false)) {
			X_LOG_DBG("Failed to create key for enctype %d "
				   "(error: %s)",
				   enctypes[i], error_message(ret));
			continue;
		}

		kt_entry.principal = princ;
		kt_entry.vno = vno;
		kt_entry.keyblock = key;
		kt_entry.aliases = aliases;
		ret = krb5_kt_add_entry(krbctx, keytab, &kt_entry);
		krb5_free_keyblock_contents(krbctx, &key);
		if (ret) {
			X_LOG_ERR("Failed to add entry to "
				  "keytab for enctype %d (error: %s)",
				   enctypes[i], error_message(ret));
			goto out;
		}

	}

	ret = 0;

out:
	SAFE_FREE(enctypes);
	return ret;
}

static krb5_error_code fill_mem_keytab_from_secrets(
		x_auth_context_t *auth_context,
		krb5_context krbctx,
		krb5_keytab keytab)
{
	krb5_error_code kerr;
	krb5_kt_cursor kt_cursor;
	krb5_keytab_entry kt_entry;
	krb5_kvno kvno = 0; /* FIXME: fetch current vno from KDC ? */

	auto smbd_conf = x_smbd_conf_get();

	std::string pwd = x_smbd_secrets_fetch_machine_password(smbd_conf->workgroup);
	if (pwd.empty()) {
		X_LOG_ERR("failed to fetch machine password");
		return KRB5_LIBOS_CANTREADPWD;
	}

	ZERO_STRUCT(kt_entry);
	ZERO_STRUCT(kt_cursor);
#if 0
	/* check if the keytab already has any entry */
	ret = krb5_kt_start_seq_get(krbctx, *keytab, &kt_cursor);
	if (ret != KRB5_KT_END && ret != ENOENT ) {
		/* check if we have our special enctype used to hold
		 * the clear text password. If so, check it out so that
		 * we can verify if the keytab needs to be upgraded */
		while ((ret = krb5_kt_next_entry(krbctx, *keytab,
					   &kt_entry, &kt_cursor)) == 0) {
			if (smb_get_enctype_from_kt_entry(&kt_entry) == CLEARTEXT_PRIV_ENCTYPE) {
				break;
			}
			smb_krb5_kt_free_entry(krbctx, &kt_entry);
			ZERO_STRUCT(kt_entry);
		}

		if (ret != 0 && ret != KRB5_KT_END && ret != ENOENT ) {
			/* Error parsing keytab */
			DEBUG(1, (__location__ ": Failed to parse memory "
				  "keytab!\n"));
			goto out;
		}

		if (ret == 0) {
			/* found private entry,
			 * check if keytab is up to date */

			if ((pwd_len == KRB5_KEY_LENGTH(KRB5_KT_KEY(&kt_entry))) &&
			    (memcmp(KRB5_KEY_DATA(KRB5_KT_KEY(&kt_entry)),
						pwd, pwd_len) == 0)) {
				/* keytab is already up to date, return */
				smb_krb5_kt_free_entry(krbctx, &kt_entry);
				goto out;
			}

			smb_krb5_kt_free_entry(krbctx, &kt_entry);
			ZERO_STRUCT(kt_entry);


			/* flush keytab, we need to regen it */
			ret = flush_keytab(krbctx, *keytab);
			if (ret) {
				DEBUG(1, (__location__ ": Failed to flush "
					  "memory keytab!\n"));
				goto out;
			}
		}
	}

	{
		krb5_kt_cursor zero_csr;
		ZERO_STRUCT(zero_csr);
		if ((memcmp(&kt_cursor, &zero_csr, sizeof(krb5_kt_cursor)) != 0) && *keytab) {
			krb5_kt_end_seq_get(krbctx, *keytab, &kt_cursor);
		}
	}
#endif
	/* keytab is not up to date, fill it up */

	krb5_principal princ = nullptr;
	kerr = get_host_principal(*smbd_conf, krbctx, &princ);
	if (kerr) {
		X_LOG_ERR("Failed to get host principal!");
		return kerr;
	}
	auto unique_princ = x_krb5_principal_ptr_t(princ, [krbctx](krb5_principal p) {
		krb5_free_principal(krbctx, p);
	});

	krb5_principals alias_princs = (krb5_principals)calloc(sizeof(*alias_princs), 1);
	if (!alias_princs) {
		return -1;
	}

	auto unique_princs = x_krb5_principals_ptr_t(alias_princs, [krbctx](krb5_principals p) {
		free_Principals(p);
	});

	kerr = get_alias_principals(*smbd_conf, krbctx, alias_princs);
	if (kerr) {
		X_LOG_ERR("Failed to get cluster principals!");
		return kerr;
	}
	kerr = fill_keytab_from_password(*smbd_conf, krbctx, keytab,
					princ, alias_princs, kvno, pwd);
	if (kerr) {
		X_LOG_ERR("Failed to fill memory keytab!");
		return kerr;
	}

	std::string pwd_old = x_smbd_secrets_fetch_prev_machine_password(smbd_conf->workgroup);
	if (pwd_old.empty()) {
		X_LOG_DBG("no prev machine password");
	} else {
		kerr = fill_keytab_from_password(*smbd_conf, krbctx, keytab,
				princ, alias_princs, kvno -1, pwd_old);
		if (kerr) {
			X_LOG_ERR("Failed to fill memory keytab!");
			return kerr;
		}
	}
	return 0;
#if 0
	/* add our private enctype + cleartext password so that we can
	 * update the keytab if secrets change later on */
	ZERO_STRUCT(kt_entry);
	kt_entry.principal = princ;
	kt_entry.vno = 0;

	KRB5_KEY_TYPE(KRB5_KT_KEY(&kt_entry)) = CLEARTEXT_PRIV_ENCTYPE;
	KRB5_KEY_LENGTH(KRB5_KT_KEY(&kt_entry)) = pwd_len;
	KRB5_KEY_DATA(KRB5_KT_KEY(&kt_entry)) = (uint8_t *)pwd;

	ret = krb5_kt_add_entry(krbctx, *keytab, &kt_entry);
	if (ret) {
		DEBUG(1, (__location__ ": Failed to add entry to "
			  "keytab for private enctype (%d) (error: %s)\n",
			   CLEARTEXT_PRIV_ENCTYPE, error_message(ret)));
		goto out;
	}
	ret = 0;

out:

	{
		krb5_kt_cursor zero_csr;
		ZERO_STRUCT(zero_csr);
		if ((memcmp(&kt_cursor, &zero_csr, sizeof(krb5_kt_cursor)) != 0) && *keytab) {
			krb5_kt_end_seq_get(krbctx, *keytab, &kt_cursor);
		}
	}

	if (princ) {
		krb5_free_principal(krbctx, princ);
	}
	if (node_princs) {
		krb5_free_principals(krbctx, node_princs);
	}
	return ret;
#endif
}

/* we use g_krb5_context to cache the keytab, actually we do not need krb5 MEMORY,
 * but I cannot find a simple way to create keytab and keys.
 * should use a generation number in name to recreate keytab after password changing.
 */
#define SRV_MEM_KEYTAB_NAME "MEMORY:cifs_srv_keytab"
static std::shared_ptr<auth_krb5_context_t> load_krb5_context(x_auth_context_t *context)
{
	auto ret = std::make_shared<auth_krb5_context_t>();
	krb5_error_code k5err = krb5_init_context(&ret->k5ctx);
	X_ASSERT(!k5err);
	k5err = krb5_kt_resolve(ret->k5ctx, SRV_MEM_KEYTAB_NAME, &ret->keytab);
	X_ASSERT(!k5err);
	k5err = fill_mem_keytab_from_secrets(context, ret->k5ctx, ret->keytab);
	X_ASSERT(!k5err);
	return ret;
}

int x_auth_krb5_init(x_auth_context_t *context)
{
	initialize_krb5_error_table();
	g_krb5_context = load_krb5_context(context);
	// x_auth_register(
	return 0;
}

