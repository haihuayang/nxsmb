
#ifndef __auth__hxx__
#define __auth__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "samba/include/config.h"
#include <vector>
#include <string>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "smb2.hxx"
#include "misc.hxx"
#include "include/utils.hxx"
#include "include/librpc/misc.hxx"
#include "include/librpc/security.hxx"
#include "include/librpc/samr.hxx"
#include <gssapi.h>
extern "C" {
#include "samba/libcli/util/ntstatus.h"
#include "samba/source3/include/ntioctl.h"
}


#define GENSEC_FEATURE_SESSION_KEY	0x00000001
#define GENSEC_FEATURE_SIGN		0x00000002
#define GENSEC_FEATURE_SEAL		0x00000004
#define GENSEC_FEATURE_DCE_STYLE	0x00000008
#define GENSEC_FEATURE_ASYNC_REPLIES	0x00000010
#define GENSEC_FEATURE_DATAGRAM_MODE	0x00000020
#define GENSEC_FEATURE_SIGN_PKT_HEADER	0x00000040
#define GENSEC_FEATURE_NEW_SPNEGO	0x00000080
#define GENSEC_FEATURE_UNIX_TOKEN	0x00000100
#define GENSEC_FEATURE_NTLM_CCACHE	0x00000200
#define GENSEC_FEATURE_LDAP_STYLE	0x00000400

#define GENSEC_EXPIRE_TIME_INFINITY (NTTIME)0x8000000000000000LL

struct x_auth_context_t;

struct x_auth_t;

struct x_dom_sid_with_attrs_t
{
	idl::dom_sid sid;
	uint32_t attrs;
};

struct x_auth_info_t
{
	uint32_t user_flags;

	std::string account_name;
	std::string user_principal;
	std::string full_name;
	std::string logon_domain;
	std::string dns_domain_name;

	uint32_t acct_flags;
#if 0
	uint8_t user_session_key[16];
	uint8_t lm_session_key[8];
#endif
	uint32_t logon_count;
	uint32_t bad_password_count;

	idl::NTTIME logon_time;
	idl::NTTIME logoff_time;
	idl::NTTIME kickoff_time;
	idl::NTTIME pass_last_set_time;
	idl::NTTIME pass_can_change_time;
	idl::NTTIME pass_must_change_time;

	std::string logon_server;
	std::string logon_script;
	std::string profile_path;
	std::string home_directory;
	std::string home_drive;

	uint32_t rid, primary_gid;
	idl::dom_sid domain_sid;
	std::vector<idl::samr_RidWithAttribute> group_rids;

	/*
	 * info3.sids and res_group sids
	 */
	std::vector<x_dom_sid_with_attrs_t> other_sids;
	std::vector<uint8_t> session_key;
	uint32_t time_rec = -1; // auth expired time in seconds, -1 means no expiration
};

struct x_auth_upcall_t;
struct x_auth_cbs_t
{
	void (*updated)(x_auth_upcall_t *upcall, NTSTATUS status,
			bool is_bind,
			std::vector<uint8_t> &out_security,
			std::shared_ptr<x_auth_info_t> &auth_info);
};

struct x_auth_upcall_t
{
	const x_auth_cbs_t *cbs;
	void updated(NTSTATUS status, bool is_bind,
			std::vector<uint8_t> &out_security,
			std::shared_ptr<x_auth_info_t> auth_info) {
		cbs->updated(this, status, is_bind, out_security, auth_info);
	}
};

struct x_auth_ops_t
{
	NTSTATUS (*update)(x_auth_t *auth, const uint8_t *in_buf, size_t in_len,
			bool is_bind,
			std::vector<uint8_t> &out, x_auth_upcall_t *auth_upcall,
			std::shared_ptr<x_auth_info_t> &auth_info);
	void (*destroy)(x_auth_t *auth);
	bool (*have_feature)(x_auth_t *auth, uint32_t feature);
	NTSTATUS (*check_packet)(x_auth_t *auth, const uint8_t *data, size_t data_len,
			const uint8_t *whole_pdu, size_t pdu_length,
			const uint8_t *sig, size_t sig_len);
	NTSTATUS (*sign_packet)(x_auth_t *auth, const uint8_t *data, size_t data_len,
			const uint8_t *whole_pdu, size_t pdu_length,
			std::vector<uint8_t> &sig);
};

struct x_auth_t
{
	explicit x_auth_t(x_auth_context_t *context, const x_auth_ops_t *ops)
		: context(context), ops(ops) { }

	NTSTATUS update(const uint8_t *in_buf, size_t in_len,
			bool is_bind,
			std::vector<uint8_t> &out, x_auth_upcall_t *upcall,
			std::shared_ptr<x_auth_info_t> &auth_info) {
		return ops->update(this, in_buf, in_len, is_bind, out, upcall, auth_info);
	}

	bool have_feature(uint32_t feature) {
		return ops->have_feature(this, feature);
	}

	NTSTATUS check_packet(const uint8_t *data, size_t data_len,
			const uint8_t *whole_pdu, size_t pdu_length,
			const uint8_t *sig, size_t sig_len) {
		return ops->check_packet(this, data, data_len, whole_pdu, pdu_length, sig, sig_len);
	}

	NTSTATUS sign_packet(const uint8_t *data, size_t data_len,
			const uint8_t *whole_pdu, size_t pdu_length,
			std::vector<uint8_t> &sig) {
		return ops->sign_packet(this, data, data_len, whole_pdu, pdu_length, sig);
	}
#if 0
	const std::shared_ptr<x_smbconf_t> get_smbconf() const {
		return x_auth_context_get_smbconf(context);
	}
#endif
	x_auth_context_t * const context;
	const x_auth_ops_t * const ops;
};

static inline void x_auth_destroy(x_auth_t *auth) {
	return auth->ops->destroy(auth);
}

struct x_auth_mech_t
{
	gss_const_OID oid;
	x_auth_t *(*create)(x_auth_context_t *context);
};

int x_auth_spnego_init(x_auth_context_t *context);
x_auth_t *x_auth_create_ntlmssp(x_auth_context_t *context);
int x_auth_ntlmssp_init(x_auth_context_t *context);
x_auth_t *x_auth_create_krb5(x_auth_context_t *context);
int x_auth_krb5_init(x_auth_context_t *context);

x_auth_t *x_auth_create_by_oid(x_auth_context_t *context, gss_const_OID oid);
int x_auth_register(x_auth_context_t *context, const x_auth_mech_t *mech);

extern const x_auth_mech_t x_auth_mech_spnego;

x_auth_context_t *x_auth_create_context();

#endif /* __auth__hxx__ */

