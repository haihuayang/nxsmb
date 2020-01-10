
#ifndef __smbd__hxx__
#define __smbd__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "samba/include/config.h"
#include "include/evtmgmt.hxx"
#include "include/wbpool.hxx"
#include <vector>
#include <memory>
#include <mutex>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "smbconf.hxx"
#include "misc.hxx"
#include "include/utils.hxx"
#include "include/librpc/ndr_misc.hxx"
#include "include/librpc/ndr_security.hxx"
#include "include/librpc/ndr_samr.hxx"
extern "C" {
#include "samba/libcli/smb/smb_constants.h"
#include "samba/libcli/smb/smb2_constants.h"
#include "samba/libcli/util/ntstatus.h"
#include "samba/lib/util/byteorder.h"
#include "samba/source4/heimdal/lib/gssapi/gssapi/gssapi.h"
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

#define X_NT_STATUS_INTERNAL_BLOCKED	NT_STATUS(1)

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
	uint16_t logon_count;
	uint16_t bad_password_count;

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
};

struct x_auth_upcall_t;
struct x_auth_cbs_t
{
	void (*updated)(x_auth_upcall_t *upcall, NTSTATUS status, std::vector<uint8_t> &out_security,
			std::shared_ptr<x_auth_info_t> &auth_info);
};

struct x_auth_upcall_t
{
	const x_auth_cbs_t *cbs;
	void updated(NTSTATUS status, std::vector<uint8_t> &out_security, std::shared_ptr<x_auth_info_t> auth_info) {
		cbs->updated(this, status, out_security, auth_info);
	}
};

struct x_auth_ops_t
{
	NTSTATUS (*update)(x_auth_t *auth, const uint8_t *in_buf, size_t in_len,
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
			std::vector<uint8_t> &out, x_auth_upcall_t *upcall,
			std::shared_ptr<x_auth_info_t> &auth_info) {
		return ops->update(this, in_buf, in_len, out, upcall, auth_info);
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


struct x_smbconf_t
{
	x_smbconf_t() {
		strcpy((char *)guid, "rio-svr1");
	}
	std::vector<uint16_t> dialects{0x302, 0x210, 0x202};
	// std::vector<uint16_t> dialects{0x201};
	size_t max_trans = 1024 * 1024;
	size_t max_read = 1024 * 1024;
	size_t max_write = 1024 * 1024;
	uint8_t guid[16];
};

struct x_smbd_t
{
	x_epoll_upcall_t upcall;
	uint64_t ep_id;
	int fd;

	x_smbconf_t conf;

	x_auth_context_t *auth_context;
	std::vector<uint8_t> negprot_spnego;
};

struct x_msg_t
{
	explicit x_msg_t(size_t nbt_hdr) : nbt_hdr(nbt_hdr) {
		in_buf = new uint8_t[nbt_hdr & 0xffffff];
	}
	~x_msg_t() {
		if (in_buf) {
			delete[] in_buf;
		}
		if (out_buf) {
			delete[] out_buf;
		}
	}
	x_dlink_t dlink;
	uint64_t mid;
	uint16_t opcode;
	bool do_signing{false};
	const uint32_t nbt_hdr;
	enum {
		STATE_READING,
		STATE_PROCESSING,
		STATE_COMPLETE,
		STATE_ABORT,
	} state = STATE_READING;
	unsigned int in_len = 0;
	unsigned int in_off;
	uint8_t *in_buf;
	unsigned int out_len = 0;
	unsigned int out_off;
	uint8_t *out_buf = NULL;
};
X_DECLARE_MEMBER_TRAITS(msg_dlink_traits, x_msg_t, dlink)

struct x_smbuser_t
{
	// security token
};

using x_smb2_key_t = std::array<uint8_t, 16>;
struct x_smbdconn_t;
struct x_smbdsess_t
{
	explicit x_smbdsess_t(x_smbdconn_t *smbdconn);
	~x_smbdsess_t() {
		if (auth) {
			x_auth_destroy(auth);
		}
	}
	void incref() {
		X_ASSERT(refcnt++ > 0);
	}

	void decref() {
		if (unlikely(--refcnt == 0)) {
			delete this;
		}
	}
#if 0
	enum {
		SF_PROCESSING = 1,
		SF_WAITINPUT = 1 << 1,
		SF_ACTIVE = 1 << 2,
		SF_BLOCKED = 1 << 3,
		SF_FAILED = 1 << 4,
		SF_EXPIRED = 1 << 5,
		SF_SHUTDOWN = 1 << 6,
	};
#endif
	enum {
		S_PROCESSING,
		S_WAIT_INPUT,
		S_ACTIVE,
		S_BLOCKED,
		S_FAILED,
		S_EXPIRED,
		S_SHUTDOWN,
	};
	x_dqlink_t hash_link;
	x_dlink_t conn_link;

	x_auth_upcall_t auth_upcall;

	x_smbdconn_t *smbdconn;
	uint64_t id;
	x_tick_t timeout;
	std::atomic<uint32_t> state{S_PROCESSING};
	std::atomic<int> refcnt;
	std::mutex mutex;
	std::shared_ptr<x_smbuser_t> user;
	x_auth_t *auth{nullptr};
	x_msg_t *authmsg{nullptr};

	x_smb2_key_t signing_key, decryption_key, encryption_key, application_key;

};
X_DECLARE_MEMBER_TRAITS(smbdsess_hash_traits, x_smbdsess_t, hash_link)
X_DECLARE_MEMBER_TRAITS(smbdsess_conn_traits, x_smbdsess_t, conn_link)

struct x_fdevt_user_t
{
	x_dlink_t link;
	void (*func)(x_smbdconn_t *smbdconn, x_fdevt_user_t *);
};
X_DECLARE_MEMBER_TRAITS(fdevt_user_conn_traits, x_fdevt_user_t, link)

struct x_smbdconn_t
{
	enum { MAX_MSG = 4 };
	x_smbdconn_t(x_smbd_t *smbd, int fd_, const struct sockaddr_in &sin_)
		: smbd(smbd), fd(fd_), sin(sin_) { }
	~x_smbdconn_t();

	const x_smbconf_t &get_conf() const {
		return smbd->conf;
	}

	void incref() {
		X_ASSERT(refcnt++ > 0);
	}

	void decref() {
		if (unlikely(--refcnt == 0)) {
			delete this;
		}
	}

	x_epoll_upcall_t upcall;
	uint64_t ep_id;
	std::mutex mutex;
	x_smbd_t * const smbd;
	std::atomic<int> refcnt{1};
	enum { STATE_RUNNING, STATE_DONE } state{STATE_RUNNING};
	int fd;
	unsigned int count_msg = 0;
	const struct sockaddr_in sin;
	uint16_t dialect;

	uint16_t server_security_mode;
	uint32_t server_capabilities;
	uint16_t client_security_mode;
	uint32_t client_capabilities;
	idl::GUID client_guid;

	uint64_t credit_seq_low = 0;
	uint64_t credit_seq_range = 1;
	uint64_t credit_granted = 1;
	uint64_t credit_max = lp_smb2_max_credits();
	// xconn->smb2.credits.bitmap = bitmap_talloc(xconn, xconn->smb2.credits.max);
	uint32_t read_length = 0;
	uint32_t nbt_hdr;
	x_msg_t *recving_msg = NULL;
	x_msg_t *sending_msg = NULL;
	x_tp_ddlist_t<msg_dlink_traits> send_queue;
	x_tp_ddlist_t<smbdsess_conn_traits> session_list;
	x_tp_ddlist_t<smbdsess_conn_traits> session_wait_input_list;
	x_tp_ddlist_t<fdevt_user_conn_traits> fdevt_user_list;
};

int x_smbdsess_pool_init(x_evtmgmt_t *ep, uint32_t count);
x_smbdsess_t *x_smbdsess_create(x_smbdconn_t *smbdconn);
x_smbdsess_t *x_smbdsess_find(uint64_t id, const x_smbdconn_t *smbdconn);
void x_smbdsess_release(x_smbdsess_t *smbdsess);

int x_auth_spnego_init(x_auth_context_t *context);
x_auth_t *x_auth_create_ntlmssp(x_auth_context_t *context);
int x_auth_ntlmssp_init(x_auth_context_t *context);
x_auth_t *x_auth_create_krb5(x_auth_context_t *context);
int x_auth_krb5_init(x_auth_context_t *context);

x_auth_context_t *x_auth_create_context();
x_auth_t *x_auth_create_by_oid(x_auth_context_t *context, gss_const_OID oid);
int x_auth_register(x_auth_context_t *context, const x_auth_mech_t *mech);

extern const x_auth_mech_t x_auth_mech_spnego;

x_auth_t *x_smbd_create_auth(x_smbd_t *smbd);

void x_smbdconn_remove_sessions(x_smbdconn_t *smbdconn);
void x_smbdconn_post_user(x_smbdconn_t *smbdconn, x_fdevt_user_t *fdevt_user);

void x_smbdconn_reply(x_smbdconn_t *smbdconn, x_msg_t *msg, x_smbdsess_t *smbdsess);
int x_smb2_reply_error(x_smbdconn_t *smbdconn, x_msg_t *msg, x_smbdsess_t *smbdsess,
		NTSTATUS status);

int x_smbdconn_process_smb1negoprot(x_smbdconn_t *smbdconn, x_msg_t *msg,
		const uint8_t *buf, size_t len);
int x_smb2_process_NEGPROT(x_smbdconn_t *smbdconn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len);
int x_smb2_process_SESSSETUP(x_smbdconn_t *smbdconn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len);

// void x_smbdsess_auth_updated(x_auth_upcall_t *upcall, NTSTATUS status, std::vector<uint8_t> &response);

void x_smbd_wbpool_request(x_wbcli_t *wbcli);

void x_smb2_key_derivation(const uint8_t *KI, size_t KI_len,
		const x_array_const_t<char> &label,
		const x_array_const_t<char> &context,
		x_smb2_key_t &key);
NTSTATUS x_smb2_sign_msg(uint8_t *data, size_t length, uint16_t dialect,
		const x_smb2_key_t &key);

#endif /* __smbd__hxx__ */

