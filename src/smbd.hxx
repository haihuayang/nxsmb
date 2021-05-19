
#ifndef __smbd__hxx__
#define __smbd__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "samba/include/config.h"
#include "include/evtmgmt.hxx"
#include "include/wbpool.hxx"
#include <vector>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "smbconf.hxx"
#include "smb2.hxx"
#include "misc.hxx"
#include "network.hxx"
#include "include/utils.hxx"
#include "include/librpc/misc.hxx"
#include "include/librpc/security.hxx"
#include "include/librpc/samr.hxx"
extern "C" {
#include "samba/libcli/smb/smb_constants.h"
#include "samba/libcli/smb/smb2_constants.h"
#include "samba/libcli/util/ntstatus.h"
#include "samba/lib/util/byteorder.h"
#include "samba/source3/include/ntioctl.h"
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
#define X_NT_STATUS_INTERNAL_TERMINATE	NT_STATUS(2)

struct x_auth_context_t;
const std::shared_ptr<x_smbconf_t> x_auth_context_get_smbconf(const x_auth_context_t *);

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

	const std::shared_ptr<x_smbconf_t> get_smbconf() const {
		return x_auth_context_get_smbconf(context);
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


struct x_smbd_t
{
	x_epoll_upcall_t upcall;
	uint64_t ep_id;
	int fd;

	std::shared_ptr<x_smbconf_t> smbconf;
	uint32_t capabilities;

	x_auth_context_t *auth_context;
	std::vector<uint8_t> negprot_spnego;
};
int x_smbd_parse_cmdline(std::shared_ptr<x_smbconf_t> &smbconf, int argc, char **argv);

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
	// x_dlink_t dlink;
	uint64_t mid;
	uint32_t hdr_flags;
	uint16_t opcode;
	uint16_t credits_requested;
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
//X_DECLARE_MEMBER_TRAITS(msg_dlink_traits, x_msg_t, dlink)

using x_msg_ptr_t = std::shared_ptr<x_msg_t>;


struct x_smbduser_t
{
	// security token
};

struct x_smbd_open_t;

struct x_smb2_create_close_info_t
{
	idl::NTTIME out_create_ts;
	idl::NTTIME out_last_access_ts;
	idl::NTTIME out_last_write_ts;
	idl::NTTIME out_change_ts;
	uint64_t out_allocation_size{0};
	uint64_t out_end_of_file{0};
	uint32_t out_file_attributes{0};
};

struct x_smb2_requ_create_t
{
	uint8_t in_oplock_level;
	uint32_t in_impersonation_level;
	uint32_t in_desired_access;
	uint32_t in_file_attributes;
	uint32_t in_share_access;
	uint32_t in_create_disposition;
	uint32_t in_create_options;

	std::u16string in_name;
	// TODO in_contexts

	uint8_t out_oplock_level;
	uint8_t out_create_flags;
	uint32_t out_create_action;
	x_smb2_create_close_info_t out_info;

	// TODO out_contexts
};

struct x_smbd_conn_t;
struct x_smbd_tcon_t;
struct x_smbd_tcon_ops_t
{
	x_smbd_open_t *(*create)(std::shared_ptr<x_smbd_tcon_t>&,
			NTSTATUS &status, uint32_t in_hdr_flags,
			x_smb2_requ_create_t &);
};

struct x_smbd_tcon_t
{ 
	x_smbd_tcon_t(const std::shared_ptr<x_smbshare_t> &share) : smbshare(share) { }
	x_smbshare_type_t get_share_type() const {
		return smbshare->type;
	}

	const x_smbd_tcon_ops_t *ops;
	uint32_t tid;
	uint32_t share_access;
	std::shared_ptr<x_smbshare_t> smbshare;
	// std::vector<std::shared_ptr<x_smbd_open_t>> smbd_opens;
};

static inline x_smbd_open_t *x_smbd_tcon_op_create(std::shared_ptr<x_smbd_tcon_t> &smbd_tcon,
		NTSTATUS &status, uint32_t in_hdr_flags, x_smb2_requ_create_t &requ_create)
{
	return smbd_tcon->ops->create(smbd_tcon, status, in_hdr_flags, requ_create);
}

void x_smbd_tcon_init_ipc(x_smbd_tcon_t *smbd_tcon);
void x_smbd_tcon_init_disk(x_smbd_tcon_t *smbd_tcon);

int x_smbd_disk_init(size_t max_open);
int x_smbd_ipc_init();

struct x_smb2_requ_ioctl_t
{
	uint16_t struct_size;
	uint16_t reserved0;
	uint32_t ctl_code;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	uint32_t input_offset;
	uint32_t input_length;
	uint32_t max_input_length;
	uint32_t output_offset;
	uint32_t output_length;
	uint32_t max_output_length;
	uint32_t flags;
	uint32_t reserved1;
};

struct x_smb2_requ_read_t
{
	uint16_t struct_size;
	uint8_t flags;
	uint8_t reserved;
	uint32_t length;
	uint64_t offset;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	uint32_t minimum_count;
	uint32_t reserved1;
	uint32_t remaining_bytes;
	uint32_t reserved2; // channel
};

struct x_smb2_resp_read_t
{
	uint16_t struct_size;
	uint16_t data_offset;
	uint32_t data_length;
	uint32_t read_remaining;
	uint32_t reserved;
};

struct x_smb2_requ_write_t
{
	uint16_t struct_size;
	uint16_t data_offset;
	uint32_t data_length;
	uint64_t offset;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	uint32_t channel;
	uint32_t remaining_bytes;
	uint32_t reserved;
	uint32_t flags;
};

struct x_smb2_resp_write_t
{
	uint16_t struct_size;
	uint16_t reserved;
	uint32_t write_count;
	uint32_t write_remaining;
};

struct x_smb2_requ_close_t
{
	uint16_t struct_size;
	uint16_t flags;
	uint32_t reserved;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
};

struct x_smb2_resp_close_t
{
	uint16_t struct_size;
	uint16_t flags{0};
	uint32_t reserved{0};
	x_smb2_create_close_info_t out_info;
};

struct x_smb2_requ_getinfo_t
{
	uint16_t struct_size;
	uint8_t  info_class;
	uint8_t  info_level;
	uint32_t output_buffer_length;
	uint16_t input_buffer_offset;
	uint16_t reserve;
	uint32_t input_buffer_length;
	uint32_t additional;
	uint32_t flags;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
};

struct x_smb2_requ_setinfo_t
{
	uint16_t struct_size;
	uint8_t  info_class;
	uint8_t  info_level;
	uint32_t input_buffer_length;
	uint16_t input_buffer_offset;
	uint16_t reserve;
	uint32_t additional;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
};

struct x_smb2_requ_find_t
{
	uint8_t in_info_level;
	uint8_t in_flags;
	uint32_t in_file_index;
	uint32_t in_output_buffer_length;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	std::u16string in_name;
};

struct x_smb2_requ_notify_t
{
	uint16_t struct_size;
	uint16_t flags;
	uint32_t output_length;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	uint32_t filter;
	uint32_t reserved;
};

struct x_smbd_open_ops_t
{
	NTSTATUS (*read)(x_smbd_conn_t *smbd_conn,
			x_msg_ptr_t &msg,
			x_smbd_open_t *smbd_open, const x_smb2_requ_read_t &requ,
			std::vector<uint8_t> &output);
	NTSTATUS (*write)(x_smbd_conn_t *smbd_conn,
			x_msg_ptr_t &msg,
			x_smbd_open_t *smbd_open, const x_smb2_requ_write_t &requ,
			const uint8_t *data,
			x_smb2_resp_write_t &resp);
	NTSTATUS (*getinfo)(x_smbd_conn_t *smbd_conn,
			x_msg_ptr_t &msg,
			x_smbd_open_t *smbd_open, const x_smb2_requ_getinfo_t &requ, std::vector<uint8_t> &output);
	NTSTATUS (*setinfo)(x_smbd_conn_t *smbd_conn,
			x_msg_ptr_t &msg,
			x_smbd_open_t *smbd_open, const x_smb2_requ_setinfo_t &requ, const uint8_t *data);
	NTSTATUS (*find)(x_smbd_conn_t *smbd_conn,
			x_msg_ptr_t &msg,
			x_smbd_open_t *smbd_open, const x_smb2_requ_find_t &requ,
			std::vector<uint8_t> &output);
	NTSTATUS (*ioctl)(x_smbd_conn_t *smbd_conn,
			x_msg_ptr_t &msg,
			x_smbd_open_t *smbd_open,
			uint32_t ctl_code,
			const uint8_t *in_input_data,
			uint32_t in_input_size,
			uint32_t in_max_output,
			std::vector<uint8_t> &output);
	NTSTATUS (*notify)(x_smbd_conn_t *smbd_conn,
			x_msg_ptr_t &msg,
			x_smbd_open_t *smbd_open, const x_smb2_requ_notify_t &requ, std::vector<uint8_t> &output);
	NTSTATUS (*close)(x_smbd_conn_t *smbd_conn,
			x_msg_ptr_t &msg,
			x_smbd_open_t *smbd_open, const x_smb2_requ_close_t &requ,
			x_smb2_resp_close_t &resp);
	void (*destroy)(x_smbd_open_t *smbd_open);
};

struct x_smbd_open_t
{
	void incref() {
		X_ASSERT(refcnt++ > 0);
	}

	void decref() {
		if (unlikely(--refcnt == 0)) {
			ops->destroy(this);
		}
	}
	x_dqlink_t hash_link;
	// x_dlink_t tcon_link;
	const x_smbd_open_ops_t *ops;
	uint64_t id;

	uint32_t access_mask, share_access;
	std::shared_ptr<x_smbd_tcon_t> smbd_tcon;
	std::atomic<int> refcnt{1};
};
X_DECLARE_MEMBER_TRAITS(smbd_open_hash_traits, x_smbd_open_t, hash_link)

static inline NTSTATUS x_smbd_open_op_read(x_smbd_conn_t *smbd_conn,
		x_msg_ptr_t &msg,
		x_smbd_open_t *smbd_open, const x_smb2_requ_read_t &requ, std::vector<uint8_t> &output)
{
	return smbd_open->ops->read(smbd_conn, msg, smbd_open, requ, output);
}

static inline NTSTATUS x_smbd_open_op_write(x_smbd_conn_t *smbd_conn,
		x_msg_ptr_t &msg,
		x_smbd_open_t *smbd_open, const x_smb2_requ_write_t &requ,
		const uint8_t *data,
		x_smb2_resp_write_t &resp)
{
	return smbd_open->ops->write(smbd_conn, msg, smbd_open, requ, data, resp);
}

static inline NTSTATUS x_smbd_open_op_getinfo(x_smbd_conn_t *smbd_conn,
		x_msg_ptr_t &msg,
		x_smbd_open_t *smbd_open, const x_smb2_requ_getinfo_t &requ, std::vector<uint8_t> &output)
{
	return smbd_open->ops->getinfo(smbd_conn, msg, smbd_open, requ, output);
}

static inline NTSTATUS x_smbd_open_op_setinfo(x_smbd_conn_t *smbd_conn,
		x_msg_ptr_t &msg,
		x_smbd_open_t *smbd_open, const x_smb2_requ_setinfo_t &requ, const uint8_t *data)
{
	return smbd_open->ops->setinfo(smbd_conn, msg, smbd_open, requ, data);
}

static inline NTSTATUS x_smbd_open_op_find(x_smbd_conn_t *smbd_conn,
		x_msg_ptr_t &msg,
		x_smbd_open_t *smbd_open, const x_smb2_requ_find_t &requ, std::vector<uint8_t> &output)
{
	return smbd_open->ops->find(smbd_conn, msg, smbd_open, requ, output);
}

static inline NTSTATUS x_smbd_open_op_ioctl(x_smbd_conn_t *smbd_conn,
		x_msg_ptr_t &msg,
		x_smbd_open_t *smbd_open,
		uint32_t ctl_code,
		const uint8_t *in_input_data,
		uint32_t in_input_size,
		uint32_t in_max_output,
		std::vector<uint8_t> &output)
{
	return smbd_open->ops->ioctl(smbd_conn, msg, smbd_open, ctl_code, in_input_data, in_input_size, in_max_output, output);
}

static inline NTSTATUS x_smbd_open_op_notify(x_smbd_conn_t *smbd_conn,
		x_msg_ptr_t &msg,
		x_smbd_open_t *smbd_open, const x_smb2_requ_notify_t &requ, std::vector<uint8_t> &output)
{
	return smbd_open->ops->notify(smbd_conn, msg, smbd_open, requ, output);
}

static inline NTSTATUS x_smbd_open_op_close(x_smbd_conn_t *smbd_conn,
		x_msg_ptr_t &msg,
		x_smbd_open_t *smbd_open, const x_smb2_requ_close_t &requ,
		x_smb2_resp_close_t &resp)
{
	return smbd_open->ops->close(smbd_conn, msg, smbd_open, requ, resp);
}

void x_smbd_open_insert_local(x_smbd_open_t *smbd_open);
x_smbd_open_t *x_smbd_open_find(uint64_t id, const x_smbd_tcon_t *smbd_tcon);
void x_smbd_open_release(x_smbd_open_t *smbd_open);

#if 0
x_smbd_open_t *x_smbd_open_create(x_smbd_tcon_t *smbd_tcon);
struct x_smbd_tcon_t
{
	x_dqlink_t hash_link;
	x_dlink_t link_session;
	std::atomic<int> ref;

	/* pointer share */
};
X_DECLARE_MEMBER_TRAITS(tcon_dlink_traits, x_smbd_tcon_t, link_session)
#endif
using x_smb2_key_t = std::array<uint8_t, 16>;
struct x_smbd_sess_t
{
	explicit x_smbd_sess_t(x_smbd_conn_t *smbd_conn);
	~x_smbd_sess_t() {
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

	x_smbd_conn_t *smbd_conn;
	uint64_t id;
	x_tick_t timeout;
	std::atomic<uint32_t> state{S_PROCESSING};
	std::atomic<int> refcnt;
	std::mutex mutex;
	std::shared_ptr<x_smbduser_t> user;
	x_auth_t *auth{nullptr};
	x_msg_ptr_t authmsg;

	x_smb2_preauth_t preauth;
	x_smb2_key_t signing_key, decryption_key, encryption_key, application_key;

	uint32_t next_tcon_id = 1;
	std::map<uint32_t, std::shared_ptr<x_smbd_tcon_t>> tcon_table; // TODO map is non-standard-layout
	//x_tp_ddlist_t<tcon_dlink_traits> tcon_list;
};
X_DECLARE_MEMBER_TRAITS(smbd_sess_hash_traits, x_smbd_sess_t, hash_link)
X_DECLARE_MEMBER_TRAITS(smbd_sess_conn_traits, x_smbd_sess_t, conn_link)

struct x_fdevt_user_t
{
	x_dlink_t link;
	void (*func)(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *);
};
X_DECLARE_MEMBER_TRAITS(fdevt_user_conn_traits, x_fdevt_user_t, link)

struct x_smbd_conn_t
{
	enum { MAX_MSG = 4 };
	x_smbd_conn_t(x_smbd_t *smbd, int fd, const x_sockaddr_t &saddr)
		: smbd(smbd), fd(fd), saddr(saddr) { }
	~x_smbd_conn_t();

	const std::shared_ptr<x_smbconf_t> get_smbconf() const {
		return smbd->smbconf;
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
	const x_sockaddr_t saddr;
	uint16_t cipher = 0;
	uint16_t dialect;

	uint16_t server_security_mode;
	uint16_t client_security_mode;
	uint32_t server_capabilities;
	uint32_t client_capabilities;

	idl::GUID client_guid;

	uint64_t credit_seq_low = 0;
	uint64_t credit_seq_range = 1;
	uint64_t credit_granted = 1;
	uint64_t credit_max;
	// xconn->smb2.credits.bitmap = bitmap_talloc(xconn, xconn->smb2.credits.max);
	uint32_t read_length = 0;
	uint32_t nbt_hdr;
	x_smb2_preauth_t preauth;
	x_msg_ptr_t recving_msg;
	x_msg_ptr_t sending_msg;
	std::list<x_msg_ptr_t> send_queue;
	// x_tp_ddlist_t<msg_dlink_traits> send_queue;
	x_tp_ddlist_t<smbd_sess_conn_traits> session_list;
	x_tp_ddlist_t<smbd_sess_conn_traits> session_wait_input_list;
	x_tp_ddlist_t<fdevt_user_conn_traits> fdevt_user_list;
};

std::shared_ptr<x_smbshare_t> x_smbd_find_share(x_smbd_t *smbd, const std::string &name);
// void x_smbshares_foreach(std::function<bool(std::shared_ptr<x_smbshare_t> &share)>);
// int x_smbd_load_shares();

int x_smbd_sess_pool_init(x_evtmgmt_t *ep, uint32_t count);
x_smbd_sess_t *x_smbd_sess_create(x_smbd_conn_t *smbd_conn);
x_smbd_sess_t *x_smbd_sess_find(uint64_t id, const x_smbd_conn_t *smbd_conn);
void x_smbd_sess_release(x_smbd_sess_t *smbd_sess);

int x_auth_spnego_init(x_auth_context_t *context);
x_auth_t *x_auth_create_ntlmssp(x_auth_context_t *context);
int x_auth_ntlmssp_init(x_auth_context_t *context);
x_auth_t *x_auth_create_krb5(x_auth_context_t *context);
int x_auth_krb5_init(x_auth_context_t *context);

x_auth_context_t *x_auth_create_context(x_smbd_t *smbd);
x_auth_t *x_auth_create_by_oid(x_auth_context_t *context, gss_const_OID oid);
int x_auth_register(x_auth_context_t *context, const x_auth_mech_t *mech);

int x_smbd_open_pool_init(x_evtmgmt_t *ep, uint32_t count);

extern const x_auth_mech_t x_auth_mech_spnego;

x_auth_t *x_smbd_create_auth(x_smbd_t *smbd);

void x_smbd_conn_remove_sessions(x_smbd_conn_t *smbd_conn);
void x_smbd_conn_post_user(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user);

void x_smbd_conn_reply(x_smbd_conn_t *smbd_conn, x_msg_ptr_t &msg, x_smbd_sess_t *smbd_sess,
		x_smb2_preauth_t *preauth, uint8_t *outbuf,
		uint32_t tid, NTSTATUS status, uint32_t body_size);
int x_smb2_reply_error(x_smbd_conn_t *smbd_conn, x_msg_ptr_t &msg, x_smbd_sess_t *smbd_sess,
		uint32_t tid, NTSTATUS status, const char *file, unsigned int line);

#define X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, tid, status) \
	x_smb2_reply_error((smbd_conn), (msg), (smbd_sess), (tid), (status), __FILE__, __LINE__)

int x_smbd_conn_process_smb1negoprot(x_smbd_conn_t *smbd_conn, x_msg_ptr_t &msg,
		const uint8_t *buf, size_t len);

void x_smbd_wbpool_request(x_wbcli_t *wbcli);

void x_smb2_key_derivation(const uint8_t *KI, size_t KI_len,
		const x_array_const_t<char> &label,
		const x_array_const_t<char> &context,
		x_smb2_key_t &key);
NTSTATUS x_smb2_sign_msg(uint8_t *data, size_t length, uint16_t dialect,
		const x_smb2_key_t &key);

uint16_t x_smb2_dialect_match(x_smbd_conn_t *smbd_conn,
		const void *dialects,
		size_t dialect_count);

/* TODO */
#define DEBUG(...) do { } while (0)

#endif /* __smbd__hxx__ */

