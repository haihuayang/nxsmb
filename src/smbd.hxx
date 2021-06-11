
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

#include "auth.hxx"
#include "network.hxx"

#define X_NT_STATUS_INTERNAL_BLOCKED	NT_STATUS(1)
#define X_NT_STATUS_INTERNAL_TERMINATE	NT_STATUS(2)


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

x_auth_context_t *x_auth_create_context(x_smbd_t *smbd);

struct x_smbd_conn_t;
struct x_smbd_sess_t;
struct x_smbd_tcon_t;
struct x_smbd_open_t;

struct x_smb2_msg_t
{
	static std::atomic<int> count;
	x_smb2_msg_t(x_buf_t *in_buf) : in_buf(in_buf) {
		++count;
	}
	~x_smb2_msg_t() {
		x_buf_release(in_buf);
		--count;
	}

	void incref() {
		X_ASSERT(refcnt++ > 0);
	}

	void decref() {
		if (unlikely(--refcnt == 0)) {
			delete this;
		}
	}

	const uint8_t *get_in_data() const {
		return in_buf->data + in_offset;
	}

	x_job_t job;
	void *requ_state = nullptr;

	int refcnt = 1;

	x_buf_t *in_buf;
	const uint8_t *in_hdr;
	uint32_t in_offset, in_requ_len;
	bool compound_followed = false;

	NTSTATUS status{NT_STATUS_OK};
	uint16_t opcode;
	uint64_t in_mid;
	uint64_t in_tid;
	uint32_t in_hdr_flags;
	uint32_t out_hdr_flags{};

	uint16_t in_credit_charge{};
	uint16_t in_credit_requested{};
	uint16_t out_credit_granted;

	uint32_t out_length = 0;
	x_bufref_t *out_buf_head{}, *out_buf_tail{};
	x_smbd_sess_t *smbd_sess{};
	x_smbd_tcon_t *smbd_tcon{};
	x_smbd_open_t *smbd_open{};
};

void x_smb2_reply(x_smbd_conn_t *smbd_conn,
		x_smb2_msg_t *msg,
		x_bufref_t *buf_head,
		x_bufref_t *buf_tail,
		NTSTATUS status,
		uint32_t reply_size);

struct x_smbduser_t
{
	// security token
};

struct x_smbd_open_ops_t;
struct x_smbd_open_t
{
	void incref() {
		X_ASSERT(refcnt++ > 0);
	}
	void decref();

	x_dqlink_t hash_link;
	x_dlink_t tcon_link;
	const x_smbd_open_ops_t *ops;
	uint64_t id;
	enum {
		S_PENDING,
		S_OPENED,
		S_CLOSED,
	} state;

	uint32_t access_mask, share_access;
	std::atomic<int> refcnt{1};
	x_smbd_tcon_t *smbd_tcon;
};
X_DECLARE_MEMBER_TRAITS(open_tcon_traits, x_smbd_open_t, tcon_link)

struct x_smbd_tcon_ops_t;
struct x_smbd_tcon_t
{ 
	x_smbd_tcon_t(x_smbd_sess_t *smbd_sess,
			const std::shared_ptr<x_smbshare_t> &share)
		: smbd_sess(smbd_sess), smbshare(share) { }
	x_smbshare_type_t get_share_type() const {
		return smbshare->type;
	}

	void incref() {
		X_ASSERT(refcnt++ > 0);
	}

	void decref() {
		if (unlikely(--refcnt == 0)) {
			delete this;
		}
	}

	x_dqlink_t hash_link;
	x_dlink_t sess_link;
	const x_smbd_tcon_ops_t *ops;
	std::atomic<int> refcnt{1};
	uint32_t tid;
	uint32_t share_access;
	x_smbd_sess_t * const smbd_sess;
	std::shared_ptr<x_smbshare_t> smbshare;
	x_tp_ddlist_t<open_tcon_traits> open_list;
};
X_DECLARE_MEMBER_TRAITS(tcon_sess_traits, x_smbd_tcon_t, sess_link)

struct x_smbd_sess_t
{
	static std::atomic<int> count;
	explicit x_smbd_sess_t(x_smbd_conn_t *smbd_conn);
	~x_smbd_sess_t();
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
	// uint16_t security_mode = 0;
	bool signing_required = false;
	std::shared_ptr<x_smbduser_t> user;
	x_auth_t *auth{nullptr};
	x_auto_ref_t<x_smb2_msg_t> authmsg;

	x_smb2_preauth_t preauth;
	x_smb2_key_t signing_key, decryption_key, encryption_key, application_key;

	x_tp_ddlist_t<tcon_sess_traits> tcon_list;
};
X_DECLARE_MEMBER_TRAITS(smbd_sess_conn_traits, x_smbd_sess_t, conn_link)
#if 0
struct x_smbd_tcon_ops_t
{
	x_smbd_open_t *(*create)(std::shared_ptr<x_smbd_tcon_t>&,
			NTSTATUS &status, uint32_t in_hdr_flags,
			x_smb2_requ_create_t &);
};

static inline x_smbd_open_t *x_smbd_tcon_op_create(std::shared_ptr<x_smbd_tcon_t> &smbd_tcon,
		NTSTATUS &status, uint32_t in_hdr_flags, x_smb2_requ_create_t &requ_create)
{
	return smbd_tcon->ops->create(smbd_tcon, status, in_hdr_flags, requ_create);
}
#endif
void x_smbd_tcon_init_ipc(x_smbd_tcon_t *smbd_tcon);
void x_smbd_tcon_init_disk(x_smbd_tcon_t *smbd_tcon);

int x_smbd_disk_init(size_t max_open);
int x_smbd_ipc_init();


void x_smbd_open_insert_local(x_smbd_open_t *smbd_open);
x_smbd_open_t *x_smbd_open_find(uint64_t id_presistent, uint64_t id_volatile,
		const x_smbd_tcon_t *smbd_tcon);
x_smbd_open_t *x_smbd_open_find(uint64_t id_presistent, uint64_t id_volatile,
		uint32_t tid, const x_smbd_sess_t *smbd_sess);
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
struct x_fdevt_user_t
{
	x_dlink_t link;
	void (*func)(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *, bool cancelled);
};
X_DECLARE_MEMBER_TRAITS(fdevt_user_conn_traits, x_fdevt_user_t, link)

struct x_smbd_conn_t
{
	enum { MAX_MSG = 4 };
	enum state_t { STATE_RUNNING, STATE_DONE };
	x_smbd_conn_t(x_smbd_t *smbd, int fd, const x_sockaddr_t &saddr);
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
	std::atomic<state_t> state{STATE_RUNNING};
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
	std::vector<bool> seq_bitmap;
	// xconn->smb2.credits.bitmap = bitmap_talloc(xconn, xconn->smb2.credits.max);
	x_smb2_preauth_t preauth;

	uint32_t nbt_hdr;
	uint32_t recv_len = 0;
	x_buf_t *recv_buf{};
	x_bufref_t *send_buf_head{}, *send_buf_tail{};

	x_tp_ddlist_t<smbd_sess_conn_traits> session_list;
	x_tp_ddlist_t<smbd_sess_conn_traits> session_wait_input_list;
	x_tp_ddlist_t<fdevt_user_conn_traits> fdevt_user_list;
};

std::shared_ptr<x_smbshare_t> x_smbd_find_share(x_smbd_t *smbd, const std::string &name);
// void x_smbshares_foreach(std::function<bool(std::shared_ptr<x_smbshare_t> &share)>);
// int x_smbd_load_shares();

int x_smbd_open_pool_init(uint32_t count);
int x_smbd_tcon_pool_init(uint32_t count);
int x_smbd_sess_pool_init(uint32_t count);
x_smbd_sess_t *x_smbd_sess_create(x_smbd_conn_t *smbd_conn);
x_smbd_sess_t *x_smbd_sess_find(uint64_t id, const x_smbd_conn_t *smbd_conn);
void x_smbd_sess_release(x_smbd_sess_t *smbd_sess);

x_auth_t *x_smbd_create_auth(x_smbd_t *smbd);

x_smbd_tcon_t *x_smbd_tcon_find(uint32_t id, const x_smbd_sess_t *smbd_sess);
void x_smbd_tcon_insert(x_smbd_tcon_t *smbd_tcon);
void x_smbd_tcon_release(x_smbd_tcon_t *smbd_tcon);

void x_smbd_conn_remove_sessions(x_smbd_conn_t *smbd_conn);
bool x_smbd_conn_post_user(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user);
#if 0
void x_smbd_conn_reply(x_smbd_conn_t *smbd_conn, x_msg_ptr_t &msg, x_smbd_sess_t *smbd_sess,
		x_smb2_preauth_t *preauth, uint8_t *outbuf,
		uint32_t tid, NTSTATUS status, uint32_t body_size);
int x_smb2_reply_error(x_smbd_conn_t *smbd_conn, x_msg_ptr_t &msg, x_smbd_sess_t *smbd_sess,
		uint32_t tid, NTSTATUS status, const char *file, unsigned int line);
void x_smb2_reply(x_smbd_sess_t *smbd_sess,
		x_smb2_requ_t *requ, uint8_t *outhdr, uint32_t body_size, NTSTATUS status);
static inline bool msg_is_signed(const x_msg_ptr_t &msg)
{
	uint32_t flags = x_get_le32(msg->in_buf + SMB2_HDR_FLAGS);
	return flags & SMB2_HDR_FLAG_SIGNED;
}

#define X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, tid, status) \
	x_smb2_reply_error((smbd_conn), (msg), (smbd_sess), (tid), (status), __FILE__, __LINE__)
#endif

int x_smbd_conn_process_smb1negoprot(x_smbd_conn_t *smbd_conn, x_smb2_msg_t *msg);

void x_smbd_wbpool_request(x_wbcli_t *wbcli);


uint16_t x_smb2_dialect_match(x_smbd_conn_t *smbd_conn,
		const void *dialects,
		size_t dialect_count);

#define X_SMB2_OP_DECL(X) \
extern NTSTATUS x_smb2_process_##X(x_smbd_conn_t *smbd_conn, x_smb2_msg_t *msg);
	X_SMB2_OP_ENUM
#undef X_SMB2_OP_DECL

void x_smbd_conn_requ_done(x_smbd_conn_t *smbd_conn, x_smb2_msg_t *msg,
		NTSTATUS status);

#define RETURN_OP_STATUS(msg, status) do { \
	X_LOG_OP("mid=%ld op=%d 0x%lx at %s:%d", (msg)->in_mid, (msg)->opcode, \
			(status).v, __FILE__, __LINE__); \
	return (status); \
} while (0)

/* TODO */
#define DEBUG(...) do { } while (0)

struct x_smb2_requ_t;
struct x_smb2_requ_ops_t
{
	void (*reply)(x_smb2_requ_t *requ);
	void (*destroy)(x_smb2_requ_t *requ);
};

struct x_smb2_requ_t
{
	const x_smb2_requ_ops_t *ops;
	uint64_t mid;
	uint32_t hdr_flags;
	uint16_t opcode;
	uint16_t credits_requested;
	uint32_t tid;
	x_bufref_t in_buf;
};

#if 0
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
#endif

#endif /* __smbd__hxx__ */

