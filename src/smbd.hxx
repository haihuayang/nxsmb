
#ifndef __smbd__hxx__
#define __smbd__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "samba/include/config.h"
#include "include/evtmgmt.hxx"
#include "include/timerq.hxx"
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
#include "smbd_conf.hxx"
#include "smb2.hxx"
#include "smb2_state.hxx"
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

#include "smbd_user.hxx"
#include "network.hxx"

#define X_NT_STATUS_INTERNAL_BLOCKED	NT_STATUS(1)
#define X_NT_STATUS_INTERNAL_TERMINATE	NT_STATUS(2)

x_auth_t *x_smbd_create_auth();
const std::vector<uint8_t> &x_smbd_get_negprot_spnego();

enum class x_smbd_timer_t {
	SESSSETUP,
	BREAK,
	LAST,
};
void x_smbd_add_timer(x_smbd_timer_t timer_id, x_timerq_entry_t *entry);
bool x_smbd_cancel_timer(x_smbd_timer_t timer_id, x_timerq_entry_t *entry);

//x_auth_context_t *x_smbd_create_auth_context();

struct x_smbd_conn_t;
struct x_smbd_sess_t;
struct x_smbd_chan_t;
struct x_smbd_tcon_t;
struct x_smbd_open_t;
struct x_smbd_lease_t;
struct x_smbd_object_t;
struct x_smbd_requ_t;

template <class T>
T *x_smbd_ref_inc(T *);

template <class T>
void x_smbd_ref_dec(T *);

template <class T>
inline void x_smbd_ref_dec_if(T *t)
{
	if (t) {
		x_smbd_ref_dec(t);
	}
}

#define X_SMBD_REF_DEC(t) do { x_smbd_ref_dec(t); (t) = nullptr; } while (0)

template <class T>
struct x_smbd_ptr_t
{
	explicit x_smbd_ptr_t(T *t) noexcept : val(t) { }
	~x_smbd_ptr_t() noexcept {
		x_smbd_ref_dec_if(val);
	}
	x_smbd_ptr_t(x_smbd_ptr_t<T> &&o) noexcept {
		val = std::exchange(o.val, nullptr);
	}
	x_smbd_ptr_t<T> &operator=(x_smbd_ptr_t<T> &&o) noexcept {
		if (this != &o) {
			x_smbd_ref_dec_if(val);
			val = std::exchange(o.val, nullptr);
		}
		return *this;
	}

	x_smbd_ptr_t(const x_smbd_ptr_t<T> &o) = delete;
	x_smbd_ptr_t<T> &operator=(const x_smbd_ptr_t<T> &t) = delete;

	operator T*() const noexcept {
		return val;
	}
	T *operator->() const noexcept {
		return val;
	}

	T *val;
};


extern __thread x_smbd_conn_t *g_smbd_conn_curr;
#define X_SMBD_CONN_ASSERT(smbd_conn) X_ASSERT((smbd_conn) == g_smbd_conn_curr)
const x_smb2_uuid_t &x_smbd_conn_curr_client_guid();

struct x_fdevt_user_t
{
	x_dlink_t link;
	void (*func)(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *, bool terminated);
};
X_DECLARE_MEMBER_TRAITS(fdevt_user_conn_traits, x_fdevt_user_t, link)

int x_smbd_srv_init(int port);

// x_smbd_conn_t *x_smbd_conn_incref(x_smbd_conn_t *smbd_conn);
// void x_smbd_conn_decref(x_smbd_conn_t *smbd_conn);
int x_smbd_conn_negprot(x_smbd_conn_t *smbd_conn,
		uint16_t dialect,
		uint16_t cipher,
		uint16_t client_security_mode,
		uint16_t server_security_mode,
		uint32_t client_capabilities,
		uint32_t server_capabilities,
		const x_smb2_uuid_t &client_guid);
int x_smbd_conn_negprot_smb1(x_smbd_conn_t *smbd_conn);
uint16_t x_smbd_conn_get_dialect(const x_smbd_conn_t *smbd_conn);
uint32_t x_smbd_conn_get_capabilities(const x_smbd_conn_t *smbd_conn);
void x_smbd_conn_update_preauth(x_smbd_conn_t *smbd_conn,
		const void *data, size_t length);
const x_smb2_preauth_t *x_smbd_conn_get_preauth(x_smbd_conn_t *smbd_conn);
void x_smbd_conn_link_chan(x_smbd_conn_t *smbd_conn, x_dlink_t *link);
void x_smbd_conn_unlink_chan(x_smbd_conn_t *smbd_conn, x_dlink_t *link);


struct x_smbd_key_set_t
{
	x_smb2_key_t signing_key, decryption_key, encryption_key, application_key;
};

/*
struct x_smbd_chan_link_conn_t
{
	y_dlink_t link;
};
*/
struct x_smbd_requ_async_fn_t
{
	void (*cancel_fn)(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
	void (*done_fn)(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ, NTSTATUS status);
};

struct x_smbd_requ_state_t
{
	virtual ~x_smbd_requ_state_t() { }
	virtual void async_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ, NTSTATUS status) = 0;
};

struct x_smbd_requ_t
{
	explicit x_smbd_requ_t(x_buf_t *in_buf);
	~x_smbd_requ_t();

	const uint8_t *get_in_data() const {
		return in_buf->data + in_offset;
	}

	bool is_signed() const {
	       return (in_hdr_flags & SMB2_HDR_FLAG_SIGNED) != 0;
	}

	x_job_t job;
	x_dqlink_t hash_link;
	x_dlink_t async_link; // link into open
	void *requ_state = nullptr;
	// std::unique_ptr<x_smbd_requ_state_t> state;

	int refcnt = 1;

	x_buf_t *in_buf;
	// const uint8_t *in_hdr;
	uint32_t in_offset, in_requ_len;
	bool compound_followed = false;
	bool async = false;
	uint16_t opcode;

	NTSTATUS status{NT_STATUS_OK};
	uint64_t async_id{};
	uint64_t in_mid;
	uint32_t in_tid;
	uint32_t in_hdr_flags;
	uint32_t out_hdr_flags{};

	uint16_t in_credit_charge{};
	uint16_t in_credit_requested{};
	uint16_t out_credit_granted;

	uint32_t out_length = 0;
	x_bufref_t *out_buf_head{}, *out_buf_tail{};
	x_smbd_sess_t *smbd_sess{};
	x_smbd_chan_t *smbd_chan{};
	x_smbd_tcon_t *smbd_tcon{};
	x_smbd_open_t *smbd_open{};
	x_smbd_object_t *smbd_object{};
	void (*cancel_fn)(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
	void (*async_done_fn)(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ, NTSTATUS status);
};
X_DECLARE_MEMBER_TRAITS(requ_async_traits, x_smbd_requ_t, async_link)

template <>
inline x_smbd_requ_t *x_smbd_ref_inc(x_smbd_requ_t *smbd_requ)
{
	X_ASSERT(smbd_requ->refcnt++ > 0);
	return smbd_requ;
}

template <>
inline void x_smbd_ref_dec(x_smbd_requ_t *smbd_requ)
{
	if (unlikely(--smbd_requ->refcnt == 0)) {
		delete smbd_requ;
	}
}

void x_smb2_sesssetup_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ, NTSTATUS status,
		std::vector<uint8_t> &out_security);

void x_smbd_conn_send_remove_chan(x_smbd_conn_t *smbd_conn, x_smbd_chan_t *smbd_chan);

void x_smbd_conn_set_async(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		void (*cancel_fn)(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ));

void x_smb2_reply(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		x_bufref_t *buf_head,
		x_bufref_t *buf_tail,
		NTSTATUS status,
		size_t reply_size);
#if 0
struct x_smbd_open_t
{
	/*
	void incref() {
		X_ASSERT(refcnt++ > 0);
	}
	void decref();
*/
	bool check_access(uint32_t access) const {
		return (access_mask & access);
	}

	x_dqlink_t hash_link;
	x_dlink_t tcon_link;
	x_smbd_object_t *smbd_object{};
	x_smbd_tcon_t *smbd_tcon;
	uint64_t id;
	enum {
		S_PENDING,
		S_OPENED,
		S_CLOSED,
	} state;

	uint32_t access_mask, share_access;
#if 0
	uint32_t notify_filter = 0;
	uint8_t oplock;
	/* open's on the same file sharing the same lease can have different parent key */
	x_smb2_lease_key_t parent_lease_key;
	x_smbd_lease_t *smbd_lease{};
#endif
	std::atomic<int> refcnt{1};
};

X_DECLARE_MEMBER_TRAITS(open_tcon_traits, x_smbd_open_t, tcon_link)
// X_DECLARE_MEMBER_TRAITS(open_object_traits, x_smbd_open_t, object_link)
#endif

int x_smbd_open_table_init(uint32_t count);

struct x_smbd_tcon_ops_t;
#if 0
struct x_smbd_tcon_t
{ 
	x_smbd_tcon_t(x_smbd_sess_t *smbd_sess,
			const std::shared_ptr<x_smbd_share_t> &share)
		: smbd_sess(smbd_sess), smbd_share(share) { }
	x_smbd_share_type_t get_share_type() const {
		return smbd_share->type;
	}

	x_dqlink_t hash_link;
	x_dlink_t sess_link;
	const x_smbd_tcon_ops_t *ops;
	std::atomic<int> refcnt{1};
	uint32_t tid;
	uint32_t share_access;
	x_smbd_sess_t * const smbd_sess;
	std::shared_ptr<x_smbd_share_t> smbd_share;
	x_tp_ddlist_t<open_tcon_traits> open_list;
};
X_DECLARE_MEMBER_TRAITS(tcon_sess_traits, x_smbd_tcon_t, sess_link)

template <>
inline x_smbd_tcon_t *x_smbd_ref_inc(x_smbd_tcon_t *smbd_tcon)
{
	X_ASSERT(smbd_tcon->refcnt++ > 0);
	return smbd_tcon;
}

template <>
inline void x_smbd_ref_dec(x_smbd_tcon_t *smbd_tcon)
{
	if (unlikely(--smbd_tcon->refcnt == 0)) {
		delete smbd_tcon;
	}
}
#endif

struct x_smbd_tcon_ops_t
{
	NTSTATUS (*create)(x_smbd_tcon_t *smbd_tcon, x_smbd_open_t **psmbd_open,
			x_smbd_requ_t *smbd_requ,
			std::unique_ptr<x_smb2_state_create_t> &state);
};

int x_smbd_tcon_table_init(uint32_t count);

NTSTATUS x_smbd_tcon_op_create(x_smbd_tcon_t *smbd_tcon,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_create_t> &state);

x_smbd_tcon_t *x_smbd_tcon_create(x_smbd_sess_t *smbd_sess, 
		const std::shared_ptr<x_smbd_share_t> &smbshare,
		uint32_t share_access);
uint32_t x_smbd_tcon_get_id(const x_smbd_tcon_t *smbd_tcon);
bool x_smbd_tcon_access_check(const x_smbd_tcon_t *smbd_tcon, uint32_t desired_access);
bool x_smbd_tcon_match(const x_smbd_tcon_t *smbd_tcon, const x_smbd_sess_t *smbd_sess, uint32_t tid);
std::shared_ptr<x_smbd_share_t> x_smbd_tcon_get_share(const x_smbd_tcon_t *smbd_tcon);
x_smbd_tcon_t *x_smbd_tcon_lookup(uint32_t id, const x_smbd_sess_t *smbd_sess);
bool x_smbd_tcon_unlink_open(x_smbd_tcon_t *smbd_tcon, x_dlink_t *link);
bool x_smbd_tcon_disconnect(x_smbd_tcon_t *smbd_tcon);



x_smbd_chan_t *x_smbd_chan_create(x_smbd_sess_t *smbd_sess,
		x_smbd_conn_t *smbd_conn);
bool x_smbd_chan_is_active(const x_smbd_chan_t *smbd_chan);
const x_smb2_key_t *x_smbd_chan_get_signing_key(x_smbd_chan_t *smbd_chan);
void x_smbd_chan_update_preauth(x_smbd_chan_t *smbd_chan,
		const void *data, size_t length);
x_smbd_conn_t *x_smbd_chan_get_conn(const x_smbd_chan_t *smbd_chan);
NTSTATUS x_smbd_chan_update_auth(x_smbd_chan_t *smbd_chan,
		x_smbd_requ_t *smbd_requ,
		const uint8_t *in_security_data,
		uint32_t in_security_length,
		std::vector<uint8_t> &out_security,
		std::shared_ptr<x_auth_info_t> &auth_info,
		bool new_auth);
void x_smbd_chan_unlinked(x_dlink_t *conn_link, x_smbd_conn_t *smbd_conn);
void x_smbd_chan_logoff(x_smbd_chan_t *smbd_chan);
bool x_smbd_chan_post_user(x_smbd_chan_t *smbd_chan, x_fdevt_user_t *fdevt_user);

#if 0
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
	x_dqlink_t hash_link;

	uint64_t id;
	x_tick_t timeout;
	std::atomic<int> refcnt;
	std::mutex mutex;
	// uint16_t security_mode = 0;
	bool signing_required = false;
	std::shared_ptr<x_smbd_user_t> smbd_user;
	x_auth_t *auth{nullptr};
	x_auto_ref_t<x_smbd_requ_t> authmsg;

	x_smb2_key_t signing_key, decryption_key, encryption_key, application_key;

	x_tp_ddlist_t<tcon_sess_traits> tcon_list;
	// x_tp_ddlist_t<chan_sess_traits> chan_list;
};
// X_DECLARE_MEMBER_TRAITS(smbd_sess_conn_traits, x_smbd_sess_t, conn_link)
#endif

int x_smbd_sess_table_init(uint32_t count);
x_smbd_sess_t *x_smbd_sess_create(uint64_t &id);
x_smbd_sess_t *x_smbd_sess_lookup(uint64_t id, const x_smb2_uuid_t &client_guid);
NTSTATUS x_smbd_sess_auth_succeeded(x_smbd_sess_t *smbd_sess,
		std::shared_ptr<x_smbd_user_t> &smbd_user,
		const x_smbd_key_set_t &keys);
// x_smbd_sess_t * x_smbd_sess_incref(x_smbd_sess_t *smbd_sess);
// void x_smbd_sess_decref(x_smbd_sess_t *smbd_sess);
uint64_t x_smbd_sess_get_id(const x_smbd_sess_t *smbd_sess);
bool x_smbd_sess_is_signing_required(const x_smbd_sess_t *smbd_sess);
x_smbd_chan_t *x_smbd_sess_lookup_chan(x_smbd_sess_t *smbd_sess, x_smbd_conn_t *smbd_conn);
x_smbd_chan_t *x_smbd_sess_get_active_chan(x_smbd_sess_t *smbd_sess);
bool x_smbd_sess_add_chan(x_smbd_sess_t *smbd_sess, x_smbd_chan_t *smbd_chan);
void x_smbd_sess_remove_chan(x_smbd_sess_t *smbd_sess, x_smbd_chan_t *smbd_chan);
std::shared_ptr<x_smbd_user_t> x_smbd_sess_get_user(const x_smbd_sess_t *smbd_sess);
NTSTATUS x_smbd_sess_logoff(x_smbd_sess_t *smbd_sess);
bool x_smbd_sess_link_tcon(x_smbd_sess_t *smbd_sess, x_dlink_t *link);
bool x_smbd_sess_unlink_tcon(x_smbd_sess_t *smbd_sess, x_dlink_t *link);

void x_smbd_tcon_init_ipc(x_smbd_tcon_t *smbd_tcon);
void x_smbd_tcon_init_posixfs(x_smbd_tcon_t *smbd_tcon);

int x_smbd_posixfs_init(size_t max_open);
const x_smbd_tcon_ops_t *x_smbd_posixfs_get_tcon_ops();
int x_smbd_ipc_init();
const x_smbd_tcon_ops_t *x_smbd_ipc_get_tcon_ops();


#if 0
void x_smbd_open_init(x_smbd_open_t *smbd_open, x_smbd_object_t *smbd_object, x_smbd_tcon_t *smbd_tcon, uint32_t share_access, uint32_t access_mask);
void x_smbd_open_insert_local(x_smbd_open_t *smbd_open);
x_smbd_open_t *x_smbd_open_find(uint64_t id_presistent, uint64_t id_volatile,
		const x_smbd_tcon_t *smbd_tcon);
x_smbd_open_t *x_smbd_open_find(uint64_t id_presistent, uint64_t id_volatile,
		uint32_t tid, const x_smbd_sess_t *smbd_sess);
void x_smbd_open_release(x_smbd_open_t *smbd_open);

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
#if 0
struct x_smbd_conn_t
{
	enum { MAX_MSG = 4 };
	enum state_t { STATE_RUNNING, STATE_DONE };
	x_smbd_conn_t(x_smbd_t *smbd, int fd, const x_sockaddr_t &saddr, uint32_t max_credits);
	~x_smbd_conn_t();

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

	x_ddlist_t chan_list, chan_wait_input_list;
	// x_tp_ddlist_t<smbd_sess_conn_traits> session_list;
	// x_tp_ddlist_t<smbd_sess_conn_traits> session_wait_input_list;
	x_tp_ddlist_t<fdevt_user_conn_traits> fdevt_user_list;
};
#endif
//std::shared_ptr<x_smbd_share_t> x_smbd_find_share(const std::string &name);


// void x_smbshares_foreach(std::function<bool(std::shared_ptr<x_smbshare_t> &share)>);
// int x_smbd_load_shares();

int x_smbd_open_pool_init(uint32_t count);
int x_smbd_tcon_pool_init(uint32_t count);
void x_smbd_sess_lookup(uint64_t id, const x_smbd_conn_t *smbd_conn,
		x_smbd_sess_t **psmbd_sess, x_smbd_chan_t **psmbd_chan,
		bool match_conn);
x_smbd_chan_t *x_smbd_chan_lookup(uint64_t id, const x_smbd_conn_t *smbd_conn,
		bool match_conn);
x_smbd_sess_t * x_smbd_chan_get_sess(x_smbd_chan_t *smbd_chan);
const x_smb2_key_t *x_smbd_sess_get_signing_key(x_smbd_sess_t *smbd_sess);

void x_smbd_sess_release(x_smbd_sess_t *smbd_sess);
void x_smbd_sess_done(x_smbd_sess_t *smbd_sess);

int x_smbd_requ_pool_init(uint32_t count);
x_smbd_requ_t *x_smbd_requ_lookup(uint64_t id, const x_smbd_conn_t *smbd_conn);
void x_smbd_requ_insert(x_smbd_requ_t *smbd_requ);
void x_smbd_requ_remove(x_smbd_requ_t *smbd_requ);


x_smbd_tcon_t *x_smbd_tcon_lookup(uint32_t id, const x_smbd_sess_t *smbd_sess);
void x_smbd_tcon_insert(x_smbd_tcon_t *smbd_tcon);
void x_smbd_tcon_unlinked(x_dlink_t *link, x_smbd_sess_t *smbd_sess);

void x_smbd_conn_terminate_sessions(x_smbd_conn_t *smbd_conn);
bool x_smbd_conn_post_user_2(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user);
void x_smbd_conn_post_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
void x_smbd_conn_send_unsolicited(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess,
		x_bufref_t *buf, uint16_t opcode);
#if 0
void x_smbd_conn_reply(x_smbd_conn_t *smbd_conn, x_msg_ptr_t &smbd_requ, x_smbd_sess_t *smbd_sess,
		x_smb2_preauth_t *preauth, uint8_t *outbuf,
		uint32_t tid, NTSTATUS status, uint32_t body_size);
int x_smb2_reply_error(x_smbd_conn_t *smbd_conn, x_msg_ptr_t &smbd_requ, x_smbd_sess_t *smbd_sess,
		uint32_t tid, NTSTATUS status, const char *file, unsigned int line);
void x_smb2_reply(x_smbd_sess_t *smbd_sess,
		x_smb2_requ_t *requ, uint8_t *outhdr, uint32_t body_size, NTSTATUS status);
static inline bool msg_is_signed(const x_msg_ptr_t &smbd_requ)
{
	uint32_t flags = x_get_le32(smbd_requ->in_buf + SMB2_HDR_FLAGS);
	return flags & SMB2_HDR_FLAG_SIGNED;
}

#define X_SMB2_REPLY_ERROR(smbd_conn, smbd_requ, smbd_sess, tid, status) \
	x_smb2_reply_error((smbd_conn), (smbd_requ), (smbd_sess), (tid), (status), __FILE__, __LINE__)
#endif
void x_smb2_send_lease_break(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess,
		const x_smb2_lease_key_t *lease_key,
		uint16_t new_epoch,
		uint32_t flags,
		uint32_t current_state, uint32_t new_state);
void x_smb2_send_oplock_break(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess,
		const x_smbd_open_t *smbd_open, uint8_t oplock_level);

#if 0
static inline const idl::GUID &x_smbd_get_client_guid(const x_smbd_conn_t &conn)
{
	return conn.client_guid;
}

static inline const idl::GUID &x_smbd_get_client_guid(const x_smbd_sess_t &sess)
{
	return x_smbd_get_client_guid(*sess.smbd_conn);
}

static inline const idl::GUID &x_smbd_get_client_guid(const x_smbd_tcon_t &tcon)
{
	return x_smbd_get_client_guid(*tcon.smbd_sess);
}

static inline const idl::GUID &x_smbd_get_client_guid(const x_smbd_open_t &open)
{
	return x_smbd_get_client_guid(*open.smbd_tcon);
}
#endif

int x_smbd_conn_process_smb1negprot(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);

void x_smbd_wbpool_request(x_wbcli_t *wbcli);


struct x_smb2_fsctl_validate_negotiate_info_state_t
{
	uint32_t in_capabilities;
	uint16_t in_security_mode;
	uint16_t in_num_dialects;
	x_smb2_uuid_t in_guid;
	const uint16_t *in_dialects;
	uint32_t out_capabilities;
	uint16_t out_security_mode;
	uint16_t out_dialect;
	x_smb2_uuid_t out_guid;
};

NTSTATUS x_smbd_conn_validate_negotiate_info(const x_smbd_conn_t *smbd_conn,
		x_smb2_fsctl_validate_negotiate_info_state_t &fsctl_state);

extern NTSTATUS x_smb2_process_negprot(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
extern NTSTATUS x_smb2_process_sesssetup(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
extern NTSTATUS x_smb2_process_logoff(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
extern NTSTATUS x_smb2_process_tcon(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
extern NTSTATUS x_smb2_process_tdis(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
extern NTSTATUS x_smb2_process_create(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
extern NTSTATUS x_smb2_process_close(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
extern NTSTATUS x_smb2_process_flush(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
extern NTSTATUS x_smb2_process_read(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
extern NTSTATUS x_smb2_process_write(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
extern NTSTATUS x_smb2_process_lock(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
extern NTSTATUS x_smb2_process_ioctl(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
extern NTSTATUS x_smb2_process_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
extern NTSTATUS x_smb2_process_keepalive(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
extern NTSTATUS x_smb2_process_query_directory(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
extern NTSTATUS x_smb2_process_notify(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
extern NTSTATUS x_smb2_process_getinfo(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
extern NTSTATUS x_smb2_process_setinfo(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
extern NTSTATUS x_smb2_process_break(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);

void x_smbd_conn_requ_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		NTSTATUS status);

#define RETURN_OP_STATUS(smbd_requ, status) do { \
	X_LOG_OP("mid=%ld op=%d 0x%lx at %s:%d", (smbd_requ)->in_mid, (smbd_requ)->opcode, \
			(status).v, __FILE__, __LINE__); \
	return (status); \
} while (0)

/* TODO */
#define DEBUG(...) do { } while (0)

extern x_evtmgmt_t *g_evtmgmt;
int x_smbd_ctrl_init(x_evtmgmt_t *evtmgmt);

void x_smbd_open_append_notify(x_smbd_open_t *smbd_open,
		uint32_t action,
		const std::u16string &path);

void x_smbd_schedule_async(x_job_t *job);

#endif /* __smbd__hxx__ */

