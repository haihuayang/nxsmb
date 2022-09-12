
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

#if 0
enum class x_smbd_tcon_type_t {
	DEFAULT,
	DFS_ROOT,
	DFS_VOLUME,
};
#endif

struct x_smbd_conn_t;
struct x_smbd_sess_t;
struct x_smbd_chan_t;
struct x_smbd_tcon_t;
struct x_smbd_open_t;
struct x_smbd_lease_t;
struct x_smbd_object_t;
struct x_smbd_requ_t;
struct x_smbd_share_t;
struct x_smbd_topdir_t;

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

struct x_smbd_key_set_t
{
	x_smb2_key_t signing_key, decryption_key, encryption_key, application_key;
};


struct x_fdevt_user_t
{
	x_dlink_t link;
	void (*func)(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *, bool terminated);
};
X_DECLARE_MEMBER_TRAITS(fdevt_user_conn_traits, x_fdevt_user_t, link)


int x_smbd_conn_srv_init(int port);


extern __thread x_smbd_conn_t *g_smbd_conn_curr;
#define X_SMBD_CONN_ASSERT(smbd_conn) X_ASSERT((smbd_conn) == g_smbd_conn_curr)
const x_smb2_uuid_t &x_smbd_conn_curr_client_guid();

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
bool x_smbd_conn_post_user(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user);
void x_smbd_conn_post_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
void x_smbd_conn_send_unsolicited(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess,
		x_bufref_t *buf, uint16_t opcode);
void x_smbd_conn_send_remove_chan(x_smbd_conn_t *smbd_conn, x_smbd_chan_t *smbd_chan);
void x_smbd_conn_set_async(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		void (*cancel_fn)(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ));
void x_smb2_sesssetup_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ, NTSTATUS status,
		std::vector<uint8_t> &out_security);
void x_smb2_reply(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		x_bufref_t *buf_head,
		x_bufref_t *buf_tail,
		NTSTATUS status,
		size_t reply_size);


int x_smbd_sess_table_init(uint32_t count);
x_smbd_sess_t *x_smbd_sess_create(uint64_t &id);
x_smbd_sess_t *x_smbd_sess_lookup(uint64_t id, const x_smb2_uuid_t &client_guid);
NTSTATUS x_smbd_sess_auth_succeeded(x_smbd_sess_t *smbd_sess,
		std::shared_ptr<x_smbd_user_t> &smbd_user,
		const x_smbd_key_set_t &keys);
uint64_t x_smbd_sess_get_id(const x_smbd_sess_t *smbd_sess);
bool x_smbd_sess_is_signing_required(const x_smbd_sess_t *smbd_sess);
x_smbd_chan_t *x_smbd_sess_lookup_chan(x_smbd_sess_t *smbd_sess, x_smbd_conn_t *smbd_conn);
x_smbd_chan_t *x_smbd_sess_get_active_chan(x_smbd_sess_t *smbd_sess);
bool x_smbd_sess_link_chan(x_smbd_sess_t *smbd_sess, x_dlink_t *link);
bool x_smbd_sess_unlink_chan(x_smbd_sess_t *smbd_sess, x_dlink_t *link);
void x_smbd_sess_remove_chan(x_smbd_sess_t *smbd_sess, x_smbd_chan_t *smbd_chan);
std::shared_ptr<x_smbd_user_t> x_smbd_sess_get_user(const x_smbd_sess_t *smbd_sess);
NTSTATUS x_smbd_sess_logoff(x_smbd_sess_t *smbd_sess);
bool x_smbd_sess_link_tcon(x_smbd_sess_t *smbd_sess, x_dlink_t *link);
bool x_smbd_sess_unlink_tcon(x_smbd_sess_t *smbd_sess, x_dlink_t *link);
const x_smb2_key_t *x_smbd_sess_get_signing_key(const x_smbd_sess_t *smbd_sess);



x_smbd_chan_t *x_smbd_chan_create(x_smbd_sess_t *smbd_sess,
		x_smbd_conn_t *smbd_conn);
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
x_smbd_chan_t *x_smbd_chan_match(x_dlink_t *conn_link, x_smbd_conn_t *smbd_conn);
x_smbd_chan_t *x_smbd_chan_get_active(x_dlink_t *conn_link);
bool x_smbd_chan_is_active(const x_smbd_chan_t *smbd_chan);
void x_smbd_chan_logoff(x_dlink_t *link, x_smbd_sess_t *smbd_sess);
bool x_smbd_chan_post_user(x_smbd_chan_t *smbd_chan, x_fdevt_user_t *fdevt_user);



int x_smbd_tcon_table_init(uint32_t count);
NTSTATUS x_smbd_tcon_op_create(x_smbd_tcon_t *smbd_tcon,
		x_smbd_requ_t *smbd_requ,
		x_smbd_lease_t *smbd_lease,
		std::unique_ptr<x_smb2_state_create_t> &state);
x_smbd_tcon_t *x_smbd_tcon_create(x_smbd_sess_t *smbd_sess, 
		const std::shared_ptr<x_smbd_share_t> &smbshare,
		const std::string &volume,
		uint32_t share_access);
uint32_t x_smbd_tcon_get_id(const x_smbd_tcon_t *smbd_tcon);
bool x_smbd_tcon_access_check(const x_smbd_tcon_t *smbd_tcon, uint32_t desired_access);
uint32_t x_smbd_tcon_get_share_access(const x_smbd_tcon_t *smbd_tcon);
bool x_smbd_tcon_match(const x_smbd_tcon_t *smbd_tcon, const x_smbd_sess_t *smbd_sess, uint32_t tid);
x_smbd_sess_t *x_smbd_tcon_get_sess(const x_smbd_tcon_t *smbd_tcon);
std::shared_ptr<x_smbd_share_t> x_smbd_tcon_get_share(const x_smbd_tcon_t *smbd_tcon);
x_smbd_tcon_t *x_smbd_tcon_lookup(uint32_t id, const x_smbd_sess_t *smbd_sess);
bool x_smbd_tcon_unlink_open(x_smbd_tcon_t *smbd_tcon, x_dlink_t *link);
bool x_smbd_tcon_disconnect(x_smbd_tcon_t *smbd_tcon);
void x_smbd_tcon_unlinked(x_dlink_t *link, x_smbd_sess_t *smbd_sess);



int x_smbd_open_table_init(uint32_t count);
bool x_smbd_open_has_space();
x_smbd_open_t *x_smbd_open_lookup(uint64_t id_presistent, uint64_t id_volatile,
		const x_smbd_tcon_t *smbd_tcon);
bool x_smbd_open_store(x_smbd_open_t *smbd_open);
NTSTATUS x_smbd_open_close(x_smbd_open_t *smbd_open,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_close_t> &state,
		std::vector<x_smb2_change_t> &changes);
void x_smbd_open_unlinked(x_dlink_t *link, x_smbd_tcon_t *smbd_tcon,
		std::vector<x_smb2_change_t> &changes);



int x_smbd_posixfs_init(size_t max_open);
int x_smbd_ipc_init();


struct x_smbd_requ_t
{
	explicit x_smbd_requ_t(x_buf_t *in_buf, uint32_t in_msgsize);
	~x_smbd_requ_t();

	const uint8_t *get_in_data() const {
		return in_buf->data + in_offset;
	}

	bool is_signed() const {
	       return (in_hdr_flags & SMB2_HDR_FLAG_SIGNED) != 0;
	}

	x_job_t job;
	x_dlink_t async_link; // link into open
	void *requ_state = nullptr;

	x_buf_t *in_buf;
	uint64_t id;
	uint32_t in_msgsize, in_offset, in_requ_len;
	bool compound_followed = false;
	bool async = false;
	uint16_t opcode;

	NTSTATUS status{NT_STATUS_OK};
	uint64_t in_mid;
	uint32_t in_tid;
	uint32_t in_hdr_flags;
	uint32_t out_hdr_flags{};

	uint16_t in_credit_charge{};
	uint16_t in_credit_requested{};
	uint16_t out_credit_granted;

	uint32_t out_length = 0;
	uint32_t last_reply_size = 0;
	x_bufref_t *last_buf_head{}; // it does not hold reference of buf
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


int x_smbd_requ_pool_init(uint32_t count);
x_smbd_requ_t *x_smbd_requ_create(x_buf_t *in_buf, uint32_t in_msgsize);
uint64_t x_smbd_requ_get_async_id(const x_smbd_requ_t *smbd_requ);
x_smbd_requ_t *x_smbd_requ_async_lookup(uint64_t id, const x_smbd_conn_t *smbd_conn, bool remove);
void x_smbd_requ_async_insert(x_smbd_requ_t *smbd_requ);
void x_smbd_requ_async_remove(x_smbd_requ_t *smbd_requ);


NTSTATUS x_smbd_dfs_resolve_path(
		const std::shared_ptr<x_smbd_share_t> &smbd_share,
		const std::u16string &in_path,
		bool dfs,
		std::shared_ptr<x_smbd_topdir_t> &topdir,
		std::u16string &path);

void x_smb2_send_lease_break(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess,
		const x_smb2_lease_key_t *lease_key,
		uint16_t new_epoch,
		uint32_t flags,
		uint32_t current_state, uint32_t new_state);
void x_smb2_send_oplock_break(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess,
		const x_smbd_open_t *smbd_open, uint8_t oplock_level);


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

int x_smbd_conn_process_smb1negprot(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
NTSTATUS x_smb2_process_negprot(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
NTSTATUS x_smb2_process_sesssetup(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
NTSTATUS x_smb2_process_logoff(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
NTSTATUS x_smb2_process_tcon(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
NTSTATUS x_smb2_process_tdis(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
NTSTATUS x_smb2_process_create(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
NTSTATUS x_smb2_process_close(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
NTSTATUS x_smb2_process_flush(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
NTSTATUS x_smb2_process_read(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
NTSTATUS x_smb2_process_write(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
NTSTATUS x_smb2_process_lock(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
NTSTATUS x_smb2_process_ioctl(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
NTSTATUS x_smb2_process_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
NTSTATUS x_smb2_process_keepalive(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
NTSTATUS x_smb2_process_query_directory(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
NTSTATUS x_smb2_process_notify(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
NTSTATUS x_smb2_process_getinfo(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
NTSTATUS x_smb2_process_setinfo(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
NTSTATUS x_smb2_process_break(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);

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

void x_smbd_notify_change(std::shared_ptr<x_smbd_topdir_t> &topdir,
		const std::vector<x_smb2_change_t> &changes);

void x_smbd_schedule_async(x_job_t *job);

#endif /* __smbd__hxx__ */

