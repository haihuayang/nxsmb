
#ifndef __smbd__hxx__
#define __smbd__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

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
#include <fcntl.h>
#include <unistd.h>
#include "smb2.hxx"
#include "smb2_state.hxx"
#include "smbd_proto.hxx"
#include "misc.hxx"
#include "network.hxx"
#include "include/utils.hxx"
#include "include/librpc/misc.hxx"
#include "include/librpc/security.hxx"
#include "include/librpc/samr.hxx"

#include "smbd_user.hxx"
#include "network.hxx"

const NTSTATUS X_NT_STATUS_INTERNAL_BLOCKED	= {1};
const NTSTATUS X_NT_STATUS_INTERNAL_TERMINATE	= {2};

x_auth_t *x_smbd_create_auth(const void *sec_buf, size_t sec_len);
const std::vector<uint8_t> &x_smbd_get_negprot_spnego();

enum {
	X_SMBD_MAX_THREAD = 256,
};

enum {
	/* in seconds */
	X_SMBD_DURABLE_TIMEOUT_MAX = (5 * 60),
};

enum class x_smbd_timer_id_t {
	SESSSETUP,
	BREAK,
	LAST,
};

void x_smbd_add_timer(x_timer_job_t *entry, x_smbd_timer_id_t timer_id);
void x_smbd_add_timer(x_timer_job_t *entry, x_tick_diff_t expires);
bool x_smbd_del_timer(x_timer_job_t *entry);

std::array<x_tick_t, 2> x_smbd_get_time();

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
struct x_smbd_qdir_t;
struct x_smbd_lease_t;
struct x_smbd_object_t;
struct x_smbd_stream_t;
struct x_smbd_requ_t;
struct x_smbd_share_t;
struct x_smbd_volume_t;

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

struct x_smb2_state_create_t
{
	x_smb2_state_create_t(const x_smb2_uuid_t &client_guid);
	~x_smb2_state_create_t();

	const x_smb2_uuid_t in_client_guid;

	uint8_t in_oplock_level;
	uint8_t out_oplock_level;
	uint32_t in_contexts{0};
	uint32_t out_contexts{0};

	uint32_t in_impersonation_level;
	uint32_t in_desired_access;
	uint32_t in_file_attributes;
	uint32_t in_share_access;
	x_smb2_create_disposition_t in_create_disposition;
	uint32_t in_create_options;
	std::shared_ptr<idl::security_descriptor> in_security_descriptor;

	x_smb2_lease_t lease;
	uint64_t in_allocation_size{0};
	uint64_t in_timestamp{0};

	bool is_dollar_data = false;
	bool end_with_sep = false;
	std::u16string in_path;
	std::u16string in_ads_name;

	uint8_t out_create_flags = 0;
	bool replay_operation = false;
	bool replay_reserved = false;
	uint32_t open_attempt = 0;
	uint32_t out_maximal_access{0};
	uint8_t out_qfid_info[32];

	uint32_t granted_access{0}; // internally used

	x_smbd_object_t *smbd_object{};
	x_smbd_stream_t *smbd_stream{};
	x_smbd_lease_t *smbd_lease{};
	std::shared_ptr<x_smbd_share_t> smbd_share;
	long open_priv_data;

	uint64_t in_dh_id_persistent;
	uint64_t in_dh_id_volatile;
	uint32_t in_dh_timeout;
	uint32_t in_dh_flags;
	x_smb2_uuid_t in_create_guid;
};

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
	uint16_t signing_algo;
	uint16_t cryption_algo;
	uint32_t unused1 = 0;

	x_smb2_key_t signing_key, application_key;
	x_smb2_cryption_key_t decryption_key, encryption_key;
};


struct x_fdevt_user_t
{
	typedef void func_t(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *);
	x_fdevt_user_t(func_t f) : func(f) {}
	x_fdevt_user_t(const x_fdevt_user_t &) = delete;
	x_fdevt_user_t &operator=(const x_fdevt_user_t &) = delete;
	x_dlink_t link;
	func_t *const func;
};
X_DECLARE_MEMBER_TRAITS(fdevt_user_conn_traits, x_fdevt_user_t, link)

enum {
	X_SMBD_OPEN_ID_NON_DURABLE = 0xfffffffeu, // resolve id for non durable
};

struct x_smbd_open_state_t
{
	uint64_t id_persistent;
	const uint32_t access_mask, share_access;
	const x_smb2_uuid_t client_guid;
	const x_smb2_uuid_t create_guid;
	const idl::dom_sid owner;
	const x_smb2_lease_key_t parent_lease_key;
	const long priv_data;

	uint16_t channel_sequence;
	x_smb2_create_action_t create_action;
	uint8_t oplock_level{X_SMB2_OPLOCK_LEVEL_NONE};
	x_smbd_dhmode_t dhmode;
	bool replay_cached = false;

	bool initial_delete_on_close = false;
	uint32_t durable_timeout_msec = 0;
	uint64_t current_offset = 0;
	uint64_t channel_generation;
};

struct x_smbd_file_handle_t
{
	int cmp(const x_smbd_file_handle_t &other) const
	{
		if (base.handle_type != other.base.handle_type) {
			return base.handle_type - other.base.handle_type;
		}
		if (base.handle_bytes != other.base.handle_bytes) {
			return int(base.handle_bytes - other.base.handle_bytes);
		}
		return memcmp(base.f_handle, other.base.f_handle, base.handle_bytes);
	}

	struct file_handle base;
	unsigned char f_handle[MAX_HANDLE_SZ];
};

enum {
	X_SMBD_DURABLE_MAGIC_ACTIVE	= 0x656c626172756441ul,
	X_SMBD_DURABLE_MAGIC_DEAD	= 0x656c626172756444ul,
};

struct x_smbd_durable_t
{
	uint64_t magic;
	uint64_t expired_msec;
	uint64_t id_volatile;
	x_smbd_open_state_t open_state;
	x_smbd_file_handle_t file_handle;
	/* TODO lease state */
};


int x_smbd_conn_srv_init(int port);


extern __thread x_smbd_conn_t *g_smbd_conn_curr;
#define X_SMBD_CONN_ASSERT(smbd_conn) X_ASSERT((smbd_conn) == g_smbd_conn_curr)
const x_smb2_uuid_t &x_smbd_conn_curr_client_guid();
uint16_t x_smbd_conn_curr_dialect();
uint16_t x_smbd_conn_curr_get_signing_algo();
uint16_t x_smbd_conn_curr_get_cryption_algo();
std::shared_ptr<std::u16string> x_smbd_conn_curr_name();

int x_smbd_conn_negprot(x_smbd_conn_t *smbd_conn,
		uint16_t dialect,
		uint16_t encryption_algo,
		uint16_t signing_algo,
		uint16_t client_security_mode,
		uint16_t server_security_mode,
		uint32_t client_capabilities,
		uint32_t server_capabilities,
		const x_smb2_uuid_t &client_guid);
int x_smbd_conn_negprot_smb1(x_smbd_conn_t *smbd_conn);
uint16_t x_smbd_conn_get_dialect(const x_smbd_conn_t *smbd_conn);
uint16_t x_smbd_conn_get_cryption_algo(const x_smbd_conn_t *smbd_conn);
uint32_t x_smbd_conn_get_capabilities(const x_smbd_conn_t *smbd_conn);
void x_smbd_conn_update_preauth(x_smbd_conn_t *smbd_conn,
		const void *data, size_t length);
const x_smb2_preauth_t *x_smbd_conn_get_preauth(x_smbd_conn_t *smbd_conn);
void x_smbd_conn_link_chan(x_smbd_conn_t *smbd_conn, x_dlink_t *link);
void x_smbd_conn_unlink_chan(x_smbd_conn_t *smbd_conn, x_dlink_t *link);
bool x_smbd_conn_post_user(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool always);
#define X_SMBD_CHAN_POST_USER(smbd_chan, evt) do { \
	auto __evt = (evt); \
	x_smbd_chan_post_user((smbd_chan), &__evt->base, true); \
} while (0)

void x_smbd_conn_post_cancel(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		NTSTATUS status);
void x_smbd_conn_send_unsolicited(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess,
		x_bufref_t *buf, uint16_t opcode);
void x_smbd_conn_send_remove_chan(x_smbd_conn_t *smbd_conn, x_smbd_chan_t *smbd_chan);
void x_smb2_sesssetup_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ, NTSTATUS status,
		const std::vector<uint8_t> &out_security);
void x_smb2_reply(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		x_bufref_t *buf_head,
		x_bufref_t *buf_tail,
		NTSTATUS status,
		size_t reply_size);
NTSTATUS x_smbd_conn_dispatch_update_counts(
		x_smbd_requ_t *smbd_requ,
		bool modify_call);
void x_smbd_conn_post_interim(x_smbd_requ_t *smbd_requ);


int x_smbd_sess_table_init(uint32_t count);
uint32_t x_smbd_sess_get_count();
x_smbd_sess_t *x_smbd_sess_create(uint64_t &id);
x_smbd_sess_t *x_smbd_sess_lookup(NTSTATUS &status,
		uint64_t id, const x_smb2_uuid_t &client_guid);
NTSTATUS x_smbd_sess_auth_succeeded(x_smbd_sess_t *smbd_sess,
		bool is_bind, uint8_t security_mode,
		std::shared_ptr<x_smbd_user_t> &smbd_user,
		const x_smbd_key_set_t &keys,
		uint32_t time_rec);
uint64_t x_smbd_sess_get_id(const x_smbd_sess_t *smbd_sess);
uint16_t x_smbd_sess_get_dialect(const x_smbd_sess_t *smbd_sess);
bool x_smbd_sess_is_signing_required(const x_smbd_sess_t *smbd_sess);
x_smbd_chan_t *x_smbd_sess_lookup_chan(x_smbd_sess_t *smbd_sess, x_smbd_conn_t *smbd_conn);
x_smbd_chan_t *x_smbd_sess_get_active_chan(x_smbd_sess_t *smbd_sess);
bool x_smbd_sess_link_chan(x_smbd_sess_t *smbd_sess, x_dlink_t *link);
bool x_smbd_sess_unlink_chan(x_smbd_sess_t *smbd_sess, x_dlink_t *link,
		bool shutdown);
void x_smbd_sess_remove_chan(x_smbd_sess_t *smbd_sess, x_smbd_chan_t *smbd_chan);
std::shared_ptr<x_smbd_user_t> x_smbd_sess_get_user(const x_smbd_sess_t *smbd_sess);
NTSTATUS x_smbd_sess_logoff(x_smbd_sess_t *smbd_sess);
void x_smbd_sess_close_previous(const x_smbd_sess_t *smbd_sess, uint64_t previous_session_id);
bool x_smbd_sess_link_tcon(x_smbd_sess_t *smbd_sess, x_dlink_t *link);
bool x_smbd_sess_unlink_tcon(x_smbd_sess_t *smbd_sess, x_dlink_t *link);
void x_smbd_sess_update_num_open(x_smbd_sess_t *smbd_sess, int opens);
const x_smb2_key_t *x_smbd_sess_get_signing_key(const x_smbd_sess_t *smbd_sess,
		uint16_t *p_signing_algo);
uint16_t x_smbd_sess_get_cryption_algo(const x_smbd_sess_t *smbd_sess);
const x_smb2_cryption_key_t *x_smbd_sess_get_decryption_key(const x_smbd_sess_t *smbd_sess);
const x_smb2_cryption_key_t *x_smbd_sess_get_encryption_key(x_smbd_sess_t *smbd_sess,
		uint64_t *nonce_low, uint64_t *nonce_high);

bool x_smbd_sess_post_user(x_smbd_sess_t *smbd_sess, x_fdevt_user_t *evt);
#define X_SMBD_SESS_POST_USER(smbd_sess, evt) do { \
	auto __evt = (evt); \
	if (!x_smbd_sess_post_user((smbd_sess), &__evt->base)) { \
		X_LOG_WARN("x_smbd_sess_post_user failed"); \
		delete __evt; \
	} \
} while (0)



x_smbd_chan_t *x_smbd_chan_create(x_smbd_sess_t *smbd_sess,
		x_smbd_conn_t *smbd_conn);
const x_smb2_key_t *x_smbd_chan_get_signing_key(x_smbd_chan_t *smbd_chan,
		uint16_t *p_signing_algo);
void x_smbd_chan_update_preauth(x_smbd_chan_t *smbd_chan,
		const void *data, size_t length);
x_smbd_conn_t *x_smbd_chan_get_conn(const x_smbd_chan_t *smbd_chan);
NTSTATUS x_smbd_chan_update_auth(x_smbd_chan_t *smbd_chan,
		x_smbd_requ_t *smbd_requ,
		const uint8_t *in_security_data,
		uint32_t in_security_length,
		std::vector<uint8_t> &out_security,
		bool is_bind, uint8_t security_mode,
		bool new_auth);
void x_smbd_chan_unlinked(x_dlink_t *conn_link, x_smbd_conn_t *smbd_conn);
x_smbd_chan_t *x_smbd_chan_match(x_dlink_t *conn_link, x_smbd_conn_t *smbd_conn);
x_smbd_chan_t *x_smbd_chan_get_active(x_dlink_t *conn_link);
bool x_smbd_chan_is_active(const x_smbd_chan_t *smbd_chan);
void x_smbd_chan_logoff(x_dlink_t *link, x_smbd_sess_t *smbd_sess);
bool x_smbd_chan_post_user(x_smbd_chan_t *smbd_chan, x_fdevt_user_t *fdevt_user, bool always);



int x_smbd_tcon_table_init(uint32_t count);
x_smbd_tcon_t *x_smbd_tcon_create(x_smbd_sess_t *smbd_sess, 
		const std::shared_ptr<x_smbd_share_t> &smbshare,
		std::shared_ptr<x_smbd_volume_t> &&volume,
		uint32_t share_access);
uint32_t x_smbd_tcon_get_id(const x_smbd_tcon_t *smbd_tcon);
bool x_smbd_tcon_access_check(const x_smbd_tcon_t *smbd_tcon, uint32_t desired_access);
uint32_t x_smbd_tcon_get_share_access(const x_smbd_tcon_t *smbd_tcon);
std::shared_ptr<x_smbd_user_t> x_smbd_tcon_get_user(const x_smbd_tcon_t *smbd_tcon);
bool x_smbd_tcon_get_read_only(const x_smbd_tcon_t *smbd_tcon);
bool x_smbd_tcon_get_durable_handle(const x_smbd_tcon_t *smbd_tcon);
bool x_smbd_tcon_get_continuously_available(const x_smbd_tcon_t *smbd_tcon);
bool x_smbd_tcon_get_abe(const x_smbd_tcon_t *smbd_tcon);
bool x_smbd_tcon_match(const x_smbd_tcon_t *smbd_tcon, const x_smbd_sess_t *smbd_sess, uint32_t tid);
x_smbd_sess_t *x_smbd_tcon_get_sess(const x_smbd_tcon_t *smbd_tcon);
bool x_smbd_tcon_same_sess(const x_smbd_tcon_t *smbd_tcon1, const x_smbd_tcon_t *smbd_tcon2);
std::shared_ptr<x_smbd_share_t> x_smbd_tcon_get_share(const x_smbd_tcon_t *smbd_tcon);
x_smbd_tcon_t *x_smbd_tcon_lookup(uint32_t id, const x_smbd_sess_t *smbd_sess);
bool x_smbd_tcon_link_open(x_smbd_tcon_t *smbd_tcon, x_dlink_t *link);
bool x_smbd_tcon_unlink_open(x_smbd_tcon_t *smbd_tcon, x_dlink_t *link);
bool x_smbd_tcon_disconnect(x_smbd_tcon_t *smbd_tcon);
void x_smbd_tcon_unlinked(x_dlink_t *link, x_smbd_sess_t *smbd_sess, bool shutdown);
std::u16string x_smbd_tcon_get_volume_label(const x_smbd_tcon_t *smbd_tcon);
NTSTATUS x_smbd_tcon_resolve_path(x_smbd_tcon_t *smbd_tcon,
		const std::u16string &in_path,
		bool dfs,
		std::shared_ptr<x_smbd_share_t> &smbd_share,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		std::u16string &path,
		long &path_priv_data,
		long &open_priv_data);



int x_smbd_open_table_init(uint32_t count);
int x_smbd_object_pool_init(size_t max_open);

int x_smbd_posixfs_init(size_t max_open);
int x_smbd_ipc_init();


struct x_smbd_requ_t
{
	enum {
		S_INIT,
		S_PROCESSING,
		S_CANCELLED,
	};

	enum {
		INTERIM_S_NONE,
		INTERIM_S_IMMEDIATE,
		INTERIM_S_SCHEDULED,
		INTERIM_S_SENT,
	};

	explicit x_smbd_requ_t(x_buf_t *in_buf, uint32_t in_msgsize, bool encrypted);
	~x_smbd_requ_t();

	const uint8_t *get_in_data() const {
		return in_buf->data + in_offset;
	}

	bool is_signed() const {
		return (in_smb2_hdr.flags & X_SMB2_HDR_FLAG_SIGNED) != 0;
	}

	bool is_compound_related() const {
		return (in_smb2_hdr.flags & X_SMB2_HDR_FLAG_CHAINED) != 0;
	}

	bool is_compound_followed() const {
		return in_smb2_hdr.next_command != 0;
	}

	template <class T>
	std::unique_ptr<T> release_state() {
		X_ASSERT(requ_state);
		std::unique_ptr<T> state{(T *)requ_state};
		requ_state = nullptr;
		return state;
	}

	template <class T>
	T *get_requ_state() const {
		X_ASSERT(requ_state);
		return (T *)requ_state;
	}

	template <class T>
	void save_requ_state(std::unique_ptr<T> &state) {
		X_ASSERT(!requ_state);
		requ_state = state.release();
	}

	bool set_processing() {
		uint32_t old_val = S_INIT;
		return std::atomic_compare_exchange_strong(&async_state,
				&old_val, S_PROCESSING);
	}

	bool set_cancelled() {
		uint32_t old_val = S_INIT;
		return std::atomic_compare_exchange_strong(&async_state,
				&old_val, S_CANCELLED);
	}

	x_dlink_t async_link; // link into open
	x_dlink_t conn_link; // link into conn
	x_timer_job_t interim_timer;
	void *requ_state = nullptr;

	x_buf_t *in_buf;
	uint64_t id = 0;
	uint64_t channel_generation;
	const uint64_t compound_id;

	x_tick_t start;
	x_smb2_header_t in_smb2_hdr;
	uint32_t in_msgsize, in_offset, in_requ_len;
	std::atomic<uint32_t> async_state = S_INIT;
	uint8_t interim_state = INTERIM_S_NONE;
	bool encrypted;
	bool request_counters_updated = false;
	bool done = false;

	NTSTATUS status{NT_STATUS_OK};
	NTSTATUS sess_status{NT_STATUS_OK};
	uint32_t out_hdr_flags{};

	uint16_t out_credit_granted;

	uint32_t out_length = 0;
	x_bufref_t *out_buf_head{}, *out_buf_tail{};
	x_smbd_sess_t *smbd_sess{};
	x_smbd_chan_t *smbd_chan{};
	x_smbd_tcon_t *smbd_tcon{};
	x_smbd_open_t *smbd_open{};
	void (*cancel_fn)(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ);
	void (*async_done_fn)(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
			NTSTATUS status);
};
X_DECLARE_MEMBER_TRAITS(requ_async_traits, x_smbd_requ_t, async_link)


int x_smbd_requ_pool_init(uint32_t count);
x_smbd_requ_t *x_smbd_requ_create(x_buf_t *in_buf, uint32_t in_msgsize, bool encrypted);
uint64_t x_smbd_requ_get_async_id(const x_smbd_requ_t *smbd_requ);
x_smbd_requ_t *x_smbd_requ_async_lookup(uint64_t id, const x_smbd_conn_t *smbd_conn, bool remove);
void x_smbd_requ_async_insert(x_smbd_requ_t *smbd_requ,
		void (*cancel_fn)(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ),
		int64_t interim_timeout_ns);
bool x_smbd_requ_async_remove(x_smbd_requ_t *smbd_requ);
void x_smbd_requ_async_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		NTSTATUS status);
void x_smbd_requ_done(x_smbd_requ_t *smbd_requ);
NTSTATUS x_smbd_requ_init_open(x_smbd_requ_t *smbd_requ,
		uint64_t id_persistent, uint64_t id_volatile,
		bool modify_call);


NTSTATUS x_smbd_dfs_resolve_path(
		const std::shared_ptr<x_smbd_share_t> &smbd_share,
		const std::u16string &in_path,
		bool dfs,
		std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		std::u16string &path);

void x_smb2_send_lease_break(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess,
		const x_smb2_lease_key_t *lease_key,
		uint8_t current_state, uint8_t new_state,
		uint16_t new_epoch, uint32_t flags);
void x_smb2_send_oplock_break(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess,
		uint64_t id_persistent, uint64_t id_volatile, uint8_t oplock_level);


void x_smbd_wbpool_request(x_wbcli_t *wbcli);


struct x_smb2_fsctl_validate_negotiate_info_state_t
{
	uint32_t in_capabilities;
	uint16_t in_security_mode;
	std::vector<uint16_t> in_dialects;
	x_smb2_uuid_t in_guid;
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
NTSTATUS x_smb2_process_ioctl_torture(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ);
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
	X_LOG_OP("mid=%ld op=%d %s at %s:%d", (smbd_requ)->in_smb2_hdr.mid, \
			(smbd_requ)->in_smb2_hdr.opcode, \
			x_ntstatus_str(status), __FILE__, __LINE__); \
	return (status); \
} while (0)

#define RETURN_STATUS(status) do { \
	X_LOG_DBG("%s", x_ntstatus_str(status)); \
	return (status); \
} while (0)

/* TODO */
#define DEBUG(...) do { } while (0)

extern x_evtmgmt_t *g_evtmgmt;
int x_smbd_ctrl_init(x_evtmgmt_t *evtmgmt);

void x_smbd_schedule_notify(
		uint32_t notify_action,
		uint32_t notify_filter,
		const x_smb2_lease_key_t &ignore_lease_key,
		const x_smb2_uuid_t &client_guid,
		x_smbd_object_t *parent_object,
		x_smbd_object_t *new_parent_object,
		const std::u16string &path_base,
		const std::u16string &new_path_base);

void x_smbd_set_notify_schedulable(bool f);
void x_smbd_flush_notifies();

void x_smbd_object_notify_change(x_smbd_object_t *smbd_object,
		uint32_t notify_action,
		uint32_t notify_filter,
		uint32_t prefix_length,
		const std::u16string &fullpath,
		const std::u16string *new_name_path,
		const x_smb2_lease_key_t &ignore_lease_key,
		const x_smb2_uuid_t &client_guid,
		bool last_level,
		long open_priv_data);

void x_smbd_simple_notify_change(const std::shared_ptr<x_smbd_volume_t> &smbd_volume,
		const std::u16string &path,
		const std::u16string &fullpath,
		const std::u16string *new_fullpath,
		uint32_t notify_action,
		uint32_t notify_filter,
		const x_smb2_lease_key_t &ignore_lease_key,
		const x_smb2_uuid_t &client_guid,
		bool last_level);

void x_smbd_schedule_async(x_job_t *job);

#endif /* __smbd__hxx__ */

