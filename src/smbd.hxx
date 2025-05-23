
#ifndef __smbd__hxx__
#define __smbd__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

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
#include "smbd_proto.hxx"
#include "misc.hxx"
#include "network.hxx"
#include "include/utils.hxx"
#include "include/librpc/misc.hxx"
#include "include/librpc/security.hxx"
#include "include/librpc/samr.hxx"

#include "smbd_file.hxx"
#include "smbd_user.hxx"
#include "network.hxx"

const NTSTATUS X_NT_STATUS_INTERNAL_BLOCKED	= {1};
const NTSTATUS X_NT_STATUS_INTERNAL_TERMINATE	= {2};

x_auth_t *x_smbd_create_auth(const void *sec_buf, size_t sec_len);
const std::vector<uint8_t> &x_smbd_get_negprot_spnego();

enum {
	/* in seconds */
	X_SMBD_DURABLE_TIMEOUT_MAX = (5 * 60),
};

enum {
	X_SMBD_MAX_LOCKS_PER_OPEN = 10000,
};

enum class x_smbd_timer_id_t {
	SESSSETUP,
	BREAK,
	LAST,
};

void x_smbd_add_timer(x_timer_job_t *entry, x_smbd_timer_id_t timer_id);

std::array<x_tick_t, 2> x_smbd_get_time();

enum class x_smbd_feature_option_t {
	disabled,
	enabled,
	desired,
	required,
};

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
struct x_smbd_requ_state_sesssetup_t;

struct x_smbd_key_set_t
{
	uint16_t signing_algo;
	uint16_t cryption_algo;
	uint32_t unused1 = 0;

	x_smb2_key_t signing_key, application_key;
	x_smb2_cryption_key_t decryption_key, encryption_key;
};


struct x_smbd_open_state_t
{
	enum {
		F_APP_INSTANCE_ID = 0x1,
		F_APP_INSTANCE_VERSION = 0x2,
		F_REPLAY_CACHED = 0x4,
		F_INITIAL_DELETE_ON_CLOSE = 0x08,
	};
	const uint32_t access_mask, share_access;
	const x_smb2_uuid_t client_guid;
	const x_smb2_uuid_t create_guid;
	const x_smb2_uuid_t app_instance_id;
	const uint64_t app_instance_version_high;
	const uint64_t app_instance_version_low;
	const x_smb2_lease_key_t parent_lease_key;

	const idl::dom_sid owner;

	uint32_t flags;
	uint16_t channel_sequence;
	x_smb2_create_action_t create_action;
	uint8_t oplock_level{X_SMB2_OPLOCK_LEVEL_NONE};
	x_smbd_dhmode_t dhmode;
	uint32_t durable_timeout_msec = 0;
	uint64_t current_offset = 0;
	uint64_t channel_generation;
	std::vector<x_smb2_lock_element_t> locks;
};

struct x_smbd_lease_data_t
{
	const x_smb2_uuid_t key;
	const uint8_t version;
	uint8_t state{0};
	uint16_t epoch;
	bool breaking{false};
	uint8_t breaking_to_requested{0}, breaking_to_required{0};
};

struct x_smbd_durable_t
{
	uint64_t disconnect_msec;
	uint64_t id_volatile;
	x_smbd_lease_data_t lease_data;
	x_smbd_file_handle_t file_handle;
	x_smbd_open_state_t open_state;
};


int x_smbd_conn_srv_init(int port);

struct x_smbd_negprot_t
{
	uint16_t dialect;
	uint16_t client_security_mode;
	uint16_t server_security_mode;
	uint16_t cryption_algo = X_SMB2_ENCRYPTION_INVALID_ALGO;
	uint16_t signing_algo = X_SMB2_SIGNING_INVALID_ALGO;
	uint32_t compression_algos = 0;
	uint32_t compression_flags = 0;
	uint32_t client_capabilities;
	uint32_t server_capabilities;
	uint32_t max_trans_size, max_read_size, max_write_size;
	x_smb2_uuid_t client_guid;
};

int x_smbd_conn_negprot(x_smbd_conn_t *smbd_conn,
		const x_smbd_negprot_t &negprot, bool smb1);
const x_smb2_uuid_t &x_smbd_conn_get_client_guid(const x_smbd_conn_t *smbd_conn);
const std::shared_ptr<std::u16string> &x_smbd_conn_get_client_name(const x_smbd_conn_t *smbd_conn);
const x_smbd_negprot_t &x_smbd_conn_get_negprot(const x_smbd_conn_t *smbd_conn);
uint16_t x_smbd_conn_get_dialect(const x_smbd_conn_t *smbd_conn);
uint16_t x_smbd_conn_get_cryption_algo(const x_smbd_conn_t *smbd_conn);
uint32_t x_smbd_conn_get_capabilities(const x_smbd_conn_t *smbd_conn);
x_smb2_preauth_t *x_smbd_conn_get_preauth(x_smbd_conn_t *smbd_conn);
void x_smbd_conn_update_preauth(x_smbd_conn_t *smbd_conn,
		const void *data, size_t length);
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
NTSTATUS x_smbd_conn_dispatch_update_counts(
		x_smbd_requ_t *smbd_requ,
		bool modify_call);


int x_smbd_sess_table_init(uint32_t count);
uint32_t x_smbd_sess_get_count();
x_smbd_sess_t *x_smbd_sess_create(const x_smbd_conn_t *smbd_conn);
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
uint32_t x_smbd_sess_get_chan_count(const x_smbd_sess_t *smbd_sess);
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
		X_LOG(SMB, WARN, "x_smbd_sess_post_user failed"); \
		delete __evt; \
	} \
} while (0)



x_smbd_chan_t *x_smbd_chan_create(x_smbd_sess_t *smbd_sess,
		x_smbd_conn_t *smbd_conn);
const x_smb2_key_t *x_smbd_chan_get_signing_key(x_smbd_chan_t *smbd_chan,
		uint16_t *p_signing_algo);
x_smb2_preauth_t *x_smbd_chan_get_preauth(x_smbd_chan_t *smbd_chan);
void x_smbd_chan_update_preauth(x_smbd_chan_t *smbd_chan,
		const void *data, size_t length);
x_smbd_conn_t *x_smbd_chan_get_conn(const x_smbd_chan_t *smbd_chan);
NTSTATUS x_smbd_chan_update_auth(x_smbd_chan_t *smbd_chan,
		x_smbd_requ_t *smbd_requ,
		x_smbd_requ_state_sesssetup_t *state,
		const uint8_t *in_security_data,
		uint32_t in_security_length,
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
bool x_smbd_tcon_encrypted(const x_smbd_tcon_t *smbd_tcon);
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



int x_smbd_open_table_init(uint32_t count);
int x_smbd_object_pool_init(size_t max_open);

int x_smbd_posixfs_init(size_t max_open);
int x_smbd_ipc_init();


void x_smbd_post_lease_break(x_smbd_sess_t *smbd_sess,
		x_smb2_lease_key_t lease_key,
		uint8_t curr_state, uint8_t new_state,
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

int x_smbd_conn_process_smb1negprot(x_smbd_conn_t *smbd_conn,
		x_buf_t *in_buf, uint32_t in_msgsize,
		x_out_buf_t &out_buf);

#define X_SMB2_OP_DECL(x) NTSTATUS x_smb2_parse_##x(x_smbd_conn_t *smbd_conn, \
		x_smbd_requ_t **p_smbd_requ, x_in_buf_t &in_buf);
X_SMB2_OP_ENUM


#define RETURN_STATUS(status) do { \
	X_LOG(SMB, DBG, "%s", x_ntstatus_str(status)); \
	return (status); \
} while (0)

/* TODO */
#define DEBUG(...) do { } while (0)

void x_smbd_ctrl_init();

void x_smbd_notify_change(
		x_smbd_object_t *smbd_object,
		uint32_t action,
		uint32_t filter,
		const x_smb2_lease_key_t &ignore_lease_key,
		const x_smb2_uuid_t &client_guid,
		std::u16string &path_base,
		std::u16string &new_path_base);

void x_smbd_notify_post_deleting(x_smbd_open_t *smbd_open, NTSTATUS status);

void x_smbd_schedule_async(x_job_t *job);

void x_smbd_init();

/* Declare counter id below, e.g., X_SMBD_COUNTER_DECL(name) */
#define X_SMBD_COUNTER_ENUM \
	X_SMBD_COUNTER_DECL(smbd_sess_bind) \
	X_SMBD_COUNTER_DECL(smbd_reply_interim) \
	X_SMBD_COUNTER_DECL(smbd_cancel_success) \
	X_SMBD_COUNTER_DECL(smbd_cancel_toolate) \
	X_SMBD_COUNTER_DECL(smbd_cancel_noent) \
	X_SMBD_COUNTER_DECL(smbd_wakeup_stale) \
	X_SMBD_COUNTER_DECL(smbd_toomany_open) \
	X_SMBD_COUNTER_DECL(smbd_toomany_tcon) \
	X_SMBD_COUNTER_DECL(smbd_toomany_sess) \
	X_SMBD_COUNTER_DECL(smbd_stale_sess) \
	X_SMBD_COUNTER_DECL(smbd_toomany_chan) \
	X_SMBD_COUNTER_DECL(smbd_fail_alloc_chan) \
	X_SMBD_COUNTER_DECL(smbd_fail_alloc_qdir) \

enum {
#undef X_SMBD_COUNTER_DECL
#define X_SMBD_COUNTER_DECL(x) X_SMBD_COUNTER_ID_ ## x,
	X_SMBD_COUNTER_ENUM
	X_SMBD_COUNTER_ID_MAX,
};

/* Declare pair counter id below, e.g., X_SMBD_PAIR_COUNTER_DECL(name) */
#define X_SMBD_PAIR_COUNTER_ENUM \
	X_SMBD_PAIR_COUNTER_DECL(durable_fd) \
	X_SMBD_PAIR_COUNTER_DECL(smbd_conn) \
	X_SMBD_PAIR_COUNTER_DECL(smbd_sess) \
	X_SMBD_PAIR_COUNTER_DECL(smbd_chan) \
	X_SMBD_PAIR_COUNTER_DECL(smbd_tcon) \
	X_SMBD_PAIR_COUNTER_DECL(smbd_object) \
	X_SMBD_PAIR_COUNTER_DECL(smbd_stream) \
	X_SMBD_PAIR_COUNTER_DECL(smbd_lease) \
	X_SMBD_PAIR_COUNTER_DECL(posixfs_ads) \
	X_SMBD_PAIR_COUNTER_DECL(smbd_open) \
	X_SMBD_PAIR_COUNTER_DECL(smbd_replay) \
	X_SMBD_PAIR_COUNTER_DECL(smbd_requ) \
	X_SMBD_PAIR_COUNTER_DECL(smbd_qdir) \
	X_SMBD_PAIR_COUNTER_DECL(auth_krb5) \
	X_SMBD_PAIR_COUNTER_DECL(auth_ntlmssp) \

enum {
#undef X_SMBD_PAIR_COUNTER_DECL
#define X_SMBD_PAIR_COUNTER_DECL(x) X_SMBD_PAIR_COUNTER_ID_ ## x,
	X_SMBD_PAIR_COUNTER_ENUM
	X_SMBD_PAIR_COUNTER_ID_MAX,
};

/* Declare histogram id below, e.g., X_SMBD_HISTOGRAM_DECL(name) */
#define X_SMBD_HISTOGRAM_ENUM \
	X_SMBD_HISTOGRAM_DECL(smbd_op_negprot) \
	X_SMBD_HISTOGRAM_DECL(smbd_op_sesssetup) \
	X_SMBD_HISTOGRAM_DECL(smbd_op_logoff) \
	X_SMBD_HISTOGRAM_DECL(smbd_op_tcon) \
	X_SMBD_HISTOGRAM_DECL(smbd_op_tdis) \
	X_SMBD_HISTOGRAM_DECL(smbd_op_create) \
	X_SMBD_HISTOGRAM_DECL(smbd_op_close) \
	X_SMBD_HISTOGRAM_DECL(smbd_op_flush) \
	X_SMBD_HISTOGRAM_DECL(smbd_op_read) \
	X_SMBD_HISTOGRAM_DECL(smbd_op_write) \
	X_SMBD_HISTOGRAM_DECL(smbd_op_lock) \
	X_SMBD_HISTOGRAM_DECL(smbd_op_ioctl) \
	X_SMBD_HISTOGRAM_DECL(smbd_op_cancel) \
	X_SMBD_HISTOGRAM_DECL(smbd_op_keepalive) \
	X_SMBD_HISTOGRAM_DECL(smbd_op_querydir) \
	X_SMBD_HISTOGRAM_DECL(smbd_op_notify) \
	X_SMBD_HISTOGRAM_DECL(smbd_op_getinfo) \
	X_SMBD_HISTOGRAM_DECL(smbd_op_setinfo) \
	X_SMBD_HISTOGRAM_DECL(smbd_op_break) \

enum {
#undef X_SMBD_HISTOGRAM_DECL
#define X_SMBD_HISTOGRAM_DECL(x) X_SMBD_HISTOGRAM_ID_ ## x,
	X_SMBD_HISTOGRAM_ENUM
	X_SMBD_HISTOGRAM_ID_MAX,
};

extern x_stats_module_t x_smbd_stats;

#define X_SMBD_COUNTER_INC(id, num) \
	X_STATS_COUNTER_INC(x_smbd_stats.counter_base + X_SMBD_COUNTER_ID_##id, (num))

#define X_SMBD_COUNTER_INC_CREATE(id, num) \
	X_STATS_COUNTER_INC_CREATE(x_smbd_stats.pair_counter_base + X_SMBD_PAIR_COUNTER_ID_##id, (num))

#define X_SMBD_COUNTER_INC_DELETE(id, num) \
	X_STATS_COUNTER_INC_DELETE(x_smbd_stats.pair_counter_base + X_SMBD_PAIR_COUNTER_ID_##id, (num))

#define X_SMBD_HISTOGRAM_UPDATE_(id, elapsed) do { \
	local_stats.histograms[x_smbd_stats.histogram_base + id].update(elapsed); \
} while (0)

#define X_SMBD_HISTOGRAM_UPDATE(id, elapsed) \
	X_SMBD_HISTOGRAM_UPDATE_(X_SMBD_HISTOGRAM_ID_ ## id, elapsed)

void x_smbd_stats_init();

#endif /* __smbd__hxx__ */

