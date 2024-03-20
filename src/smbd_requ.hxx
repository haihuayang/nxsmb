
#ifndef __smbd_requ__hxx__
#define __smbd_requ__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "smbd.hxx"
#include "smb2.hxx"

struct x_smbd_requ_state_async_t
{
	virtual ~x_smbd_requ_state_async_t() { }
	virtual void async_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
			NTSTATUS status) = 0;
};

struct x_smbd_requ_state_read_t : x_smbd_requ_state_async_t
{
	~x_smbd_requ_state_read_t() {
		if (out_buf) {
			x_buf_release(out_buf);
		}
	}
	void async_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
			NTSTATUS status) override;

	uint8_t in_flags;
	uint32_t in_length;
	uint64_t in_offset;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	uint32_t in_minimum_count;
	x_buf_t *out_buf{};
	uint32_t out_buf_length;
};

struct x_smbd_requ_state_write_t : x_smbd_requ_state_async_t
{
	~x_smbd_requ_state_write_t() {
		if (in_buf) {
			x_buf_release(in_buf);
		}
	}
	void async_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
			NTSTATUS status) override;

	uint64_t in_offset;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	uint32_t in_flags;

	x_buf_t *in_buf{};
	uint32_t in_buf_offset;
	uint32_t in_buf_length;

	uint32_t out_count;
	uint32_t out_remaining;
};

struct x_smbd_requ_state_lock_t : x_smbd_requ_state_async_t
{
	void async_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
			NTSTATUS status) override;

	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	uint32_t in_lock_sequence_index;
	std::vector<x_smb2_lock_element_t> in_lock_elements;
};

struct x_smbd_requ_state_getinfo_t
{
	x_smb2_info_class_t in_info_class;
	x_smb2_info_level_t in_info_level;
	uint32_t in_output_buffer_length;
	uint32_t in_additional;
	uint32_t in_input_buffer_length;
	uint32_t in_flags;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;

	std::vector<uint8_t> out_data;
};

struct x_smbd_requ_state_setinfo_t
{
	x_smb2_info_class_t in_info_class;
	x_smb2_info_level_t in_info_level;
	uint32_t in_additional;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	std::vector<uint8_t> in_data;
};

struct x_smbd_requ_state_rename_t : x_smbd_requ_state_async_t
{
	void async_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
			NTSTATUS status) override;

	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	bool in_replace_if_exists;
	std::u16string in_path, in_stream_name;
};

struct x_smbd_requ_state_disposition_t : x_smbd_requ_state_async_t
{
	void async_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
			NTSTATUS status) override;

	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	bool delete_pending;
};

struct x_smbd_requ_state_qdir_t : x_smbd_requ_state_async_t
{
	void async_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
			NTSTATUS status) override;

	x_smb2_info_level_t in_info_level;
	uint8_t in_flags;
	uint32_t in_file_index;
	uint32_t in_output_buffer_length;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	std::u16string in_name;
	x_buf_t *out_buf{};
	uint32_t out_buf_length{0};
};

struct x_smbd_requ_state_ioctl_t : x_smbd_requ_state_async_t
{
	~x_smbd_requ_state_ioctl_t() {
		if (in_buf) {
			x_buf_release(in_buf);
		}
		if (out_buf) {
			x_buf_release(out_buf);
		}
	}
	void async_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
			NTSTATUS status) override;

	uint32_t ctl_code;
	uint32_t in_flags;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	uint32_t in_max_input_length;
	uint32_t in_max_output_length;

	x_buf_t *in_buf{};
	uint32_t in_buf_offset;
	uint32_t in_buf_length{0};
	x_buf_t *out_buf{};
	uint32_t out_buf_length{0};
#if 0
	std::vector<uint8_t> in_data;
	std::vector<uint8_t> out_data;
#endif
};

struct x_smbd_requ_state_notify_t : x_smbd_requ_state_async_t
{
	void async_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
			NTSTATUS status) override;

	uint32_t in_output_buffer_length;
	std::vector<std::pair<uint32_t, std::u16string>> out_notify_changes;
};

struct x_smbd_requ_state_lease_break_t
{
	uint32_t in_flags;
	uint32_t in_state;
	x_smb2_lease_key_t in_key;
	uint64_t in_duration;

	/* NT_STATUS_OPLOCK_BREAK_IN_PROGRESS, send another break noti */
	bool more_break = false;
	uint16_t more_epoch;
	uint32_t more_break_from;
	uint32_t more_break_to;
	uint32_t more_flags;
};

struct x_smbd_requ_state_oplock_break_t
{
	uint8_t in_oplock_level;
	uint8_t out_oplock_level;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
};

struct x_smbd_requ_state_close_t
{
	uint16_t in_struct_size;
	uint16_t in_flags;
	uint32_t in_reserved;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;

	uint16_t out_struct_size;
	uint16_t out_flags{0};
	uint32_t out_reserved{0};
	x_smb2_create_close_info_t out_info;
};

struct x_smbd_requ_state_create_t : x_smbd_requ_state_async_t
{
	x_smbd_requ_state_create_t(const x_smb2_uuid_t &client_guid);
	~x_smbd_requ_state_create_t();
	void async_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
			NTSTATUS status) override;

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

	uint32_t valid_flags = 0;
	uint64_t in_dh_id_persistent;
	uint64_t in_dh_id_volatile;
	uint32_t in_dh_timeout;
	uint32_t in_dh_flags;
	x_smb2_uuid_t in_create_guid;
	x_smb2_uuid_t in_context_app_instance_id;
	uint64_t in_context_app_instance_version_high = 0;
	uint64_t in_context_app_instance_version_low = 0;
};

enum {
	X_SMB2_CONTEXT_FLAG_MXAC = 1,
	X_SMB2_CONTEXT_FLAG_QFID = 2,
	X_SMB2_CONTEXT_FLAG_ALSI = 4,
	X_SMB2_CONTEXT_FLAG_DHNQ = 8,
	X_SMB2_CONTEXT_FLAG_DHNC = 0x10,
	X_SMB2_CONTEXT_FLAG_DH2Q = 0x20,
	X_SMB2_CONTEXT_FLAG_DH2C = 0x40,
};

struct x_smbd_requ_state_sesssetup_t : x_smbd_requ_state_async_t
{
	void async_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
			NTSTATUS status) override;

	uint8_t in_flags;
	uint8_t in_security_mode;
	uint64_t in_previous_session_id;
	std::vector<uint8_t> out_security;
};

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
		x_smbd_requ_state_async_t *ptr = requ_state.release();
		return std::unique_ptr<T>{dynamic_cast<T *>(ptr)};
	}

	std::unique_ptr<x_smbd_requ_state_async_t> release_state() {
		X_ASSERT(requ_state);
		return std::move(requ_state);
	}

	template <class T>
	T *get_requ_state() const {
		X_ASSERT(requ_state);
		return dynamic_cast<T *>(requ_state.get());
	}

	template <class T>
	void save_requ_state(std::unique_ptr<T> &state) {
		X_ASSERT(!requ_state);
		requ_state = std::move(state);
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
	std::unique_ptr<x_smbd_requ_state_async_t> requ_state;

	x_buf_t *in_buf;
	uint64_t id = 0;
	uint64_t channel_generation;
	const uint64_t compound_id;

	x_tick_t start;
	x_smb2_header_t in_smb2_hdr;
	uint32_t in_msgsize, in_offset, in_requ_len;
	std::atomic<uint32_t> async_state = S_INIT;
	std::atomic<int32_t> async_pending = 0;
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
};
X_DECLARE_MEMBER_TRAITS(requ_async_traits, x_smbd_requ_t, async_link)

#define X_SMBD_REQU_DBG_FMT "requ(%p 0x%lx mid=%lu sid=0x%lx tid=0x%x op=%d)"
#define X_SMBD_REQU_DBG_ARG(smbd_requ) (smbd_requ), (smbd_requ)->id, \
		(smbd_requ)->in_smb2_hdr.mid, (smbd_requ)->in_smb2_hdr.sess_id, \
		(smbd_requ)->in_smb2_hdr.tid, (smbd_requ)->in_smb2_hdr.opcode

#define X_SMBD_REQU_RETURN_STATUS(smbd_requ, status) do { \
	X_LOG(SMB, OP, X_SMBD_REQU_DBG_FMT " %s", \
			X_SMBD_REQU_DBG_ARG(smbd_requ), \
			x_ntstatus_str(status)); \
	return (status); \
} while (0)

#define X_SMBD_REQU_LOG(level, smbd_requ, fmt, ...) \
	X_LOG(SMB, level, X_SMBD_REQU_DBG_FMT fmt, X_SMBD_REQU_DBG_ARG(smbd_requ), ##__VA_ARGS__)

using x_smbd_requ_id_list_t = std::vector<uint64_t>;

int x_smbd_requ_pool_init(uint32_t count);
x_smbd_requ_t *x_smbd_requ_create(x_buf_t *in_buf, uint32_t in_msgsize, bool encrypted);
uint64_t x_smbd_requ_get_async_id(const x_smbd_requ_t *smbd_requ);
x_smbd_requ_t *x_smbd_requ_lookup(uint64_t id);
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

static inline bool x_smbd_requ_verify_creditcharge(
		x_smbd_requ_t *smbd_requ, uint32_t data_length)
{
	uint32_t credit_charge = std::max(smbd_requ->in_smb2_hdr.credit_charge, uint16_t(1u));
	/* must be uint16_t so data_length is 0, it because 0 */
	uint16_t needed_charge = x_convert<uint16_t>((data_length - 1) / 65536 + 1);
	return needed_charge <= credit_charge;
}

struct x_smbd_scheduler_t
{
	x_smbd_scheduler_t();
	~x_smbd_scheduler_t();
};

void x_smbd_schedule_release_open(x_smbd_open_t *smbd_open);
void x_smbd_schedule_release_lease(x_smbd_lease_t *smbd_lease);
void x_smbd_schedule_wakeup_oplock_pending_list(x_smbd_requ_id_list_t &oplock_pending_list);
void x_smbd_schedule_clean_pending_requ_list(x_tp_ddlist_t<requ_async_traits> &pending_requ_list);
void x_smbd_schedule_notify(
		uint32_t notify_action,
		uint32_t notify_filter,
		const x_smb2_lease_key_t &ignore_lease_key,
		const x_smb2_uuid_t &client_guid,
		x_smbd_object_t *parent_object,
		x_smbd_object_t *new_parent_object,
		const std::u16string &path_base,
		const std::u16string &new_path_base);



#endif /* __smbd_requ__hxx__ */

