
#ifndef __smbd_requ__hxx__
#define __smbd_requ__hxx__

#ifndef __cplusplus
#error "Must be c++"
#endif

#include "smbd.hxx"
#include "smb2.hxx"
#include "nxfsd.hxx"

struct x_nxfsd_conn_t;

struct x_smbd_requ_state_read_t : x_nxfsd_requ_state_async_t
{
	~x_smbd_requ_state_read_t() {
		if (out_buf) {
			x_buf_release(out_buf);
		}
	}
	void async_done(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ,
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

struct x_smbd_requ_state_write_t : x_nxfsd_requ_state_async_t
{
	~x_smbd_requ_state_write_t() {
		if (in_buf) {
			x_buf_release(in_buf);
		}
	}
	void async_done(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ,
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

struct x_smbd_requ_state_lock_t : x_nxfsd_requ_state_async_t
{
	void async_done(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ,
			NTSTATUS status) override;

	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	uint32_t in_lock_sequence_index;
	std::vector<x_smb2_lock_element_t> in_lock_elements;
};

struct x_smbd_requ_state_getinfo_t : x_nxfsd_requ_state_async_t
{
	void async_done(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ,
			NTSTATUS status) override;

	uint16_t in_dialect;
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

struct x_smbd_requ_state_setinfo_t : x_nxfsd_requ_state_async_t
{
	void async_done(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ,
			NTSTATUS status) override;

	x_smb2_info_class_t in_info_class;
	x_smb2_info_level_t in_info_level;
	uint32_t in_additional;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	std::vector<uint8_t> in_data;
};

struct x_smbd_requ_state_rename_t : x_nxfsd_requ_state_async_t
{
	void async_done(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ,
			NTSTATUS status) override;
	NTSTATUS resume(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ) override;

	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	bool in_replace_if_exists;
	std::u16string in_path, in_stream_name;
};

struct x_smbd_requ_state_disposition_t : x_nxfsd_requ_state_async_t
{
	void async_done(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ,
			NTSTATUS status) override;
	NTSTATUS resume(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ) override;

	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	bool delete_pending;
};

struct x_smbd_requ_state_qdir_t : x_nxfsd_requ_state_async_t
{
	void async_done(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ,
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

struct x_smbd_requ_state_ioctl_t : x_nxfsd_requ_state_async_t
{
	~x_smbd_requ_state_ioctl_t() {
		if (in_buf) {
			x_buf_release(in_buf);
		}
		if (out_buf) {
			x_buf_release(out_buf);
		}
	}
	void async_done(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ,
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

struct x_smbd_requ_state_notify_t : x_nxfsd_requ_state_async_t
{
	void async_done(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ,
			NTSTATUS status) override;

	uint32_t in_output_buffer_length;
	std::vector<std::pair<uint32_t, std::u16string>> out_notify_changes;
};

struct x_smbd_requ_state_lease_break_t
{
	const x_smb2_uuid_t in_client_guid;
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

struct x_smbd_requ_state_create_t : x_nxfsd_requ_state_open_t
{
	x_smbd_requ_state_create_t(const x_smb2_uuid_t &client_guid,
			uint32_t server_capabilities)
		: x_nxfsd_requ_state_open_t(client_guid, server_capabilities) {}

	~x_smbd_requ_state_create_t();
	void async_done(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ,
			NTSTATUS status) override;
	NTSTATUS resume(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ) override;
	const char16_t *unresolved_path;
};

struct x_smbd_requ_state_sesssetup_t : x_nxfsd_requ_state_async_t
{
	void async_done(void *ctx_conn, x_nxfsd_requ_t *nxfsd_requ,
			NTSTATUS status) override;

	uint8_t in_flags;
	uint8_t in_security_mode;
	uint64_t in_previous_session_id;
	std::vector<uint8_t> out_security;
};

struct x_smbd_requ_t
{
	explicit x_smbd_requ_t(x_nxfsd_conn_t *nxfsd_conn, x_buf_t *in_buf,
			uint32_t in_msgsize, bool encrypted);
	~x_smbd_requ_t();

	x_nxfsd_requ_t base;

	bool is_signed() const {
		return (in_smb2_hdr.flags & X_SMB2_HDR_FLAG_SIGNED) != 0;
	}

	bool is_compound_related() const {
		return (in_smb2_hdr.flags & X_SMB2_HDR_FLAG_CHAINED) != 0;
	}

	bool is_compound_followed() const {
		return in_smb2_hdr.next_command != 0;
	}

	uint64_t channel_generation;
	const uint64_t compound_id;

	x_smb2_header_t in_smb2_hdr;
	bool encrypted;
	bool request_counters_updated = false;

	NTSTATUS sess_status{NT_STATUS_OK};
	uint32_t out_hdr_flags{};

	uint16_t out_credit_granted;

	x_smbd_sess_t *smbd_sess{};
	x_smbd_chan_t *smbd_chan{};
	x_smbd_tcon_t *smbd_tcon{};
};

static inline x_smbd_requ_t *x_smbd_requ_from_base(x_nxfsd_requ_t *nxfsd_requ)
{
	return X_CONTAINER_OF(nxfsd_requ, x_smbd_requ_t, base);
}

static inline const x_smbd_requ_t *x_smbd_requ_from_base(const x_nxfsd_requ_t *nxfsd_requ)
{
	return X_CONTAINER_OF(nxfsd_requ, x_smbd_requ_t, base);
}


#define X_SMBD_REQU_SUB_DBG_FMT "mid=%lu sid=0x%lx tid=0x%x op=%d"
#define X_SMBD_REQU_SUB_DBG_ARG(smbd_requ) \
		(smbd_requ)->in_smb2_hdr.mid, (smbd_requ)->in_smb2_hdr.sess_id, \
		(smbd_requ)->in_smb2_hdr.tid, (smbd_requ)->in_smb2_hdr.opcode

#define X_SMBD_REQU_DBG_FMT "requ(%p 0x%lx " X_SMBD_REQU_SUB_DBG_FMT ")"
#define X_SMBD_REQU_DBG_ARG(smbd_requ) (smbd_requ), (smbd_requ)->base.id, \
		X_SMBD_REQU_SUB_DBG_ARG(smbd_requ)

#define X_SMBD_REQU_RETURN_STATUS(smbd_requ, status) do { \
	X_LOG(SMB, OP, X_SMBD_REQU_DBG_FMT " %s", \
			X_SMBD_REQU_DBG_ARG(smbd_requ), \
			x_ntstatus_str(status)); \
	return (status); \
} while (0)

#define X_SMBD_REQU_LOG(level, smbd_requ, fmt, ...) \
	X_LOG(SMB, level, X_SMBD_REQU_DBG_FMT fmt, X_SMBD_REQU_DBG_ARG(smbd_requ), ##__VA_ARGS__)


x_smbd_requ_t *x_smbd_requ_create(x_nxfsd_conn_t *nxfsd_conn, x_buf_t *in_buf, uint32_t in_msgsize, bool encrypted);
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

void x_smbd_schedule_release_lease(x_smbd_lease_t *smbd_lease);
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

