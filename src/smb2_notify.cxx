
#include "smbd.hxx"
#include "smbd_open.hxx"
#include "smbd_conf.hxx"

namespace {
enum {
	X_SMB2_NOTIFY_REQU_BODY_LEN = 0x20,
	X_SMB2_NOTIFY_RESP_BODY_LEN = 0x08,
};
}

struct x_smb2_in_notify_t
{
	uint16_t struct_size;
	uint16_t flags;
	uint32_t output_buffer_length;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	uint32_t filter;
	uint32_t reserved;
};

struct x_smb2_out_notify_t
{
	uint16_t struct_size;
	uint16_t output_buffer_offset;
	uint32_t output_buffer_length;
};

static NTSTATUS x_smb2_reply_notify(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		const x_smb2_state_notify_t &state)
{
	X_LOG_OP("%ld RESP SUCCESS", smbd_requ->in_smb2_hdr.mid);
	/* TODO seem windows server remember in_output_buffer_length */
	uint32_t output_buffer_length = std::min(state.in_output_buffer_length,
			smbd_requ->smbd_open->notify_buffer_length);

	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_out_notify_t) +
			output_buffer_length);

	uint8_t *out_hdr = bufref->get_data();
	x_smb2_out_notify_t *out_notify = (x_smb2_out_notify_t *)(out_hdr + sizeof(x_smb2_header_t));
	uint8_t *out_body = (uint8_t *)(out_notify + 1);

	size_t body_length = x_smb2_notify_marshall(state.out_notify_changes,
			out_body, output_buffer_length);
	NTSTATUS status;
	if (body_length == 0) {
		status = NT_STATUS_NOTIFY_ENUM_DIR;
	} else {
		status = NT_STATUS_OK;
	}
	bufref->length = x_convert_assert<uint32_t>(sizeof(x_smb2_header_t) +
			sizeof(x_smb2_out_notify_t) + body_length);

	out_notify->struct_size = X_H2LE16(sizeof(x_smb2_out_notify_t) + 1);
	out_notify->output_buffer_offset = X_H2LE16(sizeof(x_smb2_header_t) + sizeof(x_smb2_out_notify_t));
	out_notify->output_buffer_length = X_H2LE32(x_convert_assert<uint32_t>(body_length));

	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, status, 
			bufref->length);
	return status;
}

static void x_smb2_notify_async_done(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		NTSTATUS status)
{
	X_LOG_DBG("status=0x%x", status.v);
	auto state = smbd_requ->release_state<x_smb2_state_notify_t>();
	if (!smbd_conn) {
		return;
	}
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_notify(smbd_conn, smbd_requ, *state);
	}
	x_smbd_conn_requ_done(smbd_conn, smbd_requ, status);
}

NTSTATUS x_smb2_process_notify(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	if (smbd_requ->in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_in_notify_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if (!smbd_requ->smbd_sess) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_USER_SESSION_DELETED);
	}

	const uint8_t *in_hdr = smbd_requ->get_in_data();
	auto state = std::make_unique<x_smb2_state_notify_t>();
	const x_smb2_in_notify_t *in_notify = (const x_smb2_in_notify_t *)(in_hdr + sizeof(x_smb2_header_t));

	uint16_t in_flags = X_LE2H16(in_notify->flags);
	uint64_t in_file_id_persistent = X_LE2H64(in_notify->file_id_persistent);
	uint64_t in_file_id_volatile = X_LE2H64(in_notify->file_id_volatile);
	uint32_t in_output_buffer_length = X_LE2H32(in_notify->output_buffer_length);
	uint32_t in_filter = X_LE2H32(in_notify->filter);

	// TODO smbd_smb2_request_verify_creditcharge
	if (in_output_buffer_length > x_smbd_conf_get()->max_trans_size) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	X_LOG_OP("%ld NOTIFY 0x%lx,0x%lx, filter=0x%x, length=%d",
			smbd_requ->in_smb2_hdr.mid,
			in_file_id_persistent, in_file_id_volatile,
			in_filter, in_output_buffer_length);
	state->in_output_buffer_length = in_output_buffer_length;

	NTSTATUS status = x_smbd_requ_init_open(smbd_requ,
			in_file_id_persistent,
			in_file_id_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		RETURN_OP_STATUS(smbd_requ, status);
	}

	auto smbd_open = smbd_requ->smbd_open;
	if (x_smbd_open_is_data(smbd_open)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if (!smbd_open->check_access(idl::SEC_DIR_LIST)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
	}

	/* notify filter cannot be overwritten */
	if (smbd_open->notify_filter == 0) {
		smbd_open->notify_filter = in_filter | X_FILE_NOTIFY_CHANGE_VALID;
		smbd_open->notify_buffer_length = in_output_buffer_length;
		if (in_flags & X_SMB2_WATCH_TREE) {
			smbd_open->notify_filter |= X_FILE_NOTIFY_CHANGE_WATCH_TREE;
			++smbd_open->smbd_object->smbd_volume->watch_tree_cnt;
		}
	}

	smbd_requ->async_done_fn = x_smb2_notify_async_done;
	status = x_smbd_open_op_notify(smbd_open,
			smbd_conn, smbd_requ, state);
	if (NT_STATUS_IS_OK(status)) {
		return x_smb2_reply_notify(smbd_conn, smbd_requ, *state);
	}

	RETURN_OP_STATUS(smbd_requ, status);
}


