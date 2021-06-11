
#include "smbd_open.hxx"
#include "core.hxx"

namespace {
enum {
	X_SMB2_READ_REQU_BODY_LEN = 0x30,
	X_SMB2_READ_RESP_BODY_LEN = 0x10,
};

struct x_smb2_in_read_t
{
	uint16_t struct_size;
	uint8_t reserved0;
	uint8_t flags;
	uint32_t length;
	uint64_t offset;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	uint32_t minimum_count;
	uint32_t channel;
	uint32_t remaining_bytes;
	uint16_t read_channel_info_offset;
	uint16_t read_channel_info_length;
};

struct x_smb2_out_read_t
{
	uint16_t struct_size;
	uint8_t data_offset;
	uint8_t reserved0;
	uint32_t data_length;
	uint32_t data_remaining;
	uint32_t reserved1;
};

}

static void x_smb2_reply_read(x_smbd_conn_t *smbd_conn,
		x_smb2_msg_t *msg,
		const x_smb2_state_read_t &state)
{
	X_LOG_OP("%ld RESP SUCCESS", msg->in_mid);

	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_out_read_t) +
			state.out_data.size());

	uint8_t *out_hdr = bufref->get_data();

	x_smb2_out_read_t *out_read = (x_smb2_out_read_t *)(out_hdr + SMB2_HDR_BODY);
	out_read->struct_size = X_H2LE16(sizeof(x_smb2_out_read_t) + 1);
	out_read->data_offset = SMB2_HDR_BODY + sizeof(x_smb2_out_read_t);
	out_read->reserved0 = 0;
	out_read->data_length = X_H2LE32(state.out_data.size());
	out_read->data_remaining = 0;
	out_read->reserved1 = 0;
	memcpy(out_read + 1, state.out_data.data(), state.out_data.size());

	x_smb2_reply(smbd_conn, msg, bufref, bufref, NT_STATUS_OK, 
			SMB2_HDR_BODY + sizeof(x_smb2_out_read_t) + state.out_data.size());
}

static void parse_read_in(x_smb2_state_read_t &state,
		const uint8_t *in_hdr)
{
	const x_smb2_in_read_t *in_read = (const x_smb2_in_read_t *)(in_hdr + SMB2_HDR_BODY);
	state.in_flags = X_LE2H8(in_read->flags);
	state.in_length = X_LE2H32(in_read->length);
	state.in_offset = X_LE2H64(in_read->offset);
	state.in_file_id_persistent = X_LE2H64(in_read->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_read->file_id_volatile);
	state.in_minimum_count = X_LE2H32(in_read->minimum_count);
}

NTSTATUS x_smb2_process_READ(x_smbd_conn_t *smbd_conn, x_smb2_msg_t *msg)
{
	// TODO smbd_smb2_request_verify_creditcharge
	if (msg->in_requ_len < SMB2_HDR_BODY + sizeof(x_smb2_in_read_t)) {
		RETURN_OP_STATUS(msg, NT_STATUS_INVALID_PARAMETER);
	}

	if (!msg->smbd_sess) {
		RETURN_OP_STATUS(msg, NT_STATUS_USER_SESSION_DELETED);
	}

	if (msg->smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		RETURN_OP_STATUS(msg, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = msg->get_in_data();

	auto state = std::make_unique<x_smb2_state_read_t>();
	parse_read_in(*state, in_hdr);

	X_LOG_OP("%ld READ 0x%lx, 0x%lx", msg->in_mid,
			state->in_file_id_persistent, state->in_file_id_volatile);

	if (msg->smbd_open) {
	} else if (msg->smbd_tcon) {
		msg->smbd_open = x_smbd_open_find(state->in_file_id_persistent,
				state->in_file_id_volatile,
				msg->smbd_tcon);
	} else {
		uint32_t tid = x_get_le32(in_hdr + SMB2_HDR_TID);
		msg->smbd_open = x_smbd_open_find(state->in_file_id_persistent,
				state->in_file_id_volatile, tid, msg->smbd_sess);
	}

	if (!msg->smbd_open) {
		RETURN_OP_STATUS(msg, NT_STATUS_FILE_CLOSED);
	}

	NTSTATUS status = x_smbd_open_op_read(smbd_conn, msg, state);
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_read(smbd_conn, msg, *state);
		return status;
	}

	RETURN_OP_STATUS(msg, status);
}
#if 0
static x_smbd_open_t *x_smbd_open_find_or_error(x_smbd_conn_t *smbd_conn,
		x_msg_ptr_t &msg,
		const uint8_t *inhdr,
		uint64_t file_id_volatile)
{
	uint64_t in_session_id = BVAL(inhdr, SMB2_HDR_SESSION_ID);
	uint32_t in_tid = IVAL(inhdr, SMB2_HDR_TID);
	NTSTATUS status;
	if (in_session_id == 0) {
		X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, in_tid, NT_STATUS_USER_SESSION_DELETED);
		return nullptr;
	}
	if (in_tid == 0) {
		x_auto ref_t<x_smbd_sess_t> smbd_sess = x_smbd_sess_find(smbd_conn, status, in_session_id);
		if (smbd_sess) {
			X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, NT_STATUS_NETWORK_NAME_DELETED);
		} else {
			X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, in_tid, NT_STATUS_USER_SESSION_DELETED);
		}
		return nullptr;
	}
	x_smbd_open_t *smbd_open = x_smbd_open_find(smbd_conn, file_id_volatile, in_tld, in_session_id);
	if (smbd_open) {
		return smbd_open;
	}

	x_auto_ref_t<x_smbd_tcon_t> smbd_tcon{x_smbd_tcon_find(smbd_conn,
			in_tld, in_session_id)};
	if (smbd_tcon) {
		X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, NT_STATUS_FILE_CLOSED);
		return nullptr;
	}

	x_auto ref_t<x_smbd_sess_t> smbd_sess = x_smbd_sess_find(smbd_conn, status, in_session_id);
	if (smbd_sess) {
		X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, in_tid, NT_STATUS_NETWORK_NAME_DELETED);
	} else {
		X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, in_tid, NT_STATUS_USER_SESSION_DELETED);
	}
	return nullptr;
}
#endif

