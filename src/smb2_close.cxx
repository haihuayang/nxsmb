
#include "smbd_open.hxx"
#include "core.hxx"

enum {
	X_SMB2_CLOSE_REQU_BODY_LEN = 0x18,
	X_SMB2_CLOSE_RESP_BODY_LEN = 0x3c,
};

struct x_smb2_in_close_t
{
	uint16_t struct_size;
	uint16_t flags;
	uint32_t reserved0;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
};

static bool decode_in_close(x_smb2_state_close_t &state,
		const uint8_t *in_hdr)
{
	const x_smb2_in_close_t *in_close = (const x_smb2_in_close_t *)(in_hdr + SMB2_HDR_BODY);

	state.in_flags = X_LE2H16(in_close->flags);
	state.in_file_id_persistent = X_LE2H64(in_close->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_close->file_id_volatile);

	return true;
}

struct x_smb2_out_close_t
{
	uint16_t struct_size;
	uint16_t flags;
	uint32_t reserved0;
	x_smb2_create_close_info_t info;
};

static void encode_out_close(const x_smb2_state_close_t &state,
		uint8_t *out_hdr)
{
	x_smb2_out_close_t *out_close = (x_smb2_out_close_t *)(out_hdr + SMB2_HDR_BODY);

	out_close->struct_size = X_H2LE16(X_SMB2_CLOSE_RESP_BODY_LEN);
	out_close->flags = X_H2LE16(state.out_flags);
	out_close->reserved0 = 0;
	/* TODO x_smb2_out_close_t is not 8 bytes aligned, sizeof() is not 0x3c */
	if (state.out_flags & SMB2_CLOSE_FLAGS_FULL_INFORMATION) {
		/* TODO not work for big-endian */
		memcpy(&out_close->info, &state.out_info, sizeof(state.out_info));
	} else {
		memset(&out_close->info, 0, sizeof(out_close->info));
	}
}

static void x_smb2_reply_close(x_smbd_conn_t *smbd_conn,
		x_smb2_msg_t *msg,
		const x_smb2_state_close_t &state)
{
	x_bufref_t *bufref = x_bufref_alloc(X_SMB2_CLOSE_RESP_BODY_LEN);

	uint8_t *out_hdr = bufref->get_data();
	
	encode_out_close(state, out_hdr);
	x_smb2_reply(smbd_conn, msg, bufref, bufref, NT_STATUS_OK, 
			SMB2_HDR_BODY + X_SMB2_CLOSE_RESP_BODY_LEN);
}

NTSTATUS x_smb2_process_CLOSE(x_smbd_conn_t *smbd_conn, x_smb2_msg_t *msg)
{
	if (msg->in_requ_len < SMB2_HDR_BODY + X_SMB2_CLOSE_REQU_BODY_LEN) {
		RETURN_OP_STATUS(msg, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = msg->get_in_data();

	if (!msg->smbd_sess) {
		RETURN_OP_STATUS(msg, NT_STATUS_USER_SESSION_DELETED);
	}

	if (msg->smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		RETURN_OP_STATUS(msg, NT_STATUS_INVALID_PARAMETER);
	}

	auto state = std::make_unique<x_smb2_state_close_t>();
	if (!decode_in_close(*state, in_hdr)) {
		RETURN_OP_STATUS(msg, NT_STATUS_INVALID_PARAMETER);
	}

	X_LOG_OP("%ld CLOSE 0x%lx, 0x%lx", msg->in_mid,
			state->in_file_id_persistent, state->in_file_id_volatile);

	if (msg->smbd_open) {
	} else if (msg->smbd_tcon) {
		msg->smbd_open = x_smbd_open_find(state->in_file_id_persistent,
				state->in_file_id_volatile,
				msg->smbd_tcon);
	} else {
		msg->smbd_open = x_smbd_open_find(state->in_file_id_persistent,
				state->in_file_id_volatile, msg->in_tid, msg->smbd_sess);
	}


	if (!msg->smbd_open) {
		RETURN_OP_STATUS(msg, NT_STATUS_FILE_CLOSED);
	}


	/* TODO signing/encryption */

	NTSTATUS status = x_smbd_open_op_close(smbd_conn, msg, state);
	if (!NT_STATUS_IS_OK(status)) {
		RETURN_OP_STATUS(msg, status);
	}

	x_smbd_open_release(msg->smbd_open);
	msg->smbd_open = nullptr;
	x_smb2_reply_close(smbd_conn, msg, *state);
	return status;
}
