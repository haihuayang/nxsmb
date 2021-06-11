
#include "smbd_open.hxx"
#include "core.hxx"

enum {
	X_SMB2_FIND_REQU_BODY_LEN = 0x20,
	X_SMB2_FIND_RESP_BODY_LEN = 0x08,
};

struct x_smb2_in_find_t
{
	uint16_t struct_size;
	uint8_t info_level;
	uint8_t flags;
	uint32_t file_index;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	uint16_t name_offset;
	uint16_t name_length;
	uint32_t output_buffer_length;
};

static bool decode_in_find(x_smb2_state_find_t &state,
		const uint8_t *in_hdr, uint32_t in_len)
{
	const x_smb2_in_find_t *in_find = (const x_smb2_in_find_t *)(in_hdr + SMB2_HDR_BODY);

	uint16_t in_name_offset             = X_LE2H16(in_find->name_offset);
	uint16_t in_name_length             = X_LE2H16(in_find->name_length);

	if (in_name_length % 2 != 0 || !x_check_range<uint32_t>(in_name_offset, in_name_length, 
				SMB2_HDR_BODY + sizeof(x_smb2_in_find_t), in_len)) {
		return false;
	}

	state.in_info_level = X_LE2H8(in_find->info_level);
	state.in_flags = X_LE2H8(in_find->flags);
	state.in_file_index = X_LE2H32(in_find->file_index);
	state.in_file_id_persistent = X_LE2H64(in_find->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_find->file_id_volatile);
	state.in_output_buffer_length = X_LE2H32(in_find->output_buffer_length);

	state.in_name.assign((char16_t *)(in_hdr + in_name_offset),
			(char16_t *)(in_hdr + in_name_offset + in_name_length));

	return true;
}

struct x_smb2_out_find_t
{
	uint16_t struct_size;
	uint16_t offset;
	uint32_t length;
};

static void encode_out_find(const x_smb2_state_find_t &state,
		uint8_t *out_hdr)
{
	x_smb2_out_find_t *out_find = (x_smb2_out_find_t *)(out_hdr + SMB2_HDR_BODY);

	out_find->struct_size = X_H2LE16(sizeof(x_smb2_out_find_t) + 1);
	out_find->offset = X_H2LE16(SMB2_HDR_BODY + sizeof(x_smb2_out_find_t));
	out_find->length = X_H2LE32(state.out_data.size());
	memcpy(out_find + 1, state.out_data.data(), state.out_data.size());
}

static void x_smb2_reply_find(x_smbd_conn_t *smbd_conn,
		x_smb2_msg_t *msg,
		const x_smb2_state_find_t &state)
{
	X_LOG_OP("%ld RESP SUCCESS", msg->in_mid);

	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_out_find_t) +
			state.out_data.size());

	uint8_t *out_hdr = bufref->get_data();
	encode_out_find(state, out_hdr);
	x_smb2_reply(smbd_conn, msg, bufref, bufref, NT_STATUS_OK, 
			SMB2_HDR_BODY + sizeof(x_smb2_out_find_t) + state.out_data.size());
}

NTSTATUS x_smb2_process_QUERY_DIRECTORY(x_smbd_conn_t *smbd_conn, x_smb2_msg_t *msg)
{
	if (msg->in_requ_len < SMB2_HDR_BODY + sizeof(x_smb2_in_find_t)) {
		RETURN_OP_STATUS(msg, NT_STATUS_INVALID_PARAMETER);
	}

	if (!msg->smbd_sess) {
		RETURN_OP_STATUS(msg, NT_STATUS_USER_SESSION_DELETED);
	}

	if (msg->smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		RETURN_OP_STATUS(msg, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = msg->get_in_data();

	auto state = std::make_unique<x_smb2_state_find_t>();
	if (!decode_in_find(*state, in_hdr, msg->in_requ_len)) {
		RETURN_OP_STATUS(msg, NT_STATUS_INVALID_PARAMETER);
	}

	X_LOG_OP("%ld FIND 0x%lx, 0x%lx", msg->in_mid,
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

	NTSTATUS status = x_smbd_open_op_find(smbd_conn, msg, state);
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_find(smbd_conn, msg, *state);
		return status;
	}

	RETURN_OP_STATUS(msg, status);
}

