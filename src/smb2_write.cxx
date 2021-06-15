
#include "smbd_open.hxx"
#include "core.hxx"

namespace {
enum {
	X_SMB2_WRITE_REQU_BODY_LEN = 0x30,
	X_SMB2_WRITE_RESP_BODY_LEN = 0x10,
};
}

struct x_smb2_in_write_t
{
	uint16_t struct_size;
	uint16_t data_offset;
	uint32_t length;
	uint64_t offset;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	uint32_t channel;
	uint32_t remaining_bytes;
	uint16_t write_channel_info_offset;
	uint16_t write_channel_info_length;
	uint32_t flags;
};

static bool decode_in_write(x_smb2_state_write_t &state,
		const uint8_t *in_hdr, uint32_t in_len)
{
	const x_smb2_in_write_t *in_write = (const x_smb2_in_write_t *)(in_hdr + SMB2_HDR_BODY);
	uint16_t in_data_offset = X_LE2H16(in_write->data_offset);
	uint32_t in_length = X_LE2H32(in_write->length);

	if (!x_check_range<uint32_t>(in_data_offset, in_length,
				SMB2_HDR_BODY + sizeof(x_smb2_in_write_t), in_len)) {
		return false;
	}

	state.in_offset = X_LE2H64(in_write->offset);
	state.in_file_id_persistent = X_LE2H64(in_write->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_write->file_id_volatile);
	state.in_flags = X_LE2H8(in_write->flags);

	/* TODO avoid copying */
	state.in_data.assign(in_hdr + in_data_offset, in_hdr + in_data_offset + in_length);
	return true;
}

struct x_smb2_out_write_t
{
	uint16_t struct_size;
	uint16_t reserved0;
	uint32_t count;
	uint32_t remaining;
	uint16_t write_channel_info_offset;
	uint16_t write_channel_info_length;
};

static void encode_out_write(const x_smb2_state_write_t &state,
		uint8_t *out_hdr)
{
	x_smb2_out_write_t *out_write = (x_smb2_out_write_t *)(out_hdr + SMB2_HDR_BODY);
	out_write->struct_size = X_H2LE16(sizeof(x_smb2_out_write_t) + 1);
	out_write->reserved0 = 0;
	out_write->count = X_H2LE32(state.out_count);
	out_write->remaining = X_H2LE32(state.out_remaining);
	out_write->write_channel_info_offset = 0;
	out_write->write_channel_info_length = 0;
}

static void x_smb2_reply_write(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		const x_smb2_state_write_t &state)
{
	X_LOG_OP("%ld WRITE SUCCESS", smbd_requ->in_mid);

	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_out_write_t));

	uint8_t *out_hdr = bufref->get_data();
	encode_out_write(state, out_hdr);

	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, NT_STATUS_OK, 
			SMB2_HDR_BODY + sizeof(x_smb2_out_write_t));
}

NTSTATUS x_smb2_process_WRITE(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	if (smbd_requ->in_requ_len < SMB2_HDR_BODY + sizeof(x_smb2_in_write_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if (!smbd_requ->smbd_sess) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_USER_SESSION_DELETED);
	}

	if (smbd_requ->smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = smbd_requ->get_in_data();

	auto state = std::make_unique<x_smb2_state_write_t>();
	if (!decode_in_write(*state, in_hdr, smbd_requ->in_requ_len)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	X_LOG_OP("%ld WRITE 0x%lx, 0x%lx", smbd_requ->in_mid,
			state->in_file_id_persistent, state->in_file_id_volatile);

	if (smbd_requ->smbd_open) {
	} else if (smbd_requ->smbd_tcon) {
		smbd_requ->smbd_open = x_smbd_open_find(state->in_file_id_persistent,
				state->in_file_id_volatile,
				smbd_requ->smbd_tcon);
	} else {
		uint32_t tid = x_get_le32(in_hdr + SMB2_HDR_TID);
		smbd_requ->smbd_open = x_smbd_open_find(state->in_file_id_persistent,
				state->in_file_id_volatile, tid, smbd_requ->smbd_sess);
	}

	if (!smbd_requ->smbd_open) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_FILE_CLOSED);
	}

	NTSTATUS status = x_smbd_open_op_write(smbd_conn, smbd_requ, state);
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_write(smbd_conn, smbd_requ, *state);
		return status;
	}

	RETURN_OP_STATUS(smbd_requ, status);
}

