
#include "smbd_open.hxx"
#include "core.hxx"

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

static bool decode_in_notify(x_smb2_state_notify_t &state,
		const uint8_t *in_hdr, uint32_t in_len)
{
	const x_smb2_in_notify_t *in_notify = (const x_smb2_in_notify_t *)(in_hdr + SMB2_HDR_BODY);

	state.in_flags = X_LE2H16(in_notify->flags);
	state.in_output_buffer_length = X_LE2H32(in_notify->output_buffer_length);
	state.in_file_id_persistent = X_LE2H64(in_notify->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_notify->file_id_volatile);
	state.in_filter = X_LE2H32(in_notify->filter);
	return true;
}

struct x_smb2_out_notify_t
{
	uint16_t struct_size;
	uint16_t output_buffer_offset;
	uint32_t output_buffer_length;
};

static void encode_out_notify(const x_smb2_state_notify_t &state,
		uint8_t *out_hdr)
{
	x_smb2_out_notify_t *out_notify = (x_smb2_out_notify_t *)(out_hdr + SMB2_HDR_BODY);
	out_notify->struct_size = X_H2LE16(sizeof(x_smb2_out_notify_t) + 1);
	out_notify->output_buffer_offset = X_H2LE16(SMB2_HDR_BODY + sizeof(x_smb2_out_notify_t));
	out_notify->output_buffer_length = X_H2LE32(state.out_data.size());
	memcpy(out_notify + 1, state.out_data.data(), state.out_data.size());
}

static void x_smb2_reply_notify(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		const x_smb2_state_notify_t &state)
{
	X_LOG_OP("%ld RESP SUCCESS", smbd_requ->in_mid);

	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_out_notify_t) +
			state.out_data.size());

	uint8_t *out_hdr = bufref->get_data();
	encode_out_notify(state, out_hdr);
	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, NT_STATUS_OK, 
			SMB2_HDR_BODY + sizeof(x_smb2_out_notify_t) + state.out_data.size());
}

NTSTATUS x_smb2_process_NOTIFY(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	if (smbd_requ->in_requ_len < SMB2_HDR_BODY + sizeof(x_smb2_in_notify_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if (!smbd_requ->smbd_sess) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_USER_SESSION_DELETED);
	}

	if (smbd_requ->smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = smbd_requ->get_in_data();

	auto state = std::make_unique<x_smb2_state_notify_t>();
	if (!decode_in_notify(*state, in_hdr, smbd_requ->in_requ_len)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	X_LOG_OP("%ld NOTIFY 0x%lx, 0x%lx", smbd_requ->in_mid,
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

	NTSTATUS status = x_smbd_open_op_notify(smbd_conn, smbd_requ, state);
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_notify(smbd_conn, smbd_requ, *state);
		return status;
	}

	RETURN_OP_STATUS(smbd_requ, status);
}

