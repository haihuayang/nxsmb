
#include "smbd_open.hxx"
#include "core.hxx"

namespace {
enum {
	X_SMB2_GETINFO_REQU_BODY_LEN = 0x28,
	X_SMB2_GETINFO_RESP_BODY_LEN = 0x08,
};
}

struct x_smb2_in_getinfo_t
{
	uint16_t struct_size;
	uint8_t info_class;
	uint8_t info_level;
	uint32_t output_buffer_length;
	uint16_t input_buffer_offset;
	uint16_t reserved0;
	uint32_t input_buffer_length;;
	uint32_t additional;
	uint32_t flags;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
};

static bool decode_in_getinfo(x_smb2_state_getinfo_t &state,
		const uint8_t *in_hdr, uint32_t in_len)
{
	const x_smb2_in_getinfo_t *in_getinfo = (const x_smb2_in_getinfo_t *)(in_hdr + SMB2_HDR_BODY);

	state.in_info_class = X_LE2H8(in_getinfo->info_class);
	state.in_info_level = X_LE2H8(in_getinfo->info_level);
	state.in_output_buffer_length = X_LE2H32(in_getinfo->output_buffer_length);
	state.in_additional = X_LE2H32(in_getinfo->additional);
	state.in_flags = X_LE2H32(in_getinfo->flags);
	state.in_file_id_persistent = X_LE2H64(in_getinfo->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_getinfo->file_id_volatile);

	/* TODO input_data ? */
#if 0
	if (!x_check_range(requ_getinfo.input_buffer_offset, requ_getinfo.input_buffer_length,
				0x40 + X_SMB2_GETINFO_REQU_BODY_LEN, in_len)) {
		return X_SMB2_REPLY_ERROR(smbd_conn, smbd_requ, smbd_sess, in_tid, NT_STATUS_INVALID_PARAMETER);
	}

	const std::shared_ptr<x_smbconf_t> smbconf = smbd_conn->get_smbconf();
	if (requ_getinfo.input_buffer_length > smbconf->max_trans) {
		return X_SMB2_REPLY_ERROR(smbd_conn, smbd_requ, smbd_sess, in_tid, NT_STATUS_INVALID_PARAMETER);
	}

	if (requ_getinfo.output_buffer_length > smbconf->max_trans) {
		return X_SMB2_REPLY_ERROR(smbd_conn, smbd_requ, smbd_sess, in_tid, NT_STATUS_INVALID_PARAMETER);
	}
#endif
	return true;
}

struct x_smb2_out_getinfo_t
{
	uint16_t struct_size;
	uint16_t output_buffer_offset;
	uint32_t output_buffer_length;
};

static void encode_out_getinfo(const x_smb2_state_getinfo_t &state,
		uint8_t *out_hdr)
{
	x_smb2_out_getinfo_t *out_getinfo = (x_smb2_out_getinfo_t *)(out_hdr + SMB2_HDR_BODY);
	out_getinfo->struct_size = X_H2LE16(sizeof(x_smb2_out_getinfo_t) +
			(state.out_data.size() ? 1 : 0));
	out_getinfo->output_buffer_offset = X_H2LE16(SMB2_HDR_BODY + sizeof(x_smb2_out_getinfo_t));
	out_getinfo->output_buffer_length = X_H2LE32(state.out_data.size());
	memcpy(out_getinfo + 1, state.out_data.data(), state.out_data.size());
}

static void x_smb2_reply_getinfo(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		const x_smb2_state_getinfo_t &state)
{
	X_LOG_OP("%ld RESP SUCCESS", smbd_requ->in_mid);

	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_out_getinfo_t) +
			state.out_data.size());

	uint8_t *out_hdr = bufref->get_data();
	encode_out_getinfo(state, out_hdr);
	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, NT_STATUS_OK, 
			SMB2_HDR_BODY + sizeof(x_smb2_out_getinfo_t) + state.out_data.size());
}

NTSTATUS x_smb2_process_GETINFO(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	if (smbd_requ->in_requ_len < SMB2_HDR_BODY + sizeof(x_smb2_in_getinfo_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if (!smbd_requ->smbd_sess) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_USER_SESSION_DELETED);
	}

	if (smbd_requ->smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = smbd_requ->get_in_data();

	auto state = std::make_unique<x_smb2_state_getinfo_t>();
	if (!decode_in_getinfo(*state, in_hdr, smbd_requ->in_requ_len)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	X_LOG_OP("%ld GETINFO 0x%lx, 0x%lx", smbd_requ->in_mid,
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

	NTSTATUS status = x_smbd_open_op_getinfo(smbd_conn, smbd_requ, state);
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_getinfo(smbd_conn, smbd_requ, *state);
		return status;
	}

	RETURN_OP_STATUS(smbd_requ, status);
}

