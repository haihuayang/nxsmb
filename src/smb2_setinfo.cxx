
#include "smbd_open.hxx"
#include "smbd_object.hxx"

namespace {
enum {
	X_SMB2_SETINFO_REQU_BODY_LEN = 0x20,
	X_SMB2_SETINFO_RESP_BODY_LEN = 0x2,
};
}

struct x_smb2_in_setinfo_t
{
	uint16_t struct_size;
	uint8_t  info_class;
	uint8_t  info_level;
	uint32_t input_buffer_length;
	uint16_t input_buffer_offset;
	uint16_t reserve;
	uint32_t additional;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
};

static bool decode_in_setinfo(x_smb2_state_setinfo_t &state,
		const uint8_t *in_hdr, uint32_t in_len)
{
	const x_smb2_in_setinfo_t *in_setinfo = (const x_smb2_in_setinfo_t *)(in_hdr + SMB2_HDR_BODY);
	uint16_t in_input_buffer_offset = X_LE2H16(in_setinfo->input_buffer_offset);
	uint32_t in_input_buffer_length = X_LE2H32(in_setinfo->input_buffer_length);

	if (!x_check_range<uint32_t>(in_input_buffer_offset, in_input_buffer_length,
				SMB2_HDR_BODY + sizeof(x_smb2_in_setinfo_t), in_len)) {
		return false;
	}

	state.in_info_class = X_LE2H8(in_setinfo->info_class);
	state.in_info_level = X_LE2H8(in_setinfo->info_level);
	state.in_additional = X_LE2H32(in_setinfo->additional);
	state.in_file_id_persistent = X_LE2H64(in_setinfo->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_setinfo->file_id_volatile);

	state.in_data.assign(in_hdr + in_input_buffer_offset,
			in_hdr + in_input_buffer_offset + in_input_buffer_length);
	return true;
}

struct x_smb2_out_setinfo_t
{
	uint16_t struct_size;
};

static void encode_out_setinfo(const x_smb2_state_setinfo_t &state,
		uint8_t *out_hdr)
{
	x_smb2_out_setinfo_t *out_setinfo = (x_smb2_out_setinfo_t *)(out_hdr + SMB2_HDR_BODY);
	out_setinfo->struct_size = X_H2LE16(sizeof(x_smb2_out_setinfo_t));
}

static void x_smb2_reply_setinfo(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		const x_smb2_state_setinfo_t &state)
{
	X_LOG_OP("%ld SETINFO SUCCESS", smbd_requ->in_mid);

	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_out_setinfo_t));

	uint8_t *out_hdr = bufref->get_data();
	encode_out_setinfo(state, out_hdr);

	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, NT_STATUS_OK, 
			SMB2_HDR_BODY + sizeof(x_smb2_out_setinfo_t));
}

#if 0
static NTSTATUS process_setinfo(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique<x_smb2_state_setinfo_t> &state)
{
	if (state->in_info_class == SMB2_GETINFO_FILE) {
		return x_smbd_open_op_setinfo_file(smbd_conn, smbd_requ, state);
	} else if (state->in_info_class == SMB2_GETINFO_FS) {
		return x_smbd_open_op_setinfo_fs(smbd_conn, smbd_requ, state);
	} else if (state->in_info_class == SMB2_GETINFO_SECURITY) {
		return setinfo_security(disk_open, smbd_requ, *state);
	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}
}
#endif
NTSTATUS x_smb2_process_setinfo(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	if (smbd_requ->in_requ_len < SMB2_HDR_BODY + sizeof(x_smb2_in_setinfo_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = smbd_requ->get_in_data();

	auto state = std::make_unique<x_smb2_state_setinfo_t>();
	if (!decode_in_setinfo(*state, in_hdr, smbd_requ->in_requ_len)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	X_LOG_OP("%ld SETINFO 0x%lx, 0x%lx", smbd_requ->in_mid,
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

	x_smbd_object_t *smbd_object = smbd_requ->smbd_open->smbd_object;

	/* different INFO request different access, so check access inside the op func */
	NTSTATUS status = smbd_object->ops->setinfo(smbd_object, smbd_conn, smbd_requ, state);
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_setinfo(smbd_conn, smbd_requ, *state);
		return status;
	}

	RETURN_OP_STATUS(smbd_requ, status);
}
