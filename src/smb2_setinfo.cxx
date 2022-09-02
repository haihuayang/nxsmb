
#include "smbd_open.hxx"

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

static NTSTATUS smb2_setinfo_dispatch(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smb2_state_setinfo_t> &state,
		std::vector<x_smb2_change_t> &changes)
{
	if (state->in_info_class == SMB2_GETINFO_FILE) {
		if (state->in_info_level == SMB2_FILE_INFO_FILE_RENAME_INFORMATION) {
			/* MS-FSA 2.1.5.14.11 */
			if (!smbd_requ->smbd_open->check_access(idl::SEC_STD_DELETE)) {
				RETURN_OP_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
			}
			bool replace_if_exists;
			std::u16string path, stream_name;
			NTSTATUS status = x_smb2_rename_info_decode(replace_if_exists,
					path, stream_name, state->in_data);
			if (!NT_STATUS_IS_OK(status)) {
				RETURN_OP_STATUS(smbd_requ, status);
			}
			return x_smbd_open_op_rename(smbd_requ->smbd_open, smbd_requ,
					replace_if_exists, path, stream_name, changes);
		} else if (state->in_info_level == SMB2_FILE_INFO_FILE_DISPOSITION_INFORMATION) {
			/* MS-FSA 2.1.5.14.3 */
			if (!smbd_requ->smbd_open->check_access(idl::SEC_STD_DELETE)) {
				RETURN_OP_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
			}
			if (state->in_data.size() < 1) {
				RETURN_OP_STATUS(smbd_requ, NT_STATUS_INFO_LENGTH_MISMATCH);
			}
			bool delete_on_close = (state->in_data[0] != 0);
			return x_smbd_open_op_set_delete_on_close(smbd_requ->smbd_open, smbd_requ,
					delete_on_close);
		}
	}

	/* different INFO request different access, so check access inside the op func */
	return x_smbd_open_op_setinfo(smbd_requ->smbd_open, smbd_conn, smbd_requ,
			state, changes);
}

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

	if (!smbd_requ->smbd_open) {
		smbd_requ->smbd_open = x_smbd_open_lookup(state->in_file_id_persistent,
				state->in_file_id_volatile,
				smbd_requ->smbd_tcon);
		if (!smbd_requ->smbd_open) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_FILE_CLOSED);
		}
	}

	std::vector<x_smb2_change_t> changes;
	NTSTATUS status = smb2_setinfo_dispatch(smbd_conn, smbd_requ, state, changes);
	if (NT_STATUS_IS_OK(status)) {
		x_smbd_notify_change(smbd_requ->smbd_open->smbd_object->topdir, changes);
		x_smb2_reply_setinfo(smbd_conn, smbd_requ, *state);
		return status;
	}

	RETURN_OP_STATUS(smbd_requ, status);
}
