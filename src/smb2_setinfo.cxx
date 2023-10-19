
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

struct x_smb2_out_setinfo_t
{
	uint16_t struct_size;
};

static void encode_out_setinfo(uint8_t *out_hdr)
{
	x_smb2_out_setinfo_t *out_setinfo = (x_smb2_out_setinfo_t *)(out_hdr + sizeof(x_smb2_header_t));
	out_setinfo->struct_size = X_H2LE16(sizeof(x_smb2_out_setinfo_t));
}

static void x_smb2_reply_setinfo(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ)
{
	X_LOG_OP("%ld SETINFO SUCCESS", smbd_requ->in_smb2_hdr.mid);

	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_out_setinfo_t));

	uint8_t *out_hdr = bufref->get_data();
	encode_out_setinfo(out_hdr);

	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, NT_STATUS_OK, 
			sizeof(x_smb2_header_t) + sizeof(x_smb2_out_setinfo_t));
}

static NTSTATUS smb2_setinfo_dispatch(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smbd_requ_state_setinfo_t> &state)
{
	if (state->in_info_class == x_smb2_info_class_t::FILE) {
		if (state->in_info_level == x_smb2_info_level_t::FILE_DISPOSITION_INFORMATION) {
			auto smbd_open = smbd_requ->smbd_open;
			/* MS-FSA 2.1.5.14.3 */
			if (!smbd_open->check_access_any(idl::SEC_STD_DELETE)) {
				RETURN_OP_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
			}
			if (state->in_data.size() < 1) {
				RETURN_OP_STATUS(smbd_requ, NT_STATUS_INFO_LENGTH_MISMATCH);
			}
			bool delete_on_close = (state->in_data[0] != 0);
			auto lock = std::lock_guard(smbd_open->smbd_object->mutex);
			return x_smbd_open_op_set_delete_on_close(
					smbd_requ->smbd_open,
					delete_on_close);
		}
	}

	/* different INFO request different access, so check access inside the op func */
	return x_smbd_open_op_setinfo(smbd_requ->smbd_open, smbd_conn, smbd_requ,
			state);
}

static NTSTATUS decode_in_rename(x_smbd_requ_state_rename_t &state,
		const uint8_t *in_hdr,
		uint16_t in_input_buffer_offset,
		uint32_t in_input_buffer_length)
{
	if (in_input_buffer_length < sizeof(x_smb2_rename_info_t)) {
		RETURN_STATUS(NT_STATUS_INVALID_PARAMETER);
	}
	const x_smb2_rename_info_t *in_info = (const x_smb2_rename_info_t *)(in_hdr + in_input_buffer_offset);
	uint32_t file_name_length = X_LE2H32(in_info->file_name_length);
	if ((file_name_length % 2) != 0 || file_name_length +
			sizeof(x_smb2_rename_info_t) > in_input_buffer_length) {
		RETURN_STATUS(NT_STATUS_INVALID_PARAMETER);
	}
	if (file_name_length == 0) {
		RETURN_STATUS(NT_STATUS_INFO_LENGTH_MISMATCH);
	}

	const char16_t *in_name_begin = (const char16_t *)(in_info + 1);
	const char16_t *in_name_end = in_name_begin + file_name_length / 2;
	const char16_t *sep = x_next_sep(in_name_begin, in_name_end, u':');
	if (sep == in_name_end) {
		state.in_path = x_utf16le_decode(in_name_begin, in_name_end);
		state.in_stream_name.clear();
	} else if (sep == in_name_begin) {
		bool is_dollar_data;
		NTSTATUS status = x_smb2_parse_stream_name(state.in_stream_name,
				is_dollar_data, sep + 1, in_name_end);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		state.in_path.clear();
	} else {
		/* rename not allow both path and stream */
		RETURN_STATUS(NT_STATUS_SHARING_VIOLATION);
	}

	state.in_replace_if_exists = in_info->replace_if_exists;

	return NT_STATUS_OK;
}

void x_smbd_requ_state_rename_t::async_done(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		NTSTATUS status)
{
	X_LOG_DBG("status=0x%x", status.v);
	if (!smbd_conn) {
		return;
	}
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_setinfo(smbd_conn, smbd_requ);
	}
	x_smbd_conn_requ_done(smbd_conn, smbd_requ, status);
}

static NTSTATUS x_smb2_process_rename(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		std::unique_ptr<x_smbd_requ_state_rename_t> &state)
{
	X_LOG_OP("%ld RENAME 0x%lx, 0x%lx", smbd_requ->in_smb2_hdr.mid,
			state->in_file_id_persistent, state->in_file_id_volatile);

	/* MS-FSA 2.1.5.14.11 */
	if (!smbd_requ->smbd_open->check_access_any(idl::SEC_STD_DELETE)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
	}

	if (smbd_requ->smbd_open->smbd_stream) {
		if (state->in_path.size()) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_OBJECT_NAME_INVALID);
		}
	} else {
		if (state->in_stream_name.size()) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
		}
	}

	NTSTATUS status = x_smbd_open_rename(smbd_requ, state);
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_setinfo(smbd_conn, smbd_requ);
		return status;
	}

	RETURN_OP_STATUS(smbd_requ, status);
}

NTSTATUS x_smb2_process_setinfo(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	if (smbd_requ->in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_in_setinfo_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = smbd_requ->get_in_data();
	uint32_t in_len = smbd_requ->in_requ_len;
	const x_smb2_in_setinfo_t *in_setinfo = (const x_smb2_in_setinfo_t *)(in_hdr + sizeof(x_smb2_header_t));
	uint16_t in_input_buffer_offset = X_LE2H16(in_setinfo->input_buffer_offset);
	uint32_t in_input_buffer_length = X_LE2H32(in_setinfo->input_buffer_length);

	if (!x_check_range<uint32_t>(in_input_buffer_offset, in_input_buffer_length,
				sizeof(x_smb2_header_t) + sizeof(x_smb2_in_setinfo_t), in_len)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if (in_input_buffer_length > x_smbd_conn_get_negprot(smbd_conn).max_trans_size) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if (!x_smbd_requ_verify_creditcharge(smbd_requ,
				in_input_buffer_length)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	auto in_info_class = x_smb2_info_class_t(X_LE2H8(in_setinfo->info_class));
	auto in_info_level = x_smb2_info_level_t(X_LE2H8(in_setinfo->info_level));
	uint64_t in_file_id_persistent = X_LE2H64(in_setinfo->file_id_persistent);
	uint64_t in_file_id_volatile = X_LE2H64(in_setinfo->file_id_volatile);

	NTSTATUS status = x_smbd_requ_init_open(smbd_requ,
			in_file_id_persistent,
			in_file_id_volatile,
			true);
	if (!NT_STATUS_IS_OK(status)) {
		RETURN_OP_STATUS(smbd_requ, status);
	}

	if (in_info_class == x_smb2_info_class_t::FILE) {
		if (in_info_level == x_smb2_info_level_t::FILE_RENAME_INFORMATION) {
			auto state = std::make_unique<x_smbd_requ_state_rename_t>();
			NTSTATUS status = decode_in_rename(*state, in_hdr, 
					in_input_buffer_offset, in_input_buffer_length);
			if (!NT_STATUS_IS_OK(status)) {
				RETURN_OP_STATUS(smbd_requ, status);
			}

			state->in_file_id_persistent = in_file_id_persistent;
			state->in_file_id_volatile = in_file_id_volatile;

			return x_smb2_process_rename(smbd_conn, smbd_requ, state);
		}
	}

	auto state = std::make_unique<x_smbd_requ_state_setinfo_t>();
	state->in_info_class = in_info_class;
	state->in_info_level = in_info_level;
	state->in_additional = X_LE2H32(in_setinfo->additional);
	state->in_file_id_persistent = in_file_id_persistent;
	state->in_file_id_volatile = in_file_id_volatile;
	state->in_data.assign(in_hdr + in_input_buffer_offset,
			in_hdr + in_input_buffer_offset + in_input_buffer_length);

	X_LOG_OP("%ld SETINFO 0x%lx, 0x%lx", smbd_requ->in_smb2_hdr.mid,
			state->in_file_id_persistent, state->in_file_id_volatile);

	status = smb2_setinfo_dispatch(smbd_conn, smbd_requ, state);
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_setinfo(smbd_conn, smbd_requ);
		return status;
	}

	RETURN_OP_STATUS(smbd_requ, status);
}
