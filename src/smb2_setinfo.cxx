
#include "smbd_open.hxx"

namespace {

struct x_smbd_requ_rename_t : x_smbd_requ_t
{
	x_smbd_requ_rename_t(x_smbd_conn_t *smbd_conn, x_in_buf_t &in_buf,
			uint32_t in_msgsize, bool encrypted,
			uint64_t file_id_persistent, uint64_t file_id_volatile,
			bool replace_if_exists, std::u16string &&dst)
		: x_smbd_requ_t(smbd_conn, in_buf,
				in_msgsize, encrypted)
		, in_file_id_persistent(file_id_persistent)
		, in_file_id_volatile(file_id_volatile)
		, in_replace_if_exists(replace_if_exists), in_dst(std::move(dst))
	{
	}
	NTSTATUS process(void *ctx_conn) override;
	NTSTATUS done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status) override;

	const uint64_t in_file_id_persistent;
	const uint64_t in_file_id_volatile;
	const bool in_replace_if_exists;
	std::u16string in_dst;
	int attempt = 0;
};

struct x_smbd_requ_disposition_t : x_smbd_requ_t
{
	x_smbd_requ_disposition_t(x_smbd_conn_t *smbd_conn, x_in_buf_t &in_buf,
			uint32_t in_msgsize, bool encrypted,
			uint64_t file_id_persistent, uint64_t file_id_volatile,
			bool delete_on_close)
		: x_smbd_requ_t(smbd_conn, in_buf,
				in_msgsize, encrypted)
		, in_file_id_persistent(file_id_persistent)
		, in_file_id_volatile(file_id_volatile)
		, in_delete_on_close(delete_on_close)
	{
	}
	NTSTATUS process(void *ctx_conn) override;
	NTSTATUS done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status) override;

	const uint64_t in_file_id_persistent;
	const uint64_t in_file_id_volatile;
	const bool in_delete_on_close;
};

struct x_smbd_requ_setinfo_t : x_smbd_requ_t
{
	x_smbd_requ_setinfo_t(x_smbd_conn_t *smbd_conn, x_in_buf_t &in_buf,
			uint32_t in_msgsize, bool encrypted,
			x_smbd_requ_state_setinfo_t &state)
		: x_smbd_requ_t(smbd_conn, in_buf,
				in_msgsize, encrypted)
		, state(std::move(state))
	{
	}
	NTSTATUS process(void *ctx_conn) override;
	NTSTATUS done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status) override;

	x_smbd_requ_state_setinfo_t state;
};

}


static void encode_out_setinfo(uint8_t *out_hdr)
{
	x_smb2_setinfo_resp_t *out_setinfo = (x_smb2_setinfo_resp_t *)(out_hdr + sizeof(x_smb2_header_t));
	out_setinfo->struct_size = X_H2LE16(sizeof(x_smb2_setinfo_resp_t));
}

static void x_smb2_reply_setinfo(x_smbd_requ_t *smbd_requ)
{
	auto &out_buf = smbd_requ->get_requ_out_buf();
	out_buf.head = out_buf.tail = x_smb2_bufref_alloc(sizeof(x_smb2_setinfo_resp_t));
	out_buf.length = out_buf.head->length;

	uint8_t *out_hdr = out_buf.head->get_data();
	encode_out_setinfo(out_hdr);
}

static NTSTATUS decode_in_rename(bool &in_replace_if_exists,
		std::u16string &in_dst,
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
	in_dst = x_utf16le_decode(in_name_begin, in_name_end);
	in_replace_if_exists = in_info->replace_if_exists;

	return NT_STATUS_OK;
}

NTSTATUS x_smbd_requ_rename_t::process(void *ctx_conn)
{
	NTSTATUS status;
	if (attempt++ == 0) {
		X_SMBD_REQU_LOG(OP, this, " open=0x%lx,0x%lx '%s'",
				in_file_id_persistent, in_file_id_volatile,
				x_str_todebug(in_dst).c_str());

		status = x_smbd_requ_init_open(this,
				in_file_id_persistent,
				in_file_id_volatile,
				true);
		if (!status.ok()) {
			X_SMBD_REQU_RETURN_STATUS(this, status);
		}

		auto in_name_begin = in_dst.data();
		auto in_name_end = in_name_begin + in_dst.size();
		auto sep = x_next_sep(in_name_begin, in_name_end, u':');
		if (sep == in_name_begin) {
			if (!smbd_open->smbd_stream) {
				/* TODO we do not support rename object itself to a stream */
				X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_INVALID_PARAMETER);
			}
			bool is_dollar_data;
			std::u16string in_stream_name;
			NTSTATUS status = x_smb2_parse_stream_name(in_stream_name,
					is_dollar_data, in_name_begin + 1, in_name_end);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			this->in_dst = std::move(in_stream_name);
		} else if (sep == in_name_end) {
			if (smbd_open->smbd_stream) {
				X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_INVALID_PARAMETER);
			}
		} else {
			/* rename not allow both path and stream */
			X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_SHARING_VIOLATION);
		}

		/* MS-FSA 2.1.5.14.11 */
		if (!smbd_open->check_access_any(idl::SEC_STD_DELETE)) {
			X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_ACCESS_DENIED);
		}
	}

	return x_smbd_open_rename(this, in_dst, in_replace_if_exists);
}

NTSTATUS x_smbd_requ_rename_t::done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status)
{
	if (status.ok()) {
		x_smb2_reply_setinfo(this);
	}
	return status;
}

static NTSTATUS decode_in_disposition(bool &in_delete_on_close,
		const uint8_t *in_hdr,
		uint16_t in_input_buffer_offset,
		uint32_t in_input_buffer_length)
{
	if (in_input_buffer_length < sizeof(uint8_t)) {
		RETURN_STATUS(NT_STATUS_INVALID_PARAMETER);
	}
	in_delete_on_close = in_hdr[in_input_buffer_offset] != 0;
	return NT_STATUS_OK;
}

NTSTATUS x_smbd_requ_disposition_t::process(void *ctx_conn)
{
	X_SMBD_REQU_LOG(OP, this, " open=0x%lx,0x%lx delete=%d",
			in_file_id_persistent, in_file_id_volatile,
			in_delete_on_close);

	NTSTATUS status = x_smbd_requ_init_open(this,
			in_file_id_persistent,
			in_file_id_volatile,
			true);
	if (!status.ok()) {
		X_SMBD_REQU_RETURN_STATUS(this, status);
	}

	/* MS-FSA 2.1.5.14.11 */
	if (!smbd_open->check_access_any(idl::SEC_STD_DELETE)) {
		X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_ACCESS_DENIED);
	}

	return x_smbd_open_set_delete_pending(this,
			in_delete_on_close);
}

NTSTATUS x_smbd_requ_disposition_t::done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status)
{
	if (status.ok()) {
		x_smb2_reply_setinfo(this);
	}
	return status;
}

NTSTATUS x_smbd_requ_setinfo_t::process(void *ctx_conn)
{
	NTSTATUS status = x_smbd_requ_init_open(this,
			state.in_file_id_persistent,
			state.in_file_id_volatile,
			true);
	if (!NT_STATUS_IS_OK(status)) {
		X_SMBD_REQU_RETURN_STATUS(this, status);
	}

	X_SMBD_REQU_LOG(OP, this,  " open=0x%lx,0x%lx %d:%d 0x%x input=%lu",
			state.in_file_id_persistent, state.in_file_id_volatile,
			uint8_t(state.in_info_class), uint8_t(state.in_info_level),
			state.in_additional, state.in_data.size());

	return x_smbd_open_op_setinfo(smbd_open, this, state);
}

NTSTATUS x_smbd_requ_setinfo_t::done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status)
{
	if (status.ok()) {
		x_smb2_reply_setinfo(this);
	}
	return status;
}

NTSTATUS x_smb2_parse_SETINFO(x_smbd_conn_t *smbd_conn, x_smbd_requ_t **p_smbd_requ,
		x_in_buf_t &in_buf, uint32_t in_msgsize,
		bool encrypted)
{
	auto in_smb2_hdr = (const x_smb2_header_t *)(in_buf.get_data());

	if (in_buf.length < sizeof(x_smb2_header_t) + sizeof(x_smb2_setinfo_requ_t)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	auto in_setinfo = (const x_smb2_setinfo_requ_t *)(in_smb2_hdr + 1);
	uint16_t in_input_buffer_offset = X_LE2H16(in_setinfo->input_buffer_offset);
	uint32_t in_input_buffer_length = X_LE2H32(in_setinfo->input_buffer_length);

	if (!x_check_range<uint32_t>(in_input_buffer_offset, in_input_buffer_length,
				sizeof(x_smb2_header_t) + sizeof(x_smb2_setinfo_requ_t),
				in_buf.length)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	if (in_input_buffer_length > x_smbd_conn_get_negprot(smbd_conn).max_trans_size) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	if (!x_smbd_requ_verify_creditcharge(X_LE2H16(in_smb2_hdr->credit_charge),
				in_input_buffer_length)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	auto in_info_class = x_smb2_info_class_t(X_LE2H8(in_setinfo->info_class));
	auto in_info_level = x_smb2_info_level_t(X_LE2H8(in_setinfo->info_level));
	uint64_t in_file_id_persistent = X_LE2H64(in_setinfo->file_id_persistent);
	uint64_t in_file_id_volatile = X_LE2H64(in_setinfo->file_id_volatile);

	if (in_info_class == x_smb2_info_class_t::FILE) {
		if (in_info_level == x_smb2_info_level_t::FILE_RENAME_INFORMATION) {
			bool in_replace_if_exists;
			std::u16string in_dst;
			NTSTATUS status = decode_in_rename(in_replace_if_exists, in_dst,
					(const uint8_t *)in_smb2_hdr,
					in_input_buffer_offset, in_input_buffer_length);
			if (!status.ok()) {
				X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, status);
			}
			*p_smbd_requ = new x_smbd_requ_rename_t(smbd_conn, in_buf,
					in_msgsize, encrypted,
					in_file_id_persistent, in_file_id_volatile,
					in_replace_if_exists, std::move(in_dst));
			return NT_STATUS_OK;
		} else if (in_info_level == x_smb2_info_level_t::FILE_DISPOSITION_INFORMATION) {
			bool in_delete_on_close;
			NTSTATUS status = decode_in_disposition(in_delete_on_close,
					(const uint8_t *)in_smb2_hdr,
					in_input_buffer_offset, in_input_buffer_length);
			if (!status.ok()) {
				X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, status);
			}
			*p_smbd_requ = new x_smbd_requ_disposition_t(smbd_conn, in_buf,
					in_msgsize, encrypted,
					in_file_id_persistent, in_file_id_volatile,
					in_delete_on_close);
			return NT_STATUS_OK;
		}
	}

	x_smbd_requ_state_setinfo_t state;
	state.in_file_id_persistent = in_file_id_persistent;
	state.in_file_id_volatile = in_file_id_volatile;
	state.in_info_class = in_info_class;
	state.in_info_level = in_info_level;
	state.in_additional = X_LE2H32(in_setinfo->additional);
	auto input_ptr = (const uint8_t *)in_smb2_hdr + in_input_buffer_offset;
	state.in_data.assign(input_ptr, input_ptr + in_input_buffer_length);

	*p_smbd_requ = new x_smbd_requ_setinfo_t(smbd_conn, in_buf,
			in_msgsize, encrypted,
			state);
	return NT_STATUS_OK;
}

