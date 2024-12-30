
#include "smbd_open.hxx"
#include "smbd_requ.hxx"

namespace {

struct x_smbd_requ_getinfo_t : x_smbd_requ_t
{
	x_smbd_requ_getinfo_t(x_smbd_conn_t *smbd_conn,
			x_smbd_requ_state_getinfo_t &in_state)
		: x_smbd_requ_t(smbd_conn)
		, state(in_state)
	{
	}
	std::tuple<bool, bool, bool> get_properties() const override
	{
		return { true, true, false };
	}
	NTSTATUS process(void *ctx_conn) override;
	NTSTATUS done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status) override;

	x_smbd_requ_state_getinfo_t state;
};

}

static void encode_out_getinfo(const x_smbd_requ_state_getinfo_t &state,
		uint8_t *out_hdr)
{
	x_smb2_getinfo_resp_t *out_getinfo = (x_smb2_getinfo_resp_t *)(out_hdr + sizeof(x_smb2_header_t));
	out_getinfo->struct_size = X_H2LE16(sizeof(x_smb2_getinfo_resp_t) + 1);
	out_getinfo->output_buffer_offset = X_H2LE16(sizeof(x_smb2_header_t) + sizeof(x_smb2_getinfo_resp_t));
	out_getinfo->output_buffer_length = X_H2LE32(x_convert_assert<uint32_t>(state.out_data.size()));
	memcpy(out_getinfo + 1, state.out_data.data(), state.out_data.size());
}

static void x_smb2_reply_getinfo(x_smbd_requ_getinfo_t *requ,
		NTSTATUS status)
{
	X_SMBD_REQU_LOG(OP, requ,  " %s", x_ntstatus_str(status));

	auto &out_buf = requ->get_requ_out_buf();
	out_buf.head = out_buf.tail = x_smb2_bufref_alloc(sizeof(x_smb2_getinfo_resp_t) +
			requ->state.out_data.size());
	out_buf.length = out_buf.head->length;

	uint8_t *out_hdr = out_buf.head->get_data();
	encode_out_getinfo(requ->state, out_hdr);
}

NTSTATUS x_smbd_requ_getinfo_t::process(void *ctx_conn)
{
	X_SMBD_REQU_LOG(OP, this,  " open=0x%lx,0x%lx %d:%d input=%u output=%u",
			state.in_file_id_persistent, state.in_file_id_volatile,
			uint8_t(state.in_info_class), uint8_t(state.in_info_level),
			state.in_input_buffer_length, state.in_output_buffer_length);

	if (!x_smbd_requ_verify_creditcharge(this,
				std::max(state.in_input_buffer_length,
					state.in_output_buffer_length))) {
		X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_INVALID_PARAMETER);
	}

	NTSTATUS status = x_smbd_requ_init_open(this,
			state.in_file_id_persistent,
			state.in_file_id_volatile,
			false);
	if (!NT_STATUS_IS_OK(status)) {
		X_SMBD_REQU_RETURN_STATUS(this, status);
	}

	return x_smbd_open_op_getinfo(this->smbd_open, state);
}

NTSTATUS x_smbd_requ_getinfo_t::done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status)
{
	if (status.ok() || status == NT_STATUS_BUFFER_OVERFLOW) {
		x_smb2_reply_getinfo(this, status);
	}

	X_SMBD_REQU_RETURN_STATUS(this, status);
}

NTSTATUS x_smb2_parse_GETINFO(x_smbd_conn_t *smbd_conn, x_smbd_requ_t **p_smbd_requ,
		x_in_buf_t &in_buf)
{
	auto in_smb2_hdr = (const x_smb2_header_t *)(in_buf.get_data());

	if (in_buf.length < sizeof(x_smb2_header_t) + sizeof(x_smb2_getinfo_requ_t)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	auto in_body = (const x_smb2_getinfo_requ_t *)(in_smb2_hdr + 1);
	x_smbd_requ_state_getinfo_t state;
	state.in_info_class = x_smb2_info_class_t(X_LE2H8(in_body->info_class));
	state.in_info_level = x_smb2_info_level_t(X_LE2H8(in_body->info_level));
	state.in_output_buffer_length = X_LE2H32(in_body->output_buffer_length);
	state.in_additional = X_LE2H32(in_body->additional);
	state.in_input_buffer_length = X_LE2H32(in_body->input_buffer_length);
	state.in_flags = X_LE2H32(in_body->flags);
	state.in_file_id_persistent = X_LE2H64(in_body->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_body->file_id_volatile);
	/* TODO input_data ? */
	state.in_dialect = x_smbd_conn_get_dialect(smbd_conn);

	if (state.in_input_buffer_length > x_smbd_conn_get_negprot(smbd_conn).max_trans_size) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	if (state.in_output_buffer_length > x_smbd_conn_get_negprot(smbd_conn).max_trans_size) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}
	*p_smbd_requ = new x_smbd_requ_getinfo_t(smbd_conn, state);
	return NT_STATUS_OK;
}

