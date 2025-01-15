
#include "smbd.hxx"
#include "smbd_open.hxx"
#include "smbd_conf.hxx"
#include "util_io.hxx"

namespace {

struct x_smbd_requ_write_t : x_smbd_requ_t
{
	x_smbd_requ_write_t(x_smbd_conn_t *smbd_conn,
			x_smbd_requ_state_write_t &state)
		: x_smbd_requ_t(smbd_conn)
		, state(std::move(state))
	{
		interim_timeout_ns = X_NSEC_PER_SEC;
	}

	std::tuple<bool, bool, bool> get_properties() const override
	{
		return { true, true, false };
	}
	NTSTATUS process(void *ctx_conn) override;
	NTSTATUS done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status) override;
	NTSTATUS cancelled(void *ctx_conn, int reason) override
	{
		return NT_STATUS_CANCELLED;
	}

	x_smbd_requ_state_write_t state;
};

}

NTSTATUS x_smbd_requ_write_t::process(void *ctx_conn)
{
	if (!x_smbd_requ_verify_creditcharge(this, state.in_buf.length)) {
		X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_INVALID_PARAMETER);
	}

	X_SMBD_REQU_LOG(OP, this, " open=0x%lx,0x%lx %lu:%u",
			state.in_file_id_persistent, state.in_file_id_volatile,
			state.in_offset, state.in_buf.length);

	NTSTATUS status = x_smbd_requ_init_open(this,
			state.in_file_id_persistent,
			state.in_file_id_volatile,
			true);
	if (!NT_STATUS_IS_OK(status)) {
		X_SMBD_REQU_RETURN_STATUS(this, status);
	}

	auto smbd_open = this->smbd_open;
	if (!smbd_open->check_access_any(idl::SEC_FILE_WRITE_DATA |
				idl::SEC_FILE_APPEND_DATA)) {
		X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_ACCESS_DENIED);
	}

	if (!x_smbd_open_is_data(smbd_open)) {
		X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_INVALID_DEVICE_REQUEST);
	}

	if (state.in_buf.length > 0) {
		status = x_smbd_open_op_write(smbd_open, this, state);
	} else {
		state.out_count = 0;
		state.out_remaining = 0;
		status = NT_STATUS_OK;
	}

	return status;
}

NTSTATUS x_smbd_requ_write_t::done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status)
{
	X_SMBD_REQU_LOG(OP, this, " %s", x_ntstatus_str(status));
	if (status.ok() && !requ_out_buf.head) {
		auto &out_buf = get_requ_out_buf();
		out_buf.head = out_buf.tail = x_smb2_bufref_alloc(sizeof(x_smb2_write_resp_t));
		out_buf.length = out_buf.head->length;

		status = state.encode_resp(out_buf);
	}
	return status;
}

NTSTATUS x_smbd_requ_state_write_t::decode_requ(x_buf_t *in_requ_buf,
		uint32_t in_requ_off, uint32_t in_requ_len)
{
	auto in_smb2_hdr = (const x_smb2_header_t *)(in_requ_buf->data + in_requ_off);

	if (in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_write_requ_t)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	auto in_write = (const x_smb2_write_requ_t *)(in_smb2_hdr + 1);
	uint16_t in_data_offset = X_LE2H16(in_write->data_offset);
	uint32_t in_length = X_LE2H32(in_write->length);

	if (!x_check_range<uint32_t>(in_data_offset, in_length,
				sizeof(x_smb2_header_t) + sizeof(x_smb2_write_requ_t),
				in_requ_len)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	in_offset = X_LE2H64(in_write->offset);
	if (in_offset + in_length < in_offset) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	in_file_id_persistent = X_LE2H64(in_write->file_id_persistent);
	in_file_id_volatile = X_LE2H64(in_write->file_id_volatile);
	in_flags = X_LE2H8(in_write->flags);

	in_buf.length = in_length;
	if (in_length > 0) {
		in_buf.buf = x_buf_get(in_requ_buf);
		in_buf.offset = in_requ_off + in_data_offset;
	}

	return NT_STATUS_OK;
}

NTSTATUS x_smbd_requ_state_write_t::encode_resp(x_out_buf_t &out_buf)
{
	uint8_t *out_hdr = out_buf.head->get_data();
	auto out_body = (x_smb2_write_resp_t *)(out_hdr + sizeof(x_smb2_header_t));
	out_body->struct_size = X_H2LE16(sizeof(x_smb2_write_resp_t) + 1);
	out_body->reserved0 = 0;
	out_body->count = X_H2LE32(out_count);
	out_body->remaining = X_H2LE32(out_remaining);
	out_body->write_channel_info_offset = 0;
	out_body->write_channel_info_length = 0;

	return NT_STATUS_OK;
}

NTSTATUS x_smb2_parse_WRITE(x_smbd_conn_t *smbd_conn, x_smbd_requ_t **p_smbd_requ,
		x_in_buf_t &in_buf)
{
	auto in_smb2_hdr = (const x_smb2_header_t *)(in_buf.get_data());

	x_smbd_requ_state_write_t state;
	NTSTATUS status = state.decode_requ(in_buf.buf, in_buf.offset, in_buf.length);
	if (!status.ok()) {
		return status;
	}

	if (state.in_buf.length > x_smbd_conn_get_negprot(smbd_conn).max_write_size) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	if (!valid_write_range(state.in_offset, state.in_buf.length)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	const x_smbd_conf_t &smbd_conf = x_smbd_conf_get_curr();
	state.dev_delay_ms = smbd_conf.my_dev_delay_write_ms;

	*p_smbd_requ = new x_smbd_requ_write_t(smbd_conn, state);
	return NT_STATUS_OK;
}

