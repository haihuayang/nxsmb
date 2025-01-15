
#include "smbd.hxx"
#include "smbd_open.hxx"
#include "smbd_conf.hxx"
#include "util_io.hxx"

namespace {

struct x_smbd_requ_read_t : x_smbd_requ_t
{
	x_smbd_requ_read_t(x_smbd_conn_t *smbd_conn, x_smbd_requ_state_read_t &state)
		: x_smbd_requ_t(smbd_conn), state(std::move(state))
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

	x_smbd_requ_state_read_t state;
};

}

NTSTATUS x_smbd_requ_read_t::process(void *ctx_conn)
{
	X_ASSERT(this->smbd_chan && this->smbd_sess);

	if (!x_smbd_requ_verify_creditcharge(this, state.in_length)) {
		X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_INVALID_PARAMETER);
	}

	X_SMBD_REQU_LOG(OP, this, " open=0x%lx,0x%lx %lu:%u",
			state.in_file_id_persistent, state.in_file_id_volatile,
			state.in_offset, state.in_length);

	NTSTATUS status = x_smbd_requ_init_open(this,
			state.in_file_id_persistent,
			state.in_file_id_volatile,
			false);
	if (!NT_STATUS_IS_OK(status)) {
		X_SMBD_REQU_RETURN_STATUS(this, status);
	}

	auto smbd_open = this->smbd_open;
	if (!smbd_open->check_access_any(idl::SEC_FILE_READ_DATA |
				idl::SEC_FILE_EXECUTE)) {
		X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_ACCESS_DENIED);
	}

	if (!x_smbd_open_is_data(smbd_open)) {
		X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_INVALID_DEVICE_REQUEST);
	}

	if (state.in_length == 0) {
		state.out_buf_length = 0;
		status = NT_STATUS_OK;
	} else {
		status = x_smbd_open_op_read(smbd_open, this, state, false);
	}

	return status;
}

NTSTATUS x_smbd_requ_read_t::done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status)
{
	X_SMBD_REQU_LOG(OP, this, " %s out_length=%u", x_ntstatus_str(status),
			state.out_buf_length);
	if (status.ok() && !requ_out_buf.head) {
		if (state.out_buf_length < state.in_minimum_count) {
			return NT_STATUS_END_OF_FILE;
		}

		smbd_open->open_state.current_offset =
			state.in_offset + state.in_length;

		auto &out_buf = get_requ_out_buf();
		out_buf.head = out_buf.tail = x_smb2_bufref_alloc(sizeof(x_smb2_read_resp_t));
		out_buf.length = out_buf.head->length;

		status = state.encode_resp(out_buf);
	}
	return status;
}

NTSTATUS x_smbd_requ_state_read_t::decode_requ(x_buf_t *in_requ_buf,
		uint32_t in_requ_off, uint32_t in_requ_len)
{
	auto in_smb2_hdr = (const x_smb2_header_t *)(in_requ_buf->data + in_requ_off);

	if (in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_read_requ_t)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	auto in_body = (const x_smb2_read_requ_t *)(in_smb2_hdr + 1);
	in_flags = X_LE2H8(in_body->flags);
	in_length = X_LE2H32(in_body->length);
	in_offset = X_LE2H64(in_body->offset);
	in_file_id_persistent = X_LE2H64(in_body->file_id_persistent);
	in_file_id_volatile = X_LE2H64(in_body->file_id_volatile);
	in_minimum_count = X_LE2H32(in_body->minimum_count);

	return NT_STATUS_OK;
}

NTSTATUS x_smbd_requ_state_read_t::encode_resp(x_out_buf_t &out_buf)
{
	if (out_buf_length) {
		out_buf.head->next = out_buf.tail =
			new x_bufref_t(this->out_buf, 0, out_buf_length);
		this->out_buf = nullptr;
		out_buf.length += out_buf_length;
	}

	uint8_t *out_hdr = out_buf.head->get_data();
	auto out_read = (x_smb2_read_resp_t *)(out_hdr + sizeof(x_smb2_header_t));
	out_read->struct_size = X_H2LE16(sizeof(x_smb2_read_resp_t) + 1);
	out_read->data_offset = sizeof(x_smb2_header_t) + sizeof(x_smb2_read_resp_t);
	out_read->reserved0 = 0;
	out_read->data_length = X_H2LE32(out_buf_length);
	out_read->data_remaining = 0;
	out_read->reserved1 = 0;

	return NT_STATUS_OK;
}

NTSTATUS x_smb2_parse_READ(x_smbd_conn_t *smbd_conn, x_smbd_requ_t **p_smbd_requ,
		x_in_buf_t &in_buf)
{
	auto in_smb2_hdr = (const x_smb2_header_t *)(in_buf.get_data());

	x_smbd_requ_state_read_t state;
	NTSTATUS status = state.decode_requ(in_buf.buf, in_buf.offset, in_buf.length);
	if (!status.ok()) {
		return status;
	}

	if (state.in_length > x_smbd_conn_get_negprot(smbd_conn).max_read_size) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	if (!valid_io_range(state.in_offset, state.in_length)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	const x_smbd_conf_t &smbd_conf = x_smbd_conf_get_curr();
	state.dev_delay_ms = smbd_conf.my_dev_delay_read_ms;

	auto requ = new x_smbd_requ_read_t(smbd_conn, state);

	*p_smbd_requ = requ;
	return NT_STATUS_OK;
}

