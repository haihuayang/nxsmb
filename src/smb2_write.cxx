
#include "smbd.hxx"
#include "smbd_open.hxx"
#include "smbd_conf.hxx"
#include "util_io.hxx"

namespace {

struct x_smbd_requ_write_t : x_smbd_requ_t
{
	x_smbd_requ_write_t(x_smbd_conn_t *smbd_conn, x_in_buf_t &in_buf,
			uint32_t in_msgsize, bool encrypted,
			x_smbd_requ_state_write_t &state)
		: x_smbd_requ_t(smbd_conn, in_buf, in_msgsize, encrypted)
		, state(std::move(state))
	{
		interim_timeout_ns = X_NSEC_PER_SEC;
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

static bool decode_in_write(x_smbd_requ_state_write_t &state, x_in_buf_t &in_buf)
{
	const uint8_t *in_hdr = in_buf.get_data();
	auto in_write = (const x_smb2_write_requ_t *)(in_hdr  + sizeof(x_smb2_header_t));
	uint16_t in_data_offset = X_LE2H16(in_write->data_offset);
	uint32_t in_length = X_LE2H32(in_write->length);

	if (!x_check_range<uint32_t>(in_data_offset, in_length,
				sizeof(x_smb2_header_t) + sizeof(x_smb2_write_requ_t),
				in_buf.length)) {
		return false;
	}

	state.in_offset = X_LE2H64(in_write->offset);
	if (state.in_offset + in_length < state.in_offset) {
		return false;
	}

	state.in_file_id_persistent = X_LE2H64(in_write->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_write->file_id_volatile);
	state.in_flags = X_LE2H8(in_write->flags);

	state.in_buf.length = in_length;
	if (in_length > 0) {
		state.in_buf.buf = x_buf_get(in_buf.buf);
		state.in_buf.offset = in_buf.offset + in_data_offset;
	}
	return true;
}

static void x_smb2_reply_write(x_smbd_requ_write_t *requ)
{
	auto &out_buf = requ->get_requ_out_buf();
	out_buf.head = out_buf.tail = x_smb2_bufref_alloc(sizeof(x_smb2_write_resp_t));
	out_buf.length = out_buf.head->length;

	auto &state = requ->state;
	uint8_t *out_hdr = out_buf.head->get_data();
	auto *out_body = (x_smb2_write_resp_t *)(out_hdr + sizeof(x_smb2_header_t));
	out_body->struct_size = X_H2LE16(sizeof(x_smb2_write_resp_t) + 1);
	out_body->reserved0 = 0;
	out_body->count = X_H2LE32(state.out_count);
	out_body->remaining = X_H2LE32(state.out_remaining);
	out_body->write_channel_info_offset = 0;
	out_body->write_channel_info_length = 0;
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
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_write(this);
	}
	return status;
}

NTSTATUS x_smb2_parse_WRITE(x_smbd_conn_t *smbd_conn, x_smbd_requ_t **p_smbd_requ,
		x_in_buf_t &in_buf, uint32_t in_msgsize,
		bool encrypted)
{
	auto in_smb2_hdr = (const x_smb2_header_t *)(in_buf.get_data());

	if (in_buf.length < sizeof(x_smb2_header_t) + sizeof(x_smb2_write_requ_t)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	x_smbd_requ_state_write_t state;
	if (!decode_in_write(state, in_buf)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	if (state.in_buf.length > x_smbd_conn_get_negprot(smbd_conn).max_write_size) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	if (!valid_write_range(state.in_offset, state.in_buf.length)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	const x_smbd_conf_t &smbd_conf = x_smbd_conf_get_curr();
	state.dev_delay_ms = smbd_conf.my_dev_delay_write_ms;

	*p_smbd_requ = new x_smbd_requ_write_t(smbd_conn, in_buf,
			in_msgsize, encrypted, state);
	return NT_STATUS_OK;
}

