
#include "smbd.hxx"
#include "smbd_open.hxx"
#include "smbd_conf.hxx"
#include "util_io.hxx"

namespace {
enum {
	X_SMB2_WRITE_REQU_BODY_LEN = 0x30,
	X_SMB2_WRITE_RESP_BODY_LEN = 0x10,
};
}

static bool decode_in_write(x_smbd_requ_state_write_t &state,
		x_buf_t *in_buf, uint32_t in_offset, uint32_t in_len)
{
	const uint8_t *in_hdr = in_buf->data + in_offset;
	const x_smb2_write_requ_t *in_write = (const x_smb2_write_requ_t *)(in_hdr  + sizeof(x_smb2_header_t));
	uint16_t in_data_offset = X_LE2H16(in_write->data_offset);
	uint32_t in_length = X_LE2H32(in_write->length);

	if (!x_check_range<uint32_t>(in_data_offset, in_length,
				sizeof(x_smb2_header_t) + sizeof(x_smb2_write_requ_t), in_len)) {
		return false;
	}

	state.in_offset = X_LE2H64(in_write->offset);
	if (state.in_offset + in_length < state.in_offset) {
		return false;
	}

	state.in_file_id_persistent = X_LE2H64(in_write->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_write->file_id_volatile);
	state.in_flags = X_LE2H8(in_write->flags);

	if (in_length > 0) {
		state.in_buf = x_buf_get(in_buf);
		state.in_buf_offset = in_offset + in_data_offset;
		state.in_buf_length = in_length;
	}
	return true;
}

static void encode_out_write(const x_smbd_requ_state_write_t &state,
		uint8_t *out_hdr)
{
	x_smb2_write_resp_t *out_write = (x_smb2_write_resp_t *)(out_hdr + sizeof(x_smb2_header_t));
	out_write->struct_size = X_H2LE16(sizeof(x_smb2_write_resp_t) + 1);
	out_write->reserved0 = 0;
	out_write->count = X_H2LE32(state.out_count);
	out_write->remaining = X_H2LE32(state.out_remaining);
	out_write->write_channel_info_offset = 0;
	out_write->write_channel_info_length = 0;
}

static void x_smb2_reply_write(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		const x_smbd_requ_state_write_t &state)
{
	x_bufref_t *bufref = x_smb2_bufref_alloc(sizeof(x_smb2_write_resp_t));

	uint8_t *out_hdr = bufref->get_data();
	encode_out_write(state, out_hdr);

	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, NT_STATUS_OK, 
			sizeof(x_smb2_header_t) + sizeof(x_smb2_write_resp_t));
}

void x_smbd_requ_state_write_t::async_done(void *ctx_conn,
		x_nxfsd_requ_t *nxfsd_requ,
		NTSTATUS status)
{
	x_smbd_requ_t *smbd_requ = x_smbd_requ_from_base(nxfsd_requ);
	X_SMBD_REQU_LOG(OP, smbd_requ, " %s", x_ntstatus_str(status));
	if (!ctx_conn) {
		return;
	}
	x_smbd_conn_t *smbd_conn = (x_smbd_conn_t *)ctx_conn;
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_write(smbd_conn, smbd_requ, *this);
	}
	x_smbd_conn_requ_done(smbd_conn, smbd_requ, status);
}

NTSTATUS x_smb2_process_write(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	auto [ in_buf, in_offset, in_requ_len ] = smbd_requ->base.get_in_buf();
	if (in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_write_requ_t)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	auto state = std::make_unique<x_smbd_requ_state_write_t>();
	if (!decode_in_write(*state, in_buf, in_offset, in_requ_len)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	X_SMBD_REQU_LOG(OP, smbd_requ,  " open=0x%lx,0x%lx %lu:%u",
			state->in_file_id_persistent, state->in_file_id_volatile,
			state->in_offset, state->in_buf_length);

	if (state->in_buf_length > x_smbd_conn_get_negprot(smbd_conn).max_write_size) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if (!valid_write_range(state->in_offset, state->in_buf_length)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if (!x_smbd_requ_verify_creditcharge(smbd_requ, state->in_buf_length)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	NTSTATUS status = x_smbd_requ_init_open(smbd_requ,
			state->in_file_id_persistent,
			state->in_file_id_volatile,
			true);
	if (!NT_STATUS_IS_OK(status)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, status);
	}

	auto smbd_open = smbd_requ->base.smbd_open;
	if (!smbd_open->check_access_any(idl::SEC_FILE_WRITE_DATA |
				idl::SEC_FILE_APPEND_DATA)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
	}

	if (!x_smbd_open_is_data(smbd_open)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_DEVICE_REQUEST);
	}

	const x_smbd_conf_t &smbd_conf = x_smbd_conf_get_curr();

	if (state->in_buf) {
		status = x_smbd_open_op_write(smbd_open, &smbd_requ->base,
				state, smbd_conf.my_dev_delay_write_ms);
	} else {
		state->out_count = 0;
		state->out_remaining = 0;
		status = NT_STATUS_OK;
	}

	if (NT_STATUS_IS_OK(status)) {
		X_SMBD_REQU_LOG(OP, smbd_requ, " STATUS_SUCCESS");
		x_smb2_reply_write(smbd_conn, smbd_requ, *state);
		return status;
	}
	X_SMBD_REQU_RETURN_STATUS(smbd_requ, status);
}
