
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

struct x_smb2_in_write_t
{
	uint16_t struct_size;
	uint16_t data_offset;
	uint32_t length;
	uint64_t offset;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	uint32_t channel;
	uint32_t remaining_bytes;
	uint16_t write_channel_info_offset;
	uint16_t write_channel_info_length;
	uint32_t flags;
};

static bool decode_in_write(x_smb2_state_write_t &state,
		x_buf_t *in_buf, uint32_t in_offset, uint32_t in_len)
{
	const uint8_t *in_hdr = in_buf->data + in_offset;
	const x_smb2_in_write_t *in_write = (const x_smb2_in_write_t *)(in_hdr  + sizeof(x_smb2_header_t));
	uint16_t in_data_offset = X_LE2H16(in_write->data_offset);
	uint32_t in_length = X_LE2H32(in_write->length);

	if (!x_check_range<uint32_t>(in_data_offset, in_length,
				sizeof(x_smb2_header_t) + sizeof(x_smb2_in_write_t), in_len)) {
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

struct x_smb2_out_write_t
{
	uint16_t struct_size;
	uint16_t reserved0;
	uint32_t count;
	uint32_t remaining;
	uint16_t write_channel_info_offset;
	uint16_t write_channel_info_length;
};

static void encode_out_write(const x_smb2_state_write_t &state,
		uint8_t *out_hdr)
{
	x_smb2_out_write_t *out_write = (x_smb2_out_write_t *)(out_hdr + sizeof(x_smb2_header_t));
	out_write->struct_size = X_H2LE16(sizeof(x_smb2_out_write_t) + 1);
	out_write->reserved0 = 0;
	out_write->count = X_H2LE32(state.out_count);
	out_write->remaining = X_H2LE32(state.out_remaining);
	out_write->write_channel_info_offset = 0;
	out_write->write_channel_info_length = 0;
}

static void x_smb2_reply_write(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		const x_smb2_state_write_t &state)
{
	X_LOG_OP("%ld WRITE SUCCESS", smbd_requ->in_smb2_hdr.mid);

	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_out_write_t));

	uint8_t *out_hdr = bufref->get_data();
	encode_out_write(state, out_hdr);

	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, NT_STATUS_OK, 
			sizeof(x_smb2_header_t) + sizeof(x_smb2_out_write_t));
}

static void x_smb2_write_async_done(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		NTSTATUS status)
{
	X_LOG_DBG("status=0x%x", status.v);
	auto state = smbd_requ->release_state<x_smb2_state_write_t>();
	if (!smbd_conn) {
		return;
	}
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_write(smbd_conn, smbd_requ, *state);
	}
	x_smbd_conn_requ_done(smbd_conn, smbd_requ, status);
}

NTSTATUS x_smb2_process_write(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	if (smbd_requ->in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_in_write_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	auto state = std::make_unique<x_smb2_state_write_t>();
	if (!decode_in_write(*state, smbd_requ->in_buf, smbd_requ->in_offset, smbd_requ->in_requ_len)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	X_LOG_OP("%ld WRITE 0x%lx, 0x%lx", smbd_requ->in_smb2_hdr.mid,
			state->in_file_id_persistent, state->in_file_id_volatile);

	if (!valid_write_range(state->in_offset, state->in_buf_length)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	NTSTATUS status = x_smbd_requ_init_open(smbd_requ,
			state->in_file_id_persistent,
			state->in_file_id_volatile,
			true);
	if (!NT_STATUS_IS_OK(status)) {
		RETURN_OP_STATUS(smbd_requ, status);
	}

	if (!smbd_requ->smbd_open->check_access_any(idl::SEC_FILE_WRITE_DATA |
				idl::SEC_FILE_APPEND_DATA)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
	}

	if (!x_smbd_open_is_data(smbd_requ->smbd_open)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_DEVICE_REQUEST);
	}

	const x_smbd_conf_t &smbd_conf = x_smbd_conf_get_curr();

	if (state->in_buf) {
		smbd_requ->async_done_fn = x_smb2_write_async_done;
		status = x_smbd_open_op_write(smbd_requ->smbd_open, smbd_requ,
				state, smbd_conf.my_dev_delay_write_ms);
	} else {
		state->out_count = 0;
		state->out_remaining = 0;
		status = NT_STATUS_OK;
	}

	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_write(smbd_conn, smbd_requ, *state);
		return status;
	}
	RETURN_OP_STATUS(smbd_requ, status);
}
#if 0
static NTSTATUS x_smbd_read(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		x_smb2_state_read_t &state)
{
	auto smbd_object = smbd_requ->smbd_open->smbd_object;
	if (!smbd_object->ops->read)
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}

	ssize_t ret = smbd_object->ops->read(smbd_object, smbd_requ->smbd_open,
			state->out_data, state->in_length, state->in_offset);
	if (ret > 0) {
		state->out_data.resize(ret);
		return NT_STATUS_OK;
	} else if (ret == 0) {
		state->out_data.clear();
		return NT_STATUS_END_OF_FILE;
	} else {
		X_TODO;
		return NT_STATUS_INTERNAL_ERROR;
	}
#if 0
	++smb2_read->requ.refcount;
	smb2_read->job.ops = &async_read_job_ops;
	x_smbd_schedule_async(&smb2_read->job);

	return X_NT_STATUS_INTERNAL_BLOCKED;
#endif
}

static NTSTATUS x_smbd_write(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		x_smb2_state_write_t &state)
{
	auto smbd_object = smbd_requ->smbd_open->smbd_object;
	if (!smbd_object->ops->write)
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}

	ssize_t ret = smbd_object->ops->write(smbd_object, smbd_requ->smbd_open,
			state->out_data, state->in_offset);
	if (ret < 0) {
		X_TODO;
	} else {
		state->out_count = ret;
		state->out_remaining = 0;
	}
	return NT_STATUS_OK;
}
#endif
