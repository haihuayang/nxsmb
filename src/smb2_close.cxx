
#include "smbd.hxx"
#include "smbd_open.hxx"
#include "smbd_stats.hxx"


static bool decode_in_close(x_smbd_requ_state_close_t &state,
		const uint8_t *in_hdr)
{
	const x_smb2_close_requ_t *in_close = (const x_smb2_close_requ_t *)(in_hdr + sizeof(x_smb2_header_t));

	state.in_flags = X_LE2H16(in_close->flags);
	state.in_file_id_persistent = X_LE2H64(in_close->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_close->file_id_volatile);

	return true;
}

static void encode_out_close(const x_smbd_requ_state_close_t &state,
		uint8_t *out_hdr)
{
	x_smb2_close_resp_t *out_close = (x_smb2_close_resp_t *)(out_hdr + sizeof(x_smb2_header_t));

	out_close->struct_size = X_H2LE16(sizeof(x_smb2_close_resp_t));
	out_close->flags = X_H2LE16(state.out_flags);
	out_close->reserved0 = 0;
	/* TODO x_smb2_close_resp_t is not 8 bytes aligned, sizeof() is not 0x3c */
	if (state.out_flags & X_SMB2_CLOSE_FLAGS_FULL_INFORMATION) {
		/* TODO not work for big-endian */
		out_close->info.out_create_ts = X_H2LE64(state.out_info.out_create_ts);
		out_close->info.out_last_access_ts = X_H2LE64(state.out_info.out_last_access_ts);
		out_close->info.out_last_write_ts = X_H2LE64(state.out_info.out_last_write_ts);
		out_close->info.out_change_ts = X_H2LE64(state.out_info.out_change_ts);
		out_close->info.out_allocation_size = X_H2LE64(state.out_info.out_allocation_size);
		out_close->info.out_end_of_file = X_H2LE64(state.out_info.out_end_of_file);
		out_close->info.out_file_attributes = X_H2LE64(state.out_info.out_file_attributes);
	} else {
		out_close->info.out_create_ts = 0;
		out_close->info.out_last_access_ts = 0;
		out_close->info.out_last_write_ts = 0;
		out_close->info.out_change_ts = 0;
		out_close->info.out_allocation_size = 0;
		out_close->info.out_end_of_file = 0;
		out_close->info.out_file_attributes = 0;
	}
}

static void x_smb2_reply_close(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		const x_smbd_requ_state_close_t &state)
{
	x_bufref_t *bufref = x_smb2_bufref_alloc(sizeof(x_smb2_close_resp_t));

	uint8_t *out_hdr = bufref->get_data();
	
	encode_out_close(state, out_hdr);

	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, NT_STATUS_OK, 
			sizeof(x_smb2_header_t) + sizeof(x_smb2_close_resp_t));
}

NTSTATUS x_smb2_process_close(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_ASSERT(smbd_requ->smbd_chan && smbd_requ->smbd_sess);

	auto [ in_hdr, in_requ_len ] = smbd_requ->base.get_in_data();
	if (in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_close_requ_t)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	auto state = std::make_unique<x_smbd_requ_state_close_t>();
	if (!decode_in_close(*state, in_hdr)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	X_SMBD_REQU_LOG(OP, smbd_requ,  " open=0x%lx,0x%lx",
			state->in_file_id_persistent, state->in_file_id_volatile);

	NTSTATUS status = x_smbd_requ_init_open(smbd_requ,
			state->in_file_id_persistent,
			state->in_file_id_volatile,
			false);
	if (!NT_STATUS_IS_OK(status)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, status);
	}

	status = x_smbd_open_op_close(smbd_requ->base.smbd_open,
			smbd_requ, state);
	if (!NT_STATUS_IS_OK(status)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, status);
	}

	x_smb2_reply_close(smbd_conn, smbd_requ, *state);
	return status;
}
