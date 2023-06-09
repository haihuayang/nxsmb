
#include "smbd_open.hxx"

namespace {

struct x_smb2_in_getinfo_t
{
	uint16_t struct_size;
	uint8_t info_class;
	uint8_t info_level;
	uint32_t output_buffer_length;
	uint16_t input_buffer_offset;
	uint16_t reserved0;
	uint32_t input_buffer_length;;
	uint32_t additional;
	uint32_t flags;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
};

struct x_smb2_out_getinfo_t
{
	uint16_t struct_size;
	uint16_t output_buffer_offset;
	uint32_t output_buffer_length;
};

}

static bool decode_in_getinfo(x_smb2_state_getinfo_t &state,
		const uint8_t *in_hdr, uint32_t in_len)
{
	const x_smb2_in_getinfo_t *in_getinfo = (const x_smb2_in_getinfo_t *)(in_hdr + sizeof(x_smb2_header_t));

	state.in_info_class = x_smb2_info_class_t(X_LE2H8(in_getinfo->info_class));
	state.in_info_level = x_smb2_info_level_t(X_LE2H8(in_getinfo->info_level));
	state.in_output_buffer_length = X_LE2H32(in_getinfo->output_buffer_length);
	state.in_additional = X_LE2H32(in_getinfo->additional);
	state.in_flags = X_LE2H32(in_getinfo->flags);
	state.in_file_id_persistent = X_LE2H64(in_getinfo->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_getinfo->file_id_volatile);

	/* TODO input_data ? */
#if 0
	if (!x_check_range(requ_getinfo.input_buffer_offset, requ_getinfo.input_buffer_length,
				0x40 + X_SMB2_GETINFO_REQU_BODY_LEN, in_len)) {
		return X_SMB2_REPLY_ERROR(smbd_conn, smbd_requ, smbd_sess, in_tid, NT_STATUS_INVALID_PARAMETER);
	}

	const std::shared_ptr<x_smbconf_t> smbconf = smbd_conn->get_smbconf();
	if (requ_getinfo.input_buffer_length > smbconf->max_trans) {
		return X_SMB2_REPLY_ERROR(smbd_conn, smbd_requ, smbd_sess, in_tid, NT_STATUS_INVALID_PARAMETER);
	}

	if (requ_getinfo.output_buffer_length > smbconf->max_trans) {
		return X_SMB2_REPLY_ERROR(smbd_conn, smbd_requ, smbd_sess, in_tid, NT_STATUS_INVALID_PARAMETER);
	}
#endif
	return true;
}

static void encode_out_getinfo(const x_smb2_state_getinfo_t &state,
		uint8_t *out_hdr)
{
	x_smb2_out_getinfo_t *out_getinfo = (x_smb2_out_getinfo_t *)(out_hdr + sizeof(x_smb2_header_t));
	out_getinfo->struct_size = X_H2LE16(sizeof(x_smb2_out_getinfo_t) + 1);
	out_getinfo->output_buffer_offset = X_H2LE16(sizeof(x_smb2_header_t) + sizeof(x_smb2_out_getinfo_t));
	out_getinfo->output_buffer_length = X_H2LE32(x_convert_assert<uint32_t>(state.out_data.size()));
	memcpy(out_getinfo + 1, state.out_data.data(), state.out_data.size());
}

static void x_smb2_reply_getinfo(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		const x_smb2_state_getinfo_t &state,
		NTSTATUS status)
{
	X_LOG_OP("%ld RESP SUCCESS", smbd_requ->in_smb2_hdr.mid);

	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_out_getinfo_t) +
			state.out_data.size());

	uint8_t *out_hdr = bufref->get_data();
	encode_out_getinfo(state, out_hdr);
	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, status, 
			sizeof(x_smb2_header_t) + sizeof(x_smb2_out_getinfo_t) + state.out_data.size());
}

NTSTATUS x_smb2_process_getinfo(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	if (smbd_requ->in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_in_getinfo_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = smbd_requ->get_in_data();

	auto state = std::make_unique<x_smb2_state_getinfo_t>();
	if (!decode_in_getinfo(*state, in_hdr, smbd_requ->in_requ_len)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	X_LOG_OP("%ld GETINFO 0x%lx:%lx %d:%d", smbd_requ->in_smb2_hdr.mid,
			state->in_file_id_persistent, state->in_file_id_volatile,
			uint8_t(state->in_info_class), uint8_t(state->in_info_level));

	NTSTATUS status = x_smbd_requ_init_open(smbd_requ,
			state->in_file_id_persistent,
			state->in_file_id_volatile,
			false);
	if (!NT_STATUS_IS_OK(status)) {
		RETURN_OP_STATUS(smbd_requ, status);
	}

	status = x_smbd_open_op_getinfo(smbd_requ->smbd_open,
		       	smbd_conn, smbd_requ,
			state);
	if (NT_STATUS_IS_OK(status) || NT_STATUS_EQUAL(status, NT_STATUS_BUFFER_OVERFLOW)) {
		x_smb2_reply_getinfo(smbd_conn, smbd_requ, *state, status);
		return NT_STATUS_OK;
	}

	RETURN_OP_STATUS(smbd_requ, status);
}

