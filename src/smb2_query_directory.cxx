
#include "smbd.hxx"
#include "smbd_open.hxx"

enum {
	X_SMB2_FIND_REQU_BODY_LEN = 0x20,
	X_SMB2_FIND_RESP_BODY_LEN = 0x08,
};

struct x_smb2_in_qdir_t
{
	uint16_t struct_size;
	uint8_t info_level;
	uint8_t flags;
	uint32_t file_index;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	uint16_t name_offset;
	uint16_t name_length;
	uint32_t output_buffer_length;
};

static bool decode_in_qdir(x_smb2_state_qdir_t &state,
		const uint8_t *in_hdr, uint32_t in_len)
{
	const x_smb2_in_qdir_t *in_qdir = (const x_smb2_in_qdir_t *)(in_hdr + sizeof(x_smb2_header_t));

	uint16_t in_name_offset             = X_LE2H16(in_qdir->name_offset);
	uint16_t in_name_length             = X_LE2H16(in_qdir->name_length);

	if (in_name_length % 2 != 0 || !x_check_range<uint32_t>(in_name_offset, in_name_length, 
				sizeof(x_smb2_header_t) + sizeof(x_smb2_in_qdir_t), in_len)) {
		return false;
	}

	state.in_info_level = x_smb2_info_level_t(X_LE2H8(in_qdir->info_level));
	state.in_flags = X_LE2H8(in_qdir->flags);
	state.in_file_index = X_LE2H32(in_qdir->file_index);
	state.in_file_id_persistent = X_LE2H64(in_qdir->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_qdir->file_id_volatile);
	state.in_output_buffer_length = X_LE2H32(in_qdir->output_buffer_length);

	state.in_name.assign((char16_t *)(in_hdr + in_name_offset),
			(char16_t *)(in_hdr + in_name_offset + in_name_length));

	return true;
}

struct x_smb2_out_qdir_t
{
	uint16_t struct_size;
	uint16_t offset;
	uint32_t length;
};

static void encode_out_qdir(const x_smb2_state_qdir_t &state,
		uint8_t *out_hdr)
{
	x_smb2_out_qdir_t *out_qdir = (x_smb2_out_qdir_t *)(out_hdr + sizeof(x_smb2_header_t));

	out_qdir->struct_size = X_H2LE16(sizeof(x_smb2_out_qdir_t) + 1);
	out_qdir->offset = X_H2LE16(sizeof(x_smb2_header_t) + sizeof(x_smb2_out_qdir_t));
	out_qdir->length = X_H2LE32(x_convert_assert<uint32_t>(state.out_data.size()));
	memcpy(out_qdir + 1, state.out_data.data(), state.out_data.size());
}

static void x_smb2_reply_qdir(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		const x_smb2_state_qdir_t &state)
{
	X_LOG_OP("%ld RESP SUCCESS", smbd_requ->in_smb2_hdr.mid);

	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_out_qdir_t) +
			state.out_data.size());

	uint8_t *out_hdr = bufref->get_data();
	encode_out_qdir(state, out_hdr);
	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, NT_STATUS_OK, 
			sizeof(x_smb2_header_t) + sizeof(x_smb2_out_qdir_t) + state.out_data.size());
}

static void x_smb2_qdir_async_done(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ,
		NTSTATUS status)
{
	X_LOG_DBG("status=0x%x", status.v);
	auto state = smbd_requ->release_state<x_smb2_state_qdir_t>();
	if (!smbd_conn) {
		return;
	}
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_qdir(smbd_conn, smbd_requ, *state);
	}
	x_smbd_conn_requ_done(smbd_conn, smbd_requ, status);
}

NTSTATUS x_smb2_process_query_directory(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	if (smbd_requ->in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_in_qdir_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = smbd_requ->get_in_data();

	auto state = std::make_unique<x_smb2_state_qdir_t>();
	if (!decode_in_qdir(*state, in_hdr, smbd_requ->in_requ_len)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	X_LOG_OP("%ld FIND 0x%lx, 0x%lx", smbd_requ->in_smb2_hdr.mid,
			state->in_file_id_persistent, state->in_file_id_volatile);

	switch (state->in_info_level) {
	case x_smb2_info_level_t::FILE_ID_BOTH_DIR_INFORMATION:
	case x_smb2_info_level_t::FILE_ID_FULL_DIR_INFORMATION:
	case x_smb2_info_level_t::FILE_DIRECTORY_INFORMATION:
	case x_smb2_info_level_t::FILE_BOTH_DIR_INFORMATION:
	case x_smb2_info_level_t::FILE_FULL_DIRECTORY_INFORMATION:
	case x_smb2_info_level_t::FILE_NAMES_INFORMATION:
		break;
	default:
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if (state->in_output_buffer_length < 4) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INFO_LENGTH_MISMATCH);
	}

	NTSTATUS status = x_smbd_requ_init_open(smbd_requ,
			state->in_file_id_persistent,
			state->in_file_id_volatile,
			false);
	if (!NT_STATUS_IS_OK(status)) {
		RETURN_OP_STATUS(smbd_requ, status);
	}

	smbd_requ->async_done_fn = x_smb2_qdir_async_done;
	status = x_smbd_open_op_qdir(smbd_requ->smbd_open,
			smbd_conn, smbd_requ, state);
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_qdir(smbd_conn, smbd_requ, *state);
		return status;
	}

	RETURN_OP_STATUS(smbd_requ, status);
}

