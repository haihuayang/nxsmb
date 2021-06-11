
#include "smbd_open.hxx"

namespace {
enum {
	X_SMB2_SETINFO_REQU_BODY_LEN = 0x20,
	X_SMB2_SETINFO_RESP_BODY_LEN = 0x2,
};

struct x_smb2_in_setinfo_t
{
	uint16_t struct_size;
	uint8_t  info_class;
	uint8_t  info_level;
	uint32_t input_buffer_length;
	uint16_t input_buffer_offset;
	uint16_t reserve;
	uint32_t additional;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
};

struct x_smb2_out_setinfo_t
{
	uint16_t struct_size;
};

}

static bool decode_in_setinfo(x_smb2_state_setinfo_t &state,
		const uint8_t *in_hdr, uint32_t in_len)
{
	const x_smb2_in_setinfo_t *in_setinfo = (const x_smb2_in_setinfo_t *)(in_hdr + SMB2_HDR_BODY);
	uint16_t in_input_buffer_offset = X_LE2H16(in_setinfo->input_buffer_offset);
	uint32_t in_input_buffer_length = X_LE2H32(in_setinfo->input_buffer_length);

	if (!x_check_range<uint32_t>(in_input_buffer_offset, in_input_buffer_length,
				SMB2_HDR_BODY + sizeof(x_smb2_in_setinfo_t), in_len)) {
		return false;
	}

	state.in_info_class = X_LE2H8(in_setinfo->info_class);
	state.in_info_level = X_LE2H8(in_setinfo->info_level);
	state.in_additional = X_LE2H32(in_setinfo->additional);
	state.in_file_id_persistent = X_LE2H64(in_setinfo->file_id_persistent);
	state.in_file_id_volatile = X_LE2H64(in_setinfo->file_id_volatile);

	state.in_data.assign(in_hdr + in_input_buffer_offset,
			in_hdr + in_input_buffer_offset + in_input_buffer_length);
	return true;
}

static void encode_out_setinfo(const x_smb2_state_setinfo_t &state,
		uint8_t *out_hdr)
{
	x_smb2_out_setinfo_t *out_setinfo = (x_smb2_out_setinfo_t *)(out_hdr + SMB2_HDR_BODY);
	out_setinfo->struct_size = X_H2LE16(sizeof(x_smb2_out_setinfo_t) + 1);
}

static void x_smb2_reply_setinfo(x_smbd_conn_t *smbd_conn,
		x_smb2_msg_t *msg,
		const x_smb2_state_setinfo_t &state)
{
	X_LOG_OP("%ld WRITE SUCCESS", msg->in_mid);

	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_out_setinfo_t));

	uint8_t *out_hdr = bufref->get_data();
	encode_out_setinfo(state, out_hdr);

	x_smb2_reply(smbd_conn, msg, bufref, bufref, NT_STATUS_OK, 
			SMB2_HDR_BODY + sizeof(x_smb2_out_setinfo_t));
}

NTSTATUS x_smb2_process_SETINFO(x_smbd_conn_t *smbd_conn, x_smb2_msg_t *msg)
{
	if (msg->in_requ_len < SMB2_HDR_BODY + sizeof(x_smb2_in_setinfo_t)) {
		RETURN_OP_STATUS(msg, NT_STATUS_INVALID_PARAMETER);
	}

	if (!msg->smbd_sess) {
		RETURN_OP_STATUS(msg, NT_STATUS_USER_SESSION_DELETED);
	}

	if (msg->smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		RETURN_OP_STATUS(msg, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = msg->get_in_data();

	auto state = std::make_unique<x_smb2_state_setinfo_t>();
	if (!decode_in_setinfo(*state, in_hdr, msg->in_requ_len)) {
		RETURN_OP_STATUS(msg, NT_STATUS_INVALID_PARAMETER);
	}

	X_LOG_OP("%ld SETINFO 0x%lx, 0x%lx", msg->in_mid,
			state->in_file_id_persistent, state->in_file_id_volatile);

	if (msg->smbd_open) {
	} else if (msg->smbd_tcon) {
		msg->smbd_open = x_smbd_open_find(state->in_file_id_persistent,
				state->in_file_id_volatile,
				msg->smbd_tcon);
	} else {
		uint32_t tid = x_get_le32(in_hdr + SMB2_HDR_TID);
		msg->smbd_open = x_smbd_open_find(state->in_file_id_persistent,
				state->in_file_id_volatile, tid, msg->smbd_sess);
	}

	if (!msg->smbd_open) {
		RETURN_OP_STATUS(msg, NT_STATUS_FILE_CLOSED);
	}

	NTSTATUS status = x_smbd_open_op_setinfo(smbd_conn, msg, state);
	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_setinfo(smbd_conn, msg, *state);
		return status;
	}

	RETURN_OP_STATUS(msg, status);
}
#if 0
static void x_smb2_reply_setinfo(x_smbd_conn_t *smbd_conn,
		x_smbd_sess_t *smbd_sess,
		x_msg_ptr_t &msg, NTSTATUS status,
		uint32_t tid)
{
	X_LOG_OP("%ld SETINFO SUCCESS", msg->in_mid);

	uint8_t *outbuf = new uint8_t[8 + 0x40 + sizeof(x_smb2_out_setinfo_t)];
	uint8_t *outhdr = outbuf + 8;
	uint8_t *outbody = outhdr + 0x40;

	SSVAL(outbody, 0x00, X_SMB2_SETINFO_RESP_BODY_LEN);
	x_smbd_conn_reply(smbd_conn, msg, smbd_sess, nullptr, outbuf, tid, status, X_SMB2_SETINFO_RESP_BODY_LEN);
	return 0;
}

NTSTATUS x_smb2_process_SETINFO(x_smbd_conn_t *smbd_conn, x_smb2_msg_t *msg)
{
	if (in_len < 0x40 + X_SMB2_SETINFO_REQU_BODY_LEN) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, 0, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *inhdr = in_buf;
	const uint8_t *inbody = in_buf + 0x40;

	uint64_t in_session_id = BVAL(inhdr, SMB2_HDR_SESSION_ID);
	uint32_t in_tid = IVAL(inhdr, SMB2_HDR_TID);
	if (in_session_id == 0) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, in_tid, NT_STATUS_USER_SESSION_DELETED);
	}
	x_auto_ref_t<x_smbd_sess_t> smbd_sess{x_smbd_sess_find(in_session_id, smbd_conn)};
	if (smbd_sess == nullptr) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, in_tid, NT_STATUS_USER_SESSION_DELETED);
	}
	if (smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, NT_STATUS_INVALID_PARAMETER);
	}
	/* TODO signing/encryption */

	auto it = smbd_sess->tcon_table.find(in_tid);
	if (it == smbd_sess->tcon_table.end()) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, NT_STATUS_NETWORK_NAME_DELETED);
	}
	std::shared_ptr<x_smbd_tcon_t> smbd_tcon = it->second;

	/* TODO only for little-endian */
	x_smb2_requ_setinfo_t requ_setinfo;
	memcpy(&requ_setinfo, inbody, X_SMB2_SETINFO_REQU_BODY_LEN);

	X_LOG_OP("%ld SETINFO 0x%lx, 0x%lx", msg->mid, requ_setinfo.file_id_persistent, requ_setinfo.file_id_volatile);

	if (!x_check_range(requ_setinfo.input_buffer_offset, requ_setinfo.input_buffer_length,
				0x40 + X_SMB2_SETINFO_REQU_BODY_LEN, in_len)) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, NT_STATUS_INVALID_PARAMETER);
	}

	const std::shared_ptr<x_smbconf_t> smbconf = smbd_conn->get_smbconf();
	if (requ_setinfo.input_buffer_length > smbconf->max_trans) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, NT_STATUS_INVALID_PARAMETER);
	}

	// TODO smbd_smb2_request_verify_creditcharge
	x_auto_ref_t<x_smbd_open_t> smbd_open{x_smbd_open_find(requ_setinfo.file_id_volatile,
			smbd_tcon.get())};
	if (!smbd_open) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, NT_STATUS_FILE_CLOSED);
	}

	NTSTATUS status = x_smbd_open_op_setinfo(smbd_conn, msg, smbd_open, requ_setinfo,
			in_buf + requ_setinfo.input_buffer_offset);
	if (NT_STATUS_IS_OK(status)) {
		return x_smb2_reply_setinfo(smbd_conn, smbd_sess, msg, status, in_tid);
	} else {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, status);
	}
}
#endif
