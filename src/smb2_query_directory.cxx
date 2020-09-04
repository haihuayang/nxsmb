
#include "smbd.hxx"
#include "core.hxx"

enum {
	X_SMB2_FIND_REQU_BODY_LEN = 0x20,
	X_SMB2_FIND_RESP_BODY_LEN = 0x08,
};

static int x_smb2_reply_find(x_smbd_conn_t *smbd_conn,
		x_smbd_sess_t *smbd_sess,
		x_msg_t *msg, uint32_t tid,
		const std::vector<uint8_t> &output)
{
	X_LOG_OP("%ld RESP SUCCESS", msg->mid);

	uint8_t *outbuf = new uint8_t[8 + 0x40 + X_SMB2_FIND_RESP_BODY_LEN + output.size()];
	uint8_t *outhdr = outbuf + 8;
	uint8_t *outbody = outhdr + 0x40;

	SSVAL(outbody, 0, X_SMB2_FIND_RESP_BODY_LEN + 1);
	SSVAL(outbody, 2, 0x40 + X_SMB2_FIND_RESP_BODY_LEN);
	SIVAL(outbody, 4, output.size());
	memcpy(outbody + X_SMB2_FIND_RESP_BODY_LEN, output.data(), output.size());

	//smbd_smb2_request_setup_out
	memset(outhdr, 0, 0x40);
	SIVAL(outhdr, SMB2_HDR_PROTOCOL_ID,     SMB2_MAGIC);
	SSVAL(outhdr, SMB2_HDR_LENGTH,	  SMB2_HDR_BODY);
	SSVAL(outhdr, SMB2_HDR_CREDIT_CHARGE, 1); // TODO
	SIVAL(outhdr, SMB2_HDR_STATUS, 0);
	SIVAL(outhdr, SMB2_HDR_OPCODE, SMB2_OP_QUERY_DIRECTORY);
	SSVAL(outhdr, SMB2_HDR_CREDIT, 1); // TODO
	SIVAL(outhdr, SMB2_HDR_FLAGS, SMB2_HDR_FLAG_REDIRECT); // TODO
	SIVAL(outhdr, SMB2_HDR_NEXT_COMMAND, 0);
	SBVAL(outhdr, SMB2_HDR_MESSAGE_ID, msg->mid);
	SIVAL(outhdr, SMB2_HDR_TID, tid);
	SBVAL(outhdr, SMB2_HDR_SESSION_ID, smbd_sess->id);

	uint8_t *outnbt = outbuf + 4;
	x_put_be32(outnbt, 0x40 + X_SMB2_FIND_RESP_BODY_LEN + output.size());

	msg->out_buf = outbuf;
	msg->out_off = 4;
	msg->out_len = 4 + 0x40 + X_SMB2_FIND_RESP_BODY_LEN + output.size();

	msg->state = x_msg_t::STATE_COMPLETE;
	x_smbd_conn_reply(smbd_conn, msg, smbd_sess);
	return 0;
}

int x_smb2_process_QUERY_DIRECTORY(x_smbd_conn_t *smbd_conn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len)
{
	if (in_len < 0x40 + X_SMB2_FIND_REQU_BODY_LEN) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *inhdr = in_buf;
	const uint8_t *inbody = in_buf + 0x40;

	uint64_t in_session_id = BVAL(inhdr, SMB2_HDR_SESSION_ID);
	if (in_session_id == 0) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, NT_STATUS_USER_SESSION_DELETED);
	}
	x_auto_ref_t<x_smbd_sess_t> smbd_sess{x_smbd_sess_find(in_session_id, smbd_conn)};
	if (smbd_sess == nullptr) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, NT_STATUS_USER_SESSION_DELETED);
	}
	if (smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, NT_STATUS_INVALID_PARAMETER);
	}
	/* TODO signing/encryption */

	uint32_t in_tid = IVAL(inhdr, SMB2_HDR_TID);
	auto it = smbd_sess->tcon_table.find(in_tid);
	if (it == smbd_sess->tcon_table.end()) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, NT_STATUS_NETWORK_NAME_DELETED);
	}
	std::shared_ptr<x_smbd_tcon_t> smbd_tcon = it->second;

	/* TODO only for little-endian */
	x_smb2_requ_find_t requ_find;
	requ_find.in_info_level              = CVAL(inbody, 0x02);
	requ_find.in_flags                        = CVAL(inbody, 0x03);
	requ_find.in_file_index                   = IVAL(inbody, 0x04);
	requ_find.in_file_id_persistent           = BVAL(inbody, 0x08);
	requ_find.in_file_id_volatile             = BVAL(inbody, 0x10);
	uint16_t in_name_offset             = SVAL(inbody, 0x18);
	uint16_t in_name_length             = SVAL(inbody, 0x1A);
	requ_find.in_output_buffer_length         = IVAL(inbody, 0x1C);

	if (in_name_length % 2 != 0 || !x_check_range(in_name_offset, in_name_length, 
				0x40 + X_SMB2_FIND_REQU_BODY_LEN, in_len)) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, NT_STATUS_INVALID_PARAMETER);
	}

	requ_find.in_name.assign((char16_t *)(in_buf + in_name_offset),
			(char16_t *)(in_buf + in_name_offset + in_name_length)); 

	X_LOG_OP("%ld FIND %x,%lx %lx,%lx", msg->mid, 
			requ_find.in_info_level, requ_find.in_flags,
			requ_find.in_file_id_persistent, requ_find.in_file_id_volatile);

	// TODO smbd_smb2_request_verify_creditcharge
	x_auto_ref_t<x_smbd_open_t> smbd_open{x_smbd_open_find(requ_find.in_file_id_volatile,
			smbd_tcon.get())};
	if (!smbd_open) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, NT_STATUS_FILE_CLOSED);
	}

	std::vector<uint8_t> output;
	NTSTATUS status = x_smbd_open_op_find(smbd_open, requ_find, output);
	if (NT_STATUS_IS_OK(status)) {
		return x_smb2_reply_find(smbd_conn, smbd_sess, msg, in_tid,
				output);
	} else {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, status);
	}
	return -EBADMSG;
}

