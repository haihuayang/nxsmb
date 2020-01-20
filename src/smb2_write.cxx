
#include "smbd.hxx"
#include "core.hxx"

namespace {
enum {
	X_SMB2_WRITE_REQU_BODY_LEN = 0x30,
	X_SMB2_WRITE_RESP_BODY_LEN = 0x10,
};
}

static int x_smb2_reply_write(x_smbd_conn_t *smbd_conn,
		x_smbd_sess_t *smbd_sess,
		x_msg_t *msg, NTSTATUS status,
		uint32_t tid,
		x_smb2_resp_write_t &resp)
{
	X_LOG_OP("%ld WRITE SUCCESS", msg->mid);

	uint8_t *outbuf = new uint8_t[8 + 0x40 + X_SMB2_WRITE_RESP_BODY_LEN];
	uint8_t *outhdr = outbuf + 8;
	uint8_t *outbody = outhdr + 0x40;

	SSVAL(outbody, 0x00, X_SMB2_WRITE_RESP_BODY_LEN + 1);
	SSVAL(outbody, 0x02, 0);
	SIVAL(outbody, 0x04, resp.write_count);
	SIVAL(outbody, 0x08, resp.write_remaining);
	SIVAL(outbody, 0x0c, 0); // channel info

	//smbd_smb2_request_setup_out
	memset(outhdr, 0, 0x40);
	SIVAL(outhdr, SMB2_HDR_PROTOCOL_ID,     SMB2_MAGIC);
	SSVAL(outhdr, SMB2_HDR_LENGTH,	  SMB2_HDR_BODY);
	SSVAL(outhdr, SMB2_HDR_CREDIT_CHARGE, 1); // TODO
	SIVAL(outhdr, SMB2_HDR_STATUS, NT_STATUS_V(status));
	SIVAL(outhdr, SMB2_HDR_OPCODE, SMB2_OP_WRITE);
	SSVAL(outhdr, SMB2_HDR_CREDIT, 1); // TODO
	SIVAL(outhdr, SMB2_HDR_FLAGS, SMB2_HDR_FLAG_REDIRECT); // TODO
	SIVAL(outhdr, SMB2_HDR_NEXT_COMMAND, 0);
	SBVAL(outhdr, SMB2_HDR_MESSAGE_ID, msg->mid);
	SIVAL(outhdr, SMB2_HDR_TID, tid);
	SBVAL(outhdr, SMB2_HDR_SESSION_ID, smbd_sess->id);

	uint8_t *outnbt = outbuf + 4;
	x_put_be32(outnbt, 0x40 + X_SMB2_WRITE_RESP_BODY_LEN);

	msg->out_buf = outbuf;
	msg->out_off = 4;
	msg->out_len = 4 + 0x40 + X_SMB2_WRITE_RESP_BODY_LEN;

	msg->state = x_msg_t::STATE_COMPLETE;
	x_smbd_conn_reply(smbd_conn, msg, smbd_sess);
	return 0;
}


int x_smb2_process_WRITE(x_smbd_conn_t *smbd_conn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len)
{
	if (in_len < 0x40 + X_SMB2_WRITE_REQU_BODY_LEN) {
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
	x_smb2_requ_write_t requ_write;
	memcpy(&requ_write, inbody, X_SMB2_WRITE_REQU_BODY_LEN);

	X_LOG_OP("%ld WRITE %x,%lx %lx,%lx", msg->mid, 
			requ_write.data_length, requ_write.offset,
			requ_write.file_id_persistent, requ_write.file_id_volatile);

	if (!x_check_range(requ_write.data_offset, requ_write.data_length,
				0x40 + X_SMB2_WRITE_REQU_BODY_LEN, in_len)) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, NT_STATUS_INVALID_PARAMETER);
	}

	const x_smbconf_t &conf = smbd_conn->get_conf();
	if (requ_write.data_length > conf.max_trans) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, NT_STATUS_INVALID_PARAMETER);
	}

	// TODO smbd_smb2_request_verify_creditcharge
	x_auto_ref_t<x_smbd_open_t> smbd_open{x_smbd_open_find(requ_write.file_id_volatile,
			smbd_tcon.get())};
	if (!smbd_open) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, NT_STATUS_FILE_CLOSED);
	}

	x_smb2_resp_write_t resp_write;
	std::vector<uint8_t> output;
	NTSTATUS status = x_smbd_open_op_write(smbd_open, requ_write, in_buf + requ_write.data_offset,
			resp_write);
	if (NT_STATUS_IS_OK(status)) {
		return x_smb2_reply_write(smbd_conn, smbd_sess, msg, status, in_tid,
				resp_write);
	} else {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, status);
	}
}

