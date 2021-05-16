
#include "smbd.hxx"
#include "core.hxx"

enum {
	X_SMB2_CLOSE_REQU_BODY_LEN = 0x18,
	X_SMB2_CLOSE_RESP_BODY_LEN = 0x3c,
};

static int x_smb2_reply_close(x_smbd_conn_t *smbd_conn,
		x_smbd_sess_t *smbd_sess,
		x_msg_t *msg, NTSTATUS status,
		uint32_t tid,
		const x_smb2_resp_close_t &resp)
{
	uint8_t *outbuf = new uint8_t[8 + 0x40 + X_SMB2_CLOSE_RESP_BODY_LEN];
	uint8_t *outhdr = outbuf + 8;
	uint8_t *outbody = outhdr + 0x40;

	memcpy(outbody, &resp, X_SMB2_CLOSE_RESP_BODY_LEN);
	x_smbd_conn_reply(smbd_conn, msg, smbd_sess, nullptr, outbuf, tid, status, X_SMB2_CLOSE_RESP_BODY_LEN);
	return 0;
}

int x_smb2_process_CLOSE(x_smbd_conn_t *smbd_conn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len)
{
	if (in_len < 0x40 + X_SMB2_CLOSE_REQU_BODY_LEN) {
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
	x_smb2_requ_close_t requ_close;
	memcpy(&requ_close, inbody, X_SMB2_CLOSE_REQU_BODY_LEN);

	X_LOG_OP("%ld CLOSE 0x%lx, 0x%lx", msg->mid, requ_close.file_id_persistent, requ_close.file_id_volatile);

	// TODO smbd_smb2_request_verify_creditcharge
	x_auto_ref_t<x_smbd_open_t> smbd_open{x_smbd_open_find(requ_close.file_id_volatile,
			smbd_tcon.get())};
	if (!smbd_open) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, NT_STATUS_FILE_CLOSED);
	}

	x_smb2_resp_close_t resp_close;
	NTSTATUS status = x_smbd_open_op_close(smbd_conn, smbd_open, requ_close, resp_close);
	if (NT_STATUS_IS_OK(status)) {
		x_smbd_open_release(smbd_open);
		return x_smb2_reply_close(smbd_conn, smbd_sess, msg, status, in_tid,
				resp_close);
	} else {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, status);
	}
}
