
#include "smbd.hxx"
#include "core.hxx"

namespace {
enum {
	X_SMB2_NOTIFY_REQU_BODY_LEN = 0x20,
	X_SMB2_NOTIFY_RESP_BODY_LEN = 0x08,
};
}

static int x_smb2_reply_notify(x_smbd_conn_t *smbd_conn,
		x_smbd_sess_t *smbd_sess,
		x_msg_ptr_t &msg, uint32_t tid,
		const std::vector<uint8_t> &output)
{
	X_LOG_OP("%ld RESP SUCCESS", msg->mid);

	uint8_t *outbuf = new uint8_t[8 + 0x40 + X_SMB2_NOTIFY_RESP_BODY_LEN + output.size()];
	uint8_t *outhdr = outbuf + 8;
	uint8_t *outbody = outhdr + 0x40;

	x_put_le16(outbody, X_SMB2_NOTIFY_RESP_BODY_LEN + 1);
	x_put_le16(outbody + 2, 0x40 + X_SMB2_NOTIFY_RESP_BODY_LEN);
	x_put_le32(outbody + 4, output.size());
	memcpy(outbody + X_SMB2_NOTIFY_RESP_BODY_LEN, output.data(), output.size());
	x_smbd_conn_reply(smbd_conn, msg, smbd_sess, nullptr, outbuf, tid, NT_STATUS_OK,
			X_SMB2_NOTIFY_RESP_BODY_LEN + output.size());
	return 0;
}

int x_smb2_process_NOTIFY(x_smbd_conn_t *smbd_conn, x_msg_ptr_t &msg,
		const uint8_t *in_buf, size_t in_len)
{
	if (in_len < 0x40 + X_SMB2_NOTIFY_REQU_BODY_LEN) {
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
	x_smb2_requ_notify_t requ_notify;
	memcpy(&requ_notify, inbody, X_SMB2_NOTIFY_REQU_BODY_LEN);

	X_LOG_OP("%ld NOTIFY %x,%x %lx,%lx", msg->mid, 
			requ_notify.flags, requ_notify.filter,
			requ_notify.file_id_persistent, requ_notify.file_id_volatile);

	// TODO smbd_smb2_request_verify_creditcharge
	x_auto_ref_t<x_smbd_open_t> smbd_open{x_smbd_open_find(requ_notify.file_id_volatile,
			smbd_tcon.get())};
	if (!smbd_open) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, NT_STATUS_FILE_CLOSED);
	}

	std::vector<uint8_t> output;
	NTSTATUS status = x_smbd_open_op_notify(smbd_conn, msg, smbd_open, requ_notify, output);
	if (NT_STATUS_IS_OK(status)) {
		return x_smb2_reply_notify(smbd_conn, smbd_sess, msg, in_tid,
				output);
	} else {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, status);
	}
}
