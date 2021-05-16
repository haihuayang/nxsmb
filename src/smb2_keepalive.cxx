
#include "smbd.hxx"
#include "core.hxx"

enum {
	X_SMB2_KEEPALIVE_REQU_BODY_LEN = 0x04,
	X_SMB2_KEEPALIVE_RESP_BODY_LEN = 0x04,
};

static int x_smb2_reply_keepalive(x_smbd_conn_t *smbd_conn,
		x_smbd_sess_t *smbd_sess,
		x_msg_t *msg, NTSTATUS status)
{
	uint8_t *outbuf = new uint8_t[8 + 0x40 + X_SMB2_KEEPALIVE_RESP_BODY_LEN];
	uint8_t *outhdr = outbuf + 8;
	uint8_t *outbody = outhdr + 0x40;

	SSVAL(outbody, 0x00, X_SMB2_KEEPALIVE_RESP_BODY_LEN);
	SSVAL(outbody, 0x02, 0);

	x_smbd_conn_reply(smbd_conn, msg, smbd_sess, nullptr, outbuf, 0, status, X_SMB2_KEEPALIVE_RESP_BODY_LEN);
	return 0;
}

int x_smb2_process_KEEPALIVE(x_smbd_conn_t *smbd_conn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len)
{
	if (in_len < 0x40 + X_SMB2_KEEPALIVE_REQU_BODY_LEN) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, 0, NT_STATUS_INVALID_PARAMETER);
	}

	if (smbd_conn->session_list.empty() && smbd_conn->session_wait_input_list.empty()) {
		return -EINVAL;
	}

	const uint8_t *inhdr = in_buf;
	uint64_t in_session_id = BVAL(inhdr, SMB2_HDR_SESSION_ID);
	uint32_t in_tid = IVAL(inhdr, SMB2_HDR_TID);

	x_auto_ref_t<x_smbd_sess_t> smbd_sess;
	if (in_session_id != 0) {
		smbd_sess.set(x_smbd_sess_find(in_session_id, smbd_conn));
		if (smbd_sess == nullptr) {
			return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, in_tid, NT_STATUS_USER_SESSION_DELETED);
		}
		if (smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
			return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, NT_STATUS_INVALID_PARAMETER);
		}
	}
	/* TODO signing/encryption */

	return x_smb2_reply_keepalive(smbd_conn, smbd_sess, msg, NT_STATUS_OK);
}
