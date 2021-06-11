
#include "smbd.hxx"
#include "core.hxx"
#include "misc.hxx"

enum {
	X_SMB2_LOGOFF_REQU_BODY_LEN = 0x04,
	X_SMB2_LOGOFF_RESP_BODY_LEN = 0x04,
};

static void x_smb2_reply_logoff(x_smbd_conn_t *smbd_conn,
		x_smb2_msg_t *msg, NTSTATUS status)
{
	x_bufref_t *bufref = x_bufref_alloc(X_SMB2_LOGOFF_RESP_BODY_LEN);

	uint8_t *out_hdr = bufref->get_data();
	uint8_t *out_body = out_hdr + SMB2_HDR_BODY;

	x_put_le16(out_body, X_SMB2_LOGOFF_RESP_BODY_LEN);
	x_put_le16(out_body + 0x02, 0);

	x_smb2_reply(smbd_conn, msg, bufref, bufref, status, 
			SMB2_HDR_BODY + X_SMB2_LOGOFF_RESP_BODY_LEN);
}

NTSTATUS x_smb2_process_LOGOFF(x_smbd_conn_t *smbd_conn, x_smb2_msg_t *msg)
{
	X_LOG_OP("%ld LOGOFF 0x%lx, 0x%lx", msg->in_mid);

	if (msg->in_requ_len < SMB2_HDR_BODY + X_SMB2_LOGOFF_REQU_BODY_LEN) {
		RETURN_OP_STATUS(msg, NT_STATUS_INVALID_PARAMETER);
	}

	if (msg->smbd_sess == nullptr) {
		RETURN_OP_STATUS(msg, NT_STATUS_USER_SESSION_DELETED);
	}
	if (msg->smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		RETURN_OP_STATUS(msg, NT_STATUS_INVALID_PARAMETER);
	}

	/* TODO close tcon, opens ... */
	x_smbd_tcon_t *smbd_tcon;
	while ((smbd_tcon = msg->smbd_sess->tcon_list.get_front()) != nullptr) {
		msg->smbd_sess->tcon_list.remove(smbd_tcon);
		x_smbd_tcon_release(smbd_tcon);
		smbd_tcon->decref();
	}

	smbd_conn->session_list.remove(msg->smbd_sess);
	x_smbd_sess_release(msg->smbd_sess);
	x_smb2_reply_logoff(smbd_conn, msg, NT_STATUS_OK);
	msg->smbd_sess->decref();
	msg->smbd_sess = nullptr;
	return NT_STATUS_OK;
}
