
#include "smbd.hxx"
#include "core.hxx"

enum {
	X_SMB2_TDIS_REQU_BODY_LEN = 0x04,
	X_SMB2_TDIS_RESP_BODY_LEN = 0x04,
};

static void x_smb2_reply_tdis(x_smbd_conn_t *smbd_conn,
		x_smb2_msg_t *msg, NTSTATUS status)
{
	x_bufref_t *bufref = x_bufref_alloc(X_SMB2_TDIS_RESP_BODY_LEN);

	uint8_t *out_hdr = bufref->get_data();
	uint8_t *out_body = out_hdr + SMB2_HDR_BODY;

	x_put_le16(out_body, X_SMB2_TDIS_RESP_BODY_LEN);
	x_put_le16(out_body + 0x02, 0);

	x_smb2_reply(smbd_conn, msg, bufref, bufref, status, 
			SMB2_HDR_BODY + X_SMB2_TDIS_RESP_BODY_LEN);
}

NTSTATUS x_smb2_process_TDIS(x_smbd_conn_t *smbd_conn, x_smb2_msg_t *msg)
{
	X_LOG_OP("%ld TDIS", msg->in_mid);

	if (msg->in_requ_len < SMB2_HDR_BODY + X_SMB2_TDIS_REQU_BODY_LEN) {
		RETURN_OP_STATUS(msg, NT_STATUS_INVALID_PARAMETER);
	}

	if (!msg->smbd_sess) {
		RETURN_OP_STATUS(msg, NT_STATUS_USER_SESSION_DELETED);
	}

	if (msg->smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		RETURN_OP_STATUS(msg, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = msg->get_in_data();

	/* TODO signing/encryption */
	if (!msg->smbd_tcon) {
		uint32_t in_tid = IVAL(in_hdr, SMB2_HDR_TID);
		msg->smbd_tcon = x_smbd_tcon_find(in_tid, msg->smbd_sess);
		if (!msg->smbd_tcon) {
			RETURN_OP_STATUS(msg, NT_STATUS_NETWORK_NAME_DELETED);
		}
	}

	x_smbd_open_t *smbd_open;
	while ((smbd_open = msg->smbd_tcon->open_list.get_front()) != nullptr) {
		msg->smbd_tcon->open_list.remove(smbd_open);
		x_smbd_open_release(smbd_open);
		smbd_open->decref();
	}

	msg->smbd_sess->tcon_list.remove(msg->smbd_tcon);
	x_smb2_reply_tdis(smbd_conn, msg, NT_STATUS_OK);

	x_smbd_tcon_release(msg->smbd_tcon);
	msg->smbd_tcon->decref();
	msg->smbd_tcon = nullptr;

	return NT_STATUS_OK;
}
