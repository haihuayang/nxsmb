
#include "smbd.hxx"
#include "core.hxx"
#include "misc.hxx"

enum {
	X_SMB2_LOGOFF_REQU_BODY_LEN = 0x04,
	X_SMB2_LOGOFF_RESP_BODY_LEN = 0x04,
};

static void x_smb2_reply_logoff(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ, NTSTATUS status)
{
	x_bufref_t *bufref = x_bufref_alloc(X_SMB2_LOGOFF_RESP_BODY_LEN);

	uint8_t *out_hdr = bufref->get_data();
	uint8_t *out_body = out_hdr + SMB2_HDR_BODY;

	x_put_le16(out_body, X_SMB2_LOGOFF_RESP_BODY_LEN);
	x_put_le16(out_body + 0x02, 0);

	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, status, 
			SMB2_HDR_BODY + X_SMB2_LOGOFF_RESP_BODY_LEN);
}

NTSTATUS x_smb2_process_LOGOFF(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_LOG_OP("%ld LOGOFF 0x%lx, 0x%lx", smbd_requ->in_mid);

	if (smbd_requ->in_requ_len < SMB2_HDR_BODY + X_SMB2_LOGOFF_REQU_BODY_LEN) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if (smbd_requ->smbd_sess == nullptr) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_USER_SESSION_DELETED);
	}
	if (smbd_requ->smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	x_smbd_sess_terminate(smbd_requ->smbd_sess);

	smbd_conn->session_list.remove(smbd_requ->smbd_sess);

	x_smb2_reply_logoff(smbd_conn, smbd_requ, NT_STATUS_OK);
	smbd_requ->smbd_sess->decref();
	smbd_requ->smbd_sess = nullptr;
	return NT_STATUS_OK;
}
