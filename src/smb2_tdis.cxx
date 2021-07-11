
#include "smbd.hxx"
#include "core.hxx"

enum {
	X_SMB2_TDIS_REQU_BODY_LEN = 0x04,
	X_SMB2_TDIS_RESP_BODY_LEN = 0x04,
};

static void x_smb2_reply_tdis(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ, NTSTATUS status)
{
	x_bufref_t *bufref = x_bufref_alloc(X_SMB2_TDIS_RESP_BODY_LEN);

	uint8_t *out_hdr = bufref->get_data();
	uint8_t *out_body = out_hdr + SMB2_HDR_BODY;

	x_put_le16(out_body, X_SMB2_TDIS_RESP_BODY_LEN);
	x_put_le16(out_body + 0x02, 0);

	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, status, 
			SMB2_HDR_BODY + X_SMB2_TDIS_RESP_BODY_LEN);
}

NTSTATUS x_smb2_process_TDIS(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_LOG_OP("%ld TDIS", smbd_requ->in_mid);

	if (smbd_requ->in_requ_len < SMB2_HDR_BODY + X_SMB2_TDIS_REQU_BODY_LEN) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if (!smbd_requ->smbd_sess) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_USER_SESSION_DELETED);
	}

	if (smbd_requ->smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = smbd_requ->get_in_data();

	/* TODO signing/encryption */
	if (!smbd_requ->smbd_tcon) {
		uint32_t in_tid = IVAL(in_hdr, SMB2_HDR_TID);
		smbd_requ->smbd_tcon = x_smbd_tcon_find(in_tid, smbd_requ->smbd_sess);
		if (!smbd_requ->smbd_tcon) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_NETWORK_NAME_DELETED);
		}
	}

	x_smbd_tcon_terminate(smbd_requ->smbd_tcon);
#if 0
	x_smbd_open_t *smbd_open;
	while ((smbd_open = smbd_requ->smbd_tcon->open_list.get_front()) != nullptr) {
		smbd_requ->smbd_tcon->open_list.remove(smbd_open);
		x_smbd_open_release(smbd_open);
		smbd_open->decref();
	}
	x_smbd_tcon_release(smbd_requ->smbd_tcon);
#endif
	smbd_requ->smbd_sess->tcon_list.remove(smbd_requ->smbd_tcon);

	smbd_requ->smbd_tcon->decref();
	smbd_requ->smbd_tcon = nullptr;

	x_smb2_reply_tdis(smbd_conn, smbd_requ, NT_STATUS_OK);
	return NT_STATUS_OK;
}
