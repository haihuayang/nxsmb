
#include "smbd.hxx"
#include "core.hxx"

struct x_smb2_tdis_t
{
	uint16_t struct_size;
	uint16_t unused0;
};

using x_smb2_tdis_requ_t = x_smb2_tdis_t;
using x_smb2_tdis_resp_t = x_smb2_tdis_t;

static void x_smb2_reply_tdis(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ, NTSTATUS status)
{
	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_tdis_resp_t));

	uint8_t *out_hdr = bufref->get_data();
	x_smb2_tdis_resp_t *out_resp = (x_smb2_tdis_resp_t *)(out_hdr + SMB2_HDR_BODY);

	out_resp->struct_size = X_H2LE16(sizeof(x_smb2_tdis_resp_t));
	out_resp->unused0 = 0;

	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, status, 
			SMB2_HDR_BODY + sizeof(x_smb2_tdis_resp_t));
}

NTSTATUS x_smb2_process_tdis(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_LOG_OP("%ld TDIS", smbd_requ->in_mid);
	X_ASSERT(smbd_requ->smbd_chan && smbd_requ->smbd_sess);

	if (smbd_requ->in_requ_len < SMB2_HDR_BODY + sizeof(x_smb2_tdis_requ_t)) {
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
	x_smbd_sess_unlink_tcon(smbd_requ->smbd_sess, &smbd_requ->smbd_tcon->sess_link);

	X_SMBD_REF_DEC(smbd_requ->smbd_tcon);

	x_smb2_reply_tdis(smbd_conn, smbd_requ, NT_STATUS_OK);
	return NT_STATUS_OK;
}
