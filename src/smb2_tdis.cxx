
#include "smbd.hxx"
#include "smbd_requ.hxx"

static void x_smb2_reply_tdis(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ, NTSTATUS status)
{
	x_bufref_t *bufref = x_smb2_bufref_alloc(sizeof(x_smb2_tdis_resp_t));

	uint8_t *out_hdr = bufref->get_data();
	x_smb2_tdis_resp_t *out_resp = (x_smb2_tdis_resp_t *)(out_hdr + sizeof(x_smb2_header_t));

	out_resp->struct_size = X_H2LE16(sizeof(x_smb2_tdis_resp_t));
	out_resp->unused0 = 0;

	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, status, 
			sizeof(x_smb2_header_t) + sizeof(x_smb2_tdis_resp_t));
}

NTSTATUS x_smb2_process_tdis(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_SMBD_REQU_LOG(OP, smbd_requ,  "");

	X_ASSERT(smbd_requ->smbd_chan && smbd_requ->smbd_sess && smbd_requ->smbd_tcon);

	auto [ in_hdr, in_requ_len ] = smbd_requ->base.get_in_data();
	if (in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_tdis_requ_t)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	bool ret = x_smbd_tcon_disconnect(smbd_requ->smbd_tcon);
	X_REF_DEC(smbd_requ->smbd_tcon);

	if (!ret) {
		return NT_STATUS_NETWORK_NAME_DELETED;
	}

	x_smb2_reply_tdis(smbd_conn, smbd_requ, NT_STATUS_OK);
	return NT_STATUS_OK;
}
