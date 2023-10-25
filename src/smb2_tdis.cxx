
#include "smbd.hxx"
#include "smbd_requ.hxx"

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
	x_smb2_tdis_resp_t *out_resp = (x_smb2_tdis_resp_t *)(out_hdr + sizeof(x_smb2_header_t));

	out_resp->struct_size = X_H2LE16(sizeof(x_smb2_tdis_resp_t));
	out_resp->unused0 = 0;

	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, status, 
			sizeof(x_smb2_header_t) + sizeof(x_smb2_tdis_resp_t));
}

NTSTATUS x_smb2_process_tdis(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_LOG(SMB, OP, "%ld TDIS", smbd_requ->in_smb2_hdr.mid);
	X_ASSERT(smbd_requ->smbd_chan && smbd_requ->smbd_sess && smbd_requ->smbd_tcon);

	if (smbd_requ->in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_tdis_requ_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	bool ret = x_smbd_tcon_disconnect(smbd_requ->smbd_tcon);
	X_SMBD_REF_DEC(smbd_requ->smbd_tcon);

	if (!ret) {
		return NT_STATUS_NETWORK_NAME_DELETED;
	}

	x_smb2_reply_tdis(smbd_conn, smbd_requ, NT_STATUS_OK);
	return NT_STATUS_OK;
}
