
#include "smbd.hxx"
#include "smbd_requ.hxx"
#include "misc.hxx"

static void x_smb2_reply_logoff(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ, NTSTATUS status)
{
	x_out_buf_t out_buf;
	out_buf.head = out_buf.tail = x_smb2_bufref_alloc(sizeof(x_smb2_logoff_resp_t));
	out_buf.length = out_buf.head->length;

	uint8_t *out_hdr = out_buf.head->get_data();
	auto out_resp = (x_smb2_logoff_resp_t *)(out_hdr + sizeof(x_smb2_header_t));

	out_resp->struct_size = X_H2LE16(sizeof(x_smb2_logoff_resp_t));
	out_resp->unused0 = 0;
	x_smb2_reply(smbd_conn, smbd_requ, status, out_buf);
}

NTSTATUS x_smb2_process_logoff(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_SMBD_REQU_LOG(OP, smbd_requ,  "");

	X_ASSERT(smbd_requ->smbd_chan);
	X_ASSERT(smbd_requ->smbd_sess);

	auto [ in_hdr, in_requ_len ] = smbd_requ->get_in_data();
	if (in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_logoff_requ_t)) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	NTSTATUS status = x_smbd_sess_logoff(smbd_requ->smbd_sess);

	x_smb2_reply_logoff(smbd_conn, smbd_requ, status);
	X_REF_DEC(smbd_requ->smbd_chan);
	/* X_REF_DEC(smbd_requ->smbd_sess); we lease smbd_chan not clean
	   so it is able to sign */
	return NT_STATUS_OK;
}
