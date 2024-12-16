
#include "smbd.hxx"
#include "smbd_requ.hxx"

static void x_smb2_reply_tdis(x_smbd_requ_t *smbd_requ)
{
	auto &out_buf = smbd_requ->get_requ_out_buf();
	out_buf.head = out_buf.tail = x_smb2_bufref_alloc(sizeof(x_smb2_tdis_resp_t));
	out_buf.length = out_buf.head->length;

	uint8_t *out_hdr = out_buf.head->get_data();
	auto out_resp = (x_smb2_tdis_resp_t *)(out_hdr + sizeof(x_smb2_header_t));

	out_resp->struct_size = X_H2LE16(sizeof(x_smb2_tdis_resp_t));
	out_resp->unused0 = 0;
}

struct x_smbd_requ_tdis_t : x_smbd_requ_t
{
	using x_smbd_requ_t::x_smbd_requ_t;
	NTSTATUS process(void *ctx) override;
	NTSTATUS done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status) override;
};

NTSTATUS x_smbd_requ_tdis_t::process(void *ctx)
{
	X_SMBD_REQU_LOG(OP, this,  "");

	X_ASSERT(this->smbd_chan && this->smbd_sess && this->smbd_tcon);

	bool ret = x_smbd_tcon_disconnect(this->smbd_tcon);
	X_REF_DEC(this->smbd_tcon);

	if (!ret) {
		return NT_STATUS_NETWORK_NAME_DELETED;
	}

	return NT_STATUS_OK;
}

NTSTATUS x_smbd_requ_tdis_t::done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status)
{
	if (status.ok()) {
		x_smb2_reply_tdis(this);
	}
	return status;
}

NTSTATUS x_smb2_parse_TDIS(x_smbd_conn_t *smbd_conn, x_smbd_requ_t **p_smbd_requ,
		x_in_buf_t &in_buf, uint32_t in_msgsize,
		bool encrypted)
{
	auto in_smb2_hdr = (const x_smb2_header_t *)(in_buf.get_data());

	if (in_buf.length < sizeof(x_smb2_header_t) + sizeof(x_smb2_tdis_requ_t)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	auto requ = new x_smbd_requ_tdis_t(smbd_conn, in_buf, in_msgsize, encrypted);
	*p_smbd_requ = requ;
	return NT_STATUS_OK;
}

