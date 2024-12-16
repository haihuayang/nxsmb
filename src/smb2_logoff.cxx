
#include "smbd.hxx"
#include "smbd_requ.hxx"
#include "misc.hxx"

struct x_smbd_requ_logoff_t : x_smbd_requ_t
{
	using x_smbd_requ_t::x_smbd_requ_t;
	NTSTATUS process(void *ctx) override;
	NTSTATUS done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status) override;
};

NTSTATUS x_smbd_requ_logoff_t::process(void *ctx)
{
	X_SMBD_REQU_LOG(OP, this,  "");

	X_ASSERT(this->smbd_chan);
	X_ASSERT(this->smbd_sess);

	return x_smbd_sess_logoff(this->smbd_sess);
}

NTSTATUS x_smbd_requ_logoff_t::done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status)
{
	if (!status.ok()) {
		return status;
	}

	auto &out_buf = get_requ_out_buf();
	out_buf.head = out_buf.tail = x_smb2_bufref_alloc(sizeof(x_smb2_logoff_resp_t));
	out_buf.length = out_buf.head->length;

	uint8_t *out_hdr = out_buf.head->get_data();
	auto out_resp = (x_smb2_logoff_resp_t *)(out_hdr + sizeof(x_smb2_header_t));

	out_resp->struct_size = X_H2LE16(sizeof(x_smb2_logoff_resp_t));
	out_resp->unused0 = 0;

	X_REF_DEC(this->smbd_chan);
	/* X_REF_DEC(this->smbd_sess); we lease smbd_chan not clean
	   so it is able to sign */
	return NT_STATUS_OK;
}

NTSTATUS x_smb2_parse_LOGOFF(x_smbd_conn_t *smbd_conn, x_smbd_requ_t **p_smbd_requ,
		x_in_buf_t &in_buf, uint32_t in_msgsize,
		bool encrypted)
{
	auto in_smb2_hdr = (const x_smb2_header_t *)(in_buf.get_data());

	if (in_buf.length < sizeof(x_smb2_header_t) + sizeof(x_smb2_logoff_requ_t)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	*p_smbd_requ = new x_smbd_requ_logoff_t(smbd_conn, in_buf, in_msgsize, encrypted);
	return NT_STATUS_OK;
}

