
#include "smbd.hxx"
#include "smbd_requ.hxx"

struct x_smbd_requ_keepalive_t : x_smbd_requ_t
{
	using x_smbd_requ_t::x_smbd_requ_t;
	std::tuple<bool, bool, bool> get_properties() const override
	{
		return { false, false, false };
	}
	NTSTATUS process(void *ctx_conn) override;
	NTSTATUS done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status) override;
};

NTSTATUS x_smbd_requ_keepalive_t::process(void *ctx_conn)
{
	X_SMBD_REQU_LOG(OP, this,  "");
	return NT_STATUS_OK;
}

NTSTATUS x_smbd_requ_keepalive_t::done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status)
{
	auto &out_buf = get_requ_out_buf();
	out_buf.head = out_buf.tail = x_smb2_bufref_alloc(sizeof(x_smb2_keepalive_resp_t));
	out_buf.length = out_buf.head->length;

	uint8_t *out_hdr = out_buf.head->get_data();
	auto out_body = (x_smb2_keepalive_resp_t *)(out_hdr + sizeof(x_smb2_header_t));
	out_body->struct_size = X_H2LE16(sizeof(x_smb2_keepalive_resp_t));
	out_body->reserved0 = 0;
	return NT_STATUS_OK;
}

NTSTATUS x_smb2_parse_KEEPALIVE(x_smbd_conn_t *smbd_conn, x_smbd_requ_t **p_smbd_requ,
		x_in_buf_t &in_buf)
{
	auto in_smb2_hdr = (const x_smb2_header_t *)(in_buf.get_data());

	if (in_buf.length < sizeof(x_smb2_header_t) + sizeof(x_smb2_keepalive_requ_t)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	*p_smbd_requ = new x_smbd_requ_keepalive_t(smbd_conn);
	return NT_STATUS_OK;
}

