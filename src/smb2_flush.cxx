
#include "smbd.hxx"
#include "smbd_open.hxx"

static void x_smb2_reply_flush(x_smbd_requ_t *smbd_requ)
{
	auto &out_buf = smbd_requ->get_requ_out_buf();
	out_buf.head = out_buf.tail = x_smb2_bufref_alloc(sizeof(x_smb2_flush_resp_t));
	out_buf.length = out_buf.head->length;

	uint8_t *out_hdr = out_buf.head->get_data();
	auto out_resp = (x_smb2_flush_resp_t *)(out_hdr + sizeof(x_smb2_header_t));
	out_resp->struct_size = X_H2LE16(sizeof(x_smb2_flush_resp_t));
	out_resp->reserved0 = 0;
}

struct x_smbd_requ_flush_t : x_smbd_requ_t
{
	using x_smbd_requ_t::x_smbd_requ_t;
	std::tuple<bool, bool, bool> get_properties() const override
	{
		return { true, true, false };
	}
	NTSTATUS process(void *ctx) override;
	NTSTATUS done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status) override;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
};

NTSTATUS x_smbd_requ_flush_t::process(void *ctx)
{
	X_SMBD_REQU_LOG(OP, this,  " open=0x%lx,0x%lx",
			in_file_id_persistent, in_file_id_volatile);

	NTSTATUS status = x_smbd_requ_init_open(this,
			in_file_id_persistent,
			in_file_id_volatile,
			false);
	if (!NT_STATUS_IS_OK(status)) {
		X_SMBD_REQU_RETURN_STATUS(this, status);
	}

	if (!this->smbd_open->check_access_any(idl::SEC_FILE_WRITE_DATA)) {
		/* TODO smbd_smb2_flush_send directory flush */
		X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_ACCESS_DENIED);
	}

	// TODO async this->async_done_fn = x_smb2_flush_async_done;
	return x_smbd_open_op_flush(this->smbd_open, this);
}

NTSTATUS x_smbd_requ_flush_t::done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status)
{
	if (status.ok()) {
		x_smb2_reply_flush(this);
	}
	return status;
}

NTSTATUS x_smb2_parse_FLUSH(x_smbd_conn_t *smbd_conn, x_smbd_requ_t **p_smbd_requ,
		x_in_buf_t &in_buf, uint32_t in_msgsize,
		bool encrypted)
{
	auto in_smb2_hdr = (const x_smb2_header_t *)(in_buf.get_data());

	if (in_buf.length < sizeof(x_smb2_header_t) + sizeof(x_smb2_flush_requ_t)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	auto requ = new x_smbd_requ_flush_t(smbd_conn, in_buf, in_msgsize, encrypted);
	auto in_flush = (const x_smb2_flush_requ_t *)(in_smb2_hdr + 1);
	requ->in_file_id_persistent = X_LE2H64(in_flush->file_id_persistent);
	requ->in_file_id_volatile = X_LE2H64(in_flush->file_id_volatile);
	*p_smbd_requ = requ;
	return NT_STATUS_OK;
}

