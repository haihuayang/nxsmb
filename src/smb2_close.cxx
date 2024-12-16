
#include "smbd.hxx"
#include "smbd_open.hxx"
#include "nxfsd_stats.hxx"


static void encode_out_close(uint8_t *out_hdr,
		const x_smb2_create_close_info_t *out_info)
{
	auto out_body = (x_smb2_close_resp_t *)(out_hdr + sizeof(x_smb2_header_t));

	out_body->struct_size = X_H2LE16(sizeof(x_smb2_close_resp_t));
	out_body->reserved0 = 0;
	/* TODO x_smb2_close_resp_t is not 8 bytes aligned, sizeof() is not 0x3c */
	if (out_info) {
		out_body->flags = X_H2LE16(X_SMB2_CLOSE_FLAGS_FULL_INFORMATION);
		/* TODO not work for big-endian */
		out_body->info.out_create_ts = X_H2LE64(out_info->out_create_ts);
		out_body->info.out_last_access_ts = X_H2LE64(out_info->out_last_access_ts);
		out_body->info.out_last_write_ts = X_H2LE64(out_info->out_last_write_ts);
		out_body->info.out_change_ts = X_H2LE64(out_info->out_change_ts);
		out_body->info.out_allocation_size = X_H2LE64(out_info->out_allocation_size);
		out_body->info.out_end_of_file = X_H2LE64(out_info->out_end_of_file);
		out_body->info.out_file_attributes = X_H2LE64(out_info->out_file_attributes);
	} else {
		out_body->flags = 0;
		out_body->info.out_create_ts = 0;
		out_body->info.out_last_access_ts = 0;
		out_body->info.out_last_write_ts = 0;
		out_body->info.out_change_ts = 0;
		out_body->info.out_allocation_size = 0;
		out_body->info.out_end_of_file = 0;
		out_body->info.out_file_attributes = 0;
	}
}

struct x_smbd_requ_close_t : x_smbd_requ_t
{
	x_smbd_requ_close_t(x_smbd_conn_t *smbd_conn, x_in_buf_t &in_buf,
			uint32_t in_msgsize, bool encrypted,
			uint16_t in_flags,
			uint64_t in_file_id_persistent,
			uint64_t in_file_id_volatile)
		: x_smbd_requ_t(smbd_conn, in_buf, in_msgsize, encrypted)
		, in_flags(in_flags)
		, in_file_id_persistent(in_file_id_persistent)
		, in_file_id_volatile(in_file_id_volatile)
	{
	}
	std::tuple<bool, bool, bool> get_properties() const override
	{
		return { true, true, true };
	}
	NTSTATUS process(void *ctx_conn) override;
	NTSTATUS done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status) override;

	uint16_t in_flags;
	uint16_t out_flags = 0;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	x_smb2_create_close_info_t out_info;
};

NTSTATUS x_smbd_requ_close_t::process(void *ctx_conn)
{
	X_SMBD_REQU_LOG(OP, this,  " open=0x%lx,0x%lx",
			this->in_file_id_persistent, this->in_file_id_volatile);

	NTSTATUS status = x_smbd_requ_init_open(this,
			this->in_file_id_persistent,
			this->in_file_id_volatile,
			false);
	if (!NT_STATUS_IS_OK(status)) {
		X_SMBD_REQU_RETURN_STATUS(this, status);
	}

	x_smb2_create_close_info_t *info = nullptr;
	if (this->in_flags & X_SMB2_CLOSE_FLAGS_FULL_INFORMATION) {
		info = &this->out_info;
		out_flags = X_SMB2_CLOSE_FLAGS_FULL_INFORMATION;
	}
	return x_smbd_open_op_close(this->smbd_open, info);
}

NTSTATUS x_smbd_requ_close_t::done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status)
{
	if (status.ok()) {
		auto &out_buf = get_requ_out_buf();
		out_buf.head = out_buf.tail = x_smb2_bufref_alloc(sizeof(x_smb2_close_resp_t));
		out_buf.length = out_buf.head->length;
		uint8_t *out_hdr = out_buf.head->get_data();
		encode_out_close(out_hdr, (out_flags) ? &out_info : nullptr);
	}
	return status;
}

NTSTATUS x_smb2_parse_CLOSE(x_smbd_conn_t *smbd_conn, x_smbd_requ_t **p_smbd_requ,
		x_in_buf_t &in_buf, uint32_t in_msgsize,
		bool encrypted)
{
	auto in_smb2_hdr = (const x_smb2_header_t *)(in_buf.get_data());

	if (in_buf.length < sizeof(x_smb2_header_t) + sizeof(x_smb2_close_requ_t)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	auto in_body = (const x_smb2_close_requ_t *)(in_smb2_hdr + 1);

	auto requ = new x_smbd_requ_close_t(smbd_conn, in_buf,
			in_msgsize, encrypted,
			X_LE2H16(in_body->flags),
			X_LE2H64(in_body->file_id_persistent),
			X_LE2H64(in_body->file_id_volatile));
	*p_smbd_requ = requ;
	return NT_STATUS_OK;
}

