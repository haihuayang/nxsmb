
#include "smbd.hxx"
#include "smbd_open.hxx"

namespace {

struct x_smb2_in_flush_t
{
	uint16_t struct_size;
	uint16_t reserved0;
	uint32_t reserved1;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
};

struct x_smb2_out_flush_t
{
	uint16_t struct_size;
	uint16_t reserved0;
};

}

static void x_smb2_reply_flush(x_smbd_conn_t *smbd_conn,
		x_smbd_requ_t *smbd_requ)
{
	X_LOG_OP("%ld FLUSH SUCCESS", smbd_requ->in_smb2_hdr.mid);

	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_out_flush_t));

	uint8_t *out_hdr = bufref->get_data();
	x_smb2_out_flush_t *out_flush = (x_smb2_out_flush_t *)(out_hdr + sizeof(x_smb2_header_t));
	out_flush->struct_size = X_H2LE16(sizeof(x_smb2_out_flush_t));
	out_flush->reserved0 = 0;

	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, NT_STATUS_OK, 
			sizeof(x_smb2_header_t) + sizeof(x_smb2_out_flush_t));
}

NTSTATUS x_smb2_process_flush(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	if (smbd_requ->in_requ_len < sizeof(x_smb2_header_t) + sizeof(x_smb2_in_flush_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = smbd_requ->get_in_data();
	const x_smb2_in_flush_t *in_flush = (const x_smb2_in_flush_t *)(in_hdr + sizeof(x_smb2_header_t));
	uint64_t in_file_id_persistent = X_LE2H64(in_flush->file_id_persistent);
	uint64_t in_file_id_volatile = X_LE2H64(in_flush->file_id_volatile);

	X_LOG_OP("%ld FLUSH 0x%lx, 0x%lx", smbd_requ->in_smb2_hdr.mid,
			in_file_id_persistent, in_file_id_volatile);

	NTSTATUS status = x_smbd_requ_init_open(smbd_requ,
			in_file_id_persistent,
			in_file_id_volatile,
			false);
	if (!NT_STATUS_IS_OK(status)) {
		RETURN_OP_STATUS(smbd_requ, status);
	}

	if (!smbd_requ->smbd_open->check_access_any(idl::SEC_FILE_WRITE_DATA)) {
		/* TODO smbd_smb2_flush_send directory flush */
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
	}

	// TODO async smbd_requ->async_done_fn = x_smb2_flush_async_done;
	status = x_smbd_open_op_flush(smbd_requ->smbd_open, smbd_requ);

	if (NT_STATUS_IS_OK(status)) {
		x_smb2_reply_flush(smbd_conn, smbd_requ);
		return status;
	}
	RETURN_OP_STATUS(smbd_requ, status);
}

