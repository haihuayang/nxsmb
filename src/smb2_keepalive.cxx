
#include "smbd.hxx"
#include "smbd_requ.hxx"

struct x_smb2_keepalive_t
{
	uint16_t struct_size;
	uint16_t reserved0;
};

static void encode_out_keepalive(uint8_t *out_hdr)
{
	x_smb2_keepalive_t *keepalive = (x_smb2_keepalive_t *)(out_hdr + sizeof(x_smb2_header_t));

	keepalive->struct_size = X_H2LE16(sizeof(x_smb2_keepalive_t));
	keepalive->reserved0 = 0;
}

static void x_smb2_reply_keepalive(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_keepalive_t));

	uint8_t *out_hdr = bufref->get_data();
	
	encode_out_keepalive(out_hdr);
	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, NT_STATUS_OK, 
			sizeof(x_smb2_header_t) + sizeof(x_smb2_keepalive_t));
}

NTSTATUS x_smb2_process_keepalive(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	if (smbd_requ->in_requ_len < sizeof(x_smb2_header_t) + sizeof(struct x_smb2_keepalive_t)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	X_LOG(SMB, OP, "%ld KEEPALIVE", smbd_requ->in_smb2_hdr.mid);

	x_smb2_reply_keepalive(smbd_conn, smbd_requ);
	return NT_STATUS_OK;
}
