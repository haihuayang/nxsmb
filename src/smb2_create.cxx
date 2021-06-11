
#include "smbd_open.hxx"
#include "core.hxx"
#include "include/charset.hxx"

enum {
	X_SMB2_CREATE_REQU_BODY_LEN = 0x38,
	X_SMB2_CREATE_RESP_BODY_LEN = 0x58,
};

struct x_smb2_in_create_t
{
	uint16_t struct_size;
	uint8_t reserved0;
	uint8_t oplock_level;
	uint32_t impersonation_level;
	uint64_t create_flags;
	uint64_t reserved1;
	uint32_t desired_access;
	uint32_t file_attributes;
	uint32_t share_access;
	uint32_t create_disposition;
	uint32_t create_options;
	uint16_t name_offset;
	uint16_t name_length;
	uint32_t context_offset;
	uint32_t context_length;
};

struct x_smb2_out_create_t
{
	uint16_t struct_size;
	uint8_t oplock_level;
	uint8_t create_flags;
	uint32_t create_action;
	uint64_t create_ts;
	uint64_t last_access_ts;
	uint64_t last_write_ts;
	uint64_t change_ts;
	uint64_t allocation_size;
	uint64_t end_of_file;
	uint32_t file_attributes;
	uint32_t reserved0;
	uint64_t file_id_persistent;
	uint64_t file_id_volatile;
	uint32_t context_offset;
	uint32_t context_length;
};

static NTSTATUS parse_create_in(x_smb2_requ_create_t &requ_create,
		x_smb2_msg_t *msg,
		const uint8_t *in_hdr, uint32_t in_len)
{
	const x_smb2_in_create_t *in_create = (const x_smb2_in_create_t *)(in_hdr + SMB2_HDR_BODY);
	uint16_t in_name_offset          = X_LE2H16(in_create->name_offset);
	uint16_t in_name_length          = X_LE2H16(in_create->name_length);
	uint32_t in_context_offset       = X_LE2H32(in_create->context_offset);
	uint32_t in_context_length       = X_LE2H32(in_create->context_length);

	if (in_name_length % 2 != 0 || !x_check_range<uint32_t>(in_name_offset, in_name_length, 
				SMB2_HDR_BODY + X_SMB2_CREATE_REQU_BODY_LEN, in_len)) {
		RETURN_OP_STATUS(msg, NT_STATUS_INVALID_PARAMETER);
	}

	if (!x_check_range<uint32_t>(in_context_offset, in_context_length, 
				SMB2_HDR_BODY + X_SMB2_CREATE_REQU_BODY_LEN, in_len)) {
		RETURN_OP_STATUS(msg, NT_STATUS_INVALID_PARAMETER);
	}

	requ_create.in_oplock_level         = in_create->oplock_level;
	requ_create.in_impersonation_level  = X_LE2H32(in_create->impersonation_level);
	requ_create.in_desired_access       = X_LE2H32(in_create->desired_access);
	requ_create.in_file_attributes      = X_LE2H32(in_create->file_attributes);
	requ_create.in_share_access         = X_LE2H32(in_create->share_access);
	requ_create.in_create_disposition   = X_LE2H32(in_create->create_disposition);
	requ_create.in_create_options       = X_LE2H32(in_create->create_options);

	requ_create.in_name.assign((char16_t *)(in_hdr + in_name_offset),
			(char16_t *)(in_hdr + in_name_offset + in_name_length)); 

	return NT_STATUS_OK;
}

static void x_smb2_reply_create(x_smbd_conn_t *smbd_conn,
		x_smb2_msg_t *msg, NTSTATUS status,
		x_smbd_open_t *smbd_open,
		const x_smb2_requ_create_t &requ_create,
		const std::vector<uint8_t> &output)
{
	X_LOG_OP("%ld RESP SUCCESS 0x%lx,0x%lx", msg->in_mid, smbd_open->id, smbd_open->id);

	x_bufref_t *bufref = x_bufref_alloc(X_SMB2_CREATE_RESP_BODY_LEN + output.size());

	uint8_t *out_hdr = bufref->get_data();
	uint8_t *out_body = out_hdr + SMB2_HDR_BODY;

	x_smb2_out_create_t *out_create = (x_smb2_out_create_t *)(out_hdr + SMB2_HDR_BODY);
	out_create->struct_size = X_H2LE16(X_SMB2_CREATE_RESP_BODY_LEN + 1);
	out_create->oplock_level = requ_create.out_oplock_level;
	out_create->create_flags = requ_create.out_create_flags;
	out_create->create_action = X_H2LE32(requ_create.out_create_action);
	out_create->create_ts = X_H2LE64(requ_create.out_info.out_create_ts.val);
	out_create->last_access_ts = X_H2LE64(requ_create.out_info.out_last_access_ts.val);
	out_create->last_write_ts = X_H2LE64(requ_create.out_info.out_last_write_ts.val);
	out_create->change_ts = X_H2LE64(requ_create.out_info.out_change_ts.val);
	out_create->allocation_size = X_H2LE64(requ_create.out_info.out_allocation_size);
	out_create->end_of_file = X_H2LE64(requ_create.out_info.out_end_of_file);
	out_create->file_attributes = X_H2LE32(requ_create.out_info.out_file_attributes);
	out_create->reserved0 = 0;
	out_create->file_id_persistent = X_H2LE64(smbd_open->id);
	out_create->file_id_volatile = X_H2LE64(smbd_open->id);
	if (output.empty()) {
		out_create->context_offset = out_create->context_length = 0;
	} else {
		out_create->context_offset = X_H2LE32(SMB2_HDR_BODY + X_SMB2_CREATE_RESP_BODY_LEN);
		out_create->context_length = X_H2LE32(output.size());
	}

	memcpy(out_body + X_SMB2_CREATE_RESP_BODY_LEN, output.data(), output.size());
	msg->smbd_open = smbd_open;
	x_smb2_reply(smbd_conn, msg, bufref, bufref, status, 
			SMB2_HDR_BODY + X_SMB2_CREATE_RESP_BODY_LEN + output.size());
}

NTSTATUS x_smb2_process_CREATE(x_smbd_conn_t *smbd_conn, x_smb2_msg_t *msg)
{
	X_LOG_OP("%ld CREATE", msg->in_mid);

	if (msg->in_requ_len < SMB2_HDR_BODY + X_SMB2_CREATE_REQU_BODY_LEN + 1) {
		RETURN_OP_STATUS(msg, NT_STATUS_INVALID_PARAMETER);
	}

	if (!msg->smbd_sess) {
		RETURN_OP_STATUS(msg, NT_STATUS_USER_SESSION_DELETED);
	}

	if (msg->smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		RETURN_OP_STATUS(msg, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = msg->get_in_data();

	/* TODO check limit of open for both total and per conn*/
	/* TODO signing/encryption */

	if (!msg->smbd_tcon) {
		uint32_t in_tid = IVAL(in_hdr, SMB2_HDR_TID);
		msg->smbd_tcon = x_smbd_tcon_find(in_tid, msg->smbd_sess);
		if (!msg->smbd_tcon) {
			RETURN_OP_STATUS(msg, NT_STATUS_NETWORK_NAME_DELETED);
		}
	}

	x_smb2_requ_create_t requ_create;
	NTSTATUS status = parse_create_in(requ_create, msg, in_hdr, msg->in_requ_len);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	X_LOG_OP("%ld CREATE '%s'", msg->in_mid, x_convert_utf16_to_utf8(requ_create.in_name).c_str());
	x_auto_ref_t<x_smbd_open_t> smbd_open{x_smbd_tcon_op_create(msg->smbd_tcon,
			status, msg->in_hdr_flags, requ_create)};
	if (smbd_open) {
		x_smbd_open_insert_local(smbd_open);
		x_smb2_reply_create(smbd_conn, msg, status,
				smbd_open,
				requ_create, std::vector<uint8_t>());
		return status;
	}

	RETURN_OP_STATUS(msg, status);
}
