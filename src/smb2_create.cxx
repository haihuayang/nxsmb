
#include "smbd.hxx"
#include "core.hxx"
#include "include/charset.hxx"

enum {
	X_SMB2_CREATE_REQU_BODY_LEN = 0x38,
	X_SMB2_CREATE_RESP_BODY_LEN = 0x58,
};

static int x_smb2_reply_create(x_smbd_conn_t *smbd_conn,
		x_smbd_sess_t *smbd_sess,
		x_msg_t *msg, NTSTATUS status,
		uint32_t tid,
		x_smbd_open_t *smbd_open,
		const x_smb2_requ_create_t &requ_create,
		const std::vector<uint8_t> &output)
{
	X_LOG_OP("%ld RESP SUCCESS 0x%lx,0x%lx", msg->mid, smbd_open->id, smbd_open->id);

	uint8_t *outbuf = new uint8_t[8 + 0x40 + X_SMB2_CREATE_RESP_BODY_LEN + output.size()];
	uint8_t *outhdr = outbuf + 8;
	uint8_t *outbody = outhdr + 0x40;

	SSVAL(outbody, 0x00, X_SMB2_CREATE_RESP_BODY_LEN + 1);
	SCVAL(outbody, 0x02, requ_create.out_oplock_level);		/* oplock level */
	SCVAL(outbody, 0x03, requ_create.out_create_flags);		/* create flags - SMB3 only*/
	SIVAL(outbody, 0x04, requ_create.out_create_action);		/* create action */
	SBVAL(outbody, 0x08, requ_create.out_info.out_create_ts.val);		/* creation time */
	SBVAL(outbody, 0x10, requ_create.out_info.out_last_access_ts.val);		/* last access time */
	SBVAL(outbody, 0x18, requ_create.out_info.out_last_write_ts.val);		/* last write time */
	SBVAL(outbody, 0x20, requ_create.out_info.out_change_ts.val);			/* change time */
	SBVAL(outbody, 0x28, requ_create.out_info.out_allocation_size);		/* allocation size */
	SBVAL(outbody, 0x30, requ_create.out_info.out_end_of_file);			/* end of file */
	SIVAL(outbody, 0x38, requ_create.out_info.out_file_attributes);		/* file attributes */
	SIVAL(outbody, 0x3C, 0);		/* reserved */
	SBVAL(outbody, 0x40, smbd_open->id);		/* file id (persistent) */
	SBVAL(outbody, 0x48, smbd_open->id);		/* file id (volatile) */
	SIVAL(outbody, 0x50, output.empty() ? 0 : 0x40 + X_SMB2_CREATE_RESP_BODY_LEN);	/* create contexts offset */
	SIVAL(outbody, 0x54, output.size());	/* create contexts length */

	memcpy(outbody + X_SMB2_CREATE_RESP_BODY_LEN, output.data(), output.size());
	x_smbd_conn_reply(smbd_conn, msg, smbd_sess, nullptr, outbuf, tid, status,
			X_SMB2_CREATE_RESP_BODY_LEN + output.size());
	return 0;
}

int x_smb2_process_CREATE(x_smbd_conn_t *smbd_conn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len)
{
	if (in_len < 0x40 + X_SMB2_CREATE_REQU_BODY_LEN + 1) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, 0,  NT_STATUS_INVALID_PARAMETER);
	}

	/* TODO check limit of open for both total and per conn*/
	const uint8_t *inhdr = in_buf;
	const uint8_t *inbody = in_buf + 0x40;

	uint64_t in_session_id = BVAL(inhdr, SMB2_HDR_SESSION_ID);
	uint32_t in_tid = IVAL(inhdr, SMB2_HDR_TID);
	if (in_session_id == 0) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, in_tid, NT_STATUS_USER_SESSION_DELETED);
	}
	x_auto_ref_t<x_smbd_sess_t> smbd_sess{x_smbd_sess_find(in_session_id, smbd_conn)};
	if (smbd_sess == nullptr) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, in_tid, NT_STATUS_USER_SESSION_DELETED);
	}
	if (smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, NT_STATUS_INVALID_PARAMETER);
	}
	/* TODO signing/encryption */

	auto it = smbd_sess->tcon_table.find(in_tid);
	if (it == smbd_sess->tcon_table.end()) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, NT_STATUS_NETWORK_NAME_DELETED);
	}
	std::shared_ptr<x_smbd_tcon_t> smbd_tcon = it->second;

	x_smb2_requ_create_t requ_create;
	requ_create.in_oplock_level         = CVAL(inbody, 0x03);
	requ_create.in_impersonation_level  = IVAL(inbody, 0x04);
	requ_create.in_desired_access       = IVAL(inbody, 0x18);
	requ_create.in_file_attributes      = IVAL(inbody, 0x1C);
	requ_create.in_share_access         = IVAL(inbody, 0x20);
	requ_create.in_create_disposition   = IVAL(inbody, 0x24);
	requ_create.in_create_options       = IVAL(inbody, 0x28);
	uint16_t in_name_offset          = SVAL(inbody, 0x2C);
	uint16_t in_name_length          = SVAL(inbody, 0x2E);
	uint32_t in_context_offset       = IVAL(inbody, 0x30);
	uint32_t in_context_length       = IVAL(inbody, 0x34);	

	if (in_name_length % 2 != 0 || !x_check_range(in_name_offset, in_name_length, 
				0x40 + X_SMB2_CREATE_REQU_BODY_LEN, in_len)) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, NT_STATUS_INVALID_PARAMETER);
	}

	if (!x_check_range(in_context_offset, in_context_length, 
				0x40 + X_SMB2_CREATE_REQU_BODY_LEN, in_len)) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, NT_STATUS_INVALID_PARAMETER);
	}

	requ_create.in_name.assign((char16_t *)(in_buf + in_name_offset),
			(char16_t *)(in_buf + in_name_offset + in_name_length)); 

	X_LOG_OP("%ld CREATE '%s'", msg->mid, x_convert_utf16_to_utf8(requ_create.in_name).c_str());
	NTSTATUS status;
	x_auto_ref_t<x_smbd_open_t> smbd_open{x_smbd_tcon_op_create(smbd_tcon,
			status, msg->hdr_flags, requ_create)};
	if (smbd_open) {
		x_smbd_open_insert_local(smbd_open);
		return x_smb2_reply_create(smbd_conn, smbd_sess, msg, status,
				smbd_tcon->tid, smbd_open,
				requ_create, std::vector<uint8_t>());
	}

	if (NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_BLOCKED)) {
		return 0;
	}

	return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, in_tid, status);
#if 0
	if (smbd_tcon->smbd_share->type == x_smbd_share_t::TYPE_IPC) {
		if (dhnc || dh2c) {
			return X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, NT_STATUS_OBJECT_NAME_NOT_FOUND);
		}
		status = x_smbd_open_np_file(smbd_open);
	} else {
		X_TODO;
	}

	smbd_tcon->opens.push_back(smbd_open);

	return -EBADMSG;
#endif
}
