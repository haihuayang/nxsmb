
#include "smbd.hxx"
#include "core.hxx"
#include "include/charset.hxx"


static std::shared_ptr<x_smbd_tcon_t> make_tcon(x_smbd_sess_t *smbd_sess,
		const std::shared_ptr<x_smbd_share_t> &smbd_share)
{
	auto smbd_tcon = std::make_shared<x_smbd_tcon_t>(smbd_share);
	std::lock_guard<std::mutex> lock(smbd_sess->mutex);
	while (true) {
		uint32_t id = smbd_sess->next_tcon_id++;
		if (id == 0) {
			continue;
		}
		if (smbd_sess->tcon_table.find(id) != smbd_sess->tcon_table.end()) {
			continue;
		}
		smbd_tcon->tid = id;
		smbd_sess->tcon_table[id] = smbd_tcon;
		return smbd_tcon;
	}
}

/*******************************************************************
 Can this user access with share with the required permissions ?
********************************************************************/

static uint32_t share_get_maximum_access(const std::shared_ptr<x_smbd_share_t> &share)
{
	return idl::SEC_RIGHTS_DIR_ALL;
}

/****************************************************************************
  Setup the share access mask for a connection.
****************************************************************************/

static uint32_t create_share_access_mask(const std::shared_ptr<x_smbd_share_t> &share,
		x_smbd_sess_t *smbd_sess)
{
	uint32_t share_access = share_get_maximum_access(share);

	if (share->read_only) {
		share_access &=
			~(idl::SEC_FILE_WRITE_DATA | idl::SEC_FILE_APPEND_DATA |
			  idl::SEC_FILE_WRITE_EA | idl::SEC_FILE_WRITE_ATTRIBUTE |
			  idl::SEC_DIR_DELETE_CHILD );
	}
#if 0
	if (security_token_has_privilege(token, SEC_PRIV_SECURITY)) {
		share_access |= SEC_FLAG_SYSTEM_SECURITY;
	}
	if (security_token_has_privilege(token, SEC_PRIV_RESTORE)) {
		share_access |= SEC_RIGHTS_PRIV_RESTORE;
	}
	if (security_token_has_privilege(token, SEC_PRIV_BACKUP)) {
		share_access |= SEC_RIGHTS_PRIV_BACKUP;
	}
	if (security_token_has_privilege(token, SEC_PRIV_TAKE_OWNERSHIP)) {
		share_access |= SEC_STD_WRITE_OWNER;
	}
#endif
	return share_access;
}
#if 0
/*******************************************************************
 Calculate access mask and if this user can access this share.
********************************************************************/

static NTSTATUS check_user_share_access(x_smbd_share_t *smbd_share,
		x_smbd_sess_t *smbd_sess)
				const struct auth_session_info *session_info,
				uint32_t *p_share_access,
				bool *p_readonly_share)
{
	uint32_t share_access = 0;
	bool readonly_share = false;

	if (!user_ok_token(session_info->unix_info->unix_name,
			   session_info->info->domain_name,
			   session_info->security_token, snum)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	readonly_share = is_share_read_only_for_token(
		session_info->unix_info->unix_name,
		session_info->info->domain_name,
		session_info->security_token,
		conn);

	share_access = create_share_access_mask(snum,
					readonly_share,
					session_info->security_token);

	if ((share_access & (FILE_READ_DATA|FILE_WRITE_DATA)) == 0) {
		/* No access, read or write. */
		DEBUG(3,("user %s connection to %s denied due to share "
			 "security descriptor.\n",
			 session_info->unix_info->unix_name,
			 lp_servicename(talloc_tos(), snum)));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!readonly_share &&
	    !(share_access & FILE_WRITE_DATA)) {
		/* smb.conf allows r/w, but the security descriptor denies
		 * write. Fall back to looking at readonly. */
		readonly_share = True;
		DEBUG(5,("falling back to read-only access-evaluation due to "
			 "security descriptor\n"));
	}

	*p_share_access = share_access;
	*p_readonly_share = readonly_share;

	return NT_STATUS_OK;
}
#endif

enum {
	X_SMB2_TCON_BODY_LEN = 0x8,
};

static int x_smb2_reply_tcon(x_smbd_conn_t *smbd_conn,
		x_smbd_sess_t *smbd_sess,
		x_msg_t *msg, NTSTATUS status,
		uint32_t tid,
		uint8_t out_share_type,
		uint32_t out_share_flags,
		uint32_t out_share_capabilities,
		uint32_t out_access_mask)
{
	uint8_t *outbuf = new uint8_t[8 + 0x40 + 0x10];
	uint8_t *outhdr = outbuf + 8;
	uint8_t *outbody = outhdr + 0x40;

	SSVAL(outbody, 0x00, 0x10);
	SCVAL(outbody, 0x02, out_share_type);
	SCVAL(outbody, 0x03, 0); // reserved
	SIVAL(outbody, 0x04, out_share_flags);
	SIVAL(outbody, 0x08, out_share_capabilities);
	SIVAL(outbody, 0x0c, out_access_mask);

	//smbd_smb2_request_setup_out
	memset(outhdr, 0, 0x40);
	SIVAL(outhdr, SMB2_HDR_PROTOCOL_ID,     SMB2_MAGIC);
	SSVAL(outhdr, SMB2_HDR_LENGTH,          SMB2_HDR_BODY);
	SSVAL(outhdr, SMB2_HDR_CREDIT_CHARGE, 1); // TODO
	SIVAL(outhdr, SMB2_HDR_STATUS, NT_STATUS_V(status));
	SIVAL(outhdr, SMB2_HDR_OPCODE, SMB2_OP_TCON);
	SSVAL(outhdr, SMB2_HDR_CREDIT, 1); // TODO
	SIVAL(outhdr, SMB2_HDR_FLAGS, SMB2_HDR_FLAG_REDIRECT); // TODO
	SIVAL(outhdr, SMB2_HDR_NEXT_COMMAND, 0);
	SBVAL(outhdr, SMB2_HDR_MESSAGE_ID, msg->mid);
	// SIVAL(outhdr, SMB2_HDR_PID, );
	SIVAL(outhdr, SMB2_HDR_TID, tid);
	SBVAL(outhdr, SMB2_HDR_SESSION_ID, smbd_sess->id);

	uint8_t *outnbt = outbuf + 4;
	x_put_be32(outnbt, 0x40 + 0x10);

	msg->out_buf = outbuf;
	msg->out_off = 4;
	msg->out_len = 4 + 0x40 + 0x10;

	msg->state = x_msg_t::STATE_COMPLETE;
	msg->do_signing = true; // TODO
	x_smbd_conn_reply(smbd_conn, msg, smbd_sess);
	return 0;
}

int x_smb2_process_TCON(x_smbd_conn_t *smbd_conn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len)
{
	if (in_len < 0x40 + 0x9) {
		return x_smb2_reply_error(smbd_conn, msg, nullptr, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *inhdr = in_buf;
	const uint8_t *inbody = in_buf + 0x40;
	uint64_t in_session_id = BVAL(inhdr, SMB2_HDR_SESSION_ID);

	if (in_session_id == 0) {
		return x_smb2_reply_error(smbd_conn, msg, nullptr, NT_STATUS_USER_SESSION_DELETED);
	}
	
	x_ref_t<x_smbd_sess_t> smbd_sess{x_smbd_sess_find(in_session_id, smbd_conn)};
	if (smbd_sess == nullptr) {
		return x_smb2_reply_error(smbd_conn, msg, nullptr, NT_STATUS_USER_SESSION_DELETED);
	}
	if (smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		return x_smb2_reply_error(smbd_conn, msg, smbd_sess, NT_STATUS_INVALID_PARAMETER);
	}
	/* TODO signing/encryption */

	uint16_t in_path_offset = SVAL(inbody, 0x04);
	uint16_t in_path_length = SVAL(inbody, 0x06);
	if (in_path_length % 2 != 0) {
		return x_smb2_reply_error(smbd_conn, msg, smbd_sess, NT_STATUS_INVALID_PARAMETER);
	}

	if (in_path_offset != (SMB2_HDR_BODY + X_SMB2_TCON_BODY_LEN)) {
		return x_smb2_reply_error(smbd_conn, msg, smbd_sess, NT_STATUS_INVALID_PARAMETER);
	}
	
	if (in_path_offset + in_path_length > in_len) {
		return x_smb2_reply_error(smbd_conn, msg, smbd_sess, NT_STATUS_INVALID_PARAMETER);
	}

	/* convert lower case utf8 */
	std::string in_path = x_convert_utf16_to_lower_utf8((char16_t *)(in_buf + in_path_offset),
			(char16_t *)(in_buf + in_path_offset + in_path_length));
	/* TODO fail with NT_STATUS_ILLEGAL_CHARACTER */

	// smbd_smb2_tree_connect
	const char *in_path_s = in_path.c_str();
	if (strncmp(in_path_s, "\\\\", 2) == 0) {
		in_path_s += 2;
	}
	const char *in_share_s = strchr(in_path_s, '\\');
	if (!in_share_s) {
		return x_smb2_reply_error(smbd_conn, msg, smbd_sess, NT_STATUS_INVALID_PARAMETER);
	}

	std::string host{in_path_s, in_share_s};
	std::string share{in_share_s + 1};

	auto smbd_share = x_smbd_share_find(share);
	if (!smbd_share) {
		return x_smb2_reply_error(smbd_conn, msg, smbd_sess, NT_STATUS_BAD_NETWORK_NAME);
	}

	uint32_t share_access = create_share_access_mask(smbd_share,
			smbd_sess);

	if ((share_access & (idl::SEC_FILE_READ_DATA|idl::SEC_FILE_WRITE_DATA)) == 0) {
		/* No access, read or write. */
		DEBUG(3,("user %s connection to %s denied due to share "
			 "security descriptor.\n",
			 session_info->unix_info->unix_name,
			 lp_servicename(talloc_tos(), snum)));
		return x_smb2_reply_error(smbd_conn, msg, smbd_sess, NT_STATUS_ACCESS_DENIED);
	}

	auto smbd_tcon = make_tcon(smbd_sess, smbd_share);
	smbd_tcon->share_access = share_access;

	uint32_t out_share_flags = 0;
	uint32_t out_capabilities = 0;
#if 0
	if (lp_msdfs_root(SNUM(tcon->compat)) && lp_host_msdfs()) {
		out_share_flags |= (SMB2_SHAREFLAG_DFS|SMB2_SHAREFLAG_DFS_ROOT);
		out_capabilities = SMB2_SHARE_CAP_DFS;
	} else {
		out_capabilities = 0;
	}

	switch(lp_csc_policy(SNUM(tcon->compat))) {
		case CSC_POLICY_MANUAL:
			break;
		case CSC_POLICY_DOCUMENTS:
			*out_share_flags |= SMB2_SHAREFLAG_AUTO_CACHING;
			break;
		case CSC_POLICY_PROGRAMS:
			*out_share_flags |= SMB2_SHAREFLAG_VDO_CACHING;
			break;
		case CSC_POLICY_DISABLE:
			*out_share_flags |= SMB2_SHAREFLAG_NO_CACHING;
			break;
		default:
			break;
	}
	if (lp_hide_unreadable(SNUM(tcon->compat)) ||
			lp_hide_unwriteable_files(SNUM(tcon->compat))) {
		*out_share_flags |= SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM;
	}

	if (encryption_desired) {
		*out_share_flags |= SMB2_SHAREFLAG_ENCRYPT_DATA;
	}

#endif

	/* make_connection_snum *out_maximal_access = tcon->compat->share_access; */

	return x_smb2_reply_tcon(smbd_conn, smbd_sess, msg, NT_STATUS_OK,
			smbd_tcon->tid,
			smbd_share->type == x_smbd_share_t::TYPE_IPC ? SMB2_SHARE_TYPE_PIPE : SMB2_SHARE_TYPE_DISK,
			out_share_flags,
			out_capabilities, share_access);

	return 0;
}

