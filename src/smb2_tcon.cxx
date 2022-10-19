
#include "smbd.hxx"
#include "include/charset.hxx"
#include "smbd_share.hxx"
#include "smbd_conf.hxx"

struct x_smb2_tcon_requ_t
{
	uint16_t struct_size;
	uint16_t flags;
	uint16_t path_offset;
	uint16_t path_length;
};

struct x_smb2_tcon_resp_t
{
	uint16_t struct_size;
	uint8_t share_type;
	uint8_t unused0;
	uint32_t share_flags;
	uint32_t share_capabilities;
	uint32_t access_mask;
};


#if 0
static x_smbd_tcon_t *make_tcon(x_smbd_sess_t *smbd_sess,
		const std::shared_ptr<x_smbd_share_t> &smbshare)
{
	auto smbd_tcon = new x_smbd_tcon_t(smbd_sess, smbshare);
	if (smbshare->type == TYPE_IPC) {
		x_smbd_tcon_init_ipc(smbd_tcon);
	} else {
		x_smbd_tcon_init_posixfs(smbd_tcon);
	}

	x_smbd_tcon_insert(smbd_tcon);
	x_smbd_ref_inc(smbd_tcon);
	x_smbd_sess_link_tcon(smbd_sess, &smbd_tcon->sess_link);
	return smbd_tcon;
}
#endif
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
		x_smbd_chan_t *smbd_chan)
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

static void x_smb2_reply_tcon(x_smbd_conn_t *smbd_conn,
		x_smbd_tcon_t *smbd_tcon,
		x_smbd_requ_t *smbd_requ, NTSTATUS status,
		uint8_t out_share_type,
		uint32_t out_share_flags,
		uint32_t out_share_capabilities,
		uint32_t out_access_mask)
{
	X_LOG_OP("%ld RESP SUCCESS tid=%x", smbd_requ->in_smb2_hdr.mid, x_smbd_tcon_get_id(smbd_tcon));
	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_tcon_resp_t));

	uint8_t *out_hdr = bufref->get_data();
	x_smb2_tcon_resp_t *out_resp = (x_smb2_tcon_resp_t *)(out_hdr + SMB2_HDR_BODY);

	out_resp->struct_size = X_H2LE16(sizeof(x_smb2_tcon_resp_t));
	out_resp->share_type = X_H2LE8(out_share_type);
	out_resp->unused0 = 0;
	out_resp->share_flags = X_H2LE32(out_share_flags);
	out_resp->share_capabilities = X_H2LE32(out_share_capabilities);
	out_resp->access_mask = X_H2LE32(out_access_mask);

	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, status, 
			SMB2_HDR_BODY + sizeof(x_smb2_tcon_resp_t));
}

NTSTATUS x_smb2_process_tcon(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_LOG_OP("%ld TCON", smbd_requ->in_smb2_hdr.mid);
	X_ASSERT(smbd_requ->smbd_chan && smbd_requ->smbd_sess);

	if (smbd_requ->in_requ_len < SMB2_HDR_BODY + sizeof(x_smb2_tcon_requ_t) + 1) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = smbd_requ->get_in_data();
	const x_smb2_tcon_requ_t *in_requ = (const x_smb2_tcon_requ_t *)(in_hdr + SMB2_HDR_BODY);

	/* TODO signing/encryption */

	uint16_t in_path_offset = X_LE2H16(in_requ->path_offset);
	uint16_t in_path_length = X_LE2H16(in_requ->path_length);
	if (in_path_length % 2 != 0) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	if (!x_check_range<uint32_t>(in_path_offset, in_path_length, SMB2_HDR_BODY + sizeof(x_smb2_tcon_requ_t), smbd_requ->in_requ_len)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	/* convert lower case utf8 */
	std::string in_path = x_convert_utf16_to_lower_utf8((char16_t *)(in_hdr + in_path_offset),
			(char16_t *)(in_hdr + in_path_offset + in_path_length));
	/* TODO fail with NT_STATUS_ILLEGAL_CHARACTER */

	// smbd_smb2_tree_connect
	const char *in_path_s = in_path.c_str();
	if (strncmp(in_path_s, "\\\\", 2) == 0) {
		in_path_s += 2;
	}
	const char *in_share_s = strchr(in_path_s, '\\');
	if (!in_share_s) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	std::string host{in_path_s, in_share_s};
	++in_share_s;

	std::string share{in_share_s};

	X_LOG_OP("%ld TCON %s", smbd_requ->in_smb2_hdr.mid, in_path.c_str());

	std::string volume;
	auto smbd_share = x_smbd_find_share(share, volume);
	if (!smbd_share) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_BAD_NETWORK_NAME);
	}

	bool is_dfs = false;
	if (smbd_share->is_dfs()) {
		is_dfs = true;
	} else if (volume.size()) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_BAD_NETWORK_NAME);
	}

	uint32_t share_access = create_share_access_mask(smbd_share,
			smbd_requ->smbd_chan);

	if ((share_access & (idl::SEC_FILE_READ_DATA|idl::SEC_FILE_WRITE_DATA)) == 0) {
		/* No access, read or write. */
		DEBUG(3,("user %s connection to %s denied due to share "
			 "security descriptor.\n",
			 session_info->unix_info->unix_name,
			 lp_servicename(talloc_tos(), snum)));
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_ACCESS_DENIED);
	}

	auto smbd_tcon = x_smbd_tcon_create(smbd_requ->smbd_sess, smbd_share, volume, share_access);
	if (!smbd_tcon) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INSUFFICIENT_RESOURCES);
	}

	uint32_t out_share_flags = 0;
	uint32_t out_capabilities = 0;
	if (is_dfs && (volume.size() == 0 || volume == "-")) {
		out_share_flags |= SMB2_SHAREFLAG_DFS|SMB2_SHAREFLAG_DFS_ROOT;
		out_capabilities |= SMB2_SHARE_CAP_DFS;
	}
	if (smbd_share->abe_enabled()) {
		out_share_flags |= SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM;
	}
#if 0
	if (smbshare->type != TYPE_IPC) {
		out_capabilities |= SMB2_SHARE_CAP_SCALEOUT | SMB2_SHARE_CAP_CLUSTER;
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

	smbd_requ->smbd_tcon = x_smbd_ref_inc(smbd_tcon);
	x_smb2_reply_tcon(smbd_conn, smbd_tcon, smbd_requ, NT_STATUS_OK,
			smbd_share->get_type(),
			out_share_flags,
			out_capabilities, share_access);
	return NT_STATUS_OK;
}

