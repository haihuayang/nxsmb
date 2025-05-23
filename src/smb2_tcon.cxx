
#include "smbd.hxx"
#include "include/charset.hxx"
#include "smbd_share.hxx"
#include "smbd_conf.hxx"
#include "smbd_requ.hxx"


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
	x_ref_inc(smbd_tcon);
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
		x_smbd_sess_t *smbd_sess, x_smbd_chan_t *smbd_chan)
{
	uint32_t share_access = share_get_maximum_access(share);

	if (share->is_read_only()) {
		share_access &=
			~(idl::SEC_FILE_WRITE_DATA | idl::SEC_FILE_APPEND_DATA |
			  idl::SEC_FILE_WRITE_EA | idl::SEC_FILE_WRITE_ATTRIBUTE |
			  idl::SEC_DIR_DELETE_CHILD );
	}
	auto smbd_user = x_smbd_sess_get_user(smbd_sess);
	if (smbd_user->priviledge_mask & idl::SEC_PRIV_SECURITY_BIT) {
		share_access |= idl::SEC_FLAG_SYSTEM_SECURITY;
	}
	if (smbd_user->priviledge_mask & idl::SEC_PRIV_RESTORE_BIT) {
		share_access |= idl::SEC_RIGHTS_PRIV_RESTORE;
	}
	if (smbd_user->priviledge_mask & idl::SEC_PRIV_BACKUP_BIT) {
		share_access |= idl::SEC_RIGHTS_PRIV_BACKUP;
	}
	if (smbd_user->priviledge_mask & idl::SEC_PRIV_TAKE_OWNERSHIP_BIT) {
		share_access |= idl::SEC_STD_WRITE_OWNER;
	}

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

static void x_smb2_reply_tcon(
		x_smbd_tcon_t *smbd_tcon,
		x_smbd_requ_t *smbd_requ, NTSTATUS status,
		uint8_t out_share_type,
		uint32_t out_share_flags,
		uint32_t out_share_capabilities,
		uint32_t out_access_mask)
{
	X_SMBD_REQU_LOG(OP, smbd_requ,  " tid=%x", x_smbd_tcon_get_id(smbd_tcon));

	auto &out_buf = smbd_requ->get_requ_out_buf();
	out_buf.head = out_buf.tail = x_smb2_bufref_alloc(sizeof(x_smb2_tcon_resp_t));
	out_buf.length = out_buf.head->length;

	uint8_t *out_hdr = out_buf.head->get_data();
	auto out_resp = (x_smb2_tcon_resp_t *)(out_hdr + sizeof(x_smb2_header_t));

	out_resp->struct_size = X_H2LE16(sizeof(x_smb2_tcon_resp_t));
	out_resp->share_type = X_H2LE8(out_share_type);
	out_resp->unused0 = 0;
	out_resp->share_flags = X_H2LE32(out_share_flags);
	out_resp->share_capabilities = X_H2LE32(out_share_capabilities);
	out_resp->access_mask = X_H2LE32(out_access_mask);
}

struct x_smbd_requ_tcon_t : x_smbd_requ_t
{
	x_smbd_requ_tcon_t(x_smbd_conn_t *smbd_conn,
			std::shared_ptr<x_smbd_share_t> &smbd_share,
			std::shared_ptr<x_smbd_volume_t> &smbd_volume)
		: x_smbd_requ_t(smbd_conn)
		, smbd_share(std::move(smbd_share))
		, smbd_volume(std::move(smbd_volume))
	{
	}
	std::tuple<bool, bool, bool> get_properties() const override
	{
		return { true, false, false };
	}
	NTSTATUS process(void *ctx_conn) override;
	NTSTATUS done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status) override;

	std::shared_ptr<x_smbd_share_t> smbd_share;
	std::shared_ptr<x_smbd_volume_t> smbd_volume;
	uint32_t out_share_flags = 0;
	uint32_t out_capabilities = 0;
	uint32_t out_share_access = 0;
};

NTSTATUS x_smbd_requ_tcon_t::process(void *ctx_conn)
{
	X_ASSERT(this->smbd_chan && this->smbd_sess);

	bool is_dfs = false;
	if (smbd_share->is_dfs()) {
		is_dfs = true;
#if 0
	} else if (!smbd_volume) {
		X_SMBD_REQU_RETURN_STATUS(smbd_requ, NT_STATUS_BAD_NETWORK_NAME);
#endif
	}

	uint32_t share_access = create_share_access_mask(smbd_share,
			this->smbd_sess, this->smbd_chan);

	if ((share_access & (idl::SEC_FILE_READ_DATA|idl::SEC_FILE_WRITE_DATA)) == 0) {
		/* No access, read or write. */
		DEBUG(3,("user %s connection to %s denied due to share "
			 "security descriptor.\n",
			 session_info->unix_info->unix_name,
			 lp_servicename(talloc_tos(), snum)));
		X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_ACCESS_DENIED);
	}

	auto smbd_tcon = x_smbd_tcon_create(this->smbd_sess, smbd_share,
			std::move(smbd_volume), share_access);
	if (!smbd_tcon) {
		X_SMBD_REQU_RETURN_STATUS(this, NT_STATUS_INSUFFICIENT_RESOURCES);
	}

	/* TODO or dfs's root volume */
	if (is_dfs && !smbd_volume) {
		out_share_flags |= X_SMB2_SHAREFLAG_DFS|X_SMB2_SHAREFLAG_DFS_ROOT;
		out_capabilities |= X_SMB2_SHARE_CAP_DFS;
	}
	if (smbd_share->abe_enabled()) {
		out_share_flags |= X_SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM;
	}
#if 0
	if (smbshare->type != TYPE_IPC) {
		out_capabilities |= X_SMB2_SHARE_CAP_SCALEOUT | X_SMB2_SHARE_CAP_CLUSTER;
	}
	switch(lp_csc_policy(SNUM(tcon->compat))) {
		case CSC_POLICY_MANUAL:
			break;
		case CSC_POLICY_DOCUMENTS:
			*out_share_flags |= X_SMB2_SHAREFLAG_AUTO_CACHING;
			break;
		case CSC_POLICY_PROGRAMS:
			*out_share_flags |= X_SMB2_SHAREFLAG_VDO_CACHING;
			break;
		case CSC_POLICY_DISABLE:
			*out_share_flags |= X_SMB2_SHAREFLAG_NO_CACHING;
			break;
		default:
			break;
	}
	if (lp_hide_unreadable(SNUM(tcon->compat)) ||
			lp_hide_unwriteable_files(SNUM(tcon->compat))) {
		*out_share_flags |= X_SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM;
	}

	if (encryption_desired) {
		*out_share_flags |= X_SMB2_SHAREFLAG_ENCRYPT_DATA;
	}

#endif

	/* make_connection_snum *out_maximal_access = tcon->compat->share_access; */

	out_share_access = share_access;
	this->smbd_tcon = x_ref_inc(smbd_tcon);
	return NT_STATUS_OK;
}

NTSTATUS x_smbd_requ_tcon_t::done_smb2(x_smbd_conn_t *smbd_conn, NTSTATUS status)
{
	if (status.ok()) {
		x_smb2_reply_tcon(smbd_tcon, this, NT_STATUS_OK,
				smbd_share->get_type(),
				out_share_flags,
				out_capabilities, out_share_access);
	}
	return status;
}

NTSTATUS x_smb2_parse_TCON(x_smbd_conn_t *smbd_conn, x_smbd_requ_t **p_smbd_requ,
		x_in_buf_t &in_buf)
{
	auto in_smb2_hdr = (const x_smb2_header_t *)(in_buf.get_data());

	if (in_buf.length < sizeof(x_smb2_header_t) + sizeof(x_smb2_tcon_requ_t) + 1) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	auto in_body = (const x_smb2_tcon_requ_t *)(in_smb2_hdr + 1);

	/* TODO signing/encryption */

	uint16_t in_path_offset = X_LE2H16(in_body->path_offset);
	uint16_t in_path_length = X_LE2H16(in_body->path_length);
	if (in_path_length % 2 != 0) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	if (!x_check_range<uint32_t>(in_path_offset, in_path_length, sizeof(x_smb2_header_t) + sizeof(x_smb2_tcon_requ_t), in_buf.length)) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	auto in_path_ptr = (const uint8_t *)in_smb2_hdr + in_path_offset;
	auto in_path = x_utf16le_decode((const char16_t *)in_path_ptr,
			(const char16_t *)(in_path_ptr + in_path_length));
	auto in_path_s = in_path.data();
	auto in_path_e = in_path_s + in_path.length();
	if (in_path[0] == u'\\' && in_path[1] == u'\\') {
		in_path_s += 2;
	}

	auto in_share_s = std::find(in_path_s, in_path_e, u'\\');
	if (in_share_s == in_path_e) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_INVALID_PARAMETER);
	}

	++in_share_s;

	// X_SMBD_REQU_LOG(OP, this,  " '%s'", x_str_todebug(in_path_s, in_path_e).c_str());

	auto [smbd_share, smbd_volume] = x_smbd_resolve_share(in_share_s, in_path_e);
	if (!smbd_share) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_BAD_NETWORK_NAME);
	}

	if (smbd_share->smb_encrypt == x_smbd_feature_option_t::required &&
			x_smbd_conn_get_negprot(smbd_conn).cryption_algo == X_SMB2_ENCRYPTION_INVALID_ALGO) {
		X_SMBD_SMB2_RETURN_STATUS(in_smb2_hdr, NT_STATUS_ACCESS_DENIED);
	}

	auto requ = new x_smbd_requ_tcon_t(smbd_conn, smbd_share, smbd_volume);
	*p_smbd_requ = requ;
	return NT_STATUS_OK;
}

