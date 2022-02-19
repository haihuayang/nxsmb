#include "smbd.hxx"
#include "core.hxx"
#include "misc.hxx"
#include "smbd_ntacl.hxx"

enum {
	X_SMB2_SESSSETUP_REQU_BODY_LEN = 0x18,
	X_SMB2_SESSSETUP_RESP_BODY_LEN = 0x08,
};

enum {
	SESSSETUP_TIMEOUT = 60 * 1000000000l,
};

static void x_smb2_reply_sesssetup(x_smbd_conn_t *smbd_conn,
		x_smbd_sess_t *smbd_sess,
		x_smb2_preauth_t *preauth,
		x_smbd_requ_t *smbd_requ, NTSTATUS status,
		const std::vector<uint8_t> &out_security)
{
	x_bufref_t *bufref = x_bufref_alloc(X_SMB2_SESSSETUP_RESP_BODY_LEN +
			out_security.size());
	uint8_t *out_hdr = bufref->get_data();
	uint8_t *out_body = out_hdr + SMB2_HDR_BODY;

	uint16_t out_session_flags = 0; // TODO
	uint16_t out_security_offset = SMB2_HDR_BODY + 0x08;
	x_put_le16(out_body, 0x08 + 1);
	x_put_le16(out_body + 0x02, out_session_flags);
	x_put_le16(out_body + 0x04, out_security_offset);
	x_put_le16(out_body + 0x06, out_security.size());

	memcpy(out_body + X_SMB2_SESSSETUP_RESP_BODY_LEN, out_security.data(), out_security.size());

	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, status, 
			SMB2_HDR_BODY + X_SMB2_SESSSETUP_RESP_BODY_LEN + out_security.size());

	if (preauth) {
		preauth->update(out_hdr, SMB2_HDR_BODY + X_SMB2_SESSSETUP_RESP_BODY_LEN + out_security.size());
	}
}

static constexpr x_array_const_t<char> SMB2_24_signing_label{"SMB2AESCMAC"};
static constexpr x_array_const_t<char> SMB2_24_signing_context{"SmbSign"};
static constexpr x_array_const_t<char> SMB2_24_decryption_label{"SMB2AESCCM"};
static constexpr x_array_const_t<char> SMB2_24_decryption_context{"ServerIn "};
static constexpr x_array_const_t<char> SMB2_24_encryption_label{"SMB2AESCCM"};
static constexpr x_array_const_t<char> SMB2_24_encryption_context{"ServerOut "};
static constexpr x_array_const_t<char> SMB2_24_application_label{"SMB2APP"};
static constexpr x_array_const_t<char> SMB2_24_application_context{"SmbRpc"};

static constexpr x_array_const_t<char> SMB3_10_signing_label{"SMBSigningKey"};
static constexpr x_array_const_t<char> SMB3_10_decryption_label{"SMBC2SCipherKey"};
static constexpr x_array_const_t<char> SMB3_10_encryption_label{"SMBS2CCipherKey"};
static constexpr x_array_const_t<char> SMB3_10_application_label{"SMBAppKey"};

static std::ostream &operator<<(std::ostream &os, const x_auth_info_t &auth_info)
{
	os << "user_flags: " << auth_info.user_flags
		<< ", acct_flags: " << auth_info.acct_flags << std::endl;
	os << "account_name: \"" << auth_info.account_name << "\"" << std::endl;
	os << "user_principal: \"" << auth_info.user_principal << "\"" << std::endl;
	os << "full_name: \"" << auth_info.full_name << "\"" << std::endl;
	os << "logon_domain: \"" << auth_info.logon_domain << "\"" << std::endl;
	os << "dns_domain_name: \"" << auth_info.dns_domain_name << "\"" << std::endl;
	os << "logon_server: \"" << auth_info.logon_server << "\"" << std::endl;
	os << "logon_script: \"" << auth_info.logon_script << "\"" << std::endl;
	os << "profile_path: \"" << auth_info.profile_path << "\"" << std::endl;
	os << "home_directory: \"" << auth_info.home_directory << "\"" << std::endl;
	os << "home_drive: \"" << auth_info.home_drive << "\"" << std::endl;
	os << "logon_time: " << auth_info.logon_time << std::endl;
	os << "logoff_time: " << auth_info.logoff_time << std::endl;
	os << "kickoff_time: " << auth_info.kickoff_time << std::endl;
	os << "pass_last_set_time: " << auth_info.pass_last_set_time << std::endl;
	os << "pass_can_change_time: " << auth_info.pass_can_change_time << std::endl;
	os << "pass_must_change_time: " << auth_info.pass_must_change_time << std::endl;
	os << "primary_sid: " << auth_info.domain_sid << ", " << auth_info.rid << ", " << auth_info.primary_gid << std::endl;
	uint32_t i = 0;
	for (const auto &group_rid: auth_info.group_rids) {
		os << "\t#" << i << ": " << group_rid.rid << " " << group_rid.attributes << std::endl;
		++i;
	}

	i = 0;
	for (const auto &other_sid: auth_info.other_sids) {
		char buf[32];
		snprintf(buf, sizeof buf, "0x%x", other_sid.attrs);
		os << "\t#" << i << ": " << other_sid.sid << ", " << buf << std::endl;
		++i;
	}

	return os;
}

// smbd_smb2_auth_generic_return
static void smbd_sess_auth_succeeded(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess,
		const x_auth_info_t &auth_info)
{
	X_LOG_DBG("auth_info %s", tostr(auth_info).c_str());
	X_ASSERT(auth_info.domain_sid.num_auths < auth_info.domain_sid.sub_auths.size());
	
	/* TODO find_user by auth_info
	sort auth_info sids ..., create unique hash value 
	static void find_user(x_auth_info_t &auth_info)
	{

	}

	finalize_local_nt_token
	add_local_groups

	??? how group_mapping.tdb is generated
	add group aliases sush global_sid_Builtin_Administrators, global_sid_Builtin_Users,
	global_sid_Builtin_Backup_Operators

	*/
	/* TODO set user token ... */


	auto smbd_user = std::make_shared<x_smbd_user_t>();
	smbd_user->domain_sid = auth_info.domain_sid;
	smbd_user->uid = auth_info.rid;
	smbd_user->gid = auth_info.primary_gid;
	smbd_user->group_rids = auth_info.group_rids;
	smbd_user->other_sids = auth_info.other_sids;
	smbd_sess->smbd_user = smbd_user;

	const x_array_const_t<char> *derivation_sign_label, *derivation_sign_context,
	      *derivation_encryption_label, *derivation_encryption_context,
	      *derivation_decryption_label, *derivation_decryption_context,
	      *derivation_application_label, *derivation_application_context;

	const x_array_const_t<char> smb3_context{smbd_sess->preauth.data};
	if (smbd_conn->dialect >= SMB3_DIALECT_REVISION_310) {
		derivation_sign_label = &SMB3_10_signing_label;
		derivation_sign_context = &smb3_context;
		derivation_encryption_label = &SMB3_10_encryption_label;
		derivation_encryption_context = &smb3_context;
		derivation_decryption_label = &SMB3_10_decryption_label;
		derivation_decryption_context = &smb3_context;
		derivation_application_label = &SMB3_10_application_label;
		derivation_application_context = &smb3_context;

	} else if (smbd_conn->dialect >= SMB2_DIALECT_REVISION_224) {
		derivation_sign_label = &SMB2_24_signing_label;
		derivation_sign_context = &SMB2_24_signing_context;
		derivation_encryption_label = &SMB2_24_encryption_label;
		derivation_encryption_context = &SMB2_24_encryption_context;
		derivation_decryption_label = &SMB2_24_decryption_label;
		derivation_decryption_context = &SMB2_24_decryption_context;
		derivation_application_label = &SMB2_24_application_label;
		derivation_application_context = &SMB2_24_application_context;
	}

	std::array<uint8_t, 16> session_key;
	memcpy(session_key.data(), auth_info.session_key.data(), std::min(session_key.size(), auth_info.session_key.size()));
	if (smbd_conn->dialect >= SMB2_DIALECT_REVISION_224) {
		x_smb2_key_derivation(session_key.data(), 16,
				*derivation_sign_label,
				*derivation_sign_context,
				smbd_sess->signing_key);
		x_smb2_key_derivation(session_key.data(), 16,
				*derivation_decryption_label,
				*derivation_decryption_context,
				smbd_sess->decryption_key);
		x_smb2_key_derivation(session_key.data(), 16,
				*derivation_encryption_label,
				*derivation_encryption_context,
				smbd_sess->encryption_key);
		/* TODO encryption nonce */
		x_smb2_key_derivation(session_key.data(), 16,
				*derivation_application_label,
				*derivation_application_context,
				smbd_sess->application_key);
	} else {
		smbd_sess->signing_key = session_key;
	}
}

static inline NTSTATUS x_smbd_sess_update_auth(x_smbd_sess_t *smbd_sess, const uint8_t *inbuf, size_t inlen,
		std::vector<uint8_t> &outbuf, std::shared_ptr<x_auth_info_t>& auth_info)
{
	smbd_sess->incref(); // hold ref for auth_upcall
	return smbd_sess->auth->update(inbuf, inlen, outbuf, &smbd_sess->auth_upcall, auth_info);
}

static void smbd_sess_auth_updated(x_smbd_sess_t *smbd_sess, x_smbd_requ_t *smbd_requ,
		NTSTATUS status,
		std::vector<uint8_t> &out_security, std::shared_ptr<x_auth_info_t> &auth_info)
{
	X_LOG_OP("%ld RESP 0x%x", smbd_requ->in_mid, status.v);

	x_smbd_conn_t *smbd_conn = smbd_sess->smbd_conn;
	if (NT_STATUS_IS_OK(status)) {
		smbd_sess->state = x_smbd_sess_t::S_ACTIVE;
		smbd_conn->session_list.push_back(smbd_sess);
		smbd_sess_auth_succeeded(smbd_conn, smbd_sess, *auth_info);
		smbd_requ->out_hdr_flags |= SMB2_HDR_FLAG_SIGNED;
		smbd_requ->smbd_sess = smbd_sess;
		x_smb2_reply_sesssetup(smbd_conn, smbd_sess, NULL, smbd_requ, status, out_security);
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		smbd_sess->state = x_smbd_sess_t::S_WAIT_INPUT;
		smbd_sess->timeout = x_tick_add(tick_now, SESSSETUP_TIMEOUT);
		smbd_conn->session_wait_input_list.push_back(smbd_sess);
		smbd_requ->smbd_sess = smbd_sess;
		x_smb2_reply_sesssetup(smbd_conn, smbd_sess,
				smbd_conn->dialect >= SMB3_DIALECT_REVISION_310 ? &smbd_sess->preauth : nullptr,
				smbd_requ, status, out_security);
	} else {
#if 0
		X_SMB2_REPLY_ERROR(smbd_conn, smbd_requ, smbd_sess, 0, status);
		/* release the session */
		x_smbd_sess_release(smbd_sess);
		smbd_sess->decref();
#endif
	}
}

struct smbd_sess_auth_updated_evt_t
{
	x_fdevt_user_t base;
	x_smbd_sess_t *smbd_sess;
	NTSTATUS status;
	std::vector<uint8_t> out_security;
	std::shared_ptr<x_auth_info_t> auth_info;
};

static void smbd_sess_auth_updated_func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool cancelled)
{
	smbd_sess_auth_updated_evt_t *evt = X_CONTAINER_OF(fdevt_user, smbd_sess_auth_updated_evt_t, base);

	X_ASSERT(!NT_STATUS_EQUAL(evt->status, X_NT_STATUS_INTERNAL_BLOCKED));
	x_smbd_sess_t *smbd_sess = evt->smbd_sess;

	if (!cancelled && smbd_sess->state == x_smbd_sess_t::S_BLOCKED) {
		smbd_conn->session_list.remove(smbd_sess);
		x_auto_ref_t<x_smbd_requ_t> smbd_requ{std::move(smbd_sess->authmsg)};
		smbd_sess_auth_updated(smbd_sess, smbd_requ, evt->status, evt->out_security, evt->auth_info);
		x_smbd_conn_requ_done(smbd_conn, smbd_requ, evt->status);
	}

	smbd_sess->decref();
	delete evt;
}

static void x_smbd_sess_auth_updated(x_auth_upcall_t *auth_upcall, NTSTATUS status,
		std::vector<uint8_t> &out_security, std::shared_ptr<x_auth_info_t> &auth_info)
{
	x_smbd_sess_t *smbd_sess = X_CONTAINER_OF(auth_upcall, x_smbd_sess_t, auth_upcall);
	X_LOG_DBG("smbd_sess=%p, status=0x%x", smbd_sess, NT_STATUS_V(status));
	smbd_sess_auth_updated_evt_t *updated_evt = new smbd_sess_auth_updated_evt_t;
	updated_evt->base.func = smbd_sess_auth_updated_func;
	updated_evt->smbd_sess = smbd_sess;
	updated_evt->status = status;
	std::swap(updated_evt->out_security, out_security);
	updated_evt->auth_info = auth_info;
	x_smbd_conn_post_user(smbd_sess->smbd_conn, &updated_evt->base);
}

static const struct x_auth_cbs_t smbd_sess_auth_upcall_cbs = {
	x_smbd_sess_auth_updated,
};

NTSTATUS x_smb2_process_SESSSETUP(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_LOG_OP("%ld SESSSETUP 0x%lx, 0x%lx", smbd_requ->in_mid);

	if (smbd_requ->in_requ_len < SMB2_HDR_BODY + X_SMB2_SESSSETUP_REQU_BODY_LEN + 1) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = smbd_requ->get_in_data();
	const uint8_t *in_body = in_hdr + SMB2_HDR_BODY;
	// uint64_t in_session_id = BVAL(inhdr, SMB2_HDR_SESSION_ID);
	uint8_t in_flags = CVAL(in_body, 0x02);
	// uint8_t in_security_mode = CVAL(in_body, 0x03);
	uint16_t in_security_offset = SVAL(in_body, 0x0C);
	uint16_t in_security_length = SVAL(in_body, 0x0E);
	// TODO uint64_t in_previous_session_id = BVAL(in_body, 0x10);

	if (!x_check_range<uint32_t>(in_security_offset, in_security_length, SMB2_HDR_BODY + X_SMB2_SESSSETUP_REQU_BODY_LEN, smbd_requ->in_requ_len)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}
	
	if (in_flags & SMB2_SESSION_FLAG_BINDING) {
		if (smbd_conn->dialect < SMB2_DIALECT_REVISION_222) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_REQUEST_NOT_ACCEPTED);
		}
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_NOT_SUPPORTED);
	}

	x_smbd_sess_t *smbd_sess = smbd_requ->smbd_sess;
	if (!smbd_sess) {
		smbd_sess = x_smbd_sess_create(smbd_conn);
		/* TODO too many session */
		smbd_sess->auth = x_smbd_create_auth(smbd_conn->smbd);
		smbd_sess->auth_upcall.cbs = &smbd_sess_auth_upcall_cbs;
		if (smbd_conn->dialect >= SMB3_DIALECT_REVISION_310) {
			smbd_sess->preauth = smbd_conn->preauth;
		}

	} else {
		if (smbd_sess->state != x_smbd_sess_t::S_WAIT_INPUT) {
			smbd_sess->decref();
			/* TODO just drop the message, should we reply something for this unexpected message */
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
		}
		smbd_sess->decref();
		smbd_conn->session_wait_input_list.remove(smbd_sess);
	}

	if (smbd_conn->dialect >= SMB3_DIALECT_REVISION_310) {
		smbd_sess->preauth.update(in_hdr, smbd_requ->in_requ_len);
	}

	X_ASSERT(smbd_sess->authmsg == nullptr);
	std::vector<uint8_t> out_security;
	std::shared_ptr<x_auth_info_t> auth_info;
	NTSTATUS status = x_smbd_sess_update_auth(smbd_sess, in_hdr + in_security_offset, in_security_length, out_security, auth_info);
	X_LOG_DBG("smbd_sess=%p, smbd_requ=%p, status=0x%x", smbd_sess, smbd_requ, NT_STATUS_V(status));

	if (!NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_BLOCKED)) {
		smbd_sess_auth_updated(smbd_sess, smbd_requ, status, out_security, auth_info);
	} else {
		smbd_sess->state = x_smbd_sess_t::S_BLOCKED;
		smbd_requ->incref();
		smbd_sess->authmsg.set(smbd_requ);
		smbd_sess->incref();
		smbd_conn->session_list.push_back(smbd_sess);
	}
	smbd_sess->decref(); // release create or find
	return status;
}

