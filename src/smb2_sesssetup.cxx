#include "smbd.hxx"
#include "core.hxx"
#include "misc.hxx"

enum {
	X_SMB2_SESSSETUP_BODY_LEN = 0x18,
};

enum {
	SESSSETUP_TIMEOUT = 60 * 1000000000l,
};

static int x_smb2_reply_sesssetup(x_smbd_conn_t *smbd_conn,
		x_smbd_sess_t *smbd_sess,
		x_smb2_preauth_t *preauth,
		x_msg_t *msg, NTSTATUS status,
		const std::vector<uint8_t> &out_security)
{
#if 0
	const x_smbsrv_t *smbsrv = smbd_conn->smbsrv;
	const x_smbconf_t &conf = smbd_conn->get_conf();
	nttime_t now = nttime_current();
#endif
	uint8_t *outbuf = new uint8_t[8 + 0x40 + 0x8 + out_security.size()];
	uint8_t *outhdr = outbuf + 8;
	uint8_t *outbody = outhdr + 0x40;

	uint16_t out_session_flags = 0; // TODO
	uint16_t out_security_offset = SMB2_HDR_BODY + 0x08;
	SSVAL(outbody, 0x00, 0x08 + 1);
	SSVAL(outbody, 0x02, out_session_flags);
	SSVAL(outbody, 0x04, out_security_offset);
	SSVAL(outbody, 0x06, out_security.size());

	memcpy(outbody + 0x08, out_security.data(), out_security.size());

	x_smbd_conn_reply(smbd_conn, msg, smbd_sess, preauth, outbuf, 0, status, 0x8 + out_security.size());
	return 0;
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
#if 0
static const uint8_t SMB2_24_signing_label[] = "SMB2AESCMAC";
static const uint8_t SMB2_24_signing_context[] = "SmbSign";
static const uint8_t SMB2_24_decryption_label[] = "SMB2AESCCM";
static const uint8_t SMB2_24_decryption_context[] = "ServerIn ";
static const uint8_t SMB2_24_encryption_label[] = "SMB2AESCCM";
static const uint8_t SMB2_24_encryption_context[] = "ServerOut ";
static const uint8_t SMB2_24_application_label[] = "SMB2APP";
static const uint8_t SMB2_24_application_context[] = "SmbRpc";
#endif

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

template <class T>
std::string tostr(const T &v)
{
	std::ostringstream ostr;
	ostr << v;
	return ostr.str();
}

// smbd_smb2_auth_generic_return
static void smbd_sess_auth_succeeded(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess,
		const x_auth_info_t &auth_info)
{
	X_DBG("auth_info %s", tostr(auth_info).c_str());
	
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
	}
}

static inline NTSTATUS x_smbd_sess_update_auth(x_smbd_sess_t *smbd_sess, const uint8_t *inbuf, size_t inlen,
		std::vector<uint8_t> &outbuf, std::shared_ptr<x_auth_info_t>& auth_info)
{
	return smbd_sess->auth->update(inbuf, inlen, outbuf, &smbd_sess->auth_upcall, auth_info);
}

static void smbd_sess_auth_updated(x_smbd_sess_t *smbd_sess, NTSTATUS status,
		std::vector<uint8_t> &out_security, std::shared_ptr<x_auth_info_t> &auth_info)
{
	x_msg_t *msg = smbd_sess->authmsg;
	X_LOG_OP("%ld RESP 0x%x", msg->mid, status.v);

	smbd_sess->authmsg = nullptr;
	x_smbd_conn_t *smbd_conn = smbd_sess->smbd_conn;
	if (NT_STATUS_IS_OK(status)) {
		smbd_sess->state = x_smbd_sess_t::S_ACTIVE;
		smbd_conn->session_list.push_back(smbd_sess);
		smbd_sess_auth_succeeded(smbd_conn, smbd_sess, *auth_info);
		msg->do_signing = true;
		x_smb2_reply_sesssetup(smbd_conn, smbd_sess, NULL, msg, status, out_security);
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		smbd_sess->state = x_smbd_sess_t::S_WAIT_INPUT;
		smbd_sess->timeout = x_tick_add(tick_now, SESSSETUP_TIMEOUT);
		smbd_conn->session_wait_input_list.push_back(smbd_sess);
		x_smb2_reply_sesssetup(smbd_conn, smbd_sess, &smbd_sess->preauth,
				msg, status, out_security);
	} else {
		X_SMB2_REPLY_ERROR(smbd_conn, msg, smbd_sess, 0, status);
		/* release the session */
		x_smbd_sess_release(smbd_sess);
		smbd_sess->decref();
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

static void smbd_sess_auth_updated_func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user)
{
	smbd_sess_auth_updated_evt_t *evt = X_CONTAINER_OF(fdevt_user, smbd_sess_auth_updated_evt_t, base);

	X_ASSERT(!NT_STATUS_EQUAL(evt->status, X_NT_STATUS_INTERNAL_BLOCKED));
	x_smbd_sess_t *smbd_sess = evt->smbd_sess;

	if (smbd_sess->state == x_smbd_sess_t::S_BLOCKED) {
		smbd_conn->session_list.remove(smbd_sess);
		smbd_sess_auth_updated(smbd_sess, evt->status, evt->out_security, evt->auth_info);
	}

	smbd_sess->decref();
	delete evt;
}

static void x_smbd_sess_auth_updated(x_auth_upcall_t *auth_upcall, NTSTATUS status,
		std::vector<uint8_t> &out_security, std::shared_ptr<x_auth_info_t> &auth_info)
{
	x_smbd_sess_t *smbd_sess = X_CONTAINER_OF(auth_upcall, x_smbd_sess_t, auth_upcall);
	X_DBG("smbd_sess=%p, authmsg=%p, status=0x%x", smbd_sess, smbd_sess->authmsg, NT_STATUS_V(status));
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

int x_smb2_process_SESSSETUP(x_smbd_conn_t *smbd_conn, x_msg_t *msg,
		const uint8_t *in_buf, size_t in_len)
{
	// x_smb2_verify_size(msg, X_SMB2_NEGPROT_BODY_LEN);
	if (in_len < 0x40 + 0x19) {
		return -EBADMSG;
	}

	const uint8_t *inhdr = in_buf;
	const uint8_t *inbody = in_buf + 0x40;
	uint64_t in_session_id = BVAL(inhdr, SMB2_HDR_SESSION_ID);
	uint8_t in_flags = CVAL(inbody, 0x02);
	// TODO uint8_t in_security_mode = CVAL(inbody, 0x03);
	uint16_t in_security_offset = SVAL(inbody, 0x0C);
	uint16_t in_security_length = SVAL(inbody, 0x0E);
	// TODO uint64_t in_previous_session_id = BVAL(inbody, 0x10);

	X_LOG_OP("%ld SESSSETUP 0x%lx, 0x%lx", msg->mid);

	if (in_security_offset != (SMB2_HDR_BODY + X_SMB2_SESSSETUP_BODY_LEN)) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, 0, NT_STATUS_INVALID_PARAMETER);
	}
	
	if (in_security_offset + in_security_length > in_len) {
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, 0, NT_STATUS_INVALID_PARAMETER);
	}

	if (in_flags & SMB2_SESSION_FLAG_BINDING) {
		if (smbd_conn->dialect < SMB2_DIALECT_REVISION_222) {
			return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, 0, NT_STATUS_REQUEST_NOT_ACCEPTED);
		}
		return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, 0, NT_STATUS_NOT_SUPPORTED);
	}

	x_smbd_sess_t *smbd_sess;
	if (in_session_id == 0) {
		smbd_sess = x_smbd_sess_create(smbd_conn);
		/* TODO too many session */
		smbd_sess->auth = x_smbd_create_auth(smbd_conn->smbd);
		smbd_sess->auth_upcall.cbs = &smbd_sess_auth_upcall_cbs;
		if (smbd_conn->dialect >= SMB3_DIALECT_REVISION_310) {
			smbd_sess->preauth = smbd_conn->preauth;
		}

	} else {
		smbd_sess = x_smbd_sess_find(in_session_id, smbd_conn);
		if (smbd_sess == nullptr) {
			return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, 0, NT_STATUS_USER_SESSION_DELETED);
		}
		if (smbd_sess->state != x_smbd_sess_t::S_WAIT_INPUT) {
			smbd_sess->decref();
			/* TODO just drop the message, should we reply something for this unexpected message */
			return X_SMB2_REPLY_ERROR(smbd_conn, msg, nullptr, 0, NT_STATUS_INVALID_PARAMETER);
		}
		smbd_sess->decref();
		smbd_conn->session_wait_input_list.remove(smbd_sess);
	}

	if (smbd_conn->dialect >= SMB3_DIALECT_REVISION_310) {
		smbd_sess->preauth.update(in_buf, in_len);
	}

	X_ASSERT(smbd_sess->authmsg == nullptr);
	smbd_sess->incref(); // hold ref for auth_upcall
	smbd_sess->authmsg = msg;
	std::vector<uint8_t> out_security;
	std::shared_ptr<x_auth_info_t> auth_info;
	NTSTATUS status = x_smbd_sess_update_auth(smbd_sess, in_buf + in_security_offset, in_security_length, out_security, auth_info);
	X_DBG("smbd_sess=%p, msg=%p, status=0x%x", smbd_sess, msg, NT_STATUS_V(status));
	if (!NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_BLOCKED)) {
		smbd_sess_auth_updated(smbd_sess, status, out_security, auth_info);
	} else {
		smbd_sess->state = x_smbd_sess_t::S_BLOCKED;
		smbd_sess->incref();
		smbd_conn->session_list.push_back(smbd_sess);
	}
	smbd_sess->decref(); // release create or find
	return 0;
}

