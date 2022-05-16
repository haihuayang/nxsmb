#include "smbd.hxx"
#include "misc.hxx"
#include "smbd_ntacl.hxx"

enum {
	SESSSETUP_TIMEOUT = 60 * 1000000000l,
};

struct x_smb2_sesssetup_requ_t
{
	uint16_t struct_size;
	uint8_t flags;
	uint8_t security_mode;
	uint32_t capabilities;
	uint32_t channel;
	uint16_t security_buffer_offset;
	uint16_t security_buffer_length;
	uint64_t previous_session;
};

struct x_smb2_sesssetup_resp_t
{
	uint16_t struct_size;
	uint16_t session_flags;
	uint16_t security_buffer_offset;
	uint16_t security_buffer_length;
};



static void x_smb2_reply_sesssetup(x_smbd_conn_t *smbd_conn,
		x_smbd_chan_t *smbd_chan,
		x_smbd_requ_t *smbd_requ,
		uint16_t dialect,
		NTSTATUS status,
		const std::vector<uint8_t> &out_security)
{
	x_bufref_t *bufref = x_bufref_alloc(sizeof(x_smb2_sesssetup_resp_t) +
			out_security.size());
	uint8_t *out_hdr = bufref->get_data();
	uint8_t *out_body = out_hdr + SMB2_HDR_BODY;

	uint16_t out_session_flags = 0; // TODO
	uint16_t out_security_offset = SMB2_HDR_BODY + 0x08;
	x_put_le16(out_body, 0x08 + 1);
	x_put_le16(out_body + 0x02, out_session_flags);
	x_put_le16(out_body + 0x04, out_security_offset);
	x_put_le16(out_body + 0x06, x_convert_assert<uint16_t>(out_security.size()));

	memcpy(out_body + sizeof(x_smb2_sesssetup_resp_t), out_security.data(), out_security.size());

	if (NT_STATUS_IS_OK(status)) {
		smbd_requ->out_hdr_flags |= SMB2_HDR_FLAG_SIGNED;
	}

	x_smb2_reply(smbd_conn, smbd_requ, bufref, bufref, status, 
			SMB2_HDR_BODY + sizeof(x_smb2_sesssetup_resp_t) + out_security.size());

	if (dialect >= SMB3_DIALECT_REVISION_310 && NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		x_smbd_chan_update_preauth(smbd_chan, 
				out_hdr, SMB2_HDR_BODY + sizeof(x_smb2_sesssetup_resp_t) + out_security.size());
	}
}

void x_smb2_sesssetup_done(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ, NTSTATUS status,
		std::vector<uint8_t> &out_security)
{
	/* async done */
	X_LOG_DBG("smbd_requ=%p, status=0x%x", smbd_requ, NT_STATUS_V(status));
	x_smb2_reply_sesssetup(smbd_conn, smbd_requ->smbd_chan, smbd_requ,
			x_smbd_conn_get_dialect(smbd_conn), status, out_security);
	x_smbd_conn_requ_done(smbd_conn, smbd_requ, status);
}

NTSTATUS x_smb2_process_sesssetup(x_smbd_conn_t *smbd_conn, x_smbd_requ_t *smbd_requ)
{
	X_LOG_OP("%ld SESSSETUP 0x%lx, 0x%lx", smbd_requ->in_mid);

	if (smbd_requ->in_requ_len < SMB2_HDR_BODY + sizeof(x_smb2_sesssetup_requ_t) + 1) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}

	const uint8_t *in_hdr = smbd_requ->get_in_data();
	x_smb2_sesssetup_requ_t *requ = (x_smb2_sesssetup_requ_t *)(in_hdr + SMB2_HDR_BODY);

	uint8_t in_flags = requ->flags;
	// Not used for now uint8_t in_security_mode = requ->security_mode;
	uint16_t in_security_offset = X_LE2H16(requ->security_buffer_offset);
	uint16_t in_security_length = X_LE2H16(requ->security_buffer_length);

	if (!x_check_range<uint32_t>(in_security_offset, in_security_length, SMB2_HDR_BODY + sizeof(x_smb2_sesssetup_requ_t), smbd_requ->in_requ_len)) {
		RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
	}
	
	bool new_auth = false;
	/* smbd_sess must be valid if smbd_chan is */
	X_ASSERT(!smbd_requ->smbd_chan || smbd_requ->smbd_sess);
	uint16_t dialect = x_smbd_conn_get_dialect(smbd_conn);

	if (in_flags & SMB2_SESSION_FLAG_BINDING) {
		if (!smbd_requ->is_signed()) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_INVALID_PARAMETER);
		}
		X_ASSERT(smbd_requ->smbd_sess);

		/* TODO verify sign_algo */
		if (dialect < SMB3_DIALECT_REVISION_300) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_REQUEST_NOT_ACCEPTED);
		}

		if (!(x_smbd_conn_get_capabilities(smbd_conn) & SMB2_CAP_MULTI_CHANNEL)) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_REQUEST_NOT_ACCEPTED);
		}

		if (smbd_requ->smbd_chan) {
			if (x_smbd_chan_is_active(smbd_requ->smbd_chan)) {
				/* the chan is already setup */
				RETURN_OP_STATUS(smbd_requ, NT_STATUS_REQUEST_NOT_ACCEPTED);
			}
		} else {
			smbd_requ->smbd_chan = x_smbd_chan_create(smbd_requ->smbd_sess, smbd_conn);
			if (!smbd_requ->smbd_chan) {
				RETURN_OP_STATUS(smbd_requ, NT_STATUS_INSUFFICIENT_RESOURCES);
			}
			new_auth = true;
		}
	} else if (!smbd_requ->smbd_sess) {
		uint64_t session_id;
		smbd_requ->smbd_sess = x_smbd_sess_create(session_id);
		if (!smbd_requ->smbd_sess) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_INSUFFICIENT_RESOURCES);
		}
		smbd_requ->smbd_chan = x_smbd_chan_create(smbd_requ->smbd_sess, smbd_conn);
		if (!smbd_requ->smbd_chan) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_INSUFFICIENT_RESOURCES);
		}
		new_auth = true;
	} else if (!smbd_requ->smbd_chan) {
		smbd_requ->smbd_chan = x_smbd_sess_lookup_chan(smbd_requ->smbd_sess,
				smbd_conn);
		if (!smbd_requ->smbd_chan) {
			RETURN_OP_STATUS(smbd_requ, NT_STATUS_USER_SESSION_DELETED);
		}
	}


#if 0
	if (!smbd_requ->smbd_chan) {
		smbd_requ->smbd_chan = x_smbd_chan_create(smbd_requ->smbd_sess);
		if (
		status = x_smbd_sess_create(&smbd_requ->smbd_sess, &smbd_requ->smbd_chan);
		if (!NT_STATUS_IS_OK(status)) {
		/* TODO too many session */
		smbd_requ->smbd_chan->auth = x_smbd_create_auth();
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
#endif

	x_smbd_chan_update_preauth(smbd_requ->smbd_chan, in_hdr, smbd_requ->in_requ_len);

	std::vector<uint8_t> out_security;
	std::shared_ptr<x_auth_info_t> auth_info;
	NTSTATUS status = x_smbd_chan_update_auth(smbd_requ->smbd_chan, smbd_requ,
			in_hdr + in_security_offset, in_security_length,
			out_security, auth_info, new_auth);
	X_LOG_DBG("smbd_chan=%p, smbd_requ=%p, status=0x%x", smbd_requ->smbd_chan, smbd_requ, NT_STATUS_V(status));
	if (!NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_BLOCKED)) {
		x_smb2_reply_sesssetup(smbd_conn, smbd_requ->smbd_chan, smbd_requ,
				dialect, status, out_security);
	}
	return status;
}
#if 0
	X_ASSERT(smbd_sess->authmsg == nullptr);
static inline NTSTATUS x_smbd_sess_update_auth(x_smbd_sess_t *smbd_sess, const uint8_t *inbuf, size_t inlen,
		std::vector<uint8_t> &outbuf, std::shared_ptr<x_auth_info_t>& auth_info)
{
	smbd_sess->incref(); // hold ref for auth_upcall
	return smbd_sess->auth->update(inbuf, inlen, outbuf, &smbd_sess->auth_upcall, auth_info);
}

static void smbd_chan_auth_updated(x_smbd_chan_t *smbd_chan, x_smbd_requ_t *smbd_requ,
		NTSTATUS status,
		std::vector<uint8_t> &out_security, std::shared_ptr<x_auth_info_t> &auth_info)
{
	X_LOG_OP("%ld RESP 0x%x", smbd_requ->in_mid, status.v);

	x_smbd_conn_t *smbd_conn = smbd_chan->smbd_conn;
	X_SMBD_CONN_ASSERT(smbd_conn);

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

static void x_smbd_chan_auth_updated(x_auth_upcall_t *auth_upcall, NTSTATUS status,
		std::vector<uint8_t> &out_security, std::shared_ptr<x_auth_info_t> &auth_info)
{
	x_smbd_sess_t *smbd_sess = X_CONTAINER_OF(auth_upcall, x_smbd_sess_t, auth_upcall);
	X_LOG_DBG("smbd_sess=%p, status=0x%x", smbd_sess, NT_STATUS_V(status));
	smbd_sess_auth_updated_evt_t *updated_evt = new smbd_sess_auth_updated_evt_t;
	updated_evt->base.func = smbd_chan_auth_updated_func;
	updated_evt->smbd_chan = smbd_chan;
	updated_evt->status = status;
	std::swap(updated_evt->out_security, out_security);
	updated_evt->auth_info = auth_info;
	x_smbd_conn_post_user(smbd_sess->smbd_conn, &updated_evt->base);
}

static const struct x_auth_cbs_t smbd_chan_auth_upcall_cbs = {
	x_smbd_chan_auth_updated,
};

static x_smbd_chan_t *create_chan(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess)
{
	x_smbd_chan_t *smbd_chan = x_smbd_sess_add_chan(smbd_requ->smbd_sess, smbd_conn);
	if (!smbd_chan) {
		return nullptr;
	}

	smbd_chan->auth = x_smbd_create_auth();
	smbd_auth->auth_upcall.cbs = &
	x_smbd_chan_init_auth(smbd_chan, &smbd_sess_auth_upcall_cbs,
			x_smbd_conn_get_preauth(smbd_conn));
	return smbd_chan;
/*
		smbd_requ->smbd_chan->auth = x_smbd_create_auth();
		smbd_sess->auth_upcall.cbs = &smbd_sess_auth_upcall_cbs;
		if (smbd_conn->dialect >= SMB3_DIALECT_REVISION_310) {
			smbd_sess->preauth = smbd_conn->preauth;
		}
				RETURN_OP_STATUS(smbd_requ, NT_STATUS_INSUFFICIENT_RESOURCES);
			}
			*/
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

#if 0
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
#endif
}

#endif
