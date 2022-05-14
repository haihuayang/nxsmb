
#include "smbd.hxx"

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

static std::atomic<uint32_t> g_smbd_chan_count = 0;

struct x_smbd_chan_t
{
	/* smbd_chan must hold the ref of smbd_conn through its life,
	 * so smbd_conn is always valid, although it may be terminated
	 */
	explicit x_smbd_chan_t(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess)
		: smbd_conn(x_smbd_ref_inc(smbd_conn))
		, smbd_sess(x_smbd_ref_inc(smbd_sess)) {
		++g_smbd_chan_count;
	}
	~x_smbd_chan_t() {
		x_smbd_ref_dec(smbd_sess);
		x_smbd_ref_dec(smbd_conn);
		--g_smbd_chan_count;
	}

	enum {
		S_INIT,
		S_PROCESSING,
		S_WAIT_INPUT,
		S_ACTIVE,
		S_BLOCKED,
		S_FAILED,
		S_EXPIRED,
		S_DONE,
	};

	x_dlink_t conn_link;
	x_auth_upcall_t auth_upcall;
	x_timerq_entry_t timer;

	std::atomic<int> refcnt{1};
	std::atomic<uint16_t> state{S_INIT};
	bool key_is_valid = false;

	x_smbd_conn_t * const smbd_conn;
	x_smbd_sess_t * const smbd_sess;
	x_smbd_requ_t *auth_requ = nullptr;
	x_auth_t *auth{};
	x_smb2_preauth_t preauth;
	x_smbd_key_set_t keys;

};

template <>
x_smbd_chan_t *x_smbd_ref_inc(x_smbd_chan_t *smbd_chan)
{
	X_ASSERT(smbd_chan->refcnt++ > 0);
	return smbd_chan;
}

template <>
void x_smbd_ref_dec(x_smbd_chan_t *smbd_chan)
{
	if (unlikely(--smbd_chan->refcnt == 0)) {
		X_LOG_DBG("free smbd_chan %p", smbd_chan);
		delete smbd_chan;
	}
}

x_smbd_conn_t *x_smbd_chan_get_conn(const x_smbd_chan_t *smbd_chan)
{
	return smbd_chan->smbd_conn;
}

static inline void smbd_chan_link_conn(x_smbd_chan_t *smbd_chan, x_smbd_conn_t *smbd_conn)
{
	x_smbd_ref_inc(smbd_chan);
	x_smbd_conn_link_chan(smbd_conn, &smbd_chan->conn_link);
}

static inline void smbd_chan_unlink_conn(x_smbd_chan_t *smbd_chan, x_smbd_conn_t *smbd_conn)
{
	x_smbd_conn_unlink_chan(smbd_conn, &smbd_chan->conn_link);
	x_smbd_ref_dec(smbd_chan);
}

#if 0
x_smbd_conn_t *x_smbd_chan_get_conn(const x_smbd_chan_t *smbd_chan)
{
	return smbd_chan->smbd_conn;
}
#endif
void x_smbd_chan_update_preauth(x_smbd_chan_t *smbd_chan,
		const void *data, size_t length)
{
	// TODO check dialect if (smbd_conn->dialect >= SMB3_DIALECT_REVISION_310) {
	smbd_chan->preauth.update(data, length);
}

const x_smb2_key_t *x_smbd_chan_get_signing_key(x_smbd_chan_t *smbd_chan)
{
	// TODO memory order
	if (smbd_chan->key_is_valid) {
		return &smbd_chan->keys.signing_key;
	}
	return nullptr;
}

bool x_smbd_chan_is_active(const x_smbd_chan_t *smbd_chan)
{
	return smbd_chan->state == x_smbd_chan_t::S_ACTIVE;
}

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
static NTSTATUS smbd_chan_auth_succeeded(x_smbd_chan_t *smbd_chan,
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

	const x_array_const_t<char> *derivation_sign_label, *derivation_sign_context,
	      *derivation_encryption_label, *derivation_encryption_context,
	      *derivation_decryption_label, *derivation_decryption_context,
	      *derivation_application_label, *derivation_application_context;

	uint16_t dialect = x_smbd_conn_get_dialect(smbd_chan->smbd_conn);
	const x_array_const_t<char> smb3_context{smbd_chan->preauth.data};
	if (dialect >= SMB3_DIALECT_REVISION_310) {
		derivation_sign_label = &SMB3_10_signing_label;
		derivation_sign_context = &smb3_context;
		derivation_encryption_label = &SMB3_10_encryption_label;
		derivation_encryption_context = &smb3_context;
		derivation_decryption_label = &SMB3_10_decryption_label;
		derivation_decryption_context = &smb3_context;
		derivation_application_label = &SMB3_10_application_label;
		derivation_application_context = &smb3_context;

	} else if (dialect >= SMB2_DIALECT_REVISION_224) {
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
	if (dialect >= SMB2_DIALECT_REVISION_224) {
		x_smb2_key_derivation(session_key.data(), 16,
				*derivation_sign_label,
				*derivation_sign_context,
				smbd_chan->keys.signing_key);
		x_smb2_key_derivation(session_key.data(), 16,
				*derivation_decryption_label,
				*derivation_decryption_context,
				smbd_chan->keys.decryption_key);
		x_smb2_key_derivation(session_key.data(), 16,
				*derivation_encryption_label,
				*derivation_encryption_context,
				smbd_chan->keys.encryption_key);
		/* TODO encryption nonce */
		x_smb2_key_derivation(session_key.data(), 16,
				*derivation_application_label,
				*derivation_application_context,
				smbd_chan->keys.application_key);
	} else {
		smbd_chan->keys.signing_key = session_key;
	}
	NTSTATUS status = x_smbd_sess_auth_succeeded(smbd_chan->smbd_sess, smbd_user, smbd_chan->keys);
	if (NT_STATUS_IS_OK(status)) {
		// TODO memory order
		smbd_chan->state = x_smbd_chan_t::S_ACTIVE;
		smbd_chan->key_is_valid = true;
	}

	return status;
}

static inline bool smbd_chan_set_state(x_smbd_chan_t *smbd_chan,
		uint16_t new_state, uint16_t curr_state)
{
	uint16_t old_state = curr_state;
	bool ret = std::atomic_compare_exchange_weak_explicit(
			&smbd_chan->state, &old_state, new_state,
			std::memory_order_release,
			std::memory_order_relaxed);
	if (!ret) {
		X_LOG_WARN("smbd_chan=%p new_state=%d expected=%d but is %d",
				new_state, curr_state, old_state);
	}
	return ret;
}

static bool smbd_chan_cancel_timer(x_smbd_chan_t *smbd_chan)
{
	if (x_smbd_cancel_timer(x_smbd_timer_t::SESSSETUP, &smbd_chan->timer)) {
		x_smbd_ref_dec(smbd_chan);
		return true;
	}
	return false;
}

struct smbd_chan_auth_timeout_evt_t
{
	explicit smbd_chan_auth_timeout_evt_t(x_smbd_chan_t *smbd_chan)
		: smbd_chan(smbd_chan) { }

	~smbd_chan_auth_timeout_evt_t() {
		if (smbd_chan) {
			x_smbd_ref_dec(smbd_chan);
		}
	}

	x_fdevt_user_t base;
	x_smbd_chan_t *smbd_chan;
};

static void smbd_chan_auth_timeout_evt_func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool terminated)
{
	smbd_chan_auth_timeout_evt_t *evt = X_CONTAINER_OF(fdevt_user, smbd_chan_auth_timeout_evt_t, base);

	if (!terminated) {
		x_smbd_chan_t *smbd_chan = evt->smbd_chan;
		if (smbd_chan->state == x_smbd_chan_t::S_WAIT_INPUT) {
			smbd_chan->state = x_smbd_chan_t::S_FAILED;
			smbd_chan_unlink_conn(smbd_chan, smbd_conn);
			x_smbd_sess_remove_chan(smbd_chan->smbd_sess, smbd_chan);
		}
	}
	delete evt;
}

static void smbd_chan_auth_input_timeout(x_timerq_entry_t *timerq_entry)
{
	/* we already have a ref on smbd_chan when adding timer */
	x_smbd_chan_t *smbd_chan = X_CONTAINER_OF(timerq_entry, x_smbd_chan_t, timer);
	smbd_chan_auth_timeout_evt_t *evt = new smbd_chan_auth_timeout_evt_t(smbd_chan);
	evt->base.func = smbd_chan_auth_timeout_evt_func;
	if (!x_smbd_conn_post_user_2(smbd_chan->smbd_conn, &evt->base)) {
		/* smbd_conn is done, smbd_chan is decref by deleting evt */
		delete evt;
	}
}

/* this function is in context of smbd_conn */
static NTSTATUS smbd_chan_auth_updated(x_smbd_chan_t *smbd_chan, x_smbd_requ_t *smbd_requ,
		NTSTATUS status,
		std::shared_ptr<x_auth_info_t> &auth_info)
{
	X_LOG_OP("%ld RESP 0x%x", smbd_requ->in_mid, status.v);

	if (NT_STATUS_IS_OK(status)) {
		status = smbd_chan_auth_succeeded(smbd_chan, *auth_info);
		if (NT_STATUS_IS_OK(status)) {
			smbd_requ->out_hdr_flags |= SMB2_HDR_FLAG_SIGNED;
		}
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		// hold ref for timer, will be dec in timer func
		x_smbd_ref_inc(smbd_chan);
		smbd_chan->state = x_smbd_chan_t::S_WAIT_INPUT;
		x_smbd_add_timer(x_smbd_timer_t::SESSSETUP, &smbd_chan->timer);
	}

	return status;
}

struct smbd_chan_auth_upcall_evt_t
{
	smbd_chan_auth_upcall_evt_t(x_smbd_chan_t *smbd_chan,
			NTSTATUS status, std::vector<uint8_t> &out_security,
			std::shared_ptr<x_auth_info_t> &auth_info)
		: smbd_chan(smbd_chan), status(status)
		, out_security(std::move(out_security)), auth_info(auth_info)
	{ }
	~smbd_chan_auth_upcall_evt_t() {
		if (smbd_chan) {
			x_smbd_ref_dec(smbd_chan);
		}
	}

	x_fdevt_user_t base;
	x_smbd_chan_t *smbd_chan;
	NTSTATUS status;
	std::vector<uint8_t> out_security;
	std::shared_ptr<x_auth_info_t> auth_info;
};

static void smbd_chan_auth_upcall_evt_func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool terminated)
{
	smbd_chan_auth_upcall_evt_t *evt = X_CONTAINER_OF(fdevt_user, smbd_chan_auth_upcall_evt_t, base);

	if (!terminated) {
		x_smbd_chan_t *smbd_chan = evt->smbd_chan;
		X_ASSERT(smbd_chan->auth_requ);
		x_smbd_ptr_t<x_smbd_requ_t> smbd_requ{std::exchange(smbd_chan->auth_requ, nullptr)};

		if (smbd_chan_set_state(smbd_chan, x_smbd_chan_t::S_PROCESSING,
					x_smbd_chan_t::S_BLOCKED)) {
			NTSTATUS status = smbd_chan_auth_updated(smbd_chan, smbd_requ, evt->status,
					evt->auth_info);
			x_smb2_sesssetup_done(smbd_chan->smbd_conn, smbd_requ, status, evt->out_security);
		}
	}
	delete evt;
}

static void smbd_chan_auth_upcall_func(x_auth_upcall_t *auth_upcall, NTSTATUS status,
		std::vector<uint8_t> &out_security, std::shared_ptr<x_auth_info_t> &auth_info)
{
	X_ASSERT(!NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_BLOCKED));
	x_smbd_chan_t *smbd_chan = X_CONTAINER_OF(auth_upcall, x_smbd_chan_t, auth_upcall);
	X_LOG_DBG("smbd_chan=%p, status=0x%x", smbd_chan, NT_STATUS_V(status));
	smbd_chan_auth_upcall_evt_t *evt = new smbd_chan_auth_upcall_evt_t(
			smbd_chan, status, out_security, auth_info);
	evt->base.func = smbd_chan_auth_upcall_evt_func;
	if (!x_smbd_conn_post_user_2(smbd_chan->smbd_conn, &evt->base)) {
		delete evt;
	}
}

static const struct x_auth_cbs_t smbd_chan_auth_upcall_cbs = {
	smbd_chan_auth_upcall_func,
};

NTSTATUS x_smbd_chan_update_auth(x_smbd_chan_t *smbd_chan,
		x_smbd_requ_t *smbd_requ,
		const uint8_t *in_security_data,
		uint32_t in_security_length,
		std::vector<uint8_t> &out_security,
		std::shared_ptr<x_auth_info_t> &auth_info,
		bool new_auth)
{
	if (new_auth) {
		X_ASSERT(smbd_chan->state == x_smbd_chan_t::S_INIT);
	} else {
		X_ASSERT(smbd_chan->state == x_smbd_chan_t::S_WAIT_INPUT);
		if (!smbd_chan_cancel_timer(smbd_chan)) {
			/* timer is triggered, abort the auth */
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	smbd_chan->state = x_smbd_chan_t::S_PROCESSING;
	X_ASSERT(!smbd_chan->auth_requ);

	NTSTATUS status = smbd_chan->auth->update(in_security_data, in_security_length,
			out_security,
			&smbd_chan->auth_upcall, auth_info);
	if (NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_BLOCKED)) {
		X_ASSERT(smbd_chan_set_state(smbd_chan, x_smbd_chan_t::S_BLOCKED, x_smbd_chan_t::S_PROCESSING));
		// hold ref for auth_upcall
		x_smbd_ref_inc(smbd_chan);
		smbd_chan->auth_requ = x_smbd_ref_inc(smbd_requ);
	} else {
		status = smbd_chan_auth_updated(smbd_chan, smbd_requ, status, auth_info);
	}
	return status;
}

/* run inside context of smbd_conn */
x_smbd_chan_t *x_smbd_chan_create(x_smbd_sess_t *smbd_sess, x_smbd_conn_t *smbd_conn)
{
	x_smbd_chan_t *smbd_chan = new x_smbd_chan_t(smbd_conn, smbd_sess);
	if (!smbd_chan) {
		return nullptr;
	}

	if (!x_smbd_sess_add_chan(smbd_sess, smbd_chan)) {
		x_smbd_ref_dec(smbd_chan);
		return nullptr;
	}

	smbd_chan->auth = x_smbd_create_auth();
	smbd_chan->auth_upcall.cbs = &smbd_chan_auth_upcall_cbs;
	smbd_chan->timer.func = smbd_chan_auth_input_timeout;
	const x_smb2_preauth_t *preauth = x_smbd_conn_get_preauth(smbd_conn);
	if (preauth) {
		smbd_chan->preauth = *preauth;
	}

	X_LOG_DBG("create smbd_chan %p, smbd_sess %p, smbd_conn %p",
			smbd_chan, smbd_sess, smbd_conn);
	smbd_chan_link_conn(smbd_chan, smbd_conn);
	return smbd_chan;
}

void x_smbd_chan_unlinked(x_dlink_t *conn_link, x_smbd_conn_t *smbd_conn)
{
	/* trigger by smbd_conn, it is already unlinked */
	x_smbd_chan_t *smbd_chan = X_CONTAINER_OF(conn_link, x_smbd_chan_t, conn_link);
	X_ASSERT(smbd_conn == smbd_chan->smbd_conn);
	if (smbd_chan->state == x_smbd_chan_t::S_WAIT_INPUT) {
		if (!smbd_chan_cancel_timer(smbd_chan)) {
		}
	}
	smbd_chan->state = x_smbd_chan_t::S_DONE;
	x_smbd_sess_remove_chan(smbd_chan->smbd_sess, smbd_chan);
	/* dec the ref hold by smbd_conn */
	x_smbd_ref_dec(smbd_chan);
}

struct smbd_chan_logoff_evt_t
{
	smbd_chan_logoff_evt_t(x_smbd_chan_t *smbd_chan)
		: smbd_chan(smbd_chan)
	{ }
	~smbd_chan_logoff_evt_t() {
		if (smbd_chan) {
			x_smbd_ref_dec(smbd_chan);
		}
	}
	x_fdevt_user_t base;
	x_smbd_chan_t *smbd_chan;
};

static void smbd_chan_logoff(x_smbd_conn_t *smbd_conn, x_smbd_chan_t *smbd_chan)
{
	smbd_chan_unlink_conn(smbd_chan, smbd_conn);
	if (smbd_chan->state == x_smbd_chan_t::S_WAIT_INPUT) {
		if (!smbd_chan_cancel_timer(smbd_chan)) {
		}
	}
	smbd_chan->state = x_smbd_chan_t::S_DONE;
}

static void smbd_chan_logoff_evt_func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user, bool terminated)
{
	smbd_chan_logoff_evt_t *evt = X_CONTAINER_OF(fdevt_user, smbd_chan_logoff_evt_t, base);
	if (!terminated) {
		smbd_chan_logoff(smbd_conn, evt->smbd_chan);
	}
	delete evt;
}

void x_smbd_chan_logoff(x_smbd_chan_t *smbd_chan)
{
	if (g_smbd_conn_curr == smbd_chan->smbd_conn) {
		smbd_chan_logoff(g_smbd_conn_curr, smbd_chan);
	} else {
		smbd_chan_logoff_evt_t *evt = new smbd_chan_logoff_evt_t(smbd_chan);
		evt->base.func = smbd_chan_logoff_evt_func;
		if (!x_smbd_conn_post_user_2(smbd_chan->smbd_conn, &evt->base)) {
			delete evt;
		}
	}
}

bool x_smbd_chan_post_user(x_smbd_chan_t *smbd_chan, x_fdevt_user_t *fdevt_user)
{
	return x_smbd_conn_post_user_2(smbd_chan->smbd_conn, fdevt_user);
}
