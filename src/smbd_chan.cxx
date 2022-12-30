
#include "smbd.hxx"
#include "smbd_stats.hxx"

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

struct x_smbd_chan_t
{
	/* smbd_chan must hold the ref of smbd_conn through its life,
	 * so smbd_conn is always valid, although it may be terminated
	 */
	explicit x_smbd_chan_t(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess)
		: tick_create(tick_now)
		, smbd_conn(x_smbd_ref_inc(smbd_conn))
		, smbd_sess(x_smbd_ref_inc(smbd_sess)) {
		X_SMBD_COUNTER_INC(chan_create, 1);
	}
	~x_smbd_chan_t() {
		x_smbd_ref_dec(smbd_sess);
		x_smbd_ref_dec(smbd_conn);
		X_SMBD_COUNTER_INC(chan_delete, 1);
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
	x_dlink_t sess_link;
	x_auth_upcall_t auth_upcall;
	x_timerq_entry_t timer;
	const x_tick_t tick_create;

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
	if (x_unlikely(--smbd_chan->refcnt == 0)) {
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

static inline void smbd_chan_unlink_sess(x_smbd_chan_t *smbd_chan,
		x_smbd_sess_t *smbd_sess, bool shutdown)
{
	if (x_smbd_sess_unlink_chan(smbd_sess, &smbd_chan->sess_link, shutdown)) {
		x_smbd_ref_dec(smbd_chan);
	}
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
	// TODO check dialect if (smbd_conn->dialect >= X_SMB2_DIALECT_310) {
	if (!smbd_chan->key_is_valid) {
		smbd_chan->preauth.update(data, length);
	}
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

static void smbd_chan_set_keys(x_smbd_chan_t *smbd_chan,
		const std::vector<uint8_t> &auth_session_key)
{
	const x_array_const_t<char> *derivation_sign_label, *derivation_sign_context,
	      *derivation_encryption_label, *derivation_encryption_context,
	      *derivation_decryption_label, *derivation_decryption_context,
	      *derivation_application_label, *derivation_application_context;

	uint16_t dialect = x_smbd_conn_get_dialect(smbd_chan->smbd_conn);
	const x_array_const_t<char> smb3_context{smbd_chan->preauth.data};
	if (dialect >= X_SMB2_DIALECT_310) {
		derivation_sign_label = &SMB3_10_signing_label;
		derivation_sign_context = &smb3_context;
		derivation_encryption_label = &SMB3_10_encryption_label;
		derivation_encryption_context = &smb3_context;
		derivation_decryption_label = &SMB3_10_decryption_label;
		derivation_decryption_context = &smb3_context;
		derivation_application_label = &SMB3_10_application_label;
		derivation_application_context = &smb3_context;

	} else if (dialect >= X_SMB2_DIALECT_224) {
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
	memcpy(session_key.data(), auth_session_key.data(), std::min(session_key.size(), auth_session_key.size()));
	X_LOG_DBG("session_key=\n%s", x_hex_dump(session_key.data(), session_key.size(), "    ").c_str());
	if (dialect >= X_SMB2_DIALECT_224) {
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
	X_LOG_DBG("signing_key=\n%s", x_hex_dump(smbd_chan->keys.signing_key.data(), smbd_chan->keys.signing_key.size(), "    ").c_str());
}

// smbd_smb2_auth_generic_return
static NTSTATUS smbd_chan_auth_succeeded(x_smbd_chan_t *smbd_chan,
		bool is_bind,
		const x_auth_info_t &auth_info)
{
	X_LOG_DBG("auth_info %s", x_tostr(auth_info).c_str());
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
	smbd_user->account_name = auth_info.account_name;
	smbd_user->logon_domain = auth_info.logon_domain;

	if (!smbd_chan->key_is_valid) {
		smbd_chan_set_keys(smbd_chan, auth_info.session_key);
	}

	x_auth_destroy(smbd_chan->auth);
	smbd_chan->auth = nullptr;

	NTSTATUS status = x_smbd_sess_auth_succeeded(smbd_chan->smbd_sess, is_bind, smbd_user, smbd_chan->keys, auth_info.time_rec);
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
				smbd_chan, new_state, curr_state, old_state);
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
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user)
	{
		smbd_chan_auth_timeout_evt_t *evt = X_CONTAINER_OF(fdevt_user, smbd_chan_auth_timeout_evt_t, base);

		if (smbd_conn) {
			x_smbd_chan_t *smbd_chan = evt->smbd_chan;
			if (smbd_chan->state == x_smbd_chan_t::S_WAIT_INPUT) {
				smbd_chan->state = x_smbd_chan_t::S_FAILED;
				smbd_chan_unlink_conn(smbd_chan, smbd_conn);
				smbd_chan_unlink_sess(smbd_chan,
						smbd_chan->smbd_sess, false);
			}
		}
		delete evt;
	}

	explicit smbd_chan_auth_timeout_evt_t(x_smbd_chan_t *smbd_chan)
		: base(func), smbd_chan(smbd_chan)
	{
	}

	~smbd_chan_auth_timeout_evt_t()
	{
		if (smbd_chan) {
			x_smbd_ref_dec(smbd_chan);
		}
	}

	x_fdevt_user_t base;
	x_smbd_chan_t *smbd_chan;
};

static void smbd_chan_auth_input_timeout(x_timerq_entry_t *timerq_entry)
{
	/* we already have a ref on smbd_chan when adding timer */
	x_smbd_chan_t *smbd_chan = X_CONTAINER_OF(timerq_entry, x_smbd_chan_t, timer);
	X_SMBD_CHAN_POST_USER(smbd_chan, 
			new smbd_chan_auth_timeout_evt_t(smbd_chan));
}

/* this function is in context of smbd_conn */
static NTSTATUS smbd_chan_auth_updated(x_smbd_chan_t *smbd_chan, x_smbd_requ_t *smbd_requ,
		NTSTATUS status,
		bool is_bind,
		const x_auth_info_t &auth_info)
{
	X_LOG_OP("%ld RESP 0x%x", smbd_requ->in_smb2_hdr.mid, NT_STATUS_V(status));

	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		// hold ref for timer, will be dec in timer func
		x_smbd_ref_inc(smbd_chan);
		smbd_chan->state = x_smbd_chan_t::S_WAIT_INPUT;
		x_smbd_add_timer(x_smbd_timer_t::SESSSETUP, &smbd_chan->timer);
		return status;
	} else if (NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_BLOCKED)) {
		return status;
	}

	if (NT_STATUS_IS_OK(status)) {
		status = smbd_chan_auth_succeeded(smbd_chan, is_bind, auth_info);
		if (NT_STATUS_IS_OK(status)) {
			smbd_requ->out_hdr_flags |= X_SMB2_HDR_FLAG_SIGNED;
		}
	}

	if (!NT_STATUS_IS_OK(status)) {
		smbd_chan->state = x_smbd_chan_t::S_FAILED;
		smbd_chan_unlink_conn(smbd_chan, g_smbd_conn_curr);
		smbd_chan_unlink_sess(smbd_chan, smbd_chan->smbd_sess, false);
	}

	return status;
}

struct smbd_chan_auth_upcall_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user)
	{
		smbd_chan_auth_upcall_evt_t *evt = X_CONTAINER_OF(fdevt_user, smbd_chan_auth_upcall_evt_t, base);

		if (smbd_conn) {
			x_smbd_chan_t *smbd_chan = evt->smbd_chan;
			X_ASSERT(smbd_chan->auth_requ);
			x_smbd_ptr_t<x_smbd_requ_t> smbd_requ{std::exchange(smbd_chan->auth_requ, nullptr)};

			if (smbd_chan_set_state(smbd_chan, x_smbd_chan_t::S_PROCESSING,
						x_smbd_chan_t::S_BLOCKED)) {
				NTSTATUS status = smbd_chan_auth_updated(smbd_chan, smbd_requ,
						evt->status, evt->is_bind,
						*evt->auth_info);
				x_smb2_sesssetup_done(smbd_chan->smbd_conn, smbd_requ, status,
						evt->out_security);
			}
		}
		delete evt;
	}

	smbd_chan_auth_upcall_evt_t(x_smbd_chan_t *smbd_chan,
			NTSTATUS status,
			bool is_bind,
			std::vector<uint8_t> &out_security,
			std::shared_ptr<x_auth_info_t> &auth_info)
		: base(func)
		, smbd_chan(smbd_chan), status(status), is_bind(is_bind)
		, out_security(std::move(out_security)), auth_info(auth_info)
	{
	}

	~smbd_chan_auth_upcall_evt_t()
	{
		x_smbd_ref_dec(smbd_chan);
	}

	x_fdevt_user_t base;
	x_smbd_chan_t *const smbd_chan;
	NTSTATUS const status;
	bool const is_bind;
	std::vector<uint8_t> const out_security;
	std::shared_ptr<x_auth_info_t> const auth_info;
};

static void smbd_chan_auth_upcall_func(x_auth_upcall_t *auth_upcall,
		NTSTATUS status,
		bool is_bind,
		std::vector<uint8_t> &out_security,
		std::shared_ptr<x_auth_info_t> &auth_info)
{
	X_ASSERT(!NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_BLOCKED));
	x_smbd_chan_t *smbd_chan = X_CONTAINER_OF(auth_upcall, x_smbd_chan_t, auth_upcall);
	X_LOG_DBG("smbd_chan=%p, status=0x%x", smbd_chan, NT_STATUS_V(status));
	X_SMBD_CHAN_POST_USER(smbd_chan, new smbd_chan_auth_upcall_evt_t(
				smbd_chan, status, is_bind, out_security, auth_info));
}

static const struct x_auth_cbs_t smbd_chan_auth_upcall_cbs = {
	smbd_chan_auth_upcall_func,
};

NTSTATUS x_smbd_chan_update_auth(x_smbd_chan_t *smbd_chan,
		x_smbd_requ_t *smbd_requ,
		const uint8_t *in_security_data,
		uint32_t in_security_length,
		std::vector<uint8_t> &out_security,
		bool is_bind,
		bool new_auth)
{
	if (!smbd_chan->auth) {
		smbd_chan->auth = x_smbd_create_auth(in_security_data, in_security_length);
	}
	if (new_auth) {
		X_ASSERT(smbd_chan->state == x_smbd_chan_t::S_INIT);
	}
       
	if (smbd_chan->state == x_smbd_chan_t::S_WAIT_INPUT) {
		if (!smbd_chan_cancel_timer(smbd_chan)) {
			/* timer is triggered, abort the auth */
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	smbd_chan->state = x_smbd_chan_t::S_PROCESSING;
	X_ASSERT(!smbd_chan->auth_requ);

	std::shared_ptr<x_auth_info_t> auth_info;
	NTSTATUS status = smbd_chan->auth->update(in_security_data, in_security_length,
			is_bind,
			out_security,
			&smbd_chan->auth_upcall, auth_info);
	if (NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_BLOCKED)) {
		X_ASSERT(smbd_chan_set_state(smbd_chan, x_smbd_chan_t::S_BLOCKED, x_smbd_chan_t::S_PROCESSING));
		// hold ref for auth_upcall
		x_smbd_ref_inc(smbd_chan);
		smbd_chan->auth_requ = x_smbd_ref_inc(smbd_requ);
	} else {
		status = smbd_chan_auth_updated(smbd_chan, smbd_requ, status, is_bind, *auth_info);
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

	if (!x_smbd_sess_link_chan(smbd_sess, &smbd_chan->sess_link)) {
		x_smbd_ref_dec(smbd_chan);
		return nullptr;
	}
	x_smbd_ref_inc(smbd_chan); // ref by smbd_sess

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
	smbd_chan_unlink_sess(smbd_chan, smbd_chan->smbd_sess, true);

	/* dec the ref hold by smbd_conn */
	x_smbd_ref_dec(smbd_chan);
}

x_smbd_chan_t *x_smbd_chan_match(x_dlink_t *sess_link, x_smbd_conn_t *smbd_conn)
{
	x_smbd_chan_t *smbd_chan = X_CONTAINER_OF(sess_link, x_smbd_chan_t, sess_link);
	if (smbd_chan->smbd_conn == smbd_conn) {
		return x_smbd_ref_inc(smbd_chan);
	}
	return nullptr;
}

x_smbd_chan_t *x_smbd_chan_get_active(x_dlink_t *sess_link)
{
	x_smbd_chan_t *smbd_chan = X_CONTAINER_OF(sess_link, x_smbd_chan_t, sess_link);
	if (smbd_chan->state == x_smbd_chan_t::S_ACTIVE) {
		return x_smbd_ref_inc(smbd_chan);
	}
	return nullptr;
}

static void smbd_chan_logoff(x_smbd_conn_t *smbd_conn, x_smbd_chan_t *smbd_chan)
{
	smbd_chan_unlink_conn(smbd_chan, smbd_conn);
	if (smbd_chan->state == x_smbd_chan_t::S_WAIT_INPUT) {
		if (!smbd_chan_cancel_timer(smbd_chan)) {
		}
	}
	smbd_chan->state = x_smbd_chan_t::S_DONE;
}

struct smbd_chan_logoff_evt_t
{
	static void func(x_smbd_conn_t *smbd_conn, x_fdevt_user_t *fdevt_user)
	{
		smbd_chan_logoff_evt_t *evt = X_CONTAINER_OF(fdevt_user, smbd_chan_logoff_evt_t, base);
		if (smbd_conn) {
			smbd_chan_logoff(smbd_conn, evt->smbd_chan);
		}
		delete evt;
	}

	explicit smbd_chan_logoff_evt_t(x_smbd_chan_t *smbd_chan)
		: base(func), smbd_chan(smbd_chan)
	{
	}

	~smbd_chan_logoff_evt_t()
	{
		x_smbd_ref_dec(smbd_chan);
	}

	x_fdevt_user_t base;
	x_smbd_chan_t * const smbd_chan;
};

/* triggered by session logoff, may not in context of smbd_conn */
void x_smbd_chan_logoff(x_dlink_t *sess_link, x_smbd_sess_t *smbd_sess)
{
	x_smbd_chan_t *smbd_chan = X_CONTAINER_OF(sess_link, x_smbd_chan_t, sess_link);
	if (g_smbd_conn_curr == smbd_chan->smbd_conn) {
		smbd_chan_logoff(g_smbd_conn_curr, smbd_chan);
		x_smbd_ref_dec(smbd_chan);
	} else {
		X_SMBD_CHAN_POST_USER(smbd_chan, new smbd_chan_logoff_evt_t(smbd_chan));
	}
}

bool x_smbd_chan_post_user(x_smbd_chan_t *smbd_chan, x_fdevt_user_t *fdevt_user, bool always)
{
	return x_smbd_conn_post_user(smbd_chan->smbd_conn, fdevt_user, always);
}
