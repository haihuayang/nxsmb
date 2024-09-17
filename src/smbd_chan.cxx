
#include "smbd.hxx"
#include "smbd_requ.hxx"
#include "smbd_stats.hxx"
#include "smbd_conf.hxx"

static constexpr x_array_const_t<char> SMB2_24_signing_label{"SMB2AESCMAC"};
static constexpr x_array_const_t<char> SMB2_24_signing_context{"SmbSign"};
static constexpr x_array_const_t<char> SMB2_24_decryption_label{"SMB2AESCCM"};
static constexpr x_array_const_t<char> SMB2_24_decryption_context{"ServerIn "};
static constexpr x_array_const_t<char> SMB2_24_encryption_label{"SMB2AESCCM"};
static constexpr x_array_const_t<char> SMB2_24_encryption_context{"ServerOut"};
static constexpr x_array_const_t<char> SMB2_24_application_label{"SMB2APP"};
static constexpr x_array_const_t<char> SMB2_24_application_context{"SmbRpc"};

static constexpr x_array_const_t<char> SMB3_10_signing_label{"SMBSigningKey"};
static constexpr x_array_const_t<char> SMB3_10_decryption_label{"SMBC2SCipherKey"};
static constexpr x_array_const_t<char> SMB3_10_encryption_label{"SMBS2CCipherKey"};
static constexpr x_array_const_t<char> SMB3_10_application_label{"SMBAppKey"};

static long smbd_chan_auth_input_timeout(x_timer_job_t *timer);

struct x_smbd_chan_t
{
	/* smbd_chan must hold the ref of smbd_conn through its life,
	 * so smbd_conn is always valid, although it may be terminated
	 */
	explicit x_smbd_chan_t(x_smbd_conn_t *smbd_conn, x_smbd_sess_t *smbd_sess)
		: tick_create(tick_now)
		, smbd_conn(x_ref_inc(smbd_conn))
		, smbd_sess(x_ref_inc(smbd_sess)) {
		X_SMBD_COUNTER_INC_CREATE(chan, 1);
	}
	~x_smbd_chan_t() {
		if (auth) {
			x_auth_destroy(auth);
		}

		x_ref_dec(smbd_sess);
		x_ref_dec(smbd_conn);
		X_SMBD_COUNTER_INC_DELETE(chan, 1);
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
	x_timer_job_t timer{smbd_chan_auth_input_timeout};
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
x_smbd_chan_t *x_ref_inc(x_smbd_chan_t *smbd_chan)
{
	X_ASSERT(smbd_chan->refcnt++ > 0);
	return smbd_chan;
}

template <>
void x_ref_dec(x_smbd_chan_t *smbd_chan)
{
	if (x_unlikely(--smbd_chan->refcnt == 0)) {
		X_LOG(SMB, DBG, "free smbd_chan %p", smbd_chan);
		delete smbd_chan;
	}
}

x_smbd_conn_t *x_smbd_chan_get_conn(const x_smbd_chan_t *smbd_chan)
{
	return smbd_chan->smbd_conn;
}

static inline void smbd_chan_link_conn(x_smbd_chan_t *smbd_chan, x_smbd_conn_t *smbd_conn)
{
	x_ref_inc(smbd_chan);
	x_smbd_conn_link_chan(smbd_conn, &smbd_chan->conn_link);
}

static inline void smbd_chan_unlink_conn(x_smbd_chan_t *smbd_chan, x_smbd_conn_t *smbd_conn)
{
	x_smbd_conn_unlink_chan(smbd_conn, &smbd_chan->conn_link);
	x_ref_dec(smbd_chan);
}

static inline void smbd_chan_unlink_sess(x_smbd_chan_t *smbd_chan,
		x_smbd_sess_t *smbd_sess, bool shutdown)
{
	if (x_smbd_sess_unlink_chan(smbd_sess, &smbd_chan->sess_link, shutdown)) {
		x_ref_dec(smbd_chan);
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

const x_smb2_key_t *x_smbd_chan_get_signing_key(x_smbd_chan_t *smbd_chan,
		uint16_t *p_signing_algo)
{
	// TODO memory order
	if (smbd_chan->key_is_valid) {
		*p_signing_algo = smbd_chan->keys.signing_algo;
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
	os << "account_name: \"";
	if (auth_info.account_name) {
		os << x_str_todebug(*auth_info.account_name);
	} else {
		os << "<NULL>";
	}
	os << "\"" << std::endl;
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
	uint32_t auth_session_key_len =
		x_convert_assert<uint32_t>(auth_session_key.size());
	X_TODO_ASSERT(auth_session_key_len == 16 ||
			auth_session_key_len == 32);

	const x_array_const_t<char> *derivation_sign_label, *derivation_sign_context,
	      *derivation_encryption_label, *derivation_encryption_context,
	      *derivation_decryption_label, *derivation_decryption_context,
	      /* gcc warn derivation_application_label and derivation_application_context
	       * may be used uninitialized, but why it does not complain other
	       * variables?
	       */
	      *derivation_application_label = nullptr,
	      *derivation_application_context = nullptr;

	uint16_t dialect = x_smbd_conn_get_dialect(smbd_chan->smbd_conn);
	uint16_t cryption_algo = x_smbd_conn_get_cryption_algo(smbd_chan->smbd_conn);
	uint32_t out_cryption_key_len = 16;

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
		out_cryption_key_len = x_smb2_signing_get_key_size(cryption_algo);

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

	X_LOG(SMB, DBG, "session_key=\n%s", x_hex_dump(auth_session_key.data(), auth_session_key.size(), "    ").c_str());
	smbd_chan->keys.signing_algo = x_smbd_conn_curr_get_signing_algo();
	smbd_chan->keys.cryption_algo = x_smbd_conn_curr_get_cryption_algo();
	uint32_t in_cryption_key_len = out_cryption_key_len;
	if (in_cryption_key_len > auth_session_key_len) {
		in_cryption_key_len = auth_session_key_len;
	}

	auto &keys = smbd_chan->keys;
	if (dialect >= X_SMB2_DIALECT_224) {
		x_smb2_key_derivation(auth_session_key.data(), 16,
				*derivation_sign_label,
				*derivation_sign_context,
				keys.signing_key.data(), 16);
		x_smb2_key_derivation(auth_session_key.data(), in_cryption_key_len,
				*derivation_decryption_label,
				*derivation_decryption_context,
				keys.decryption_key.data(), out_cryption_key_len);
		x_smb2_key_derivation(auth_session_key.data(), in_cryption_key_len,
				*derivation_encryption_label,
				*derivation_encryption_context,
				keys.encryption_key.data(), out_cryption_key_len);
		/* TODO encryption nonce */
		x_smb2_key_derivation(auth_session_key.data(), 16,
				*derivation_application_label,
				*derivation_application_context,
				smbd_chan->keys.application_key.data(), 16);
	} else {
		memcpy(keys.signing_key.data(), auth_session_key.data(), 
				keys.signing_key.size());
	}
	X_LOG(SMB, DBG, "signing_key=\n%s", x_hex_dump(smbd_chan->keys.signing_key.data(), smbd_chan->keys.signing_key.size(), "    ").c_str());
}

// smbd_smb2_auth_generic_return
static NTSTATUS smbd_chan_auth_succeeded(x_smbd_chan_t *smbd_chan,
		bool is_bind, uint8_t security_mode,
		const x_auth_info_t &auth_info)
{
	X_LOG(SMB, DBG, "auth_info %s", x_tostr(auth_info).c_str());
	const x_smbd_conf_t &smbd_conf = x_smbd_conf_get_curr();

	X_ASSERT(auth_info.domain_sid.num_auths < auth_info.domain_sid.sub_auths.size());
	
	std::vector<idl::dom_sid> aliases;
	uint64_t priviledge_mask;
	
	x_smbd_group_mapping_get(smbd_conf.group_mapping, aliases, priviledge_mask,
			auth_info);

	auto smbd_user = std::make_shared<x_smbd_user_t>(auth_info,
			aliases, priviledge_mask);

	if (!smbd_chan->key_is_valid) {
		smbd_chan_set_keys(smbd_chan, auth_info.session_key);
	}

	NTSTATUS status = x_smbd_sess_auth_succeeded(smbd_chan->smbd_sess,
			is_bind, security_mode,
			smbd_user, smbd_chan->keys, auth_info.time_rec);
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
		X_LOG(SMB, WARN, "smbd_chan=%p new_state=%d expected=%d but is %d",
				smbd_chan, new_state, curr_state, old_state);
	}
	return ret;
}

static bool smbd_chan_cancel_timer(x_smbd_chan_t *smbd_chan)
{
	if (x_nxfsd_del_timer(&smbd_chan->timer)) {
		x_ref_dec(smbd_chan);
		return true;
	}
	return false;
}

struct smbd_chan_auth_timeout_evt_t
{
	static void func(void *arg, x_fdevt_user_t *fdevt_user)
	{
		x_smbd_conn_t *smbd_conn = (x_smbd_conn_t *)arg;
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
			x_ref_dec(smbd_chan);
		}
	}

	x_fdevt_user_t base;
	x_smbd_chan_t *smbd_chan;
};

static long smbd_chan_auth_input_timeout(x_timer_job_t *timer)
{
	/* we already have a ref on smbd_chan when adding timer */
	x_smbd_chan_t *smbd_chan = X_CONTAINER_OF(timer, x_smbd_chan_t, timer);
	X_SMBD_CHAN_POST_USER(smbd_chan, 
			new smbd_chan_auth_timeout_evt_t(smbd_chan));
	return -1;
}

/* this function is in context of smbd_conn */
static NTSTATUS smbd_chan_auth_updated(x_smbd_chan_t *smbd_chan, x_smbd_requ_t *smbd_requ,
		NTSTATUS status,
		bool is_bind, uint8_t security_mode,
		const x_auth_info_t &auth_info)
{
	X_SMBD_REQU_LOG(OP, smbd_requ,  " %s", x_ntstatus_str(status));

	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		// hold ref for timer, will be dec in timer func
		x_ref_inc(smbd_chan);
		smbd_chan->state = x_smbd_chan_t::S_WAIT_INPUT;
		x_smbd_add_timer(&smbd_chan->timer, x_smbd_timer_id_t::SESSSETUP);
		return status;
	} else if (NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_BLOCKED)) {
		return status;
	}

	if (NT_STATUS_IS_OK(status)) {
		status = smbd_chan_auth_succeeded(smbd_chan,
				is_bind, security_mode, auth_info);
		if (NT_STATUS_IS_OK(status)) {
			smbd_requ->out_hdr_flags |= X_SMB2_HDR_FLAG_SIGNED;
		}
	}

	if (!NT_STATUS_IS_OK(status)) {
		smbd_chan->state = x_smbd_chan_t::S_FAILED;
		smbd_chan_unlink_conn(smbd_chan, g_smbd_conn_curr);
		smbd_chan_unlink_sess(smbd_chan, smbd_chan->smbd_sess, false);
	}

	x_auth_destroy(smbd_chan->auth);
	smbd_chan->auth = nullptr;

	return status;
}

struct smbd_chan_auth_upcall_evt_t
{
	static void func(void *arg, x_fdevt_user_t *fdevt_user)
	{
		x_smbd_conn_t *smbd_conn = (x_smbd_conn_t *)arg;
		smbd_chan_auth_upcall_evt_t *evt = X_CONTAINER_OF(fdevt_user, smbd_chan_auth_upcall_evt_t, base);

		if (smbd_conn) {
			x_smbd_chan_t *smbd_chan = evt->smbd_chan;
			X_ASSERT(smbd_chan->auth_requ);
			x_smbd_requ_t *smbd_requ = smbd_chan->auth_requ;
			smbd_chan->auth_requ = nullptr;

			if (smbd_chan_set_state(smbd_chan, x_smbd_chan_t::S_PROCESSING,
						x_smbd_chan_t::S_BLOCKED)) {
				auto state = smbd_requ->release_state<x_smbd_requ_state_sesssetup_t>();
				NTSTATUS status = smbd_chan_auth_updated(smbd_chan, smbd_requ,
						evt->status,
						evt->is_bind, evt->security_mode,
						*evt->auth_info);
				
				std::swap(state->out_security, evt->out_security);
				state->async_done(smbd_conn, smbd_requ, status);
			}
			x_ref_dec(smbd_requ);
		}
		delete evt;
	}

	smbd_chan_auth_upcall_evt_t(x_smbd_chan_t *smbd_chan,
			NTSTATUS status,
			bool is_bind, uint8_t security_mode,
			std::vector<uint8_t> &out_security,
			std::shared_ptr<x_auth_info_t> &auth_info)
		: base(func)
		, smbd_chan(smbd_chan), status(status)
		, is_bind(is_bind), security_mode(security_mode)
		, out_security(std::move(out_security)), auth_info(auth_info)
	{
	}

	~smbd_chan_auth_upcall_evt_t()
	{
		x_ref_dec(smbd_chan);
	}

	x_fdevt_user_t base;
	x_smbd_chan_t *const smbd_chan;
	NTSTATUS const status;
	bool const is_bind;
	uint8_t const security_mode;
	std::vector<uint8_t> out_security;
	std::shared_ptr<x_auth_info_t> const auth_info;
};

static void smbd_chan_auth_upcall_func(x_auth_upcall_t *auth_upcall,
		NTSTATUS status,
		bool is_bind, uint8_t security_mode,
		std::vector<uint8_t> &out_security,
		std::shared_ptr<x_auth_info_t> &auth_info)
{
	X_ASSERT(!NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_BLOCKED));
	x_smbd_chan_t *smbd_chan = X_CONTAINER_OF(auth_upcall, x_smbd_chan_t, auth_upcall);
	X_LOG(SMB, DBG, "smbd_chan=%p, status=0x%x", smbd_chan, NT_STATUS_V(status));
	X_SMBD_CHAN_POST_USER(smbd_chan, new smbd_chan_auth_upcall_evt_t(
				smbd_chan, status, is_bind, security_mode,
				out_security, auth_info));
}

static const struct x_auth_cbs_t smbd_chan_auth_upcall_cbs = {
	smbd_chan_auth_upcall_func,
};

NTSTATUS x_smbd_chan_update_auth(x_smbd_chan_t *smbd_chan,
		x_smbd_requ_t *smbd_requ,
		const uint8_t *in_security_data,
		uint32_t in_security_length,
		std::vector<uint8_t> &out_security,
		bool is_bind, uint8_t security_mode,
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
			is_bind, security_mode,
			out_security,
			&smbd_chan->auth_upcall, auth_info);
	if (NT_STATUS_EQUAL(status, X_NT_STATUS_INTERNAL_BLOCKED)) {
		X_ASSERT(smbd_chan_set_state(smbd_chan, x_smbd_chan_t::S_BLOCKED, x_smbd_chan_t::S_PROCESSING));
		// hold ref for auth_upcall
		x_ref_inc(smbd_chan);
		smbd_chan->auth_requ = x_ref_inc(smbd_requ);
	} else {
		status = smbd_chan_auth_updated(smbd_chan, smbd_requ, status,
				is_bind, security_mode, *auth_info);
	}
	return status;
}

/* run inside context of smbd_conn */
x_smbd_chan_t *x_smbd_chan_create(x_smbd_sess_t *smbd_sess, x_smbd_conn_t *smbd_conn)
{
	x_smbd_chan_t *smbd_chan = new x_smbd_chan_t(smbd_conn, smbd_sess);
	if (!smbd_chan) {
		X_SMBD_COUNTER_INC(fail_alloc_chan, 1);
		return nullptr;
	}

	if (!x_smbd_sess_link_chan(smbd_sess, &smbd_chan->sess_link)) {
		x_ref_dec(smbd_chan);
		return nullptr;
	}
	x_ref_inc(smbd_chan); // ref by smbd_sess

	smbd_chan->auth_upcall.cbs = &smbd_chan_auth_upcall_cbs;
	const x_smb2_preauth_t *preauth = x_smbd_conn_get_preauth(smbd_conn);
	if (preauth) {
		smbd_chan->preauth = *preauth;
	}

	X_LOG(SMB, DBG, "create smbd_chan %p, smbd_sess %p, smbd_conn %p",
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
	x_ref_dec(smbd_chan);
}

x_smbd_chan_t *x_smbd_chan_match(x_dlink_t *sess_link, x_smbd_conn_t *smbd_conn)
{
	x_smbd_chan_t *smbd_chan = X_CONTAINER_OF(sess_link, x_smbd_chan_t, sess_link);
	if (smbd_chan->smbd_conn == smbd_conn) {
		return x_ref_inc(smbd_chan);
	}
	return nullptr;
}

x_smbd_chan_t *x_smbd_chan_get_active(x_dlink_t *sess_link)
{
	x_smbd_chan_t *smbd_chan = X_CONTAINER_OF(sess_link, x_smbd_chan_t, sess_link);
	if (smbd_chan->state == x_smbd_chan_t::S_ACTIVE) {
		return x_ref_inc(smbd_chan);
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
	static void func(void *arg, x_fdevt_user_t *fdevt_user)
	{
		x_smbd_conn_t *smbd_conn = (x_smbd_conn_t *)arg;
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
		x_ref_dec(smbd_chan);
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
		x_ref_dec(smbd_chan);
	} else {
		X_SMBD_CHAN_POST_USER(smbd_chan, new smbd_chan_logoff_evt_t(smbd_chan));
	}
}

bool x_smbd_chan_post_user(x_smbd_chan_t *smbd_chan, x_fdevt_user_t *fdevt_user, bool always)
{
	return x_smbd_conn_post_user(smbd_chan->smbd_conn, fdevt_user, always);
}


static std::vector<x_dom_sid_with_attrs_t> merge(
		const std::vector<x_dom_sid_with_attrs_t> &other_sids,
		const std::vector<idl::dom_sid> &aliases)
{
	std::vector<x_dom_sid_with_attrs_t> ret = other_sids;
	for (auto &sid: aliases) {
		bool found = false;
		for (auto &other: other_sids) {
			if (other.sid == sid) {
				found = true;
				break;
			}
		}
		if (!found) {
			ret.push_back({sid, 0});
		}
	}
	return ret;
}

x_smbd_user_t::x_smbd_user_t(const x_auth_info_t &auth_info,
		const std::vector<idl::dom_sid> &aliases,
		uint64_t priviledge_mask)
	: is_anonymous(auth_info.is_anonymous)
	, domain_sid(auth_info.domain_sid)
	, uid(auth_info.rid), gid(auth_info.primary_gid)
	, group_rids(auth_info.group_rids)
	, other_sids(merge(auth_info.other_sids, aliases))
	, priviledge_mask(priviledge_mask)
	, account_name(auth_info.account_name)
	, logon_domain(auth_info.logon_domain)
{
}

