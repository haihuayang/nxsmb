
#include "smbd.hxx"
#include "include/idtable.hxx"
#include "smbd_ctrl.hxx"
#include "smbd_stats.hxx"
#include "smbd_conf.hxx"
#include "smbd_dcerpc_srvsvc.hxx"


using smbd_sess_table_t = x_idtable_t<x_smbd_sess_t, x_idtable_64_traits_t>;
static smbd_sess_table_t *g_smbd_sess_table;

struct x_smbd_sess_t
{
	enum { MAX_CHAN_COUNT = 32, };
	x_smbd_sess_t() : tick_create(tick_now)
		, machine_name{x_smbd_conn_curr_name()}
	{
		X_SMBD_COUNTER_INC(sess_create, 1);
	}
	~x_smbd_sess_t() {
		X_SMBD_COUNTER_INC(sess_delete, 1);
	}

	const uint64_t tick_create;
	std::mutex mutex;
	std::shared_ptr<x_smbd_user_t> smbd_user;
	uint64_t id;
	enum {
		S_INIT,
		S_ACTIVE,
		S_DONE,
	} state = S_INIT;
	// uint16_t security_mode = 0;
	bool signing_required = false;
	bool key_is_valid = false;
	uint8_t chan_count = 0;
	x_ddlist_t chan_list;
	x_ddlist_t tcon_list;

	x_smbd_key_set_t keys;
	uint64_t tick_expired;
	const std::shared_ptr<std::u16string> machine_name;
};

template <>
x_smbd_sess_t *x_smbd_ref_inc(x_smbd_sess_t *smbd_sess)
{
	g_smbd_sess_table->incref(smbd_sess->id);
	return smbd_sess;
}

template <>
void x_smbd_ref_dec(x_smbd_sess_t *smbd_sess)
{
	g_smbd_sess_table->decref(smbd_sess->id);
}

static bool match_user(const x_smbd_user_t &u1, const x_smbd_user_t &u2)
{
	return u1.uid == u2.uid && u1.domain_sid == u2.domain_sid;
}

x_smbd_sess_t *x_smbd_sess_create(uint64_t &id)
{
	x_smbd_sess_t *smbd_sess = new x_smbd_sess_t;
	if (!g_smbd_sess_table->store(smbd_sess, smbd_sess->id)) {
		delete smbd_sess;
		return nullptr;
	}
	X_LOG_DBG("0x%lx %p", id, smbd_sess);
	return smbd_sess;
}

x_smbd_sess_t *x_smbd_sess_lookup(NTSTATUS &status,
		uint64_t id, const x_smb2_uuid_t &client_guid)
{
	/* skip client_guid checking, since session bind is signed,
	 * the check does not improve security
	 */
	auto [found, smbd_sess] = g_smbd_sess_table->lookup(id);
	if (!found) {
		return nullptr;
	}

	if (tick_now > smbd_sess->tick_expired) {
		status = NT_STATUS_NETWORK_SESSION_EXPIRED;
	} else {
		status = NT_STATUS_OK;
	}
	return smbd_sess;
}

uint64_t x_smbd_sess_get_id(const x_smbd_sess_t *smbd_sess)
{
	return smbd_sess->id;
}

bool x_smbd_sess_is_signing_required(const x_smbd_sess_t *smbd_sess)
{
	return smbd_sess->signing_required;
}

std::shared_ptr<x_smbd_user_t> x_smbd_sess_get_user(const x_smbd_sess_t *smbd_sess)
{
	return smbd_sess->smbd_user;
}

const x_smb2_key_t *x_smbd_sess_get_signing_key(const x_smbd_sess_t *smbd_sess)
{
	// TODO memory order
	if (smbd_sess->key_is_valid) {
		return &smbd_sess->keys.signing_key;
	}
	return nullptr;
}

bool x_smbd_sess_link_chan(x_smbd_sess_t *smbd_sess, x_dlink_t *link)
{
	std::lock_guard<std::mutex> lock(smbd_sess->mutex);
	if (smbd_sess->state == x_smbd_sess_t::S_DONE) {
		return false;
	}
	if (smbd_sess->chan_count >= x_smbd_sess_t::MAX_CHAN_COUNT) {
		return false;
	}
	
	smbd_sess->chan_list.push_back(link);
	++smbd_sess->chan_count;
	return true;
}

template <class L>
static void smbd_sess_terminate(x_smbd_sess_t *smbd_sess, L &lock, bool shutdown)
{
	x_dlink_t *link;
	smbd_sess->smbd_user = nullptr;
	g_smbd_sess_table->remove(smbd_sess->id);

	while ((link = smbd_sess->chan_list.get_front()) != nullptr) {
		smbd_sess->chan_list.remove(link);
		--smbd_sess->chan_count;
		lock.unlock();
		x_smbd_chan_logoff(link, smbd_sess);
		lock.lock();
	}

	X_ASSERT(smbd_sess->chan_count == 0);

	while ((link = smbd_sess->tcon_list.get_front()) != nullptr) {
		smbd_sess->tcon_list.remove(link);
		lock.unlock();
		x_smbd_tcon_unlinked(link, smbd_sess, shutdown);
		lock.lock();
	}
}

bool x_smbd_sess_unlink_chan(x_smbd_sess_t *smbd_sess, x_dlink_t *link,
		bool shutdown)
{
	std::unique_lock<std::mutex> lock(smbd_sess->mutex);
	if (!link->is_valid()) {
		return false;
	}
	smbd_sess->chan_list.remove(link);
	if (--smbd_sess->chan_count == 0) {
		if (smbd_sess->state != x_smbd_sess_t::S_DONE) {
			smbd_sess->state = x_smbd_sess_t::S_DONE;
			smbd_sess_terminate(smbd_sess, lock, shutdown);
		}
	}
	return true;
}

x_smbd_chan_t *x_smbd_sess_lookup_chan(x_smbd_sess_t *smbd_sess, x_smbd_conn_t *smbd_conn)
{
	x_dlink_t *link;
	std::lock_guard<std::mutex> lock(smbd_sess->mutex);
	for (link = smbd_sess->chan_list.get_front(); link; link = link->get_next()) {
		x_smbd_chan_t *smbd_chan = x_smbd_chan_match(link, smbd_conn);
		if (smbd_chan) {
			return smbd_chan;
		}
	}
	return nullptr;
}

x_smbd_chan_t *x_smbd_sess_get_active_chan(x_smbd_sess_t *smbd_sess)
{
	x_dlink_t *link;
	std::lock_guard<std::mutex> lock(smbd_sess->mutex);
	for (link = smbd_sess->chan_list.get_front(); link; link = link->get_next()) {
		x_smbd_chan_t *smbd_chan = x_smbd_chan_get_active(link);
		if (smbd_chan) {
			return smbd_chan;
		}
	}
	return nullptr;
}

bool x_smbd_sess_link_tcon(x_smbd_sess_t *smbd_sess, x_dlink_t *link)
{
	std::lock_guard<std::mutex> lock(smbd_sess->mutex);
	if (smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		return false;
	}
	smbd_sess->tcon_list.push_back(link);
	return true;
}

/* called by smb2_tdis */
bool x_smbd_sess_unlink_tcon(x_smbd_sess_t *smbd_sess, x_dlink_t *link)
{
	std::lock_guard<std::mutex> lock(smbd_sess->mutex);
	if (link->is_valid()) {
		smbd_sess->tcon_list.remove(link);
		return true;
	}
	return false;
}

NTSTATUS x_smbd_sess_auth_succeeded(x_smbd_sess_t *smbd_sess,
		bool is_bind,
		std::shared_ptr<x_smbd_user_t> &smbd_user,
		const x_smbd_key_set_t &keys,
		uint32_t time_rec)
{
	std::lock_guard<std::mutex> lock(smbd_sess->mutex);

	if (is_bind) {
		X_ASSERT(smbd_sess->smbd_user);
		if (!match_user(*smbd_user, *smbd_sess->smbd_user)) {
			return NT_STATUS_ACCESS_DENIED;
		}
	} else {
		smbd_sess->smbd_user = smbd_user;
		if (!smbd_sess->key_is_valid) {
			smbd_sess->keys = keys;
			smbd_sess->key_is_valid = true;
		}
		smbd_sess->state = x_smbd_sess_t::S_ACTIVE;
		auto smbd_conf = x_smbd_conf_get();
		time_rec = std::min(time_rec, smbd_conf->max_session_expiration);
		if (time_rec == X_INFINITE) {
			smbd_sess->tick_expired = UINT64_MAX;
		} else {
			smbd_sess->tick_expired = smbd_sess->tick_create + 
				(uint64_t(time_rec) * X_NSEC_PER_SEC);
			if (smbd_sess->tick_expired < smbd_sess->tick_create) {
				smbd_sess->tick_expired = UINT64_MAX;
			}
		}
	}
	return NT_STATUS_OK;
}

static NTSTATUS smbd_sess_logoff(x_smbd_sess_t *smbd_sess, bool shutdown)
{
	std::unique_lock<std::mutex> lock(smbd_sess->mutex);
	if (smbd_sess->state != x_smbd_sess_t::S_ACTIVE) {
		return NT_STATUS_USER_SESSION_DELETED;
	}
	smbd_sess->state = x_smbd_sess_t::S_DONE;

	smbd_sess_terminate(smbd_sess, lock, shutdown);
	return NT_STATUS_OK;
}

NTSTATUS x_smbd_sess_logoff(x_smbd_sess_t *smbd_sess)
{
	return smbd_sess_logoff(smbd_sess, true);
}

// smb2srv_session_close_previous_send
void x_smbd_sess_close_previous(const x_smbd_sess_t *curr_sess, uint64_t prev_session_id)
{
	if (prev_session_id == curr_sess->id) {
		return;
	}

	auto [found, prev_sess] = g_smbd_sess_table->lookup(prev_session_id);
	if (!found) {
		return;
	}

	X_ASSERT(curr_sess->smbd_user);
	if (prev_sess->smbd_user && match_user(*curr_sess->smbd_user, *prev_sess->smbd_user)) {
		smbd_sess_logoff(prev_sess, true);
	}
	x_smbd_ref_dec(prev_sess);
}

bool x_smbd_sess_post_user(x_smbd_sess_t *smbd_sess, x_fdevt_user_t *evt)
{
	x_dlink_t *link;
	bool posted = false;
	auto lock = std::lock_guard(smbd_sess->mutex);
	for (link = smbd_sess->chan_list.get_front(); link; link = link->get_next()) {
		x_smbd_chan_t *smbd_chan = x_smbd_chan_get_active(link);
		if (!smbd_chan) {
			continue;
		}
		posted = x_smbd_chan_post_user(smbd_chan, evt, false);
		x_smbd_ref_dec(smbd_chan);
		if (posted) {
			return true;
		}
	}
	return false;
}

int x_smbd_sess_table_init(uint32_t count)
{
	g_smbd_sess_table = new smbd_sess_table_t(count);
	return 0;
}

struct x_smbd_sess_list_t : x_smbd_ctrl_handler_t
{
	x_smbd_sess_list_t() : iter(g_smbd_sess_table->iter_start()) {
	}
	bool output(std::string &data) override;
	smbd_sess_table_t::iter_t iter;
};

bool x_smbd_sess_list_t::output(std::string &data)
{
	std::ostringstream os;

	bool ret = g_smbd_sess_table->iter_entry(iter, [&os](const x_smbd_sess_t *smbd_sess) {
			std::shared_ptr<x_smbd_user_t> smbd_user = smbd_sess->smbd_user;
			/* TODO list channels */
			os << idl::x_hex_t<uint64_t>(smbd_sess->id);
			if (smbd_user) {
				os << ' ' << smbd_user->domain_sid << ' ' << smbd_user->uid << ' ' << smbd_user->gid;
			} else {
				os << " - -";
			}
			os << std::endl;
			return true;
		});
	if (ret) {
		data = os.str(); // TODO avoid copying
		return true;
	} else {
		return false;
	}
}

x_smbd_ctrl_handler_t *x_smbd_sess_list_create()
{
	return new x_smbd_sess_list_t;
}

uint32_t x_smbd_sess_get_count()
{
	return g_smbd_sess_table->alloc_count;
}

static inline void smbd_sess_to_sess_info(std::vector<idl::srvsvc_NetSessInfo0> &array,
		const x_smbd_sess_t *smbd_sess, const x_tick_t now)
{
	array.push_back(idl::srvsvc_NetSessInfo0{
			smbd_sess->machine_name,
			});
}

static inline void smbd_sess_to_sess_info(std::vector<idl::srvsvc_NetSessInfo1> &array,
		const x_smbd_sess_t *smbd_sess, const x_tick_t now)
{
	std::shared_ptr<x_smbd_user_t> smbd_user = smbd_sess->smbd_user;
	array.push_back(idl::srvsvc_NetSessInfo1{
			smbd_sess->machine_name,
			smbd_user->account_name,
			1, // TODO num_open
			x_convert<uint32_t>((now - smbd_sess->tick_create) / X_NSEC_PER_SEC),
			0, // TODO idle time
			0, // user_flags
			});
}

static inline void smbd_sess_to_sess_info(std::vector<idl::srvsvc_NetSessInfo2> &array,
		const x_smbd_sess_t *smbd_sess, const x_tick_t now)
{
	std::shared_ptr<x_smbd_user_t> smbd_user = smbd_sess->smbd_user;
	array.push_back(idl::srvsvc_NetSessInfo2{
			smbd_sess->machine_name,
			smbd_user->account_name,
			1, // TODO num_open
			x_convert<uint32_t>((now - smbd_sess->tick_create) / X_NSEC_PER_SEC),
			0, // TODO idle time
			0, // user_flags
			nullptr,
			});
}

static inline void smbd_sess_to_sess_info(std::vector<idl::srvsvc_NetSessInfo10> &array,
		const x_smbd_sess_t *smbd_sess, const x_tick_t now)
{
	std::shared_ptr<x_smbd_user_t> smbd_user = smbd_sess->smbd_user;
	array.push_back(idl::srvsvc_NetSessInfo10{
			smbd_sess->machine_name,
			smbd_user->account_name,
			x_convert<uint32_t>((now - smbd_sess->tick_create) / X_NSEC_PER_SEC),
			0, // TODO idle time
			});
}

static inline void smbd_sess_to_sess_info(std::vector<idl::srvsvc_NetSessInfo502> &array,
		const x_smbd_sess_t *smbd_sess, const x_tick_t now)
{
	std::shared_ptr<x_smbd_user_t> smbd_user = smbd_sess->smbd_user;
	array.push_back(idl::srvsvc_NetSessInfo502{
			smbd_sess->machine_name,
			smbd_user->account_name,
			1, // TODO num_open
			x_convert<uint32_t>((now - smbd_sess->tick_create) / X_NSEC_PER_SEC),
			0, // TODO idle time
			0, // user_flags
			nullptr,
			nullptr,
			});
}

template <typename T>
static WERROR smbd_sess_enum(std::vector<T> &array)
{
	smbd_sess_table_t::iter_t iter = g_smbd_sess_table->iter_start();
	auto now = tick_now;
	g_smbd_sess_table->iterate(iter, [now, &array](x_smbd_sess_t *smbd_sess) {
			smbd_sess_to_sess_info(array, smbd_sess, now);
			return true;
		});
	return WERR_OK;
}

WERROR x_smbd_net_enum(idl::srvsvc_NetSessEnum &arg,
		std::vector<idl::srvsvc_NetSessInfo0> &array)
{
	return smbd_sess_enum(array);
}

WERROR x_smbd_net_enum(idl::srvsvc_NetSessEnum &arg,
		std::vector<idl::srvsvc_NetSessInfo1> &array)
{
	return smbd_sess_enum(array);
}

WERROR x_smbd_net_enum(idl::srvsvc_NetSessEnum &arg,
		std::vector<idl::srvsvc_NetSessInfo2> &array)
{
	return smbd_sess_enum(array);
}

WERROR x_smbd_net_enum(idl::srvsvc_NetSessEnum &arg,
		std::vector<idl::srvsvc_NetSessInfo10> &array)
{
	return smbd_sess_enum(array);
}

WERROR x_smbd_net_enum(idl::srvsvc_NetSessEnum &arg,
		std::vector<idl::srvsvc_NetSessInfo502> &array)
{
	return smbd_sess_enum(array);
}

static inline void smbd_sess_del_if(x_smbd_sess_t *smbd_sess,
		const std::u16string *user, const char16_t *client)
{
	auto &smbd_user = smbd_sess->smbd_user;
	if (user && smbd_user->account_name &&
			!x_strcase_equal(*user, *smbd_user->account_name)) {
		return;
	}

	if (client && !x_strcase_equal(client, *smbd_sess->machine_name)) {
		return;
	}

	smbd_sess_logoff(smbd_sess, false);
}

void x_smbd_net_sess_del(const std::u16string *user, const std::u16string *client)
{
	const char16_t *cclient = nullptr;
	if (client) {
		cclient = client->c_str();
		if (cclient[0] == u'\\' && cclient[1] == u'\\') {
			cclient += 2;
		}
	}

	smbd_sess_table_t::iter_t iter = g_smbd_sess_table->iter_start();
	g_smbd_sess_table->iterate(iter, [user, cclient](x_smbd_sess_t *smbd_sess) {
			smbd_sess_del_if(smbd_sess, user, cclient);
			return true;
		});
}
